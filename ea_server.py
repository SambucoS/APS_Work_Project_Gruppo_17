"""
ea_server.py — Electoral Authority (EA).

Responsibilities (WP2 §Actors, Phases 3-4):
  * Generate / persist (SKEA, PKEA); split SKEA via Shamir at startup.
  * Intake: verify the AS-signed token, enforce expiry/election_id/scope,
    anti-replay on token_id (O(1) set), append ciphertext to the PBB, return a
    signed receipt. (WP4 v2: no `role` check — the token has no role field.)
  * Scrutiny: freeze, Merkle-commit, reconstruct SKEA from t shares, shuffle
    (Fisher-Yates with secrets.randbelow), decrypt, validate, tally, publish.

The EA holds PKAS (preloaded out-of-band, WP2 §Key Management) to verify tokens.

Run `python ea_server.py` for the built-in self-tests.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

import crypto_utils
import shamir
from as_server import decode_signed_token
from pbb import PBB, MerkleTree

ELECTION_ID = "UNISA-CONS-STUD-2026"
VALID_LISTS = ["LISTA_01", "LISTA_02", "LISTA_03"]


class BallotRejected(Exception):
    """Raised when the EA rejects a B_packet at intake."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class ElectoralAuthority:
    def __init__(
        self,
        pkas,
        shamir_t: int = 3,
        shamir_n: int = 5,
        expected_election_id: str = ELECTION_ID,
        allowed_scopes: tuple[str, ...] = ("STUDENT",),
    ):
        """`pkas` is the AS public key (preloaded out-of-band).

        `expected_election_id` / `allowed_scopes` (WP4 revision) constrain which
        tokens this EA instance accepts at intake. A token whose eligible_scope
        is "ANY" is accepted regardless (wildcard for mixed-body elections).
        """
        self._private_key, self.public_key = crypto_utils.generate_rsa_keypair()
        self._pkas = pkas
        self._expected_election_id = expected_election_id
        self._allowed_scopes = set(allowed_scopes)

        # Split SKEA into n Shamir shares at startup (WP2 §SKEA threshold).
        skea_bytes = crypto_utils.private_key_to_bytes(self._private_key)
        self.shamir_t = shamir_t
        self.shamir_n = shamir_n
        self.skea_shares = shamir.split(skea_bytes, shamir_t, shamir_n)

        # PBB + anti-replay set + frozen flag.
        self.pbb = PBB()
        self._spent_tokens: set[str] = set()  # O(1) anti-replay (WP2 Phase 3.4)
        self._frozen = False

        # Receipts list keeps leaf hashes in PBB order (for Merkle build).
        self._leaf_hashes: list[bytes] = []

    # --- key persistence ---
    def save_keys(self, priv_path: str, pub_path: str) -> None:
        crypto_utils.save_private_key(self._private_key, priv_path)
        crypto_utils.save_public_key(self.public_key, pub_path)

    # ------------------------------------------------------------------ #
    # Phase 3 — Ballot intake
    # ------------------------------------------------------------------ #
    def submit_ballot(self, b_packet: dict) -> dict:
        """Process a B_packet; return a receipt or raise BallotRejected."""
        if self._frozen:
            raise BallotRejected("polls are frozen; no new ballots accepted")

        # 3.1 parse packet.
        try:
            ciphertext = bytes.fromhex(b_packet["ciphertext"])
            token_wire = b_packet["token"]
            if isinstance(token_wire, str):
                token_wire = token_wire.encode()
        except (KeyError, ValueError) as exc:
            raise BallotRejected(f"malformed B_packet: {exc}") from exc

        token_json_bytes, signature = decode_signed_token(token_wire)

        # 3.2 verify AS signature on token.
        if not crypto_utils.rsa_pss_verify(self._pkas, signature, token_json_bytes):
            raise BallotRejected("invalid token signature")

        token = json.loads(token_json_bytes)

        # 3.3 expiry. (WP4 v2: the `role` check is gone — there is no role field;
        # the AS issues a single token type and all gating lives here on the EA.)
        try:
            expires_at = datetime.fromisoformat(token["expires_at"])
        except (KeyError, ValueError) as exc:
            raise BallotRejected(f"bad expires_at: {exc}") from exc
        if expires_at <= _now_utc():
            raise BallotRejected("token expired")

        # 3.3b election binding + voter-category scope (WP4 revision).
        if token.get("election_id") != self._expected_election_id:
            raise BallotRejected(
                f"token election_id not valid: {token.get('election_id')!r}"
            )
        scope = token.get("eligible_scope")
        if scope != "ANY" and scope not in self._allowed_scopes:
            raise BallotRejected(f"eligible_scope not admitted: {scope!r}")

        token_id = token.get("token_id")
        if not token_id:
            raise BallotRejected("token missing token_id")

        # 3.4 anti-replay (O(1) set membership).
        if token_id in self._spent_tokens:
            # WP4 v2: informative message replaces the old OBSERVER behaviour —
            # the voter learns they already voted directly from the EA's reply.
            raise BallotRejected(
                "token already spent: your vote was recorded previously. "
                "Use your receipt to verify individually against the public PBB."
            )
        # 3.5 mark spent.
        self._spent_tokens.add(token_id)

        # 3.6 append ciphertext + token to PBB (hash-pointer chain).
        # Publishing the token lets auditors re-verify its PSS signature under
        # PKAS at universal verification (Phase 6.3).
        # WP4 v2 PRIVACY NOTE: the token_id is now a deterministic HMAC of the
        # voter identity, so the holder of the AS hmac_secret can match these
        # published token_ids back to identities (identity -> ciphertext). This
        # weakens the original ballot-secrecy guarantee — see
        # crypto_utils.derive_token_id and the WP4 notes for the full tradeoff.
        self.pbb.append(ciphertext, token_wire)

        # 3.7 compute leaf hash.
        leaf_hash = crypto_utils.sha256(ciphertext)
        self._leaf_hashes.append(leaf_hash)

        # 3.8 sign leaf hash under SKEA -> receipt.
        ea_signature = crypto_utils.rsa_pss_sign(self._private_key, leaf_hash)
        return {
            "leaf_hash": leaf_hash.hex(),
            "ea_signature": ea_signature.hex(),
        }

    # ------------------------------------------------------------------ #
    # Phase 4 — Scrutiny
    # ------------------------------------------------------------------ #
    def scrutiny(self, shares: list[dict]) -> dict:
        """Run the full scrutiny pipeline using `shares` (>= t) to recover SKEA."""
        # 4.1 freeze.
        self._frozen = True

        # 4.2 Merkle commitment over leaf hashes.
        tree = MerkleTree(list(self._leaf_hashes))
        root = tree.root
        root_signature = crypto_utils.rsa_pss_sign(self._private_key, root)

        # 4.3 key reconstruction from t shares (Lagrange interpolation).
        skea_bytes = shamir.reconstruct(shares)
        reconstructed_key = crypto_utils.private_key_from_bytes(skea_bytes)

        # 4.4 shuffle ciphertexts with Fisher-Yates + secrets.randbelow.
        ciphertexts = self.pbb.ciphertexts()
        self._fisher_yates(ciphertexts)

        # 4.5 / 4.6 decrypt + validate.
        votes: list[str | None] = []
        null_count = 0
        tally = {lst: 0 for lst in VALID_LISTS}
        for ct in ciphertexts:
            choice = self._decrypt_and_validate(reconstructed_key, ct)
            if choice is None:
                null_count += 1
                votes.append(None)
            else:
                tally[choice] += 1
                votes.append(choice)

        # WP2 §Security Notes: clear the reconstructed key from memory.
        skea_mutable = bytearray(skea_bytes)
        for i in range(len(skea_mutable)):
            skea_mutable[i] = 0
        del skea_mutable, skea_bytes, reconstructed_key

        # 4.7 publish.
        return {
            "votes": votes,           # shuffled plaintext votes (None == null)
            "null_count": null_count,
            "tally": tally,
            "merkle_root": root.hex(),
            "root_signature": root_signature.hex(),
            "n_entries": len(self.pbb.entries),
        }

    @staticmethod
    def _fisher_yates(items: list) -> None:
        """In-place Fisher-Yates shuffle using cryptographic randomness."""
        for i in range(len(items) - 1, 0, -1):
            j = secrets.randbelow(i + 1)  # NOT random.randint (WP2 §Security Notes)
            items[i], items[j] = items[j], items[i]

    @staticmethod
    def _decrypt_and_validate(private_key, ciphertext: bytes) -> str | None:
        """Decrypt + validate one ballot; return the list choice or None."""
        try:
            m_bytes = crypto_utils.rsa_oaep_decrypt(private_key, ciphertext)
            m = json.loads(m_bytes)
        except Exception:
            return None
        if m.get("elezione_id") != ELECTION_ID:
            return None
        choice = m.get("scelta_lista")
        if choice not in VALID_LISTS:
            return None
        return choice


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[ea_server] running self-tests...")
    from as_server import AuthenticationServer, encode_signed_token

    voters = {f"voter{i}" for i in range(6)}
    as_srv = AuthenticationServer(voters)
    ea = ElectoralAuthority(as_srv.public_key, shamir_t=3, shamir_n=5)

    def make_packet_from_wire(wire: bytes, choice: str) -> dict:
        m = {
            "elezione_id": ELECTION_ID,
            "scelta_lista": choice,
            "salt_nonce": secrets.token_hex(16),
        }
        ct = crypto_utils.rsa_oaep_encrypt(ea.public_key, json.dumps(m).encode())
        return {"ciphertext": ct.hex(), "token": wire}

    # Valid submissions (voter0..voter4).
    choices = ["LISTA_01", "LISTA_02", "LISTA_02", "LISTA_03", "LISTA_01"]
    wires = [as_srv.issue_token(f"voter{i}") for i in range(5)]
    receipts = [
        ea.submit_ballot(make_packet_from_wire(wires[i], choices[i]))
        for i in range(5)
    ]
    assert len(ea.pbb.entries) == 5
    print("  [ok] 5 valid ballots accepted, PBB has 5 entries")

    # Receipt signature verifies under PKEA.
    r = receipts[0]
    assert crypto_utils.rsa_pss_verify(
        ea.public_key, bytes.fromhex(r["ea_signature"]), bytes.fromhex(r["leaf_hash"])
    )
    print("  [ok] receipt signature verifies under PKEA")

    # Replay rejected: resubmit voter0's already-spent token (informative msg).
    try:
        ea.submit_ballot(make_packet_from_wire(wires[0], "LISTA_01"))
        raise AssertionError("replay accepted")
    except BallotRejected as e:
        assert "already spent" in str(e)
    print("  [ok] replayed token rejected with informative message")

    # Idempotent re-issuance is ALSO blocked: re-authenticating returns the same
    # token_id, so resubmitting the re-issued token still hits anti-replay.
    reissued = as_srv.issue_token("voter0")
    try:
        ea.submit_ballot(make_packet_from_wire(reissued, "LISTA_01"))
        raise AssertionError("re-issued token allowed a second vote")
    except BallotRejected as e:
        assert "already spent" in str(e)
    print("  [ok] re-issued (deterministic) token cannot double-vote")

    # Forged token (bad signature) rejected.
    fake = encode_signed_token(b'{"token_id":"x","election_id":"UNISA-CONS-STUD-2026","eligible_scope":"STUDENT","expires_at":"2099-01-01T00:00:00+00:00"}', b"\x00" * 512)
    try:
        ea.submit_ballot(make_packet_from_wire(fake, "LISTA_01"))
        raise AssertionError("forged token accepted")
    except BallotRejected as e:
        assert "signature" in str(e)
    print("  [ok] forged token signature rejected")

    # Wrong election_id rejected (WP4 revision).
    as2 = AuthenticationServer({"x"})
    ea2 = ElectoralAuthority(as2.public_key, shamir_t=2, shamir_n=3)

    def packet2(wire, choice="LISTA_01"):
        m = {"elezione_id": ELECTION_ID, "scelta_lista": choice,
             "salt_nonce": secrets.token_hex(16)}
        ct = crypto_utils.rsa_oaep_encrypt(ea2.public_key, json.dumps(m).encode())
        return {"ciphertext": ct.hex(), "token": wire}

    bad_elec = as2.issue_token("x", election_id="OTHER-ELECTION")
    try:
        ea2.submit_ballot(packet2(bad_elec))
        raise AssertionError("wrong election_id accepted")
    except BallotRejected as e:
        assert "election_id" in str(e)
    print("  [ok] wrong election_id rejected")

    # Wrong scope rejected; "ANY" wildcard accepted.
    as3 = AuthenticationServer({"y", "z"})
    ea3 = ElectoralAuthority(as3.public_key, shamir_t=2, shamir_n=3,
                             allowed_scopes=("STUDENT",))

    def packet3(ea_inst, wire, choice="LISTA_01"):
        m = {"elezione_id": ELECTION_ID, "scelta_lista": choice,
             "salt_nonce": secrets.token_hex(16)}
        ct = crypto_utils.rsa_oaep_encrypt(ea_inst.public_key, json.dumps(m).encode())
        return {"ciphertext": ct.hex(), "token": wire}

    prof_wire = as3.issue_token("y", eligible_scope="PROFESSOR")
    try:
        ea3.submit_ballot(packet3(ea3, prof_wire))
        raise AssertionError("disallowed scope accepted")
    except BallotRejected as e:
        assert "scope" in str(e)
    print("  [ok] disallowed eligible_scope rejected")

    any_wire = as3.issue_token("z", eligible_scope="STUDENT")
    ea3.submit_ballot(packet3(ea3, any_wire))  # STUDENT allowed -> accepted
    print("  [ok] allowed eligible_scope accepted")

    # Scrutiny with t=3 shares.
    result = ea.scrutiny(ea.skea_shares[:3])
    assert result["tally"] == {"LISTA_01": 2, "LISTA_02": 2, "LISTA_03": 1}
    assert result["null_count"] == 0
    assert len(result["votes"]) == 5
    print("  [ok] scrutiny tally correct:", result["tally"])

    # Merkle root signature verifies.
    assert crypto_utils.rsa_pss_verify(
        ea.public_key,
        bytes.fromhex(result["root_signature"]),
        bytes.fromhex(result["merkle_root"]),
    )
    print("  [ok] Merkle root signature verifies")

    # Frozen after scrutiny: no new ballots.
    new_wire = as_srv.issue_token("voter5")
    try:
        ea.submit_ballot(make_packet_from_wire(new_wire, "LISTA_01"))
        raise AssertionError("ballot accepted after freeze")
    except BallotRejected as e:
        assert "frozen" in str(e)
    print("  [ok] polls frozen after scrutiny")

    print("[ea_server] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
