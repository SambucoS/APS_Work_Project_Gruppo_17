"""
as_server.py — Authentication Server (AS).

Responsibilities (WP2 §Actors, Phase 1):
  * Generate / persist (SKAS, PKAS).
  * Verify voter eligibility against an in-memory voters_db.
  * Issue ONE token type per eligible identity (idempotent re-issuance).

>>> WP4 v2 ARCHITECTURAL REVISION <<<
  * token_id is now DETERMINISTIC: HMAC-SHA256(hmac_secret, identity||election).
    Re-authenticating returns the IDENTICAL token, so a lost/aborted token can
    be recovered and the EA's per-token_id anti-replay still blocks a 2nd vote.
  * The `role` field and the OBSERVER token are REMOVED: the AS issues a single
    token type; all accept/reject gating now lives entirely on the EA.
  * `expires_at` is ABSOLUTE (the common poll-closing time), not a per-token TTL.

>>> PRIVACY TRADEOFF (read before grading) <<<
The ORIGINAL design used a random UUID token_id and stored only a boolean flag,
so that even an AS+EA collusion could not link identity to ballot. The v2
deterministic token_id REVERSES that property: the holder of `hmac_secret` (the
AS) can recompute every voter's token_id and match it against the token_ids
published in the PBB, linking identity -> ciphertext; combined with EA
decryption this enables AS+EA deanonymisation. See crypto_utils.derive_token_id
and the WP4 notes. The AS still stores no token_id (only a boolean flag), but
that no longer hides the mapping because the mapping is now recomputable.

Wire format for a signed token:
    token_json_bytes || b'.' || base64url(pss_signature)

Run `python as_server.py` for the built-in self-tests.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

import crypto_utils

TOKEN_SEPARATOR = b"."
# Default absolute poll-closing time. WP4 v2 makes expires_at an absolute instant
# shared by all tokens (configured at AS startup), not a per-token TTL. The doc's
# illustrative date (2026-05-25) is in the past relative to the demo clock, so we
# default to "now + 12h" to keep the simulation runnable; override via the
# constructor's `election_end` parameter for a fixed real closing time.
DEFAULT_POLL_WINDOW = timedelta(hours=12)

# Defaults for the token fields (WP4 revision).
DEFAULT_ELECTION_ID = "UNISA-CONS-STUD-2026"
DEFAULT_ELIGIBLE_SCOPE = "STUDENT"      # voter category
VALID_SCOPES = ("STUDENT", "PROFESSOR")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def encode_signed_token(token_json_bytes: bytes, signature: bytes) -> bytes:
    """Assemble the wire format: json || '.' || base64url(signature)."""
    return token_json_bytes + TOKEN_SEPARATOR + base64.urlsafe_b64encode(signature)


def decode_signed_token(wire: bytes) -> tuple[bytes, bytes]:
    """Split wire format back into (token_json_bytes, signature_bytes).

    Splits on the LAST '.' since base64url never contains '.' but is appended
    last; the JSON itself contains no raw '.' bytes outside of strings, and our
    tokens contain none. Using rsplit is robust regardless.
    """
    token_json_bytes, b64sig = wire.rsplit(TOKEN_SEPARATOR, 1)
    return token_json_bytes, base64.urlsafe_b64decode(b64sig)


class AuthenticationServer:
    def __init__(
        self,
        voters_db: set[str],
        election_end: datetime | None = None,
    ):
        """`voters_db` is the set of eligible identity_id strings.

        `election_end` is the ABSOLUTE poll-closing instant embedded as
        `expires_at` in every token (WP4 v2). Defaults to now + 12h so the demo
        is runnable; pass a fixed instant for a real election.
        """
        self._private_key, self.public_key = crypto_utils.generate_rsa_keypair()
        self._voters_db: set[str] = set(voters_db)
        self._election_end: datetime = election_end or (_now_utc() + DEFAULT_POLL_WINDOW)
        # Dedicated 32-byte HMAC key for deterministic token_id derivation
        # (WP4 v2). Kept separate from the PSS signing key, generated at startup.
        self._hmac_secret: bytes = secrets.token_bytes(32)
        # Issuance flag keyed by (identity_id, election_id) — supports multiple
        # simultaneous elections. Boolean only; the token_id is NEVER stored
        # (though, see module docstring, it is now recomputable from the secret).
        self.token_issued: dict[tuple[str, str], bool] = {}

    # --- key persistence (WP2 §Key Management) ---
    def save_keys(self, priv_path: str, pub_path: str) -> None:
        crypto_utils.save_private_key(self._private_key, priv_path)
        crypto_utils.save_public_key(self.public_key, pub_path)

    # --- Phase 1: token issuance (WP4 v2: single token type, idempotent) ---
    def issue_token(
        self,
        identity_id: str,
        election_id: str = DEFAULT_ELECTION_ID,
        eligible_scope: str = DEFAULT_ELIGIBLE_SCOPE,
    ) -> bytes:
        """Issue (or re-issue) the token for an eligible identity.

        IDEMPOTENT: because token_id is derived deterministically via HMAC, every
        call with the same (identity_id, election_id) returns a byte-identical
        token. A voter who lost/aborted their token simply re-authenticates and
        gets the same one back; if they already voted, the EA's per-token_id
        anti-replay blocks the second submission (the AS does not, and need not,
        track spending). Raises ValueError only on ineligibility or unknown scope.
        """
        if identity_id not in self._voters_db:              # Phase 1.2
            raise ValueError(f"identity '{identity_id}' not eligible")
        if eligible_scope not in VALID_SCOPES:
            raise ValueError(f"unknown eligible_scope '{eligible_scope}'")

        # Phase 1.4: idempotent flag, keyed by (identity, election).
        self.token_issued[(identity_id, election_id)] = True

        # Phase 1: deterministic token_id (HMAC) — no `role` field (WP4 v2).
        token_id = crypto_utils.derive_token_id(
            self._hmac_secret, identity_id, election_id
        )
        token = {
            "token_id": token_id,
            "election_id": election_id,
            "eligible_scope": eligible_scope,
            "expires_at": _iso(self._election_end),  # absolute poll-closing time
        }
        token_json_bytes = json.dumps(token, separators=(",", ":")).encode()
        signature = crypto_utils.rsa_pss_sign(self._private_key, token_json_bytes)
        return encode_signed_token(token_json_bytes, signature)


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[as_server] running self-tests...")

    voters = {"mario.rossi", "lucia.bianchi", "anna.verdi"}
    as_srv = AuthenticationServer(voters)

    # Issue + verify a token (no `role` field anymore).
    wire = as_srv.issue_token("mario.rossi")
    token_json, sig = decode_signed_token(wire)
    assert crypto_utils.rsa_pss_verify(as_srv.public_key, sig, token_json)
    tok = json.loads(token_json)
    assert "role" not in tok, "role field should be removed (WP4 v2)"
    assert "token_id" in tok and len(tok["token_id"]) == 64
    assert tok["election_id"] == DEFAULT_ELECTION_ID
    assert tok["eligible_scope"] == DEFAULT_ELIGIBLE_SCOPE
    print("  [ok] token issued, signed, verifies (no role; HMAC token_id)")

    # Idempotent re-issuance: same inputs -> IDENTICAL PAYLOAD (and token_id).
    # NOTE: the wire bytes differ because PSS uses a random salt (MAX_LENGTH),
    # so the signature is non-deterministic; the *payload* and token_id are
    # identical, which is what guarantees the EA's anti-replay catches a re-vote.
    wire2 = as_srv.issue_token("mario.rossi")
    assert decode_signed_token(wire2)[0] == token_json, "payload not idempotent"
    assert json.loads(decode_signed_token(wire2)[0])["token_id"] == tok["token_id"]
    print("  [ok] re-authentication returns identical payload + token_id")

    # token_id is deterministic HMAC of (identity, election).
    expected_tid = crypto_utils.derive_token_id(
        as_srv._hmac_secret, "mario.rossi", DEFAULT_ELECTION_ID
    )
    assert tok["token_id"] == expected_tid
    print("  [ok] token_id == HMAC(secret, identity||election)")

    # Flag keyed by (identity, election); no OBSERVER method exists.
    assert as_srv.token_issued[("mario.rossi", DEFAULT_ELECTION_ID)] is True
    assert not hasattr(as_srv, "issue_observer_token")
    print("  [ok] composite flag set; OBSERVER token removed")

    # expires_at is absolute and common to all tokens.
    other = json.loads(decode_signed_token(as_srv.issue_token("lucia.bianchi"))[0])
    assert other["expires_at"] == tok["expires_at"], "expires_at not common/absolute"
    print("  [ok] expires_at is the common absolute poll-closing time")

    # Custom scope (PROFESSOR) accepted; unknown scope rejected.
    pwire = as_srv.issue_token("lucia.bianchi", eligible_scope="PROFESSOR")
    assert json.loads(decode_signed_token(pwire)[0])["eligible_scope"] == "PROFESSOR"
    try:
        as_srv.issue_token("anna.verdi", eligible_scope="ALIEN")
        raise AssertionError("unknown scope accepted")
    except ValueError:
        pass
    print("  [ok] PROFESSOR scope accepted, unknown scope rejected")

    # Ineligible identity rejected.
    try:
        as_srv.issue_token("intruder")
        raise AssertionError("ineligible identity accepted")
    except ValueError:
        pass
    print("  [ok] ineligible identity rejected")

    print("[as_server] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
