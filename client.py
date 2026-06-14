"""
client.py — Voter client.

Responsibilities (WP2 §Actors, Phases 2 & 5):
  * Build the ballot plaintext M with a fresh salt_nonce.
  * Encrypt M under PKEA (RSA-OAEP) and assemble the B_packet.
  * Verify the EA receipt signature (PSS under PKEA).
  * Perform individual verification: recompute the Merkle inclusion proof for
    the receipt's leaf and check it against the published signed root.

>>> DESIGN NOTE (WP2 §B_packet) <<<
The client does NOT sign the B_packet. A client signature would create
non-repudiation, which enables vote-buying / coercion (a voter could prove how
they voted). Authorization is carried solely by the AS-signed token embedded in
the packet.

Run `python client.py` for the built-in self-tests.
"""

from __future__ import annotations

import json
import secrets

import crypto_utils
from pbb import MerkleTree, verify_inclusion_proof

ELECTION_ID = "UNISA-CONS-STUD-2026"
VALID_LISTS = ["LISTA_01", "LISTA_02", "LISTA_03"]


def build_ballot_plaintext(scelta_lista: str) -> dict:
    """Build ballot M with a fresh 16-byte hex salt_nonce (WP2 §Ballot Plaintext)."""
    if scelta_lista not in VALID_LISTS:
        raise ValueError(f"invalid scelta_lista: {scelta_lista}")
    return {
        "elezione_id": ELECTION_ID,
        "scelta_lista": scelta_lista,
        "salt_nonce": secrets.token_hex(16),  # prevents dictionary attacks
    }


def build_b_packet(pkea, token_wire: bytes, scelta_lista: str) -> dict:
    """Encrypt a ballot under PKEA and assemble the B_packet (Phase 2)."""
    m = build_ballot_plaintext(scelta_lista)
    m_bytes = json.dumps(m).encode()
    ciphertext = crypto_utils.rsa_oaep_encrypt(pkea, m_bytes)
    return {
        "ciphertext": ciphertext.hex(),
        "token": token_wire.decode() if isinstance(token_wire, bytes) else token_wire,
    }
    # NOTE: deliberately NOT signed by the client (see module docstring).


def verify_receipt_signature(pkea, receipt: dict) -> bool:
    """Phase 5.2: verify the EA's PSS signature on the receipt's leaf_hash."""
    return crypto_utils.rsa_pss_verify(
        pkea,
        bytes.fromhex(receipt["ea_signature"]),
        bytes.fromhex(receipt["leaf_hash"]),
    )


def verify_inclusion(
    pkea,
    receipt: dict,
    leaf_hashes: list[bytes],
    published_root: bytes,
    root_signature: bytes,
) -> bool:
    """Full individual verification (WP2 Phase 5).

    1. verify receipt signature under PKEA
    2. verify the published Merkle root signature under PKEA
    3. recompute the inclusion proof for the receipt's leaf and check it
       reproduces the published root.
    """
    # 5.2 receipt signature.
    if not verify_receipt_signature(pkea, receipt):
        return False

    # 5.4 (part) root signature must be authentic.
    if not crypto_utils.rsa_pss_verify(pkea, root_signature, published_root):
        return False

    leaf = bytes.fromhex(receipt["leaf_hash"])
    if leaf not in leaf_hashes:
        return False

    # Rebuild the tree (client downloaded the PBB / leaves) and prove inclusion.
    tree = MerkleTree(leaf_hashes)
    if tree.root != published_root:
        return False
    idx = leaf_hashes.index(leaf)
    proof = tree.inclusion_proof(idx)
    return verify_inclusion_proof(leaf, proof, published_root)


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[client] running self-tests...")
    from as_server import AuthenticationServer
    from ea_server import ElectoralAuthority

    as_srv = AuthenticationServer({"alice", "bob"})
    ea = ElectoralAuthority(as_srv.public_key, shamir_t=2, shamir_n=3)

    # Build + submit a ballot.
    wire = as_srv.issue_token("alice")
    packet = build_b_packet(ea.public_key, wire, "LISTA_02")
    assert "ciphertext" in packet and "token" in packet
    receipt = ea.submit_ballot(packet)
    print("  [ok] B_packet built and submitted")

    # Receipt signature verifies.
    assert verify_receipt_signature(ea.public_key, receipt)
    print("  [ok] receipt signature verifies")

    # Add a few more ballots so the Merkle tree is non-trivial.
    bob_wire = as_srv.issue_token("bob")
    ea.submit_ballot(build_b_packet(ea.public_key, bob_wire, "LISTA_01"))

    # Freeze + commit (mirror scrutiny's Merkle commitment).
    result = ea.scrutiny(ea.skea_shares[:2])
    leaves = ea.pbb.leaf_hashes()
    root = bytes.fromhex(result["merkle_root"])
    root_sig = bytes.fromhex(result["root_signature"])

    # Individual verification succeeds for alice's receipt.
    assert verify_inclusion(ea.public_key, receipt, leaves, root, root_sig)
    print("  [ok] individual verification (inclusion proof) succeeds")

    # A tampered receipt fails.
    bad_receipt = dict(receipt)
    bad_receipt["leaf_hash"] = crypto_utils.sha256(b"not-my-ballot").hex()
    assert not verify_inclusion(ea.public_key, bad_receipt, leaves, root, root_sig)
    print("  [ok] tampered receipt rejected")

    # salt_nonce uniqueness across ballots.
    m1 = build_ballot_plaintext("LISTA_01")
    m2 = build_ballot_plaintext("LISTA_01")
    assert m1["salt_nonce"] != m2["salt_nonce"]
    print("  [ok] fresh salt_nonce per ballot")

    print("[client] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
