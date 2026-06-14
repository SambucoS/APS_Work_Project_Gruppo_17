"""
simulation.py - End-to-end demonstration of the UNISA voting protocol.

Runs all six WP2 phases as direct function calls (the simulated TLS channel):
  1. Authentication (AS issues tokens; deterministic HMAC token_id, no role)
  2. Ballot submission (clients encrypt + submit B_packets)
  3. Ballot intake (EA verifies, anti-replays, appends to PBB, issues receipts)
  4. Scrutiny (freeze, Merkle commit, Shamir reconstruct, shuffle, decrypt, tally)
  5. Individual verification (a voter proves their ballot is in the urn)
  6. Universal verification (an auditor recomputes everything from public data)

Usage:
    python simulation.py
    python simulation.py --voters 50
"""

from __future__ import annotations

import argparse
import json
import secrets

import crypto_utils
from as_server import AuthenticationServer, decode_signed_token
from client import build_b_packet, verify_inclusion
from ea_server import VALID_LISTS, BallotRejected, ElectoralAuthority
from pbb import MerkleTree

SHAMIR_T = 3
SHAMIR_N = 5


def _hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def run(n_voters: int) -> None:
    _hr("SETUP - key generation & out-of-band distribution")
    identities = [f"matricola_{i:04d}" for i in range(n_voters)]
    as_srv = AuthenticationServer(set(identities))
    ea = ElectoralAuthority(as_srv.public_key, shamir_t=SHAMIR_T, shamir_n=SHAMIR_N)
    pkea = ea.public_key  # delivered to clients over simulated TLS
    pkas = as_srv.public_key  # preloaded into EA + auditors
    print(f"  AS + EA RSA-4096 keypairs generated.")
    print(f"  SKEA split into Shamir ({SHAMIR_T},{SHAMIR_N}) shares.")
    print(f"  Eligible voters: {n_voters}")

    # --- Phase 1 & 2 & 3: authenticate, vote, submit ---
    _hr("PHASES 1-3 - authentication, encryption, intake")
    rng_choices = [secrets.choice(VALID_LISTS) for _ in range(n_voters)]
    expected_tally = {lst: rng_choices.count(lst) for lst in VALID_LISTS}

    receipts = []
    voter_receipt_for_demo = None
    first_token_wire = None
    for i, identity in enumerate(identities):
        token_wire = as_srv.issue_token(                          # Phase 1
            identity_id=identity,
            election_id="UNISA-CONS-STUD-2026",
            eligible_scope="STUDENT",
        )
        packet = build_b_packet(pkea, token_wire, rng_choices[i])  # Phase 2
        receipt = ea.submit_ballot(packet)                        # Phase 3
        receipts.append(receipt)
        if i == 0:
            voter_receipt_for_demo = receipt
            first_token_wire = token_wire

    print(f"  {len(receipts)} ballots accepted; PBB has {len(ea.pbb.entries)} entries.")
    print(f"  Ground-truth choices (for checking): {expected_tally}")

    # Demonstrate idempotent re-authentication (WP4 v2): re-issuing returns the
    # SAME deterministic token_id, so a lost token is recoverable without
    # enabling a second vote.
    reissued = as_srv.issue_token(identities[0])
    tid_a = json.loads(decode_signed_token(first_token_wire)[0])["token_id"]
    tid_b = json.loads(decode_signed_token(reissued)[0])["token_id"]
    print(f"  Re-authentication returns the same token_id: {tid_a == tid_b}")

    # Demonstrate EA anti-replay: resubmit voter 0's already-spent token
    # (works equally for the original or the re-issued token — same token_id).
    replay_packet = build_b_packet(pkea, reissued, rng_choices[0])
    try:
        ea.submit_ballot(replay_packet)
    except BallotRejected as e:
        print(f"  Replay correctly blocked: {e}")

    # --- Phase 4: scrutiny ---
    _hr("PHASE 4 - scrutiny (freeze, commit, reconstruct, shuffle, decrypt, tally)")
    # t shareholders provide their shares.
    provided_shares = ea.skea_shares[:SHAMIR_T]
    result = ea.scrutiny(provided_shares)
    print(f"  Merkle root: {result['merkle_root'][:32]}...")
    print(f"  Votes counted: {len(result['votes'])} (null: {result['null_count']})")
    print(f"  Published tally: {result['tally']}")
    assert result["tally"] == expected_tally, "tally mismatch!"
    print("  [PASS] published tally matches ground truth.")

    # --- Phase 5: individual verification ---
    _hr("PHASE 5 - individual verification (one voter)")
    leaves = ea.pbb.leaf_hashes()
    root = bytes.fromhex(result["merkle_root"])
    root_sig = bytes.fromhex(result["root_signature"])
    ok = verify_inclusion(pkea, voter_receipt_for_demo, leaves, root, root_sig)
    print(f"  Voter 0 receipt leaf: {voter_receipt_for_demo['leaf_hash'][:32]}...")
    print(f"  Inclusion proof verifies against signed root: {ok}")
    assert ok, "individual verification failed!"
    print("  [PASS] voter has cryptographic proof their ballot is in the urn.")

    # --- Phase 6: universal verification ---
    _hr("PHASE 6 - universal verification (independent auditor)")
    universal_verify(ea, pkas, pkea, result)

    _hr("SIMULATION COMPLETE - all phases passed")


def universal_verify(ea, pkas, pkea, result) -> None:
    """WP2 Phase 6: recompute everything from public data."""
    # 6.2 recompute hash-pointer chain.
    chain_ok = ea.pbb.verify_chain()
    print(f"  [1] Hash-pointer chain recomputed from genesis: {chain_ok}")
    assert chain_ok

    # 6.4 verify Merkle root signature.
    root = bytes.fromhex(result["merkle_root"])
    root_sig = bytes.fromhex(result["root_signature"])
    root_sig_ok = crypto_utils.rsa_pss_verify(pkea, root_sig, root)
    print(f"  [2] Merkle root signature valid under PKEA: {root_sig_ok}")
    assert root_sig_ok

    # Re-derive the Merkle root independently from the PBB leaves.
    leaves = ea.pbb.leaf_hashes()
    recomputed_root = MerkleTree(leaves).root
    print(f"  [3] Independently recomputed Merkle root matches: {recomputed_root == root}")
    assert recomputed_root == root

    # 6.5 cardinality check.
    n_valid = sum(1 for v in result["votes"] if v is not None)
    cardinality_ok = len(ea.pbb.entries) == n_valid + result["null_count"]
    print(f"  [4] Cardinality |PBB| == n_valid + n_null: {cardinality_ok} "
          f"({len(ea.pbb.entries)} == {n_valid} + {result['null_count']})")
    assert cardinality_ok

    # 6.6 recount from published plaintext list, compare to proclaimed tally.
    recount = {lst: 0 for lst in VALID_LISTS}
    for v in result["votes"]:
        if v is not None:
            recount[v] += 1
    print(f"  [5] Independent recount matches proclaimed tally: {recount == result['tally']}")
    assert recount == result["tally"]

    # 6.3 verify the PSS signature + election_id on each published token under
    # PKAS. (WP4 v2: there is no `role` field to check anymore.) The tokens are
    # published in the PBB, so any auditor can re-verify them from the dump.
    tokens = ea.pbb.tokens()
    all_tokens_ok = True
    for wire in tokens:
        token_json_bytes, signature = decode_signed_token(wire)
        if not crypto_utils.rsa_pss_verify(pkas, signature, token_json_bytes):
            all_tokens_ok = False
            break
        if json.loads(token_json_bytes).get("election_id") != "UNISA-CONS-STUD-2026":
            all_tokens_ok = False
            break
    print(f"  [6] All {len(tokens)} published tokens verify under PKAS: {all_tokens_ok}")
    assert all_tokens_ok

    print("  [PASS] universal verification succeeded - election is publicly auditable.")


def main() -> None:
    parser = argparse.ArgumentParser(description="UNISA e-voting simulation")
    parser.add_argument("--voters", type=int, default=10, help="number of voters")
    args = parser.parse_args()
    run(args.voters)


if __name__ == "__main__":
    main()
