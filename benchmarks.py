"""
benchmarks.py — Timing and message-size measurements for the voting system.

Covers every metric in WP2 §Benchmarks Required. Uses time.perf_counter();
each timing is repeated REPEATS times and the mean is reported.

Usage:
    python benchmarks.py
"""

from __future__ import annotations

import json
import random
import secrets
import statistics
import time

import crypto_utils
from as_server import AuthenticationServer
from client import build_ballot_plaintext, build_b_packet
from ea_server import ELECTION_ID, ElectoralAuthority
from pbb import PBB, MerkleTree

REPEATS = 10

# Voter counts for the scaling section.
SCALING_N = (100, 1_000, 10_000)


def _time_ms(fn, repeats: int = REPEATS) -> float:
    """Return mean wall time of `fn` in milliseconds over `repeats` runs."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)
    return statistics.mean(samples)


def _time_us(fn, repeats: int = REPEATS) -> float:
    """Return mean wall time of `fn` in microseconds over `repeats` runs."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e6)
    return statistics.mean(samples)


def main() -> None:
    print("=" * 64)
    print("  UNISA E-VOTING - BENCHMARKS  (mean of %d runs each)" % REPEATS)
    print("=" * 64)
    results: list[tuple[str, str]] = []

    # --- RSA-4096 key generation ---
    keygen_ms = _time_ms(crypto_utils.generate_rsa_keypair)
    results.append(("RSA-4096 key generation", f"{keygen_ms:.2f} ms"))

    # Fixtures reused below.
    priv, pub = crypto_utils.generate_rsa_keypair()
    as_srv = AuthenticationServer({"benchmark_voter"})
    token_wire = as_srv.issue_token("benchmark_voter")

    ballot = {
        "elezione_id": ELECTION_ID,
        "scelta_lista": "LISTA_02",
        "salt_nonce": secrets.token_hex(16),
    }
    ballot_bytes = json.dumps(ballot).encode()

    # --- OAEP encryption (single ballot) ---
    ciphertext = crypto_utils.rsa_oaep_encrypt(pub, ballot_bytes)
    enc_ms = _time_ms(lambda: crypto_utils.rsa_oaep_encrypt(pub, ballot_bytes))
    results.append(("OAEP encryption (1 ballot)", f"{enc_ms:.2f} ms"))
    results.append(("  ciphertext size", f"{len(ciphertext)} bytes"))

    # --- PSS sign (single token) ---
    leaf = crypto_utils.sha256(ciphertext)
    sign_ms = _time_ms(lambda: crypto_utils.rsa_pss_sign(priv, leaf))
    signature = crypto_utils.rsa_pss_sign(priv, leaf)
    results.append(("PSS sign (1 token/leaf)", f"{sign_ms:.2f} ms"))
    results.append(("  signature size", f"{len(signature)} bytes"))

    # --- PSS verify (single token) ---
    verify_ms = _time_ms(lambda: crypto_utils.rsa_pss_verify(pub, signature, leaf))
    results.append(("PSS verify (1 token/leaf)", f"{verify_ms:.2f} ms"))

    # --- B_packet total size ---
    b_packet = build_b_packet(pub, token_wire, "LISTA_02")
    b_packet_bytes = json.dumps(b_packet).encode()
    results.append(("B_packet total size", f"{len(b_packet_bytes)} bytes"))

    # --- Receipt size ---
    receipt = {"leaf_hash": leaf.hex(), "ea_signature": signature.hex()}
    receipt_bytes = json.dumps(receipt).encode()
    results.append(("Receipt size", f"{len(receipt_bytes)} bytes"))

    # --- Merkle tree build for N = 10, 100, 1000 ---
    for n in (10, 100, 1000):
        leaves = [crypto_utils.sha256(f"ct-{i}".encode()) for i in range(n)]
        build_ms = _time_ms(lambda lv=leaves: MerkleTree(lv))
        results.append((f"Merkle build (N={n})", f"{build_ms:.3f} ms"))

    # --- Merkle inclusion proof: time + proof size (N=1000) ---
    leaves = [crypto_utils.sha256(f"ct-{i}".encode()) for i in range(1000)]
    tree = MerkleTree(leaves)
    proof_ms = _time_ms(lambda: tree.inclusion_proof(500))
    proof = tree.inclusion_proof(500)
    proof_size = sum(len(h) for h, _ in proof)  # raw sibling-hash bytes
    results.append(("Merkle inclusion proof (N=1000)", f"{proof_ms:.4f} ms"))
    results.append(("  proof size", f"{proof_size} bytes ({len(proof)} nodes)"))

    # --- Full voting flow (1 voter), end-to-end ---
    # Keys are a one-time setup cost (already measured above as keygen), so the
    # AS/EA are built ONCE here; we time only the per-voter path:
    # authenticate -> encrypt -> submit -> receipt.
    flow_voters = [f"flow_{i}" for i in range(REPEATS)]
    flow_as = AuthenticationServer(set(flow_voters))
    flow_ea = ElectoralAuthority(flow_as.public_key, shamir_t=2, shamir_n=3)
    flow_counter = iter(flow_voters)

    def _flow_once() -> None:
        vid = next(flow_counter)
        wire = flow_as.issue_token(vid)
        packet = build_b_packet(flow_ea.public_key, wire, "LISTA_01")
        flow_ea.submit_ballot(packet)

    full_ms = _time_ms(_flow_once, repeats=REPEATS)
    results.append(("Full voting flow (1 voter)", f"{full_ms:.2f} ms"))

    # --- Anti-replay check (confirm O(1)) ---
    spent: set[str] = {secrets.token_hex(16) for _ in range(100_000)}
    probe = secrets.token_hex(16)
    replay_us = _time_us(lambda: probe in spent, repeats=1000)
    results.append(("Anti-replay set lookup", f"{replay_us:.4f} us (O(1))"))

    # --- print table ---
    print()
    width = max(len(name) for name, _ in results)
    for name, value in results:
        print(f"  {name.ljust(width)} : {value}")
    print()
    print("=" * 64)
    print("  Anti-replay note: membership in a Python set is average O(1);")
    print("  lookup time is independent of the number of spent tokens.")
    print("=" * 64)


# =========================================================================== #
# Scaling benchmarks: how cost grows with the number of voters N.
# =========================================================================== #
def _bench_n(n: int, as_srv: AuthenticationServer, ea: ElectoralAuthority) -> dict:
    """Run the full flow on `n` voters and return scaling metrics.

    Reuses the ALREADY-INITIALISED `as_srv` / `ea` (same RSA keys, same Shamir
    shares) so keygen is NOT included; only the per-N runtime is measured. The
    mutable state of both servers is reset before the run.
    """
    voter_ids = [f"voter_{i}" for i in range(n)]

    # Reset state, keep keys (no keygen, no Shamir re-split).
    as_srv._voters_db = set(voter_ids)
    as_srv.token_issued.clear()
    ea.pbb = PBB()
    ea._spent_tokens.clear()
    ea._leaf_hashes.clear()
    ea._frozen = False

    token_times: list[float] = []
    enc_times: list[float] = []
    ciphertexts: list[bytes] = []

    # --- per-voter flow: token issue -> OAEP encrypt -> intake (submit) ---
    t_loop_start = time.perf_counter()
    for vid in voter_ids:
        t0 = time.perf_counter()
        token_wire = as_srv.issue_token(
            vid, election_id="UNISA-CONS-STUD-2026", eligible_scope="STUDENT"
        )
        token_times.append((time.perf_counter() - t0) * 1e3)

        m_bytes = json.dumps(build_ballot_plaintext("LISTA_02")).encode()
        t0 = time.perf_counter()
        ct = crypto_utils.rsa_oaep_encrypt(ea.public_key, m_bytes)
        enc_times.append((time.perf_counter() - t0) * 1e3)
        ciphertexts.append(ct)

        # Real intake (token verify + PBB append + receipt sign); populates the
        # EA's PBB / leaf hashes so scrutiny below operates on real data.
        ea.submit_ballot({"ciphertext": ct.hex(), "token": token_wire})
    loop_ms = (time.perf_counter() - t_loop_start) * 1e3

    # --- pure hash-pointer append (append only), on a throwaway PBB ---
    # Measured separately so it reflects ONLY the chain append, not the crypto
    # bundled into submit_ballot (this matches the column's "append only" note).
    throwaway = PBB()
    pbb_times: list[float] = []
    for ct in ciphertexts:
        t0 = time.perf_counter()
        throwaway.append(ct)
        pbb_times.append((time.perf_counter() - t0) * 1e3)

    # --- Merkle build over N leaves ---
    leaves = ea.pbb.leaf_hashes()
    t0 = time.perf_counter()
    tree = MerkleTree(leaves)
    merkle_build_ms = (time.perf_counter() - t0) * 1e3

    # --- Merkle inclusion proof (avg over 10 random leaves) ---
    proof_times: list[float] = []
    for idx in random.sample(range(n), min(10, n)):
        t0 = time.perf_counter()
        tree.inclusion_proof(idx)
        proof_times.append((time.perf_counter() - t0) * 1e3)
    proof_total_ms = sum(proof_times)

    # --- Scrutiny: shuffle + batch decrypt + validate ---
    t0 = time.perf_counter()
    ea.scrutiny(ea.skea_shares[: ea.shamir_t])
    scrutiny_total_ms = (time.perf_counter() - t0) * 1e3
    if scrutiny_total_ms > 60_000:
        print(f"  [warning] scrutiny for N={n:,} took "
              f"{scrutiny_total_ms / 1000:.1f}s (>60s) — continuing")

    # full flow = per-voter loop + merkle build + proofs + scrutiny
    # (the throwaway append pass is an extra measurement, excluded here).
    full_flow_total_ms = loop_ms + merkle_build_ms + proof_total_ms + scrutiny_total_ms

    return {
        "N": n,
        "token_gen_avg_ms": statistics.mean(token_times),
        "oaep_enc_avg_ms": statistics.mean(enc_times),
        "pbb_insert_avg_ms": statistics.mean(pbb_times),
        "merkle_build_ms": merkle_build_ms,
        "merkle_proof_avg_ms": statistics.mean(proof_times),
        "scrutiny_total_ms": scrutiny_total_ms,
        "full_flow_total_ms": full_flow_total_ms,
    }


def run_scaling_benchmarks(n_values: tuple[int, ...] = SCALING_N) -> None:
    """Measure and print how the protocol scales with the number of voters."""
    print()
    print("=" * 100)
    print("  SCALING BENCHMARKS  (keygen excluded; times in ms)")
    print("=" * 100)
    print()

    # Build AS + EA ONCE; reuse the same keys across every N (no keygen in loop).
    as_srv = AuthenticationServer({"_bootstrap_"})
    ea = ElectoralAuthority(as_srv.public_key, shamir_t=3, shamir_n=5)

    rows = [_bench_n(n, as_srv, ea) for n in n_values]

    header = (
        f"  {'N':>7}  {'token_gen':>10}  {'oaep_enc':>10}  {'pbb_insert':>11}  "
        f"{'merkle_build':>12}  {'merkle_proof':>12}  {'scrutiny_total':>14}  "
        f"{'full_flow_total':>15}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in rows:
        print(
            f"  {r['N']:>7,}  "
            f"{r['token_gen_avg_ms']:>10.4f}  "
            f"{r['oaep_enc_avg_ms']:>10.4f}  "
            f"{r['pbb_insert_avg_ms']:>11.5f}  "
            f"{r['merkle_build_ms']:>12.4f}  "
            f"{r['merkle_proof_avg_ms']:>12.5f}  "
            f"{r['scrutiny_total_ms']:>14.1f}  "
            f"{r['full_flow_total_ms']:>15.1f}"
        )
    print()
    print("  Notes:")
    print("  - token_gen and oaep_enc are per-voter averages")
    print("  - pbb_insert is per-voter average (hash-pointer append only)")
    print("  - merkle_build is the total cost for the full N-leaf tree")
    print("  - merkle_proof is the average over 10 random leaves")
    print("  - scrutiny_total covers shuffle + batch decrypt + validate")
    print("  - full_flow_total = per-voter loop + merkle + proofs + scrutiny")
    print("=" * 100)


if __name__ == "__main__":
    main()
    run_scaling_benchmarks()
