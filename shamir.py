"""
shamir.py — (t, n) Shamir secret sharing over GF(p), p = 2**127 - 1.

Implemented FROM SCRATCH using Lagrange interpolation, per WP2 §SKEA. The only
"crypto" dependency is `secrets` for cryptographically secure coefficient/x
selection; the field arithmetic is plain Python big-int modular math.

  * split(secret_bytes, t, n) -> list of (x, y) shares
  * reconstruct(shares)       -> recovered secret_bytes

The secret (the DER bytes of SKEA) is interpreted as one big integer and split
in fixed-size CHUNKS, because a single GF(2^127-1) element can only hold 126
bits. Each chunk is shared independently; share i across all chunks is bundled
into one shareholder's share.

>>> PRODUCTION NOTE <<<
Splitting the raw private-key bytes means the key is fully reconstructed in one
place at scrutiny time — a single point of compromise. A production system would
instead use THRESHOLD RSA (e.g. Shoup's threshold RSA, or a threshold scheme
such as FROST for signatures) so that decryption is performed jointly by the
shareholders and the private key is NEVER reassembled. We use naive secret
splitting here only because WP2 specifies it for the academic simulation.

Run `python shamir.py` for the built-in self-tests.
"""

from __future__ import annotations

import secrets

# Mersenne prime: 2**127 - 1. A field element holds up to 126 bits safely, so we
# chunk the secret into 15-byte (120-bit) pieces, comfortably below p.
PRIME = 2**127 - 1
CHUNK_SIZE = 15  # bytes per field element


# --------------------------------------------------------------------------- #
# Modular helpers
# --------------------------------------------------------------------------- #
def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial with `coeffs` (constant-term first) at x mod PRIME."""
    acc = 0
    for c in reversed(coeffs):  # Horner's method
        acc = (acc * x + c) % PRIME
    return acc


def _lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """Recover f(0) from >= t distinct points via Lagrange interpolation mod PRIME."""
    secret = 0
    for j, (xj, yj) in enumerate(points):
        num = 1
        den = 1
        for m, (xm, _) in enumerate(points):
            if m == j:
                continue
            num = (num * (-xm)) % PRIME
            den = (den * (xj - xm)) % PRIME
        # Modular inverse via Fermat's little theorem (PRIME is prime).
        lagrange = (num * pow(den, PRIME - 2, PRIME)) % PRIME
        secret = (secret + yj * lagrange) % PRIME
    return secret


# --------------------------------------------------------------------------- #
# Chunking
# --------------------------------------------------------------------------- #
def _bytes_to_chunks(secret: bytes) -> list[int]:
    """Split bytes into CHUNK_SIZE-byte big-endian integers."""
    return [
        int.from_bytes(secret[i : i + CHUNK_SIZE], "big")
        for i in range(0, len(secret), CHUNK_SIZE)
    ]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def split(secret: bytes, t: int, n: int) -> list[dict]:
    """Split `secret` into `n` shares; any `t` reconstruct it.

    Returns a list of `n` share dicts:
        {"x": int, "y": [int, ...], "t": int, "secret_len": int}
    where y[k] is the share's evaluation for chunk k.
    """
    if not 2 <= t <= n:
        raise ValueError("require 2 <= t <= n")
    if len(secret) == 0:
        raise ValueError("secret must be non-empty")

    chunks = _bytes_to_chunks(secret)

    # For each chunk build a degree-(t-1) polynomial with the chunk as constant
    # term, then evaluate at x = 1..n. Each shareholder gets the same x across
    # all chunks.
    xs = list(range(1, n + 1))
    ys_per_share: list[list[int]] = [[] for _ in range(n)]

    for chunk in chunks:
        coeffs = [chunk] + [secrets.randbelow(PRIME) for _ in range(t - 1)]
        for share_idx, x in enumerate(xs):
            ys_per_share[share_idx].append(_eval_poly(coeffs, x))

    return [
        {"x": xs[i], "y": ys_per_share[i], "t": t, "secret_len": len(secret)}
        for i in range(n)
    ]


def reconstruct(shares: list[dict]) -> bytes:
    """Reconstruct the secret from a list of >= t shares."""
    if not shares:
        raise ValueError("no shares provided")

    t = shares[0]["t"]
    secret_len = shares[0]["secret_len"]
    if len(shares) < t:
        raise ValueError(f"need at least t={t} shares, got {len(shares)}")

    # Use exactly t shares.
    use = shares[:t]
    n_chunks = len(use[0]["y"])

    recovered = bytearray()
    for k in range(n_chunks):
        points = [(s["x"], s["y"][k]) for s in use]
        chunk_int = _lagrange_interpolate_at_zero(points)
        # Each chunk is CHUNK_SIZE bytes except possibly the last one. Encode
        # every chunk at its ORIGINAL byte length so leading zeros are preserved
        # exactly (mirrors _bytes_to_chunks' big-endian slicing).
        remaining = secret_len - k * CHUNK_SIZE
        chunk_len = min(CHUNK_SIZE, remaining)
        recovered += chunk_int.to_bytes(chunk_len, "big")

    return bytes(recovered)


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[shamir] running self-tests...")

    # Round-trip on a short secret.
    secret = b"SKEA-bytes-example-\x00\x01\x02\xff"
    shares = split(secret, t=3, n=5)
    assert reconstruct(shares[:3]) == secret, "t=3 reconstruct failed"
    print("  [ok] basic (3,5) round-trip")

    # Any subset of >= t shares works; verify a few combinations.
    import itertools

    for combo in itertools.combinations(range(5), 3):
        subset = [shares[i] for i in combo]
        assert reconstruct(subset) == secret, f"subset {combo} failed"
    print("  [ok] every 3-of-5 subset reconstructs identically")

    # Fewer than t shares must NOT reveal the secret (and is rejected).
    try:
        reconstruct(shares[:2])
        raise AssertionError("reconstruct accepted < t shares")
    except ValueError:
        pass
    print("  [ok] < t shares rejected")

    # Large, realistic secret: DER bytes of an RSA-4096 key are ~2.3 KB.
    big = secrets.token_bytes(2400)
    bshares = split(big, t=2, n=3)
    assert reconstruct(bshares[:2]) == big, "large secret round-trip failed"
    print("  [ok] large (2400-byte) secret round-trip")

    # Multi-byte / boundary lengths.
    for length in (1, 14, 15, 16, 30, 31):
        sec = secrets.token_bytes(length)
        sh = split(sec, t=2, n=4)
        assert reconstruct(sh[2:4]) == sec, f"length {length} failed"
    print("  [ok] boundary lengths {1,14,15,16,30,31}")

    print("[shamir] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
