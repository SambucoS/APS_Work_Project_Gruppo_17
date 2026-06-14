"""
pbb.py — Public Bulletin Board primitives.

Implements three independent but related structures from WP2:

  1. Hash-pointer chain (append-only PBB log)
        entry_hash = SHA-256(ciphertext_bytes || prev_hash_bytes)
     genesis prev_hash = 32 zero bytes. Enables universal verification (Phase 6):
     any auditor recomputes the whole chain from genesis.

  2. Merkle tree over the leaf hashes  (leaf = SHA-256(ciphertext_bytes)).
     Used for the scrutiny commitment (Phase 4) and individual verification (Phase 5).

  3. Merkle inclusion proof + verification — proves a single leaf is committed
     under a published root without revealing the other leaves.

Hashing is delegated to crypto_utils (which delegates to PyCA / hashlib).

Run `python pbb.py` for the built-in self-tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from crypto_utils import sha256

GENESIS_PREV_HASH = b"\x00" * 32


# --------------------------------------------------------------------------- #
# 1. Hash-pointer chain (the append-only PBB)
# --------------------------------------------------------------------------- #
@dataclass
class PBB:
    """Append-only, hash-pointer-chained log of accepted ciphertexts.

    Each entry is a dict matching the WP2 §PBB Entry schema. Hashes are stored
    as hex strings on the entry, but computed over raw bytes.
    """

    entries: list[dict] = field(default_factory=list)

    def append(self, ciphertext_bytes: bytes, token_wire: bytes | None = None) -> dict:
        """Append a ciphertext, linking it to the previous entry's hash.

        `token_wire` is the anonymous AS-signed token (wire format). It is
        published so any auditor can verify the token's PSS signature under PKAS
        (WP2 Phase 6.3). This is privacy-safe: the token carries NO identity, and
        the AS keeps no token_id->identity mapping, so the identity<->ballot link
        cannot be reconstructed from it.
        """
        prev_hash = (
            bytes.fromhex(self.entries[-1]["entry_hash"])
            if self.entries
            else GENESIS_PREV_HASH
        )
        entry_hash = sha256(ciphertext_bytes + prev_hash)
        entry = {
            "index": len(self.entries),
            "ciphertext": ciphertext_bytes.hex(),
            # anonymous token wire (ascii); None only if not supplied.
            "token": token_wire.decode() if token_wire is not None else None,
            "entry_hash": entry_hash.hex(),
            "prev_hash": prev_hash.hex(),
        }
        self.entries.append(entry)
        return entry

    def leaf_hashes(self) -> list[bytes]:
        """Return SHA-256(ciphertext_bytes) for every entry (Merkle leaves)."""
        return [sha256(bytes.fromhex(e["ciphertext"])) for e in self.entries]

    def ciphertexts(self) -> list[bytes]:
        """Return the raw ciphertext bytes of every entry, in order."""
        return [bytes.fromhex(e["ciphertext"]) for e in self.entries]

    def tokens(self) -> list[bytes]:
        """Return the anonymous token wires of every entry (Phase 6.3)."""
        return [
            e["token"].encode() for e in self.entries if e["token"] is not None
        ]

    def verify_chain(self) -> bool:
        """Recompute the full hash-pointer chain from genesis (Phase 6 step 2)."""
        prev_hash = GENESIS_PREV_HASH
        for i, entry in enumerate(self.entries):
            if entry["index"] != i:
                return False
            if entry["prev_hash"] != prev_hash.hex():
                return False
            ct = bytes.fromhex(entry["ciphertext"])
            expected = sha256(ct + prev_hash)
            if entry["entry_hash"] != expected.hex():
                return False
            prev_hash = expected
        return True

    def dump(self) -> list[dict]:
        """Return a deep-ish copy of the entries (for transport to auditors)."""
        return [dict(e) for e in self.entries]


# --------------------------------------------------------------------------- #
# 2. Merkle tree
# --------------------------------------------------------------------------- #
def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Internal Merkle node = SHA-256(left || right)."""
    return sha256(left + right)


@dataclass
class MerkleTree:
    """Binary Merkle tree over a list of leaf hashes.

    Odd nodes at any level are promoted (duplicated against themselves) — a
    common, simple convention. `levels[0]` is the leaves, `levels[-1]` is the
    single-element root level.
    """

    leaves: list[bytes]
    levels: list[list[bytes]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._build()

    def _build(self) -> None:
        if not self.leaves:
            # Empty tree: define the root as SHA-256(b"") so downstream code
            # always has a 32-byte root to sign.
            self.levels = [[sha256(b"")]]
            return
        self.levels = [list(self.leaves)]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = []
            for i in range(0, len(cur), 2):
                left = cur[i]
                right = cur[i + 1] if i + 1 < len(cur) else cur[i]  # promote odd
                nxt.append(_hash_pair(left, right))
            self.levels.append(nxt)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def inclusion_proof(self, leaf_index: int) -> list[tuple[bytes, str]]:
        """Return the audit path for `leaf_index`.

        Each element is (sibling_hash, side) where side is 'L'/'R' indicating
        whether the sibling sits to the left or right of the running hash.
        """
        if not self.leaves:
            raise IndexError("no leaves in tree")
        if not 0 <= leaf_index < len(self.leaves):
            raise IndexError("leaf_index out of range")

        proof: list[tuple[bytes, str]] = []
        idx = leaf_index
        for level in self.levels[:-1]:  # skip root level
            if idx % 2 == 0:  # current node is a left child
                sib = idx + 1 if idx + 1 < len(level) else idx  # promoted odd
                proof.append((level[sib], "R"))
            else:  # current node is a right child
                proof.append((level[idx - 1], "L"))
            idx //= 2
        return proof


def verify_inclusion_proof(
    leaf: bytes, proof: list[tuple[bytes, str]], root: bytes
) -> bool:
    """Recompute the root from `leaf` + `proof`; compare to `root` (Phase 5)."""
    running = leaf
    for sibling, side in proof:
        if side == "L":
            running = _hash_pair(sibling, running)
        elif side == "R":
            running = _hash_pair(running, sibling)
        else:
            return False
    return running == root


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[pbb] running self-tests...")

    # --- Hash-pointer chain ---
    pbb = PBB()
    cts = [f"ciphertext-{i}".encode() for i in range(5)]
    for ct in cts:
        pbb.append(ct)
    assert pbb.entries[0]["prev_hash"] == GENESIS_PREV_HASH.hex()
    assert pbb.verify_chain(), "fresh chain failed verification"
    print("  [ok] hash-pointer chain builds and verifies")

    # Tamper detection.
    saved = pbb.entries[2]["ciphertext"]
    pbb.entries[2]["ciphertext"] = (b"tampered").hex()
    assert not pbb.verify_chain(), "tamper not detected"
    pbb.entries[2]["ciphertext"] = saved
    assert pbb.verify_chain()
    print("  [ok] chain tamper detection")

    # --- Merkle tree: inclusion proofs for every leaf, several tree sizes ---
    for n in (1, 2, 3, 4, 5, 8, 13, 100):
        leaves = [sha256(f"leaf-{i}".encode()) for i in range(n)]
        tree = MerkleTree(leaves)
        for i in range(n):
            proof = tree.inclusion_proof(i)
            assert verify_inclusion_proof(leaves[i], proof, tree.root), (
                f"inclusion proof failed (n={n}, i={i})"
            )
        # A wrong leaf must NOT verify.
        bad = sha256(b"not-in-tree")
        assert not verify_inclusion_proof(bad, tree.inclusion_proof(0), tree.root)
    print("  [ok] Merkle inclusion proofs verify for n in {1,2,3,4,5,8,13,100}")

    # Determinism: same leaves -> same root.
    leaves = [sha256(f"x{i}".encode()) for i in range(7)]
    assert MerkleTree(leaves).root == MerkleTree(leaves).root
    print("  [ok] Merkle root determinism")

    print("[pbb] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
