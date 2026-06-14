"""
crypto_utils.py — Cryptographic primitives for the UNISA electronic voting system.

ALL cryptography is delegated to the `cryptography` (PyCA) library, per WP2 §Cryptographic
Primitives. There is no custom crypto here other than the call wrappers below.

Primitives provided:
  * RSA-4096 key generation (+ PEM save/load)
  * RSA-OAEP encryption / decryption (SHA-256, MGF1-SHA-256)
  * RSA-PSS signing / verification (SHA-256, MGF1-SHA-256, salt_length=MAX_LENGTH)
  * SHA-256 hashing helper

Run `python crypto_utils.py` to execute the built-in self-tests.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

# --------------------------------------------------------------------------- #
# Constants (WP2 §Cryptographic Primitives)
# --------------------------------------------------------------------------- #
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a fresh RSA-4096 keypair as required by the spec."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()


# --------------------------------------------------------------------------- #
# PEM serialisation (used to persist keys under keys/)
# --------------------------------------------------------------------------- #
def save_private_key(private_key: RSAPrivateKey, path: str) -> None:
    """Save an RSA private key to `path` in unencrypted PKCS8 PEM.

    NOTE: a production system would protect the private key with a passphrase
    (BestAvailableEncryption) and/or an HSM. For this academic simulation the
    key is stored unencrypted so the demo is self-contained.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def save_public_key(public_key: RSAPublicKey, path: str) -> None:
    """Save an RSA public key to `path` in SubjectPublicKeyInfo PEM."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def load_private_key(path: str) -> RSAPrivateKey:
    """Load an unencrypted PEM private key from disk."""
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def load_public_key(path: str) -> RSAPublicKey:
    """Load a PEM public key from disk."""
    with open(path, "rb") as fh:
        return serialization.load_pem_public_key(fh.read())


def private_key_to_bytes(private_key: RSAPrivateKey) -> bytes:
    """Serialise a private key to DER bytes (used by Shamir to split SKEA)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_bytes(data: bytes) -> RSAPrivateKey:
    """Reconstruct a private key from DER bytes (after Shamir reconstruction)."""
    return serialization.load_der_private_key(data, password=None)


# --------------------------------------------------------------------------- #
# RSA-OAEP encryption / decryption
# --------------------------------------------------------------------------- #
def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_oaep_encrypt(public_key: RSAPublicKey, plaintext: bytes) -> bytes:
    """RSA-OAEP encrypt `plaintext` under `public_key`."""
    return public_key.encrypt(plaintext, _oaep_padding())


def rsa_oaep_decrypt(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """RSA-OAEP decrypt `ciphertext` under `private_key`."""
    return private_key.decrypt(ciphertext, _oaep_padding())


# --------------------------------------------------------------------------- #
# RSA-PSS signing / verification
# --------------------------------------------------------------------------- #
def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def rsa_pss_sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """RSA-PSS sign `message` with `private_key`."""
    return private_key.sign(message, _pss_padding(), hashes.SHA256())


def rsa_pss_verify(public_key: RSAPublicKey, signature: bytes, message: bytes) -> bool:
    """RSA-PSS verify. Returns True if valid, False otherwise (never raises)."""
    try:
        public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# SHA-256
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of `data`."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of `data` as a 64-char hex string."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# HMAC-SHA256 PRF — deterministic token_id derivation (WP4 v2 revision)
# --------------------------------------------------------------------------- #
def derive_token_id(hmac_secret: bytes, identity_id: str, election_id: str) -> str:
    """Derive a DETERMINISTIC token_id via HMAC-SHA256.

    The same (secret, identity_id, election_id) always yields the same token_id.
    `hmac_secret` should be a dedicated 32-byte random key generated at AS
    startup, kept separate from the PSS signing key.

    Returns a 64-char hex string.

    >>> PRIVACY WARNING (WP4 v2 revision) <<<
    Making token_id a deterministic function of the voter identity is a
    deliberate architectural choice that ENABLES idempotent re-authentication
    (a voter who lost their token gets the identical one back, so the EA's
    per-token_id anti-replay still blocks a second vote). HOWEVER it WEAKENS
    ballot secrecy: anyone holding `hmac_secret` (i.e. the AS) can recompute
    token_id for every identity and match it against the token_ids published in
    the PBB, thereby linking identity -> ciphertext. Combined with the EA's
    decryption this re-introduces the AS+EA collusion linkage that the original
    random-UUID design explicitly prevented. The post-scrutiny shuffle still
    decouples PBB order from the published plaintext list, but a colluding AS+EA
    can match a specific ciphertext to a specific identity. See WP2 trust
    assumptions / WP4 notes for the full tradeoff.
    """
    msg = (identity_id + "||" + election_id).encode("utf-8")
    return hmac.new(hmac_secret, msg, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def _self_test() -> None:
    print("[crypto_utils] running self-tests...")

    # SHA-256 known answer (empty string).
    assert (
        sha256_hex(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ), "SHA-256 KAT failed"
    print("  [ok] SHA-256 known-answer test")

    priv, pub = generate_rsa_keypair()
    assert priv.key_size == RSA_KEY_SIZE
    print("  [ok] RSA-4096 keygen")

    # OAEP round-trip.
    msg = b"voto-segreto-LISTA_02"
    ct = rsa_oaep_encrypt(pub, msg)
    assert rsa_oaep_decrypt(priv, ct) == msg, "OAEP round-trip failed"
    print("  [ok] OAEP encrypt/decrypt round-trip")

    # PSS sign/verify, and rejection of tampered message.
    sig = rsa_pss_sign(priv, msg)
    assert rsa_pss_verify(pub, sig, msg), "PSS valid signature rejected"
    assert not rsa_pss_verify(pub, sig, msg + b"x"), "PSS tampered msg accepted"
    assert not rsa_pss_verify(pub, b"\x00" * len(sig), msg), "PSS bad sig accepted"
    print("  [ok] PSS sign/verify (+ tamper rejection)")

    # PEM + DER round-trips.
    der = private_key_to_bytes(priv)
    priv2 = private_key_from_bytes(der)
    assert rsa_oaep_decrypt(priv2, ct) == msg, "DER round-trip failed"
    print("  [ok] DER serialise/deserialise round-trip")

    # HMAC token_id: deterministic, identity-distinct, election-distinct.
    secret = os.urandom(32)
    id1 = derive_token_id(secret, "voter_1", "UNISA-CONS-STUD-2026")
    id2 = derive_token_id(secret, "voter_1", "UNISA-CONS-STUD-2026")
    id3 = derive_token_id(secret, "voter_2", "UNISA-CONS-STUD-2026")
    id4 = derive_token_id(secret, "voter_1", "OTHER-ELECTION")
    assert id1 == id2, "HMAC not deterministic"
    assert id1 != id3, "HMAC identity collision"
    assert id1 != id4, "HMAC election collision"
    assert len(id1) == 64
    print("  [ok] HMAC token_id deterministic + distinct (identity & election)")

    print("[crypto_utils] all self-tests passed.")


if __name__ == "__main__":
    _self_test()
