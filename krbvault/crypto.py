"""Encryption-at-rest for krbvault.

Envelope scheme (so a passphrase change never re-encrypts the blobs):

    passphrase --Argon2id--> KEK (32B)
    DEK = random(32B)                       # generated once per store
    wrapped_dek = nonce || XChaCha20Poly1305(DEK, key=KEK, aad="krbvault-dek")
    blob/field  = nonce || XChaCha20Poly1305(plaintext, key=DEK, aad=context)

Only the secret-bearing material (ticket bytes, credential values) is sealed
with the DEK. Changing the passphrase only re-wraps the DEK.

The AEAD tag authenticates every ciphertext, so a wrong passphrase (wrong KEK)
is detected when unwrapping the DEK — no separate verifier needed there.
"""
from __future__ import annotations

import nacl.bindings
import nacl.pwhash
import nacl.utils
from nacl.exceptions import CryptoError

KEK_LEN = 32
DEK_LEN = 32
SALT_LEN = nacl.pwhash.argon2id.SALTBYTES
NONCE_LEN = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

# Default Argon2id cost. The actual values used are stored in the vault's meta
# table, so a vault opens with whatever cost it was created with.
DEFAULT_OPS = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
DEFAULT_MEM = nacl.pwhash.argon2id.MEMLIMIT_MODERATE


class BadPassphrase(Exception):
    """Raised when decryption fails (wrong passphrase, wrong key, or tampering)."""


def new_salt() -> bytes:
    return nacl.utils.random(SALT_LEN)


def new_dek() -> bytes:
    return nacl.utils.random(DEK_LEN)


def derive_kek(passphrase: bytes, salt: bytes,
               ops: int = DEFAULT_OPS, mem: int = DEFAULT_MEM) -> bytes:
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    return nacl.pwhash.argon2id.kdf(KEK_LEN, passphrase, salt,
                                    opslimit=ops, memlimit=mem)


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = nacl.utils.random(NONCE_LEN)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key)
    return nonce + ct


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_LEN:
        raise BadPassphrase("ciphertext too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct, aad, nonce, key)
    except CryptoError as exc:  # wrong key or tampered data
        raise BadPassphrase("decryption failed "
                            "(wrong passphrase or corrupt vault)") from exc


# --- DEK wrapping (uses the KEK) ---------------------------------------------

def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    return _seal(kek, dek, b"krbvault-dek")


def unwrap_dek(kek: bytes, wrapped: bytes) -> bytes:
    return _open(kek, wrapped, b"krbvault-dek")


# --- data sealing (uses the DEK) ---------------------------------------------

def seal(dek: bytes, plaintext: bytes, context: str) -> bytes:
    """Seal a blob/field. ``context`` ties the ciphertext to its slot (e.g.
    "ticket" or "cred:aes256") so a sealed value cannot be swapped elsewhere."""
    return _seal(dek, plaintext, b"krbvault:" + context.encode("utf-8"))


def open_(dek: bytes, blob: bytes, context: str) -> bytes:
    return _open(dek, blob, b"krbvault:" + context.encode("utf-8"))
