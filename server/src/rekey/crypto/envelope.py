"""AES-256-GCM sealed blobs with context binding.

Blob format: 0x01 | nonce(12) | ciphertext | tag(16). The leading byte versions the format.
The context (AAD) is encoded with length prefixes so field boundaries are unambiguous.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rekey.crypto.errors import DecryptionError

_VERSION = b"\x01"
_NONCE_LEN = 12
KEY_LEN = 32


def encode_context(*fields: str | bytes | int) -> bytes:
    out = bytearray()
    for f in fields:
        data = f if isinstance(f, bytes) else str(f).encode("utf-8")
        out += len(data).to_bytes(4, "big") + data
    return bytes(out)


def seal(key: bytes, plaintext: bytes, context: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    nonce = os.urandom(_NONCE_LEN)
    return _VERSION + nonce + AESGCM(key).encrypt(nonce, plaintext, context)


def open_(key: bytes, blob: bytes, context: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(blob) < 1 + _NONCE_LEN + 16 or blob[:1] != _VERSION:
        raise DecryptionError("malformed blob")
    nonce = blob[1 : 1 + _NONCE_LEN]
    try:
        return AESGCM(key).decrypt(nonce, blob[1 + _NONCE_LEN :], context)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc
