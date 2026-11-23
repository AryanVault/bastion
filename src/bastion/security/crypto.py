"""Authenticated field encryption for data at rest (control C13).

AES-256-GCM with a random 96-bit nonce per value. The caller passes a `context` string (for
example ``memory:<id>``) that is bound in as associated data, so a ciphertext copied into a
different row or table fails to decrypt instead of silently decrypting as the wrong record.
"""

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
_VERSION = "v1"


class DecryptionError(Exception):
    """The token is malformed, was tampered with, or belongs to another key or context."""


def generate_key() -> bytes:
    return os.urandom(KEY_BYTES)


class FieldCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError(f"encryption key must be {KEY_BYTES} bytes")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, *, context: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        sealed = self._aead.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return f"{_VERSION}:" + base64.urlsafe_b64encode(nonce + sealed).decode("ascii")

    def decrypt(self, token: str, *, context: str) -> str:
        version, separator, payload = token.partition(":")
        if version != _VERSION or not separator:
            raise DecryptionError("unsupported or malformed token")
        try:
            raw = base64.b64decode(payload.encode("ascii"), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise DecryptionError("malformed token") from exc
        if len(raw) < _NONCE_BYTES + _TAG_BYTES:
            raise DecryptionError("token is too short")
        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        try:
            plaintext = self._aead.decrypt(nonce, sealed, context.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptionError("authentication failed") from exc
        return plaintext.decode("utf-8")
