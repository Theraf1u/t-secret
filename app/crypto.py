import base64
import hashlib
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


TAG_SIZE = 16


@dataclass(slots=True)
class EncryptedSecret:
    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes


class SecretCipher:
    def __init__(self, encoded_key: str) -> None:
        try:
            key = base64.urlsafe_b64decode(encoded_key.encode())
        except Exception as exc:
            raise ValueError("MASTER_KEY must be URL-safe base64") from exc
        if len(key) != 32:
            raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> EncryptedSecret:
        nonce = secrets.token_bytes(12)
        combined = self._aes.encrypt(nonce, plaintext, None)
        return EncryptedSecret(combined[:-TAG_SIZE], nonce, combined[-TAG_SIZE:])

    def decrypt(self, ciphertext: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        return self._aes.decrypt(nonce, ciphertext + auth_tag, None)


def new_access_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def new_public_code() -> str:
    return f"TS-{secrets.token_hex(3).upper()}"

