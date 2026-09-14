import base64
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto import SecretCipher, new_access_token, new_public_code, token_digest


@pytest.fixture
def cipher() -> SecretCipher:
    return SecretCipher(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())


def test_round_trip(cipher: SecretCipher) -> None:
    plaintext = "пароль: очень секретно".encode()
    encrypted = cipher.encrypt(plaintext)
    assert encrypted.ciphertext != plaintext
    assert len(encrypted.nonce) == 12
    assert len(encrypted.auth_tag) == 16
    assert cipher.decrypt(encrypted.ciphertext, encrypted.nonce, encrypted.auth_tag) == plaintext


def test_tampering_is_rejected(cipher: SecretCipher) -> None:
    encrypted = cipher.encrypt(b"secret")
    changed = bytes([encrypted.ciphertext[0] ^ 1]) + encrypted.ciphertext[1:]
    with pytest.raises(InvalidTag):
        cipher.decrypt(changed, encrypted.nonce, encrypted.auth_tag)


def test_public_values_are_random_and_non_sequential() -> None:
    tokens = {new_access_token() for _ in range(100)}
    codes = {new_public_code() for _ in range(100)}
    assert len(tokens) == 100
    assert len(codes) == 100
    assert all(code.startswith("TS-") and len(code) == 9 for code in codes)
    assert all(len(token_digest(token)) == 32 for token in tokens)


def test_invalid_master_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        SecretCipher(base64.urlsafe_b64encode(b"short").decode())

