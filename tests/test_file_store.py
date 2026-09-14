import base64
import secrets
from pathlib import Path

from app.crypto import SecretCipher
from app.file_store import EncryptedFileStore


def test_file_is_encrypted_and_plaintext_is_removed(tmp_path: Path) -> None:
    cipher = SecretCipher(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    store = EncryptedFileStore(str(tmp_path / "encrypted"), cipher)
    source = tmp_path / "config.env"
    plaintext = b"API_TOKEN=very-secret"
    source.write_bytes(plaintext)

    name, encrypted, _ = store.save_plaintext(source)
    stored = tmp_path / "encrypted" / name
    assert not source.exists()
    assert stored.exists()
    assert stored.read_bytes() != plaintext

    temporary = store.decrypt_to_temporary(name, encrypted.nonce, encrypted.auth_tag)
    try:
        assert temporary.read_bytes() == plaintext
    finally:
        temporary.unlink(missing_ok=True)
    store.delete(name)
    assert not stored.exists()


def test_store_refuses_path_escape(tmp_path: Path) -> None:
    cipher = SecretCipher(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    store = EncryptedFileStore(str(tmp_path / "encrypted"), cipher)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"keep")
    store.delete("../outside.bin")
    assert outside.exists()

