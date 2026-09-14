from datetime import UTC, datetime

from app.models import DestroyReason, RecipientMode, Secret, SecretStatus
from app.services import destroy_payload


def test_destroy_removes_all_sensitive_material() -> None:
    secret = Secret(public_code="TS-A1B2C3", token_hash=b"h" * 32, creator_id=1,
                    token_ciphertext=b"token", token_nonce=b"n" * 12, token_auth_tag=b"t" * 16,
                    ciphertext=b"cipher", nonce=b"n" * 12, auth_tag=b"t" * 16,
                    views_allowed=1, views_used=0, status=SecretStatus.ACTIVE,
                    pin_hash="$argon2id$example", recipient_mode=RecipientMode.SPECIFIC,
                    recipient_telegram_id=2, claimed_by_telegram_id=2,
                    encrypted_file_path="abc.bin", encrypted_filename=b"name",
                    filename_nonce=b"n" * 12, filename_auth_tag=b"t" * 16,
                    file_nonce=b"n" * 12, file_auth_tag=b"t" * 16)
    destroy_payload(secret, DestroyReason.MANUAL)
    for field in ("ciphertext", "nonce", "auth_tag", "token_ciphertext", "token_nonce", "token_auth_tag",
                  "pin_hash", "recipient_telegram_id", "claimed_by_telegram_id", "encrypted_file_path",
                  "encrypted_filename", "filename_nonce", "filename_auth_tag", "file_nonce", "file_auth_tag"):
        assert getattr(secret, field) is None
    assert secret.public_code == "TS-A1B2C3"
    assert secret.creator_id == 1
    assert secret.status == SecretStatus.DESTROYED

