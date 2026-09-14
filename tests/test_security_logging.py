import logging

from app.audit import safe_metadata
from app.core.logging import SensitiveDataFilter, redact


def test_sensitive_values_are_redacted() -> None:
    token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi12345"
    assert token not in redact(f"bot token={token}")
    assert "hunter2" not in redact("password=hunter2")
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "pin=482913", (), None)
    assert SensitiveDataFilter().filter(record)
    assert "482913" not in str(record.msg)


def test_audit_metadata_is_allowlisted() -> None:
    result = safe_metadata({"reason": "manual", "count": 2, "secret_content": "never",
                            "pin": "482913", "filename": "secret.env", "token": "raw"})
    assert result == {"reason": "manual", "count": 2}

