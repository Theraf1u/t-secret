import logging

from app.audit import safe_metadata
from app.core.logging import SensitiveDataFilter, redact, redact_event_dict


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


def test_redact_event_dict_covers_structlog_pipeline() -> None:
    # structlog does not route through stdlib logging.Filter by default, so the
    # structured-logging pipeline needs its own redaction pass independent of
    # SensitiveDataFilter (see app.main / app.worker_main structlog.configure).
    event = redact_event_dict(None, "info", {
        "event": "leak_test",
        "token": "raw-value-that-has-no-recognizable-pattern",
        "master_key": "another-raw-value",
        "exception": "Traceback ...\nValueError: token=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi12345",
        "count": 3,
    })
    assert event["token"] == "<redacted>"
    assert event["master_key"] == "<redacted>"
    assert "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi12345" not in event["exception"]
    assert event["count"] == 3
    assert event["event"] == "leak_test"

