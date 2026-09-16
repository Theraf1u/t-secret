import logging
import re
from typing import Any


PATTERNS = (
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"(?i)(password|passwd|pin|token|secret|master_key|api_key)\s*[=:]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", re.DOTALL),
)

# Field names that must be fully redacted regardless of their content, for
# structured log calls like log.info("x", token=raw_value) where the value
# itself carries no recognizable pattern for PATTERNS to match.
SENSITIVE_KEYS = ("password", "passwd", "pin", "token", "secret", "master_key",
                  "api_key", "ciphertext", "auth_tag", "authorization")


def redact(value: Any) -> str:
    text = str(value)
    for pattern in PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text


def redact_event_dict(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor: redact sensitive structlog kwargs and formatted
    exception text. Must run after format_exc_info so traceback text is
    already a string by the time this executes."""
    for key, value in event_dict.items():
        if not isinstance(value, str):
            continue
        if any(fragment in key.lower() for fragment in SENSITIVE_KEYS):
            event_dict[key] = "<redacted>"
        else:
            event_dict[key] = redact(value)
    return event_dict


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(redact(value) if isinstance(value, str) else value for value in record.args)
            elif isinstance(record.args, dict):
                record.args = {key: redact(value) if isinstance(value, str) else value for key, value in record.args.items()}
        return True


def install_sensitive_filter() -> None:
    root = logging.getLogger()
    for handler in root.handlers:
        handler.addFilter(SensitiveDataFilter())
