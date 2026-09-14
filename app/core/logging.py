import logging
import re
from typing import Any


PATTERNS = (
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"(?i)(password|passwd|pin|token|secret|master_key|api_key)\s*[=:]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", re.DOTALL),
)


def redact(value: Any) -> str:
    text = str(value)
    for pattern in PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text


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
