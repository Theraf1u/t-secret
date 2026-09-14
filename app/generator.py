import math
import secrets
import string
import uuid


SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"


def password(length: int, upper: bool = True, lower: bool = True,
             digits: bool = True, symbols: bool = True) -> tuple[str, int]:
    sets = [chars for enabled, chars in ((upper, string.ascii_uppercase), (lower, string.ascii_lowercase),
                                         (digits, string.digits), (symbols, SYMBOLS)) if enabled]
    if not sets:
        raise ValueError("at least one character set is required")
    alphabet = "".join(sets)
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in chars for c in value) for chars in sets):
            return value, int(length * math.log2(len(alphabet)))


def generated_value(kind: str) -> tuple[str, str, int]:
    if kind == "pin":
        value = f"{secrets.randbelow(1_000_000):06d}"
        return value, "PIN", 20
    if kind == "token":
        value = secrets.token_urlsafe(32)
        return value, "API Token", 256
    if kind == "uuid":
        value = str(uuid.uuid4())
        return value, "UUID", 122
    if kind == "key":
        value = secrets.token_urlsafe(48)
        return value, "Secret Key", 384
    raise ValueError("unsupported generator kind")
