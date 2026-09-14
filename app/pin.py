import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import Settings


def build_hasher(settings: Settings) -> PasswordHasher:
    return PasswordHasher(time_cost=settings.argon2_time_cost, memory_cost=settings.argon2_memory_cost,
                          parallelism=settings.argon2_parallelism, hash_len=32, salt_len=16)


def generate_pin() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def valid_pin(pin: str) -> bool:
    return len(pin) == 6 and pin.isascii() and pin.isdigit()


def verify_pin(hasher: PasswordHasher, hashed: str, pin: str) -> bool:
    try:
        return hasher.verify(hashed, pin)
    except (VerifyMismatchError, InvalidHashError):
        return False

