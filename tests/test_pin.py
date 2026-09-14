from types import SimpleNamespace

from app.pin import build_hasher, generate_pin, valid_pin, verify_pin


def test_generated_pin_is_six_digits() -> None:
    for _ in range(100):
        assert valid_pin(generate_pin())


def test_argon2id_pin_hash() -> None:
    settings = SimpleNamespace(argon2_time_cost=1, argon2_memory_cost=8192, argon2_parallelism=1)
    hasher = build_hasher(settings)  # type: ignore[arg-type]
    hashed = hasher.hash("482913")
    assert hashed.startswith("$argon2id$")
    assert verify_pin(hasher, hashed, "482913")
    assert not verify_pin(hasher, hashed, "482914")


def test_custom_pin_validation() -> None:
    assert valid_pin("000001")
    assert not valid_pin("12345")
    assert not valid_pin("abcdef")
    assert not valid_pin("１２３４５６")
