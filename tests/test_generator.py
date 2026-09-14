from app.generator import SYMBOLS, generated_value, password


def test_password_contains_all_enabled_sets() -> None:
    value, entropy = password(32)
    assert len(value) == 32
    assert any(c.isupper() for c in value)
    assert any(c.islower() for c in value)
    assert any(c.isdigit() for c in value)
    assert any(c in SYMBOLS for c in value)
    assert entropy >= 190


def test_generator_kinds() -> None:
    for kind in ("pin", "token", "uuid", "key"):
        value, label, entropy = generated_value(kind)
        assert value and label and entropy > 0
