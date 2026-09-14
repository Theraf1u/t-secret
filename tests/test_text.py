from datetime import UTC, datetime, timedelta

from app.text import remaining


def test_remaining_for_unlimited_secret() -> None:
    assert remaining(None) == "до открытия"


def test_remaining_formats_hours() -> None:
    value = remaining(datetime.now(UTC) + timedelta(hours=3, minutes=42))
    assert value.startswith("3 ч")
