from datetime import UTC, datetime
from zoneinfo import ZoneInfo


def remaining(expires_at: datetime | None) -> str:
    if expires_at is None:
        return "до открытия"
    seconds = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
    if seconds < 3600:
        return f"{max(1, seconds // 60)} мин"
    if seconds < 86400:
        return f"{seconds // 3600} ч {seconds % 3600 // 60} мин"
    return f"{seconds // 86400} дн {seconds % 86400 // 3600} ч"


def dt(value: datetime | None) -> str:
    return "до открытия" if value is None else value.astimezone(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M")
