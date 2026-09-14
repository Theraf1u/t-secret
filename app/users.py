from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, UserStatus


async def touch_user(session: AsyncSession, telegram_id: int) -> User:
    statement = insert(User).values(telegram_id=telegram_id, last_seen_at=datetime.now(UTC)).on_conflict_do_update(
        index_elements=[User.telegram_id], set_={"last_seen_at": datetime.now(UTC)}).returning(User)
    user = (await session.execute(statement)).scalar_one()
    await session.commit()
    return user


async def user_by_telegram_id(session: AsyncSession, telegram_id: int) -> User | None:
    return await session.scalar(select(User).where(User.telegram_id == telegram_id))


def restriction_message(user: User, action: str) -> str | None:
    now = datetime.now(UTC)
    if user.status == UserStatus.BANNED:
        return "🚫 Доступ к T-Secret ограничен администратором."
    if user.status == UserStatus.TEMP_BANNED:
        if user.ban_until and user.ban_until > now:
            until = user.ban_until.astimezone(ZoneInfo("Europe/Moscow"))
            return f"🚫 Доступ временно ограничен до {until:%d.%m.%Y %H:%M} МСК."
        user.status = UserStatus.ACTIVE
        user.ban_until = None
    if user.read_only and action in {"create", "request", "file"}:
        return "🚫 Для аккаунта включён режим только чтения."
    if user.creation_disabled and action == "create":
        return "🚫 Создание секретов для аккаунта отключено."
    if user.file_uploads_disabled and action == "file":
        return "🚫 Загрузка файлов для аккаунта отключена."
    return None
