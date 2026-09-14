from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from app.config import Settings
from app.db import Database
from app.rate_limit import RateLimiter
from app.users import restriction_message, touch_user


class SecurityMiddleware(BaseMiddleware):
    def __init__(self, settings: Settings, db: Database, limiter: RateLimiter) -> None:
        self.settings = settings
        self.db = db
        self.limiter = limiter

    async def __call__(self, handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
                       event: TelegramObject, data: dict[str, Any]) -> Any:
        actor = getattr(event, "from_user", None)
        if actor is None:
            return await handler(event, data)
        action, rate = self._classify(event)
        async with self.db.sessions() as session:
            user = await touch_user(session, actor.id)
            denial = restriction_message(user, action)
            if user.status.value == "active" and user.ban_until is None:
                await session.commit()
        if denial and actor.id not in self.settings.admin_id_set:
            await self._deny(event, denial)
            return None
        if rate and actor.id not in self.settings.admin_id_set:
            limit, window = rate
            if user.rate_limited:
                limit = max(1, limit // 2)
            allowed, ttl = await self.limiter.hit(f"middleware:{action}:{actor.id}", limit, window)
            if not allowed:
                await self._deny(event, f"🚫 Слишком много запросов. Повторите через {ttl} сек.")
                return None
        return await handler(event, data)

    def _classify(self, event: TelegramObject) -> tuple[str, tuple[int, int] | None]:
        if isinstance(event, Message):
            if event.text and event.text.startswith("/start"):
                return "start", (self.settings.start_rate_limit, self.settings.start_rate_window)
            if event.document or event.photo:
                return "file", (self.settings.file_rate_limit, self.settings.file_rate_window)
            return "read", None
        if isinstance(event, CallbackQuery):
            value = event.data or ""
            if value == "create":
                return "create", (self.settings.create_rate_limit, self.settings.create_rate_window)
            if value == "request:create":
                return "request", (self.settings.request_rate_limit, self.settings.request_rate_window)
            if value.startswith(("reveal:", "confirm:")):
                return "open", (self.settings.open_rate_limit, self.settings.open_rate_window)
        return "read", None

    async def _deny(self, event: TelegramObject, text: str) -> None:
        if isinstance(event, CallbackQuery):
            await event.answer(text, show_alert=True)
        elif isinstance(event, Message):
            await event.answer(text)
