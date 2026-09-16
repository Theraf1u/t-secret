import asyncio
import logging

import structlog
from aiogram import Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from aiogram.fsm.storage.redis import RedisStorage
from aiogram.types import BotCommand
from redis.asyncio import Redis

from app.admin import build_admin_router
from app.bot.middlewares.security import SecurityMiddleware
from app.config import get_settings
from app.core.logging import install_sensitive_filter, redact_event_dict
from app.crypto import SecretCipher
from app.db import Database
from app.file_store import EncryptedFileStore
from app.handlers import build_router
from app.rate_limit import RateLimiter
from app.ui_emoji import UiBot, load_ui_emojis


async def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(message)s")
    install_sensitive_filter()
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.format_exc_info,
        redact_event_dict,
        structlog.processors.JSONRenderer(),
    ])
    log = structlog.get_logger()
    db = Database(settings.database_url)
    await load_ui_emojis(db)
    cipher = SecretCipher(settings.master_key.get_secret_value())
    file_store = EncryptedFileStore(settings.secret_storage_path, cipher)
    storage = RedisStorage.from_url(settings.redis_url)
    rate_redis = Redis.from_url(settings.redis_url)
    session = AiohttpSession(proxy=settings.telegram_proxy) if settings.telegram_proxy else AiohttpSession()
    bot = UiBot(settings.bot_token.get_secret_value(), session=session,
                default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=storage)
    security = SecurityMiddleware(settings, db, RateLimiter(rate_redis))
    dp.message.outer_middleware(security)
    dp.callback_query.outer_middleware(security)
    dp.include_router(build_admin_router(settings, db, rate_redis))
    dp.include_router(build_router(settings, db, cipher, rate_redis, file_store))
    try:
        await bot.delete_webhook(drop_pending_updates=False)
        me = await bot.get_me()
        if me.username:
            settings.bot_username = me.username
        await bot.set_my_commands([BotCommand(command="start", description="Главное меню")])
        log.info("bot_started")
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await storage.close()
        await rate_redis.aclose()
        await db.close()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
