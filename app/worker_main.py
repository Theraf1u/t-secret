import asyncio
import logging

import structlog
from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from redis.asyncio import Redis

from app.config import get_settings
from app.core.logging import install_sensitive_filter
from app.crypto import SecretCipher
from app.db import Database
from app.file_store import EncryptedFileStore
from app.worker import cleanup_loop


async def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(message)s")
    install_sensitive_filter()
    structlog.configure(processors=[structlog.processors.TimeStamper(fmt="iso"), structlog.processors.JSONRenderer()])
    db = Database(settings.database_url)
    redis = Redis.from_url(settings.redis_url)
    cipher = SecretCipher(settings.master_key.get_secret_value())
    store = EncryptedFileStore(settings.secret_storage_path, cipher)
    session = AiohttpSession(proxy=settings.telegram_proxy) if settings.telegram_proxy else AiohttpSession()
    bot = Bot(settings.bot_token.get_secret_value(), session=session,
              default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    try:
        await cleanup_loop(db, bot, store, settings.cleanup_interval, redis, settings.worker_heartbeat_ttl)
    finally:
        await redis.aclose()
        await db.close()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())

