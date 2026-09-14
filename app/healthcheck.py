import asyncio

from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession
from redis.asyncio import Redis
from sqlalchemy import text

from app.config import get_settings
from app.crypto import SecretCipher
from app.db import Database


async def main() -> None:
    settings = get_settings()
    SecretCipher(settings.master_key.get_secret_value())
    db = Database(settings.database_url)
    redis = Redis.from_url(settings.redis_url)
    session = AiohttpSession(proxy=settings.telegram_proxy) if settings.telegram_proxy else AiohttpSession()
    bot = Bot(settings.bot_token.get_secret_value(), session=session)
    try:
        async with db.sessions() as connection:
            assert await connection.scalar(text("SELECT 1")) == 1
        assert await redis.ping()
        assert await redis.get("worker:heartbeat")
        await bot.get_me()
    finally:
        await bot.session.close()
        await redis.aclose()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
