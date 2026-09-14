import asyncio

import structlog
from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from redis.asyncio import Redis

from app.db import Database
from app.file_store import EncryptedFileStore
from app.services import expire_requests, expire_secrets


async def cleanup_loop(db: Database, bot: Bot, store: EncryptedFileStore, interval: int,
                       redis: Redis, heartbeat_ttl: int) -> None:
    log = structlog.get_logger()
    while True:
        try:
            await redis.setex("worker:heartbeat", heartbeat_ttl, "alive")
            async with db.sessions() as session:
                notifications, file_paths = await expire_secrets(session)
            async with db.sessions() as session:
                expired_requests = await expire_requests(session)
            for path in file_paths:
                store.delete(path)
            for creator_id, code in notifications:
                try:
                    await bot.send_message(creator_id, f"⌛ Секрет <code>{code}</code> истёк и был уничтожен.")
                except TelegramBadRequest:
                    pass
            if notifications:
                log.info("expired_secrets_destroyed", notified=len(notifications))
            if expired_requests:
                log.info("expired_requests_destroyed", count=expired_requests)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("cleanup_failed")
        await asyncio.sleep(interval)
