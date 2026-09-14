from redis.asyncio import Redis


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        # Increment and first expiry must be atomic so concurrent first requests
        # cannot leave a rate-limit key without a TTL.
        count, ttl = await self.redis.eval(
            """
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return {count, redis.call('TTL', KEYS[1])}
            """,
            1, key, window,
        )
        return count <= limit, max(1, ttl)

    async def pin_failure(self, secret_id: str, telegram_id: int, limit: int, window: int) -> tuple[int, int]:
        key = f"secret_pin_attempt:{secret_id}:{telegram_id}"
        await self.hit(key, limit, window)
        raw = await self.redis.get(key)
        ttl = await self.redis.ttl(key)
        return int(raw or limit), max(1, ttl)

    async def pin_status(self, secret_id: str, telegram_id: int) -> tuple[int, int]:
        key = f"secret_pin_attempt:{secret_id}:{telegram_id}"
        raw, ttl = await self.redis.get(key), await self.redis.ttl(key)
        return int(raw or 0), max(0, ttl)

    async def clear_pin_failures(self, secret_id: str, telegram_id: int) -> None:
        await self.redis.delete(f"secret_pin_attempt:{secret_id}:{telegram_id}")
