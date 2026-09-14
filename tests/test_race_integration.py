import asyncio
import base64
import os
import secrets

import pytest
from sqlalchemy import delete

from app.crypto import SecretCipher
from app.db import Database
from app.models import Secret
from app.services import consume_secret, create_secret


@pytest.mark.skipif(not os.getenv("TSECRET_INTEGRATION_DATABASE_URL"), reason="requires PostgreSQL")
async def test_only_one_parallel_view_succeeds() -> None:
    db = Database(os.environ["TSECRET_INTEGRATION_DATABASE_URL"])
    cipher = SecretCipher(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    async with db.sessions() as session:
        secret, _ = await create_secret(session, 1, cipher.encrypt(b"race"), 300, 1, cipher)

    async def open_once(viewer: int):
        async with db.sessions() as session:
            return await consume_secret(session, secret.id, viewer)

    results = await asyncio.gather(open_once(2), open_once(3))
    assert sum(result is not None for result, _ in results) == 1
    async with db.sessions() as session:
        await session.execute(delete(Secret).where(Secret.id == secret.id)); await session.commit()
    await db.close()
