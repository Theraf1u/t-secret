import asyncio

from sqlalchemy import text
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.config import get_settings
from app.db import Database


async def main() -> None:
    db = Database(get_settings().database_url)
    expected = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    try:
        for _ in range(60):
            try:
                async with db.sessions() as session:
                    version = await session.scalar(text("SELECT version_num FROM alembic_version"))
                if version == expected:
                    return
            except Exception:
                pass
            await asyncio.sleep(1)
        raise RuntimeError("database schema did not become ready")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
