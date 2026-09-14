from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Database
from app.models import AuditEvent


ALLOWED_METADATA = {"reason", "content_type", "file_size", "count", "restriction", "duration_seconds", "request_id"}
FORBIDDEN_FRAGMENTS = {"content", "plaintext", "password", "pin", "token", "key", "filename", "ciphertext", "nonce"}


def safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        lowered = key.lower()
        if key not in ALLOWED_METADATA or any(fragment in lowered for fragment in FORBIDDEN_FRAGMENTS):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value
    return result


def add_audit(session: AsyncSession, event_type: str, *, secret_code: str | None = None,
              owner_id: int | None = None, viewer_id: int | None = None,
              actor_id: int | None = None, metadata: dict[str, Any] | None = None) -> None:
    session.add(AuditEvent(event_type=event_type, secret_public_code=secret_code, owner_id=owner_id,
                           viewer_id=viewer_id, actor_id=actor_id, metadata_json=safe_metadata(metadata)))


async def write_audit(db: Database, event_type: str, **kwargs: Any) -> None:
    async with db.sessions() as session:
        add_audit(session, event_type, **kwargs)
        await session.commit()

