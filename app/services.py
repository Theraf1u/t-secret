from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import add_audit
from app.crypto import (
    EncryptedSecret,
    SecretCipher,
    new_access_token,
    new_public_code,
    token_digest,
)
from app.models import (
    ContentType,
    DestroyReason,
    RecipientMode,
    RequestStatus,
    Secret,
    SecretRequest,
    SecretStatus,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def destroy_payload(secret: Secret, reason: DestroyReason, status: SecretStatus = SecretStatus.DESTROYED) -> None:
    secret.ciphertext = None
    secret.nonce = None
    secret.auth_tag = None
    secret.token_ciphertext = None
    secret.token_nonce = None
    secret.token_auth_tag = None
    secret.encrypted_file_path = None
    secret.encrypted_filename = None
    secret.filename_nonce = None
    secret.filename_auth_tag = None
    secret.file_nonce = None
    secret.file_auth_tag = None
    secret.pin_hash = None
    secret.recipient_telegram_id = None
    secret.claimed_by_telegram_id = None
    secret.status = status
    secret.destroy_reason = reason
    secret.destroyed_at = utcnow()


async def create_secret(session: AsyncSession, creator_id: int, payload: EncryptedSecret,
                        ttl_seconds: int, views: int, cipher: SecretCipher, protection: dict | None = None,
                        commit: bool = True) -> tuple[Secret, str]:
    token = new_access_token()
    encrypted_token = cipher.encrypt(token.encode())
    expires_at = None if ttl_seconds == 0 else utcnow() + timedelta(seconds=ttl_seconds)
    protection = protection or {}
    content_type = ContentType(protection.get("content_type", "text"))
    secret = Secret(public_code=new_public_code(), token_hash=token_digest(token), creator_id=creator_id,
                    token_ciphertext=encrypted_token.ciphertext, token_nonce=encrypted_token.nonce,
                    token_auth_tag=encrypted_token.auth_tag,
                    ciphertext=None if content_type == ContentType.FILE else payload.ciphertext,
                    nonce=None if content_type == ContentType.FILE else payload.nonce,
                    auth_tag=None if content_type == ContentType.FILE else payload.auth_tag,
                    expires_at=expires_at, views_allowed=views,
                    pin_hash=protection.get("pin_hash"),
                    recipient_mode=RecipientMode(protection.get("recipient_mode", "any")),
                    recipient_telegram_id=protection.get("recipient_telegram_id"),
                    require_identity_confirmation=bool(protection.get("require_identity_confirmation", False)),
                    notify_open=bool(protection.get("notify_open", True)),
                    notify_wrong_pin=bool(protection.get("notify_wrong_pin", False)),
                    notify_wrong_user=bool(protection.get("notify_wrong_user", True)),
                    notify_expiry=bool(protection.get("notify_expiry", True)),
                    notify_destroy=bool(protection.get("notify_destroy", True)),
                    content_type=content_type,
                    encrypted_file_path=protection.get("encrypted_file_path"),
                    encrypted_filename=protection.get("encrypted_filename"),
                    filename_nonce=protection.get("filename_nonce"),
                    filename_auth_tag=protection.get("filename_auth_tag"),
                    file_nonce=protection.get("file_nonce"), file_auth_tag=protection.get("file_auth_tag"),
                    file_size=protection.get("file_size"), mime_type=protection.get("mime_type"),
                    available_at=protection.get("available_at"),
                    destroy_after_open_seconds=int(protection.get("destroy_after_open_seconds", 3600)))
    session.add(secret)
    add_audit(session, "secret_created", secret_code=secret.public_code, owner_id=creator_id,
              actor_id=creator_id, metadata={"content_type": content_type.value})
    if commit:
        await session.commit()
    else:
        await session.flush()
    await session.refresh(secret)
    return secret, token


async def secret_by_token(session: AsyncSession, token: str) -> Secret | None:
    return await session.scalar(select(Secret).where(Secret.token_hash == token_digest(token)))


async def secret_by_id(session: AsyncSession, secret_id: UUID) -> Secret | None:
    return await session.get(Secret, secret_id)


def is_available(secret: Secret) -> bool:
    has_payload = secret.encrypted_file_path is not None if secret.content_type == ContentType.FILE else secret.ciphertext is not None
    return (secret.status == SecretStatus.ACTIVE and has_payload
            and secret.views_used < secret.views_allowed
            and (secret.expires_at is None or secret.expires_at > utcnow()))


@dataclass(slots=True)
class RevealResult:
    payload: EncryptedSecret | None
    public_code: str
    creator_id: int
    destroyed: bool
    notify_open: bool
    content_type: ContentType
    encrypted_file_path: str | None = None
    file_nonce: bytes | None = None
    file_auth_tag: bytes | None = None
    encrypted_filename: bytes | None = None
    filename_nonce: bytes | None = None
    filename_auth_tag: bytes | None = None
    file_size: int | None = None
    mime_type: str | None = None


async def consume_secret(session: AsyncSession, secret_id: UUID, viewer_id: int) -> tuple[RevealResult | None, str | None]:
    async with session.begin():
        secret = await session.scalar(select(Secret).where(Secret.id == secret_id).with_for_update())
        if secret is None:
            return None, "unavailable"
        add_audit(session, "secret_access_attempt", secret_code=secret.public_code,
                  owner_id=secret.creator_id, viewer_id=viewer_id, actor_id=viewer_id)
        if secret.expires_at is not None and secret.expires_at <= utcnow() and secret.status == SecretStatus.ACTIVE:
            expired_file = secret.encrypted_file_path
            destroy_payload(secret, DestroyReason.EXPIRED, SecretStatus.EXPIRED)
            add_audit(session, "secret_expired", secret_code=secret.public_code, owner_id=secret.creator_id)
            return None, f"expired_file:{expired_file}" if expired_file else "unavailable"
        if not is_available(secret):
            return None, "unavailable"
        if secret.available_at is not None and secret.available_at > utcnow():
            return None, "not_yet"
        if secret.recipient_mode == RecipientMode.SPECIFIC and secret.recipient_telegram_id != viewer_id:
            return None, "wrong_user"
        if secret.recipient_mode == RecipientMode.FIRST:
            if secret.claimed_by_telegram_id is None:
                secret.claimed_by_telegram_id = viewer_id
                add_audit(session, "secret_claimed", secret_code=secret.public_code,
                          owner_id=secret.creator_id, viewer_id=viewer_id)
            elif secret.claimed_by_telegram_id != viewer_id:
                return None, "wrong_user"
        payload = None if secret.content_type == ContentType.FILE else EncryptedSecret(secret.ciphertext, secret.nonce, secret.auth_tag)  # type: ignore[arg-type]
        file_values = (secret.encrypted_file_path, secret.file_nonce, secret.file_auth_tag,
                       secret.encrypted_filename, secret.filename_nonce, secret.filename_auth_tag,
                       secret.file_size, secret.mime_type)
        if secret.first_opened_at is None:
            secret.first_opened_at = utcnow()
            if secret.destroy_after_open_seconds > 0:
                timed_expiry = secret.first_opened_at + timedelta(seconds=secret.destroy_after_open_seconds)
                if secret.expires_at is None or timed_expiry < secret.expires_at:
                    secret.expires_at = timed_expiry
        secret.views_used += 1
        destroyed = secret.views_used >= secret.views_allowed
        if destroyed:
            destroy_payload(secret, DestroyReason.VIEW_LIMIT)
            add_audit(session, "secret_destroyed", secret_code=secret.public_code, owner_id=secret.creator_id,
                      viewer_id=viewer_id, metadata={"reason": "view_limit"})
        add_audit(session, "secret_opened", secret_code=secret.public_code, owner_id=secret.creator_id,
                  viewer_id=viewer_id)
        return RevealResult(payload, secret.public_code, secret.creator_id, destroyed, secret.notify_open,
                            secret.content_type, *file_values), None


async def destroy_owned(session: AsyncSession, secret_id: UUID, creator_id: int) -> tuple[bool, str | None]:
    async with session.begin():
        secret = await session.scalar(select(Secret).where(Secret.id == secret_id, Secret.creator_id == creator_id).with_for_update())
        if secret is None or secret.status != SecretStatus.ACTIVE:
            return False, None
        path = secret.encrypted_file_path
        destroy_payload(secret, DestroyReason.MANUAL)
        add_audit(session, "secret_destroyed", secret_code=secret.public_code, owner_id=creator_id,
                  actor_id=creator_id, metadata={"reason": "manual"})
        return True, path


async def destroy_all_owned(session: AsyncSession, creator_id: int) -> tuple[int, list[str]]:
    paths = list((await session.scalars(select(Secret.encrypted_file_path).where(
        Secret.creator_id == creator_id, Secret.status == SecretStatus.ACTIVE,
        Secret.encrypted_file_path.is_not(None)))).all())
    values = {"ciphertext": None, "nonce": None, "auth_tag": None, "token_ciphertext": None, "token_nonce": None,
                  "token_auth_tag": None, "encrypted_file_path": None, "encrypted_filename": None, "filename_nonce": None,
                  "filename_auth_tag": None, "file_nonce": None, "file_auth_tag": None, "pin_hash": None,
                  "recipient_telegram_id": None, "claimed_by_telegram_id": None, "status": SecretStatus.DESTROYED,
                  "destroy_reason": DestroyReason.MANUAL, "destroyed_at": utcnow()}
    result = await session.execute(update(Secret).where(Secret.creator_id == creator_id,
                                  Secret.status == SecretStatus.ACTIVE).values(**values))
    await session.commit()
    if result.rowcount:
        async with session.begin():
            add_audit(session, "panic_delete", owner_id=creator_id, actor_id=creator_id,
                      metadata={"count": result.rowcount})
    return result.rowcount or 0, paths


async def count_active_owned(session: AsyncSession, creator_id: int) -> int:
    return int(await session.scalar(select(func.count()).select_from(Secret).where(
        Secret.creator_id == creator_id, Secret.status == SecretStatus.ACTIVE)) or 0)


async def expire_secrets(session: AsyncSession) -> tuple[list[tuple[int, str]], list[str]]:
    paths = list((await session.scalars(select(Secret.encrypted_file_path).where(
        Secret.status == SecretStatus.ACTIVE, Secret.expires_at.is_not(None), Secret.expires_at <= utcnow(),
        Secret.encrypted_file_path.is_not(None)))).all())
    values = {"ciphertext": None, "nonce": None, "auth_tag": None, "token_ciphertext": None, "token_nonce": None,
                  "token_auth_tag": None, "encrypted_file_path": None, "encrypted_filename": None, "filename_nonce": None,
                  "filename_auth_tag": None, "file_nonce": None, "file_auth_tag": None, "pin_hash": None,
                  "recipient_telegram_id": None, "claimed_by_telegram_id": None, "status": SecretStatus.EXPIRED,
                  "destroy_reason": DestroyReason.EXPIRED, "destroyed_at": utcnow()}
    result = await session.execute(update(Secret).where(Secret.status == SecretStatus.ACTIVE,
                                  Secret.expires_at.is_not(None), Secret.expires_at <= utcnow()).values(**values)
                                  .returning(Secret.creator_id, Secret.public_code, Secret.notify_expiry))
    rows = result.all()
    for creator_id, code, _ in rows:
        add_audit(session, "secret_expired", secret_code=code, owner_id=creator_id)
    await session.commit()
    return ([(creator_id, code) for creator_id, code, notify in rows if notify], paths)


async def list_owned(session: AsyncSession, creator_id: int, active: bool, offset: int, limit: int = 8) -> list[Secret]:
    query = select(Secret).where(Secret.creator_id == creator_id)
    query = query.where(Secret.status == SecretStatus.ACTIVE) if active else query.where(Secret.status != SecretStatus.ACTIVE)
    return list((await session.scalars(query.order_by(Secret.created_at.desc()).offset(offset).limit(limit))).all())


def recover_token(secret: Secret, cipher: SecretCipher) -> str | None:
    if secret.token_ciphertext is None or secret.token_nonce is None or secret.token_auth_tag is None:
        return None
    return cipher.decrypt(secret.token_ciphertext, secret.token_nonce, secret.token_auth_tag).decode()


async def create_request(session: AsyncSession, owner_id: int, prompt: str, ttl_seconds: int,
                         cipher: SecretCipher) -> tuple[SecretRequest, str]:
    token = new_access_token()
    token_encrypted = cipher.encrypt(token.encode())
    prompt_encrypted = cipher.encrypt(prompt.encode())
    request = SecretRequest(token_hash=token_digest(token), token_ciphertext=token_encrypted.ciphertext,
                            token_nonce=token_encrypted.nonce, token_auth_tag=token_encrypted.auth_tag,
                            prompt_ciphertext=prompt_encrypted.ciphertext, prompt_nonce=prompt_encrypted.nonce,
                            prompt_auth_tag=prompt_encrypted.auth_tag, owner_id=owner_id,
                            expires_at=utcnow() + timedelta(seconds=ttl_seconds), max_uses=1, uses=0,
                            status=RequestStatus.ACTIVE)
    session.add(request)
    add_audit(session, "secret_request_created", owner_id=owner_id, actor_id=owner_id)
    await session.commit()
    await session.refresh(request)
    return request, token


async def request_by_token(session: AsyncSession, token: str) -> SecretRequest | None:
    return await session.scalar(select(SecretRequest).where(SecretRequest.token_hash == token_digest(token)))


def request_prompt(request: SecretRequest, cipher: SecretCipher) -> str:
    if request.prompt_ciphertext is None or request.prompt_nonce is None or request.prompt_auth_tag is None:
        return ""
    return cipher.decrypt(request.prompt_ciphertext, request.prompt_nonce, request.prompt_auth_tag).decode()


async def cancel_request(session: AsyncSession, request_id: UUID, owner_id: int) -> bool:
    async with session.begin():
        request = await session.scalar(select(SecretRequest).where(
            SecretRequest.id == request_id, SecretRequest.owner_id == owner_id).with_for_update())
        if request is None or request.status != RequestStatus.ACTIVE:
            return False
        request.status = RequestStatus.CANCELLED
        request.token_ciphertext = request.token_nonce = request.token_auth_tag = None
        request.prompt_ciphertext = request.prompt_nonce = request.prompt_auth_tag = None
        return True


async def fulfill_request(session: AsyncSession, request_id: UUID, sender_id: int, payload: EncryptedSecret,
                          cipher: SecretCipher, content_type: str = "text") -> tuple[Secret | None, str | None, int | None]:
    async with session.begin():
        request = await session.scalar(select(SecretRequest).where(SecretRequest.id == request_id).with_for_update())
        if (request is None or request.status != RequestStatus.ACTIVE or request.expires_at <= utcnow()
                or request.uses >= request.max_uses):
            return None, None, None
        owner_id = request.owner_id
        request.uses += 1
        if request.uses >= request.max_uses:
            request.status = RequestStatus.FULFILLED
            request.token_ciphertext = request.token_nonce = request.token_auth_tag = None
        secret, token = await create_secret(session, sender_id, payload, 86400, 1, cipher,
                                             {"content_type": content_type, "recipient_mode": "specific",
                                              "recipient_telegram_id": owner_id}, commit=False)
        return secret, token, owner_id


async def expire_requests(session: AsyncSession) -> int:
    result = await session.execute(update(SecretRequest).where(
        SecretRequest.status == RequestStatus.ACTIVE, SecretRequest.expires_at <= utcnow()).values(
        status=RequestStatus.EXPIRED, token_ciphertext=None, token_nonce=None, token_auth_tag=None,
        prompt_ciphertext=None, prompt_nonce=None, prompt_auth_tag=None))
    await session.commit()
    return result.rowcount or 0
