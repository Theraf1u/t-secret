import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SecretStatus(str, enum.Enum):
    ACTIVE = "active"
    DESTROYED = "destroyed"
    EXPIRED = "expired"


class DestroyReason(str, enum.Enum):
    VIEW_LIMIT = "view_limit"
    MANUAL = "manual"
    EXPIRED = "expired"


class RecipientMode(str, enum.Enum):
    ANY = "any"
    SPECIFIC = "specific"
    FIRST = "first"


class ContentType(str, enum.Enum):
    TEXT = "text"
    FILE = "file"
    PASSWORD = "password"
    GENERATED = "generated"


class RequestStatus(str, enum.Enum):
    ACTIVE = "active"
    FULFILLED = "fulfilled"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    BANNED = "banned"
    TEMP_BANNED = "temporary_ban"


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = (
        Index("ix_secrets_creator_status", "creator_id", "status"),
        Index("ix_secrets_status_expires", "status", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    public_code: Mapped[str] = mapped_column(String(9), unique=True, index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, index=True)
    token_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    token_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    token_auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    creator_id: Mapped[int] = mapped_column(BigInteger, index=True)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[SecretStatus] = mapped_column(Enum(SecretStatus, name="secret_status"), default=SecretStatus.ACTIVE)
    destroy_reason: Mapped[DestroyReason | None] = mapped_column(Enum(DestroyReason, name="destroy_reason"))
    views_allowed: Mapped[int] = mapped_column(Integer, default=1)
    views_used: Mapped[int] = mapped_column(Integer, default=0)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pin_hash: Mapped[str | None] = mapped_column(String(512))
    recipient_mode: Mapped[RecipientMode] = mapped_column(Enum(RecipientMode, name="recipient_mode"), default=RecipientMode.ANY)
    recipient_telegram_id: Mapped[int | None] = mapped_column(BigInteger)
    claimed_by_telegram_id: Mapped[int | None] = mapped_column(BigInteger)
    require_identity_confirmation: Mapped[bool] = mapped_column(default=False)
    notify_open: Mapped[bool] = mapped_column(default=True)
    notify_wrong_pin: Mapped[bool] = mapped_column(default=False)
    notify_wrong_user: Mapped[bool] = mapped_column(default=True)
    notify_expiry: Mapped[bool] = mapped_column(default=True)
    notify_destroy: Mapped[bool] = mapped_column(default=True)
    content_type: Mapped[ContentType] = mapped_column(Enum(ContentType, name="content_type"), default=ContentType.TEXT)
    encrypted_file_path: Mapped[str | None] = mapped_column(String(255))
    encrypted_filename: Mapped[bytes | None] = mapped_column(LargeBinary)
    filename_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    filename_auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    file_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    file_auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    mime_type: Mapped[str | None] = mapped_column(String(255))
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroy_after_open_seconds: Mapped[int] = mapped_column(Integer, default=0)
    first_opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecretRequest(Base):
    __tablename__ = "secret_requests"
    __table_args__ = (Index("ix_secret_requests_owner_status", "owner_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, index=True)
    token_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    token_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    token_auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    prompt_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    prompt_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12))
    prompt_auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16))
    owner_id: Mapped[int] = mapped_column(BigInteger, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[RequestStatus] = mapped_column(Enum(RequestStatus, name="request_status"), default=RequestStatus.ACTIVE)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    telegram_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE)
    ban_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_only: Mapped[bool] = mapped_column(Boolean, default=False)
    creation_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    file_uploads_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    rate_limited: Mapped[bool] = mapped_column(Boolean, default=False)
    restriction_reason: Mapped[str | None] = mapped_column(Text)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_event_time", "event_type", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    secret_public_code: Mapped[str | None] = mapped_column(String(16), index=True)
    owner_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    viewer_id: Mapped[int | None] = mapped_column(BigInteger)
    actor_id: Mapped[int | None] = mapped_column(BigInteger)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)


class UiEmojiSetting(Base):
    __tablename__ = "ui_emoji_settings"

    slot: Mapped[str] = mapped_column(String(64), primary_key=True)
    custom_emoji_id: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_by: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
