"""Files, requests and advanced lifecycle settings."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_secret_manager"
down_revision = "0002_access_protection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    content = postgresql.ENUM("TEXT", "FILE", "PASSWORD", "GENERATED", name="content_type", create_type=False)
    request_status = postgresql.ENUM("ACTIVE", "FULFILLED", "CANCELLED", "EXPIRED", name="request_status", create_type=False)
    content.create(op.get_bind(), checkfirst=True)
    request_status.create(op.get_bind(), checkfirst=True)
    op.add_column("secrets", sa.Column("content_type", content, nullable=False, server_default="TEXT"))
    for name, type_ in (("encrypted_file_path", sa.String(255)), ("encrypted_filename", sa.LargeBinary()),
                        ("filename_nonce", sa.LargeBinary(12)), ("filename_auth_tag", sa.LargeBinary(16)),
                        ("file_nonce", sa.LargeBinary(12)), ("file_auth_tag", sa.LargeBinary(16)),
                        ("file_size", sa.BigInteger()), ("mime_type", sa.String(255)),
                        ("available_at", sa.DateTime(timezone=True)), ("first_opened_at", sa.DateTime(timezone=True))):
        op.add_column("secrets", sa.Column(name, type_, nullable=True))
    op.add_column("secrets", sa.Column("destroy_after_open_seconds", sa.Integer(), nullable=False, server_default="0"))
    op.create_table("secret_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("token_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("token_nonce", sa.LargeBinary(12), nullable=True),
        sa.Column("token_auth_tag", sa.LargeBinary(16), nullable=True),
        sa.Column("prompt_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("prompt_nonce", sa.LargeBinary(12), nullable=True),
        sa.Column("prompt_auth_tag", sa.LargeBinary(16), nullable=True),
        sa.Column("owner_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False),
        sa.Column("status", request_status, nullable=False),
    )
    op.create_index("ix_secret_requests_token_hash", "secret_requests", ["token_hash"], unique=True)
    op.create_index("ix_secret_requests_owner_id", "secret_requests", ["owner_id"])
    op.create_index("ix_secret_requests_expires_at", "secret_requests", ["expires_at"])
    op.create_index("ix_secret_requests_owner_status", "secret_requests", ["owner_id", "status"])


def downgrade() -> None:
    op.drop_table("secret_requests")
    for column in ("destroy_after_open_seconds", "first_opened_at", "available_at", "mime_type", "file_size",
                   "file_auth_tag", "file_nonce", "filename_auth_tag", "filename_nonce", "encrypted_filename",
                   "encrypted_file_path", "content_type"):
        op.drop_column("secrets", column)
    postgresql.ENUM(name="request_status").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="content_type").drop(op.get_bind(), checkfirst=True)
