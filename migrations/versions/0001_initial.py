"""Initial T-Secret schema."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    status = postgresql.ENUM("ACTIVE", "DESTROYED", "EXPIRED", name="secret_status", create_type=False)
    reason = postgresql.ENUM("VIEW_LIMIT", "MANUAL", "EXPIRED", name="destroy_reason", create_type=False)
    status.create(op.get_bind(), checkfirst=True)
    reason.create(op.get_bind(), checkfirst=True)
    op.create_table("secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("public_code", sa.String(9), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("token_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("token_nonce", sa.LargeBinary(12), nullable=True),
        sa.Column("token_auth_tag", sa.LargeBinary(16), nullable=True),
        sa.Column("creator_id", sa.BigInteger(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("nonce", sa.LargeBinary(12), nullable=True),
        sa.Column("auth_tag", sa.LargeBinary(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", status, nullable=False),
        sa.Column("destroy_reason", reason, nullable=True),
        sa.Column("views_allowed", sa.Integer(), nullable=False),
        sa.Column("views_used", sa.Integer(), nullable=False),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_secrets_public_code", "secrets", ["public_code"], unique=True)
    op.create_index("ix_secrets_token_hash", "secrets", ["token_hash"], unique=True)
    op.create_index("ix_secrets_creator_id", "secrets", ["creator_id"])
    op.create_index("ix_secrets_expires_at", "secrets", ["expires_at"])
    op.create_index("ix_secrets_creator_status", "secrets", ["creator_id", "status"])
    op.create_index("ix_secrets_status_expires", "secrets", ["status", "expires_at"])


def downgrade() -> None:
    op.drop_table("secrets")
    postgresql.ENUM(name="destroy_reason").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="secret_status").drop(op.get_bind(), checkfirst=True)

