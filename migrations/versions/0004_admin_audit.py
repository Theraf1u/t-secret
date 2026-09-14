"""Users, restrictions and metadata-only audit."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_admin_audit"
down_revision = "0003_secret_manager"
branch_labels = None
depends_on = None


def upgrade() -> None:
    user_status = postgresql.ENUM("ACTIVE", "BANNED", "TEMP_BANNED", name="user_status", create_type=False)
    user_status.create(op.get_bind(), checkfirst=True)
    op.create_table("users",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("telegram_id", sa.BigInteger(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("status", user_status, nullable=False),
        sa.Column("ban_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("read_only", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("creation_disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("file_uploads_disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rate_limited", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("restriction_reason", sa.Text(), nullable=True))
    op.create_index("ix_users_telegram_id", "users", ["telegram_id"], unique=True)
    op.create_index("ix_users_last_seen_at", "users", ["last_seen_at"])
    op.execute("""INSERT INTO users (telegram_id, first_seen_at, last_seen_at, status,
                read_only, creation_disabled, file_uploads_disabled, rate_limited)
                SELECT creator_id, MIN(created_at), MAX(created_at), 'ACTIVE'::user_status,
                       false, false, false, false
                FROM secrets GROUP BY creator_id ON CONFLICT (telegram_id) DO NOTHING""")
    op.create_table("audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("secret_public_code", sa.String(16), nullable=True),
        sa.Column("owner_id", sa.BigInteger(), nullable=True),
        sa.Column("viewer_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.BigInteger(), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    for name, columns in (("ix_audit_events_created_at", ["created_at"]), ("ix_audit_events_event_type", ["event_type"]),
                          ("ix_audit_events_secret_public_code", ["secret_public_code"]),
                          ("ix_audit_events_owner_id", ["owner_id"]),
                          ("ix_audit_event_time", ["event_type", "created_at"])):
        op.create_index(name, "audit_events", columns)


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("users")
    postgresql.ENUM(name="user_status").drop(op.get_bind(), checkfirst=True)
