"""PIN, recipient binding and notification settings."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_access_protection"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    mode = postgresql.ENUM("ANY", "SPECIFIC", "FIRST", name="recipient_mode", create_type=False)
    mode.create(op.get_bind(), checkfirst=True)
    op.add_column("secrets", sa.Column("pin_hash", sa.String(512), nullable=True))
    op.add_column("secrets", sa.Column("recipient_mode", mode, nullable=False, server_default="ANY"))
    op.add_column("secrets", sa.Column("recipient_telegram_id", sa.BigInteger(), nullable=True))
    op.add_column("secrets", sa.Column("claimed_by_telegram_id", sa.BigInteger(), nullable=True))
    op.add_column("secrets", sa.Column("require_identity_confirmation", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("secrets", sa.Column("notify_open", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("secrets", sa.Column("notify_wrong_pin", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("secrets", sa.Column("notify_wrong_user", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("secrets", sa.Column("notify_expiry", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("secrets", sa.Column("notify_destroy", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    for column in ("notify_destroy", "notify_expiry", "notify_wrong_user", "notify_wrong_pin", "notify_open",
                   "require_identity_confirmation", "claimed_by_telegram_id", "recipient_telegram_id", "recipient_mode", "pin_hash"):
        op.drop_column("secrets", column)
    postgresql.ENUM(name="recipient_mode").drop(op.get_bind(), checkfirst=True)
