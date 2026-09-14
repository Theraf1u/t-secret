"""UI premium emoji settings.

Revision ID: 0005_ui_premium_emojis
Revises: 0004_admin_audit
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_ui_premium_emojis"
down_revision = "0004_admin_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ui_emoji_settings",
        sa.Column("slot", sa.String(length=64), nullable=False),
        sa.Column("custom_emoji_id", sa.String(length=32), nullable=False),
        sa.Column("updated_by", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("slot"),
    )


def downgrade() -> None:
    op.drop_table("ui_emoji_settings")
