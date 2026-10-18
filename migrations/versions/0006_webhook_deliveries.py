"""Idempotent signed webhook delivery tracking."""
from alembic import op
from sqlalchemy import Column, DateTime, String, inspect

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    if "webhook_deliveries" not in inspect(op.get_bind()).get_table_names():
        op.create_table("webhook_deliveries", Column("id", String(100), primary_key=True), Column("event", String(100), nullable=False), Column("received_at", DateTime(timezone=True), nullable=False))


def downgrade():
    if "webhook_deliveries" in inspect(op.get_bind()).get_table_names():
        op.drop_table("webhook_deliveries")
