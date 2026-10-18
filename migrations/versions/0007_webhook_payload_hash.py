"""Deduplicate signed webhook payloads even if delivery headers change."""
from alembic import op
from sqlalchemy import Column, String, inspect

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("webhook_deliveries")}
    if "payload_hash" not in columns:
        op.add_column("webhook_deliveries", Column("payload_hash", String(64)))
    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes("webhook_deliveries")}
    if "uq_webhook_deliveries_payload_hash" not in indexes:
        op.create_index("uq_webhook_deliveries_payload_hash", "webhook_deliveries", ["payload_hash"], unique=True)


def downgrade():
    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes("webhook_deliveries")}
    if "uq_webhook_deliveries_payload_hash" in indexes:
        op.drop_index("uq_webhook_deliveries_payload_hash", table_name="webhook_deliveries")
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("webhook_deliveries")}
    if "payload_hash" in columns:
        op.drop_column("webhook_deliveries", "payload_hash")
