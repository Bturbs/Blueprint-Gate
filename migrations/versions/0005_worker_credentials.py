"""Scoped credentials for outbound hybrid workers."""
from alembic import op
from sqlalchemy import Boolean, Column, DateTime, JSON, String, inspect

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    if "worker_credentials" in inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "worker_credentials",
        Column("id", String(36), primary_key=True),
        Column("worker_id", String(100), nullable=False, unique=True),
        Column("token_hash", String(64), nullable=False, unique=True),
        Column("repositories", JSON, nullable=False),
        Column("capabilities", JSON, nullable=False),
        Column("disabled", Boolean, nullable=False),
        Column("expires_at", DateTime(timezone=True)),
        Column("last_seen_at", DateTime(timezone=True)),
    )


def downgrade():
    if "worker_credentials" in inspect(op.get_bind()).get_table_names():
        op.drop_table("worker_credentials")
