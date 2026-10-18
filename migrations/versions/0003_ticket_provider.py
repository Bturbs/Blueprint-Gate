"""Add ticket-scoped provider override."""
from alembic import op
from sqlalchemy import inspect, Column, String

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

def upgrade():
    if "provider_override" not in {c["name"] for c in inspect(op.get_bind()).get_columns("tickets")}:
        op.add_column("tickets", Column("provider_override", String(40)))

def downgrade():
    if "provider_override" in {c["name"] for c in inspect(op.get_bind()).get_columns("tickets")}:
        op.drop_column("tickets", "provider_override")
