"""Add global pause and commit-bound approvals for existing deployments."""
from alembic import op
from sqlalchemy import inspect, Column, String, Integer, Boolean

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "ref" not in {c["name"] for c in inspector.get_columns("approvals")}:
        op.add_column("approvals", Column("ref", String(80)))
    if "control_state" not in inspector.get_table_names():
        op.create_table("control_state", Column("id", Integer, primary_key=True), Column("paused", Boolean, nullable=False))

def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "control_state" in inspector.get_table_names():
        op.drop_table("control_state")
    if "ref" in {c["name"] for c in inspector.get_columns("approvals")}:
        op.drop_column("approvals", "ref")
