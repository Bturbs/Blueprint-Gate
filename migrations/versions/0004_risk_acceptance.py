"""Human risk acceptance decisions."""
from alembic import op
from sqlalchemy import inspect, Column, DateTime, ForeignKey, Integer, String, Text

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

def upgrade():
    if "risk_acceptances" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "risk_acceptances",
            Column("id", String(36), primary_key=True),
            Column("ticket_id", String(36), ForeignKey("tickets.id"), nullable=False),
            Column("threat_id", String(255), nullable=False),
            Column("design_revision", Integer, nullable=False),
            Column("threat_revision", String(80), nullable=False),
            Column("justification", Text, nullable=False),
            Column("residual_risk", Text, nullable=False),
            Column("scope", Text, nullable=False),
            Column("actor", String(255), nullable=False),
            Column("expires_at", DateTime(timezone=True), nullable=False),
            Column("created_at", DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_risk_acceptances_ticket_id", "risk_acceptances", ["ticket_id"])

def downgrade():
    if "risk_acceptances" in inspect(op.get_bind()).get_table_names():
        op.drop_index("ix_risk_acceptances_ticket_id", table_name="risk_acceptances")
        op.drop_table("risk_acceptances")
