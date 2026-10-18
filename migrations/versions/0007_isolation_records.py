"""Store trusted disposable-worker evidence for each completed job."""
from alembic import op
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, inspect

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    if "isolation_records" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "isolation_records",
            Column("job_id", String(36), ForeignKey("jobs.id"), primary_key=True),
            Column("boundary_id", String(128), nullable=False),
            Column("policy_digest", String(80), nullable=False),
            Column("guest_image_digest", String(80), nullable=False),
            Column("mount_manifest_digest", String(80), nullable=False),
            Column("egress_profile", JSON, nullable=False),
            Column("credential_grant_ids", JSON, nullable=False),
            Column("checkpoint_digest", String(80)),
            Column("started_at", DateTime(timezone=True)),
            Column("teardown_verified", Boolean, nullable=False),
            Column("outcome", String(30), nullable=False),
        )


def downgrade():
    if "isolation_records" in inspect(op.get_bind()).get_table_names():
        op.drop_table("isolation_records")
