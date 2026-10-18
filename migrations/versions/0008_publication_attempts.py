"""Keep remote publication history for late-effect detection."""

from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    # The initial migration creates current metadata on a fresh database.
    if not sa.inspect(op.get_bind()).has_table("publication_attempts"):
        op.create_table(
            "publication_attempts",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("job_id", sa.String(36), sa.ForeignKey("jobs.id"), nullable=False),
            sa.Column("ticket_id", sa.String(36), sa.ForeignKey("tickets.id"), nullable=False),
            sa.Column("repository", sa.String(255), nullable=False),
            sa.Column("branch", sa.String(255), nullable=False, unique=True),
            sa.Column("sha", sa.String(64), nullable=False),
            sa.Column("state", sa.String(30), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reconciled_at", sa.DateTime(timezone=True)),
            sa.Column("last_checked_at", sa.DateTime(timezone=True)),
            sa.Column("review_context", sa.JSON(), nullable=False),
        )
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("publication_attempts")}
    for name, column in (("ix_publication_attempts_job_id", "job_id"), ("ix_publication_attempts_ticket_id", "ticket_id"), ("ix_publication_attempts_state", "state")):
        if name not in indexes:
            op.create_index(name, "publication_attempts", [column])


def downgrade():
    op.drop_index("ix_publication_attempts_state", table_name="publication_attempts")
    op.drop_index("ix_publication_attempts_ticket_id", table_name="publication_attempts")
    op.drop_index("ix_publication_attempts_job_id", table_name="publication_attempts")
    op.drop_table("publication_attempts")
