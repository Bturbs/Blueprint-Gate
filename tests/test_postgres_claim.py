"""Opt-in integration check for the durable queue's locking primitive."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from adp.db import Job, Repository, Ticket


@pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1", reason="requires PostgreSQL service")
def test_skip_locked_prevents_duplicate_claims():
    url = os.environ["DATABASE_URL"]
    assert url.startswith("postgresql+psycopg://")
    engine = create_engine(url)
    with Session(engine) as setup:
        repo = Repository(full_name=f"test/{uuid4().hex}", policy={})
        ticket = Ticket(repository=repo, number=1, title="Lock test", body="")
        job = Job(ticket_id="unused", stage="product_owner", revision=1)
        setup.add_all([repo, ticket])
        setup.flush()
        job.ticket_id = ticket.id
        setup.add(job)
        setup.commit()
        job_id = job.id
        ticket_id = ticket.id
        repo_id = repo.id
    try:
        with Session(engine) as first, Session(engine) as second:
            assert first.scalar(select(Job).where(Job.id == job_id).with_for_update(skip_locked=True)) is not None
            assert second.scalar(select(Job).where(Job.id == job_id).with_for_update(skip_locked=True)) is None
            first.commit()
            assert second.scalar(select(Job).where(Job.id == job_id).with_for_update(skip_locked=True)) is not None
            second.commit()
    finally:
        with Session(engine) as cleanup:
            cleanup.delete(cleanup.get(Job, job_id))
            cleanup.delete(cleanup.get(Ticket, ticket_id))
            cleanup.delete(cleanup.get(Repository, repo_id))
            cleanup.commit()

