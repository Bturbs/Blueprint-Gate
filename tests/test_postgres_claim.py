"""Opt-in integration check for the durable queue's locking primitive."""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from adp.api import _locked_claim
from adp.db import Job, Repository, Ticket, now


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


@pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1", reason="requires PostgreSQL service")
def test_completion_lock_rejects_a_reclaimed_fence():
    engine = create_engine(os.environ["DATABASE_URL"])
    with Session(engine) as setup:
        repo = Repository(full_name=f"test/{uuid4().hex}", policy={})
        ticket = Ticket(repository=repo, number=1, title="Fence lock test", body="")
        setup.add_all([repo, ticket])
        setup.flush()
        job = Job(ticket_id=ticket.id, stage="product_owner", revision=1, state="RUNNING", claimed_by="old", fencing_token=1, lease_expires_at=now() + timedelta(minutes=20))
        setup.add(job)
        setup.commit()
        job_id, ticket_id, repo_id = job.id, ticket.id, repo.id
    try:
        with Session(engine) as reclaim, ThreadPoolExecutor(max_workers=1) as pool:
            current = reclaim.scalar(select(Job).where(Job.id == job_id).with_for_update())
            current.claimed_by = "replacement"
            current.fencing_token = 2

            def stale_completion():
                with Session(engine) as stale:
                    try:
                        _locked_claim(stale, job_id, "old", 1)
                    except HTTPException as exc:
                        return exc.status_code
                    return 200

            future = pool.submit(stale_completion)
            try:
                with pytest.raises(TimeoutError):
                    future.result(timeout=0.2)
            finally:
                reclaim.commit()
            assert future.result(timeout=5) == 409
    finally:
        with Session(engine) as cleanup:
            cleanup.delete(cleanup.get(Job, job_id))
            cleanup.delete(cleanup.get(Ticket, ticket_id))
            cleanup.delete(cleanup.get(Repository, repo_id))
            cleanup.commit()
