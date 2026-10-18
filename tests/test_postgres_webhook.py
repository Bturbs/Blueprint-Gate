"""Opt-in PostgreSQL check for concurrent webhook reservation."""
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from adp.db import WebhookDelivery


@pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1", reason="requires PostgreSQL service")
def test_payload_digest_serializes_concurrent_delivery_ids():
    engine = create_engine(os.environ["DATABASE_URL"])
    first_id, second_id = uuid4().hex, uuid4().hex
    digest = hashlib.sha256(first_id.encode()).hexdigest()
    try:
        with Session(engine) as first, ThreadPoolExecutor(max_workers=1) as pool:
            first.add(WebhookDelivery(id=first_id, event="issues", payload_hash=digest))
            first.flush()

            def changed_delivery_id():
                with Session(engine) as second:
                    second.add(WebhookDelivery(id=second_id, event="issues", payload_hash=digest))
                    try:
                        second.flush()
                    except IntegrityError:
                        second.rollback()
                        return "duplicate"
                    second.commit()
                    return "accepted"

            future = pool.submit(changed_delivery_id)
            try:
                with pytest.raises(TimeoutError):
                    future.result(timeout=0.2)
            finally:
                first.commit()
            assert future.result(timeout=5) == "duplicate"
    finally:
        with Session(engine) as cleanup:
            for delivery_id in (first_id, second_id):
                delivery = cleanup.get(WebhookDelivery, delivery_id)
                if delivery:
                    cleanup.delete(delivery)
            cleanup.commit()
