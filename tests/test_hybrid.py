from fastapi.testclient import TestClient
from datetime import timedelta
import hashlib
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import Base, Job, Repository, Ticket, WorkerCredential, now


def test_hybrid_credential_is_scoped_and_revocable(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "legacy")
    monkeypatch.setattr(api.settings, "hybrid_mode", True)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            admin = {"Authorization": "Bearer admin"}
            client.post("/repositories", headers=admin, json={"full_name": "example/one"}).raise_for_status()
            client.post("/repositories", headers=admin, json={"full_name": "example/two"}).raise_for_status()
            expiry = (now() + timedelta(days=7)).isoformat()
            issued = client.post("/workers/credentials", headers=admin, json={"worker_id": "w1", "repositories": ["example/one"], "capabilities": ["git"], "expires_at": expiry})
            assert issued.status_code == 200
            credential = issued.json()
            worker = {"Authorization": f"Bearer {credential['token']}"}
            assert client.post("/jobs/claim", headers={"Authorization": "Bearer legacy"}, json={"worker_id": "w1"}).status_code == 401
            assert client.post("/jobs/claim", headers=worker, json={"worker_id": "impersonator"}).status_code == 403
            assert client.post("/jobs/claim", headers=worker, json={"worker_id": "w1", "capabilities": ["admin"]}).status_code == 200
            assert client.post(f"/workers/credentials/{credential['id']}/revoke", headers=admin).status_code == 200
            assert client.post("/jobs/claim", headers=worker, json={"worker_id": "w1"}).status_code == 401
    finally:
        api.app.dependency_overrides.clear()


def test_worker_credential_expiry_and_paused_rotation(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "legacy")
    monkeypatch.setattr(api.settings, "hybrid_mode", False)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            admin = {"Authorization": "Bearer admin"}
            client.post("/repositories", headers=admin, json={"full_name": "example/one"}).raise_for_status()
            body = {"worker_id": "w1", "repositories": ["example/one"], "capabilities": ["git"]}
            assert client.post("/workers/credentials", headers=admin, json=body).status_code == 422
            too_long = {**body, "expires_at": (now() + timedelta(days=31)).isoformat()}
            assert client.post("/workers/credentials", headers=admin, json=too_long).status_code == 422
            issued = client.post("/workers/credentials", headers=admin, json={**body, "expires_at": (now() + timedelta(days=7)).isoformat()})
            issued.raise_for_status()
            first = issued.json()
            old = {"Authorization": f"Bearer {first['token']}"}
            assert client.post("/jobs/claim", headers={"Authorization": "Bearer legacy"}, json={"worker_id": "w1"}).status_code == 401
            with Session(engine) as db:
                repo = db.scalar(select(Repository).where(Repository.full_name == "example/one"))
                ticket = Ticket(repository_id=repo.id, number=1, title="Credential rotation", body="", priority=1)
                db.add(ticket)
                db.flush()
                db.add(Job(ticket_id=ticket.id, stage="product_owner", state="QUEUED"))
                db.commit()
            claimed = client.post("/jobs/claim", headers=old, json={"worker_id": "w1"})
            claimed.raise_for_status()
            job = claimed.json()
            rotate_url = f"/workers/credentials/{first['id']}/rotate"
            next_expiry = {"expires_at": (now() + timedelta(days=8)).isoformat()}
            assert client.post(rotate_url, headers=admin, json=next_expiry).status_code == 409
            client.post("/control/pause", headers=admin).raise_for_status()
            assert client.post(rotate_url, headers=admin, json=next_expiry).status_code == 409
            assert client.post(f"/jobs/{job['id']}/yield", headers=old, json={"worker_id": "w1", "fencing_token": job["fencing_token"]}).status_code == 200
            rotated = client.post(rotate_url, headers=admin, json=next_expiry)
            rotated.raise_for_status()
            second = rotated.json()
            assert second["token"] != first["token"]
            assert client.post("/jobs/claim", headers=old, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/heartbeat", headers=old, params={"fencing_token": job["fencing_token"]}, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/yield", headers=old, json={"worker_id": "w1", "fencing_token": job["fencing_token"]}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/complete", headers=old, json={"worker_id": "w1", "fencing_token": job["fencing_token"], "result": {}}).status_code == 401
            # Simulate a request that passed its first auth check before rotation.
            stale = api.WorkerPrincipal(first["id"], "w1", hashlib.sha256(first["token"].encode()).hexdigest(), ("example/one",), ("git",))
            api.app.dependency_overrides[api.worker_authorized] = lambda: stale
            try:
                assert client.post(f"/jobs/{job['id']}/complete", headers=old, json={"worker_id": "w1", "fencing_token": job["fencing_token"], "result": {}}).status_code == 401
            finally:
                api.app.dependency_overrides.pop(api.worker_authorized)
            client.post("/control/resume", headers=admin).raise_for_status()
            new = {"Authorization": f"Bearer {second['token']}"}
            reclaimed = client.post("/jobs/claim", headers=new, json={"worker_id": "w1"})
            reclaimed.raise_for_status()
            assert reclaimed.json()["id"] == job["id"]
            assert reclaimed.json()["revision"] == job["revision"]
            assert reclaimed.json()["fencing_token"] == job["fencing_token"] + 1
            fence = reclaimed.json()["fencing_token"]
            assert client.post(f"/jobs/{job['id']}/heartbeat", headers=new, params={"fencing_token": fence}, json={"worker_id": "w1"}).status_code == 200
            with Session(engine) as db:
                credential = db.get(WorkerCredential, first["id"])
                credential.expires_at = now() - timedelta(seconds=1)
                db.commit()
            assert client.post("/jobs/claim", headers=new, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/heartbeat", headers=new, params={"fencing_token": fence}, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/yield", headers=new, json={"worker_id": "w1", "fencing_token": fence}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/complete", headers=new, json={"worker_id": "w1", "fencing_token": fence, "result": {}}).status_code == 401
            with Session(engine) as db:
                credential = db.get(WorkerCredential, first["id"])
                credential.expires_at = now() + timedelta(days=7)
                db.commit()
            assert client.post(f"/workers/credentials/{first['id']}/revoke", headers=admin).status_code == 200
            assert client.post("/jobs/claim", headers=new, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/heartbeat", headers=new, params={"fencing_token": fence}, json={"worker_id": "w1"}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/yield", headers=new, json={"worker_id": "w1", "fencing_token": fence}).status_code == 401
            assert client.post(f"/jobs/{job['id']}/complete", headers=new, json={"worker_id": "w1", "fencing_token": fence, "result": {}}).status_code == 401
    finally:
        api.app.dependency_overrides.clear()
