from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import Base


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
            issued = client.post("/workers/credentials", headers=admin, json={"worker_id": "w1", "repositories": ["example/one"], "capabilities": ["git"]})
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
