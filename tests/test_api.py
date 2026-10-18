from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import Base, Job, Repository, Ticket


def test_poll_claim_and_worker_cannot_approve(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    async def fake_issues(self, repo):
        return [{"number": 7, "title": "Add feature", "body": "Acceptance criteria", "labels": []}]

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "worker")
    monkeypatch.setattr(api.GitHubClient, "list_issues", fake_issues)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            admin = {"Authorization": "Bearer admin"}
            worker = {"Authorization": "Bearer worker"}
            response = client.post("/repositories", headers=admin, json={"full_name": "example/project"})
            assert response.status_code == 200
            repo_id = response.json()["id"]
            assert client.post(f"/repositories/{repo_id}/poll", headers=admin).json() == {"discovered": 1, "created": 1, "replanned": 0}
            assert client.post(f"/repositories/{repo_id}/poll", headers=admin).json() == {"discovered": 1, "created": 0, "replanned": 0}
            claim = client.post("/jobs/claim", headers=worker, json={"worker_id": "w1"})
            assert claim.status_code == 200
            job = claim.json()
            assert job["stage"] == "product_owner"
            assert client.post(f"/tickets/{job['ticket']['id']}/approve-security", headers=worker, json={"actor": "worker", "justification": "I approve everything"}).status_code == 401
            stale = client.post(f"/jobs/{job['id']}/complete", headers=worker, json={"worker_id": "w1", "fencing_token": 0, "result": {"requirements": "x"}})
            assert stale.status_code == 409
            good = client.post(f"/jobs/{job['id']}/complete", headers=worker, json={"worker_id": "w1", "fencing_token": job["fencing_token"], "result": {"requirements": "x"}})
            assert good.status_code == 200
            assert good.json()["ticket_state"] == "REQUIREMENTS_READY"
            duplicate = client.post(f"/jobs/{job['id']}/complete", headers=worker, json={"worker_id": "w1", "fencing_token": job["fencing_token"], "result": {"requirements": "x"}})
            assert duplicate.status_code == 409
    finally:
        api.app.dependency_overrides.clear()


def test_issue_edit_invalidates_running_job(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    issue = {"number": 9, "title": "Feature", "body": "initial", "labels": []}

    async def fake_issues(self, repo):
        return [issue]

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "worker")
    monkeypatch.setattr(api.GitHubClient, "list_issues", fake_issues)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            admin = {"Authorization": "Bearer admin"}
            worker = {"Authorization": "Bearer worker"}
            repo_id = client.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
            client.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
            claim = client.post("/jobs/claim", headers=worker, json={"worker_id": "w"}).json()
            issue["body"] = "revised acceptance criteria"
            response = client.post(f"/repositories/{repo_id}/poll", headers=admin)
            assert response.json()["replanned"] == 1
            assert client.post(f"/jobs/{claim['id']}/complete", headers=worker, json={"worker_id": "w", "fencing_token": claim["fencing_token"], "result": {"requirements": "stale"}}).status_code == 409
            ticket = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
            assert ticket["state"] == "NEEDS_REPLAN"
            assert ticket["jobs"][-1]["state"] == "QUEUED"
    finally:
        api.app.dependency_overrides.clear()
