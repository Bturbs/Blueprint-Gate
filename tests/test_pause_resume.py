import asyncio
import subprocess
from datetime import timedelta

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api, worker
from adp.db import Base, Job, Repository, Ticket, now


def issue_worker_auth(client, worker_id):
    response = client.post("/workers/credentials", headers={"Authorization": "Bearer admin"}, json={"worker_id": worker_id, "repositories": ["example/project"], "capabilities": ["git"], "expires_at": (now() + timedelta(days=7)).isoformat()})
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def control(monkeypatch, db_engine):

    def get_db():
        with Session(db_engine) as db:
            yield db

    async def fake_issues(self, repo):
        return [{"number": 14, "title": "Resumable work", "body": "Keep progress", "labels": []}]

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "worker")
    monkeypatch.setattr(api.GitHubClient, "list_issues", fake_issues)
    api.app.dependency_overrides[api.db_session] = get_db
    with TestClient(api.app) as client:
        yield client
    api.app.dependency_overrides.clear()


def test_pause_yield_and_resume_same_job(control):
    admin = {"Authorization": "Bearer admin"}
    repo_id = control.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    worker_auth = issue_worker_auth(control, "w1")
    control.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    first = control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json()

    paused = control.post("/control/pause", headers=admin).json()
    assert paused == {"paused": True, "running_jobs": 1}
    heartbeat = control.post(f"/jobs/{first['id']}/heartbeat", headers=worker_auth, params={"fencing_token": first["fencing_token"]}, json={"worker_id": "w1"})
    assert heartbeat.json() == {"ok": True, "pause_requested": True}
    assert control.post(f"/jobs/{first['id']}/yield", headers=worker_auth, json={"worker_id": "w1", "fencing_token": first["fencing_token"]}).json()["queued"]
    assert control.get("/control", headers=admin).json() == {"paused": True, "running_jobs": 0}
    assert control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json() is None
    assert control.post(f"/jobs/{first['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": first["fencing_token"], "result": {"requirements": "stale"}}).status_code == 409

    assert control.post("/control/resume", headers=admin).json()["paused"] is False
    assert control.post("/jobs/claim", headers=issue_worker_auth(control, "other-host"), json={"worker_id": "other-host"}).json() is None
    resumed = control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json()
    assert (resumed["id"], resumed["revision"]) == (first["id"], first["revision"])
    assert resumed["fencing_token"] == first["fencing_token"] + 1
    assert control.post(f"/jobs/{first['id']}/yield", headers=worker_auth, json={"worker_id": "w1", "fencing_token": first["fencing_token"]}).status_code == 409
    done = control.post(f"/jobs/{resumed['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": resumed["fencing_token"], "result": {"requirements": "# Requirements"}})
    assert done.json()["ticket_state"] == "REQUIREMENTS_READY"


def test_repository_pause_requests_yield(control):
    admin = {"Authorization": "Bearer admin"}
    repo_id = control.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    worker_auth = issue_worker_auth(control, "w1")
    control.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    job = control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json()
    assert control.post(f"/repositories/{repo_id}/control/pause", headers=admin).json() == {"paused": True, "global_paused": False, "running_jobs": 1}
    assert control.get(f"/repositories/{repo_id}/control", headers=admin).json()["running_jobs"] == 1
    heartbeat = control.post(f"/jobs/{job['id']}/heartbeat", headers=worker_auth, params={"fencing_token": job["fencing_token"]}, json={"worker_id": "w1"})
    assert heartbeat.json()["pause_requested"] is True


def test_admin_can_release_yielded_job_for_replacement_host(control):
    admin = {"Authorization": "Bearer admin"}
    repo_id = control.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    worker_auth = issue_worker_auth(control, "old-host")
    replacement_auth = issue_worker_auth(control, "new-host")
    control.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    first = control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "old-host"}).json()
    control.post(f"/jobs/{first['id']}/yield", headers=worker_auth, json={"worker_id": "old-host", "fencing_token": first["fencing_token"]}).raise_for_status()
    assert control.post("/jobs/claim", headers=replacement_auth, json={"worker_id": "new-host"}).json() is None
    assert control.post(f"/jobs/{first['id']}/release-affinity", headers=worker_auth).status_code == 401
    released = control.post(f"/jobs/{first['id']}/release-affinity", headers=admin)
    assert released.json()["previous_worker"] == "old-host"
    replacement = control.post("/jobs/claim", headers=replacement_auth, json={"worker_id": "new-host"}).json()
    assert replacement["id"] == first["id"]
    assert replacement["fencing_token"] == first["fencing_token"] + 2


def test_expired_lease_recovers_same_job_with_new_fence(control, db_engine):
    admin = {"Authorization": "Bearer admin"}
    repo_id = control.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    worker_auth = issue_worker_auth(control, "lost-worker")
    replacement_auth = issue_worker_auth(control, "replacement")
    control.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    first = control.post("/jobs/claim", headers=worker_auth, json={"worker_id": "lost-worker"}).json()
    with Session(db_engine) as db:
        job = db.get(Job, first["id"])
        job.lease_expires_at = now() - timedelta(seconds=1)
        db.commit()

    recovered = control.post("/jobs/claim", headers=replacement_auth, json={"worker_id": "replacement"}).json()
    assert (recovered["id"], recovered["revision"]) == (first["id"], first["revision"])
    assert recovered["fencing_token"] == first["fencing_token"] + 1
    assert control.post(f"/jobs/{first['id']}/complete", headers=worker_auth, json={"worker_id": "lost-worker", "fencing_token": first["fencing_token"], "result": {"requirements": "stale"}}).status_code == 409


def test_other_workers_yielded_jobs_do_not_hide_available_work(control, db_engine):
    with Session(db_engine) as db:
        repo = Repository(full_name="example/project", policy={})
        db.add(repo)
        db.flush()
        for number in range(1, 102):
            ticket = Ticket(repository_id=repo.id, number=number, title=f"Issue {number}", body="", priority=1 if number <= 100 else 0)
            db.add(ticket)
            db.flush()
            db.add(Job(ticket_id=ticket.id, stage="product_owner", state="QUEUED", claimed_by="other-host" if number <= 100 else None))
        db.commit()
    claim = control.post("/jobs/claim", headers=issue_worker_auth(control, "new-host"), json={"worker_id": "new-host"}).json()
    assert claim["ticket"]["number"] == 101


@pytest.mark.asyncio
async def test_worker_interruption_yields_claim_and_reuses_worktree(control, tmp_path, monkeypatch):
    admin = {"Authorization": "Bearer admin"}
    repo_id = control.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    token = issue_worker_auth(control, "w1")["Authorization"].removeprefix("Bearer ")
    control.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "README.md").write_text("initial")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)

    config_path = tmp_path / "worker.yaml"
    config_path.write_text(yaml.safe_dump({"control_url": "http://127.0.0.1:8000", "worker_token_env": "ADP_WORKER_TOKEN", "worker_id": "w1", "repositories": {"example/project": {"path": str(repo), "worktrees": str(tmp_path / "worktrees")}}}))
    monkeypatch.setenv("ADP_WORKER_TOKEN", token)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(worker.httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.ASGITransport(app=api.app), **kwargs))
    started = asyncio.Event()

    async def unfinished(job, config, guard=None):
        cwd = worker.worktree(repo, job["ticket"]["number"], tmp_path / "worktrees")
        (cwd / "partial.txt").write_text("saved progress")
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(worker, "execute_job", unfinished)
    task = asyncio.create_task(worker.run_worker(config_path))
    await asyncio.wait_for(started.wait(), timeout=5)
    task.cancel()
    await asyncio.wait_for(task, timeout=5)

    ticket = control.get("/tickets", headers=admin).json()[0]
    detail = control.get(f"/tickets/{ticket['id']}", headers=admin).json()
    assert detail["jobs"][0]["state"] == "QUEUED"
    assert detail["jobs"][0]["revision"] == 1
    assert (tmp_path / "worktrees" / "issue-14" / "partial.txt").read_text() == "saved progress"

    monkeypatch.setattr(worker, "HEARTBEAT_SECONDS", 0.05)
    started.clear()
    monkeypatch.setenv("ADP_WORKER_TOKEN", token)
    resumed_worker = asyncio.create_task(worker.run_worker(config_path))
    await asyncio.wait_for(started.wait(), timeout=5)
    assert control.post("/control/pause", headers=admin).json()["running_jobs"] == 1
    await asyncio.wait_for(resumed_worker, timeout=5)
    detail = control.get(f"/tickets/{ticket['id']}", headers=admin).json()
    assert detail["jobs"][0]["state"] == "QUEUED"
    assert detail["jobs"][0]["revision"] == 1
    assert control.get("/control", headers=admin).json() == {"paused": True, "running_jobs": 0}
