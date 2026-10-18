import asyncio
from datetime import timedelta
import json
import subprocess

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api, worker
from adp.db import Approval, Base, Job, PublicationAttempt, Ticket, now
from adp.github import GitHubClient
from adp.publication import attempt_branch
from adp.runtimes import RuntimeResult


@pytest.fixture
def control(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    async def issues(self, repo):
        return [{"number": 7, "title": "Publish", "body": "Original", "labels": []}]

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "worker_token", "worker")
    monkeypatch.setattr(api.GitHubClient, "list_issues", issues)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            yield client, engine
    finally:
        api.app.dependency_overrides.clear()


def setup_claim(client):
    admin = {"Authorization": "Bearer admin"}
    repo_id = client.post("/repositories", headers=admin, json={"full_name": "example/project"}).json()["id"]
    credential = client.post("/workers/credentials", headers=admin, json={"worker_id": "w1", "repositories": ["example/project"], "capabilities": ["git"], "expires_at": (now() + timedelta(days=7)).isoformat()}).json()
    worker_auth = {"Authorization": f"Bearer {credential['token']}"}
    client.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    claim = client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json()
    return admin, worker_auth, repo_id, claim


def engineer_claim(db_engine, claim):
    with Session(db_engine) as db:
        job = db.get(Job, claim["id"])
        job.stage = "engineer"
        ticket = db.get(Ticket, job.ticket_id)
        ticket.state = "READY_TO_ENGINEER"
        ticket.design_revision = 1
        ticket.threat_revision = "verified"
        ticket.verification_passed = True
        ticket.security_approved_revision = 1
        db.add(Approval(ticket_id=ticket.id, kind="security_design", revision=1, ref="verified", actor="owner", justification="Test fixture approval"))
        job.result = {"_claim_ticket_state": "READY_TO_ENGINEER"}
        db.commit()


def test_intent_quarantines_yield_and_requires_remote_clear(control, monkeypatch):
    client, engine = control
    admin, worker_auth, _, claim = setup_claim(client)
    engineer_claim(engine, claim)
    branch = attempt_branch(7, claim["id"], claim["fencing_token"])
    sha = "a" * 40
    body = {"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": "engineer", "repository": "example/project", "branch": branch, "sha": sha}
    assert client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={**body, "branch": "adp/issue-7"}).status_code == 409
    client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json=body).raise_for_status()
    assert client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={**body, "sha": "b" * 40}).status_code == 409
    yielded = client.post(f"/jobs/{claim['id']}/yield", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"]})
    assert yielded.json()["publication_review"] is True
    assert client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json() is None
    recovery = {"worker_isolation_reset": True, "explanation": "Restarted worker VM and inspected the attempt"}
    assert client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json=recovery).status_code == 409
    client.post("/control/pause", headers=admin).raise_for_status()

    async def blocked(self, repo, branch):
        raise RuntimeError("Publication branch still exists")

    monkeypatch.setattr(api.GitHubClient, "publication_clear", blocked)
    assert client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json=recovery).status_code == 409

    async def cleared(self, repo, branch):
        assert repo == "example/project"
        assert branch == body["branch"]
        return {"branch_absent": True, "closed_unmerged_prs": []}

    monkeypatch.setattr(api.GitHubClient, "publication_clear", cleared)
    release = client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json=recovery)
    assert release.json()["job_state"] == "QUEUED"
    assert release.json()["ticket_state"] == "READY_TO_ENGINEER"
    with Session(engine) as db:
        job = db.get(Job, claim["id"])
        assert job.fencing_token == claim["fencing_token"] + 1
        assert job.result == {}

    second_branch = attempt_branch(7, claim["id"], claim["fencing_token"] + 1)
    with Session(engine) as db:
        db.add(PublicationAttempt(job_id=claim["id"], ticket_id=claim["ticket"]["id"], repository="example/project", branch=second_branch, sha="b" * 40, state="RECONCILED"))
        db.commit()
    monkeypatch.setattr(api.GitHubClient, "publication_clear", blocked)
    late = client.post("/reconcile-publications", headers=admin)
    assert late.json()[branch] == "LATE_EFFECT"
    assert late.json()[second_branch] == "LATE_EFFECT"
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert detail["state"] == "PUBLICATION_REVIEW"
    attempt_id = detail["publication_attempts"][0]["id"]

    async def all_cleared(self, repo, branch):
        assert repo == "example/project"
        assert branch in {body["branch"], second_branch}
        return {"branch_absent": True, "closed_unmerged_prs": []}

    monkeypatch.setattr(api.GitHubClient, "publication_clear", all_cleared)
    resolved = client.post(f"/publication-attempts/{attempt_id}/resolve-late", headers=admin, json=recovery)
    assert resolved.json()["ticket_state"] == "NEEDS_REPLAN"
    assert resolved.json()["repository_paused"] is True
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert {attempt["state"] for attempt in detail["publication_attempts"]} == {"RECONCILED"}


def test_issue_edit_after_successful_publication_waits_for_cleanup(control, monkeypatch):
    client, engine = control
    admin, worker_auth, repo_id, claim = setup_claim(client)
    engineer_claim(engine, claim)
    branch = attempt_branch(7, claim["id"], claim["fencing_token"])
    sha = "a" * 40
    client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": "engineer", "repository": "example/project", "branch": branch, "sha": sha}).raise_for_status()
    complete = client.post(f"/jobs/{claim['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "result": {"commit_sha": sha, "publication_branch": branch, "pr_number": 14, "checks": [{"passed": True}]}})
    assert complete.json()["ticket_state"] == "PR_OPEN"

    async def edited(self, repo):
        return [{"number": 7, "title": "Publish", "body": "Changed", "labels": []}]

    async def not_merged(self, repo, number, expected, branch):
        return False

    monkeypatch.setattr(api.GitHubClient, "list_issues", edited)
    monkeypatch.setattr(api.GitHubClient, "merged_exact", not_merged)
    client.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert detail["state"] == "PUBLICATION_REVIEW"
    assert detail["jobs"][0]["state"] == "PUBLICATION_REVIEW"
    assert all(job["state"] != "QUEUED" for job in detail["jobs"])

    async def cleared(self, repo, branch):
        return {"branch_absent": True, "closed_unmerged_prs": [14]}

    monkeypatch.setattr(api.GitHubClient, "publication_clear", cleared)
    client.post("/control/pause", headers=admin).raise_for_status()
    release = client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json={"worker_isolation_reset": True, "explanation": "Restarted VM and closed superseded PR"})
    assert release.json()["ticket_state"] == "NEEDS_REPLAN"
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    with Session(engine) as db:
        assert db.get(Ticket, claim["ticket"]["id"]).pr_number is None
    assert {job["stage"] for job in detail["jobs"]} == {"engineer", "qa", "product_owner"}


def test_review_failure_cleans_old_pr_before_republish(control, monkeypatch):
    client, engine = control
    admin, worker_auth, _, claim = setup_claim(client)
    engineer_claim(engine, claim)
    branch = attempt_branch(7, claim["id"], claim["fencing_token"])
    sha = "a" * 40
    client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": "engineer", "repository": "example/project", "branch": branch, "sha": sha}).raise_for_status()
    client.post(f"/jobs/{claim['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "result": {"commit_sha": sha, "publication_branch": branch, "pr_number": 14, "checks": [{"passed": True}]}}).raise_for_status()
    qa = client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json()
    assert qa["stage"] == "qa"
    done = client.post(f"/jobs/{qa['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": qa["fencing_token"], "result": {"checks": [{"passed": False}], "evidence": "Review failed", "passed": False}})
    assert done.status_code == 200, done.text
    assert done.json()["ticket_state"] == "PUBLICATION_REVIEW"
    assert client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json() is None
    client.post("/control/pause", headers=admin).raise_for_status()

    async def cleared(self, repo, branch):
        return {"branch_absent": True, "closed_unmerged_prs": [14]}

    monkeypatch.setattr(api.GitHubClient, "publication_clear", cleared)
    result = client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json={"worker_isolation_reset": True, "explanation": "Restarted VM and closed superseded PR"})
    assert result.json()["ticket_state"] == "QA_FAILED"
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert any(job["stage"] == "engineer" and job["state"] == "QUEUED" for job in detail["jobs"])


def test_external_exact_head_merge_is_recognized_before_issue_disappears(control, monkeypatch):
    client, engine = control
    admin, worker_auth, repo_id, claim = setup_claim(client)
    engineer_claim(engine, claim)
    branch = attempt_branch(7, claim["id"], claim["fencing_token"])
    sha = "a" * 40
    client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": "engineer", "repository": "example/project", "branch": branch, "sha": sha}).raise_for_status()
    client.post(f"/jobs/{claim['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "result": {"commit_sha": sha, "publication_branch": branch, "pr_number": 14, "checks": [{"passed": True}]}}).raise_for_status()

    async def no_issues(self, repo):
        return []

    async def merged(self, repo, number, expected, branch):
        assert (repo, number, expected) == ("example/project", 14, sha)
        assert branch == attempt_branch(7, claim["id"], claim["fencing_token"])
        return True

    monkeypatch.setattr(api.GitHubClient, "list_issues", no_issues)
    monkeypatch.setattr(api.GitHubClient, "merged_exact", merged)
    client.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert detail["state"] == "MERGED"
    assert detail["jobs"][0]["state"] == "SUCCEEDED"


def test_late_incident_survives_manual_merge_until_audited_resolution(control, monkeypatch):
    client, engine = control
    admin, worker_auth, repo_id, claim = setup_claim(client)
    engineer_claim(engine, claim)
    current_branch = attempt_branch(7, claim["id"], claim["fencing_token"])
    retired_branch = attempt_branch(7, claim["id"], claim["fencing_token"] + 1)
    sha = "a" * 40
    client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": "engineer", "repository": "example/project", "branch": current_branch, "sha": sha}).raise_for_status()
    client.post(f"/jobs/{claim['id']}/complete", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "result": {"commit_sha": sha, "publication_branch": current_branch, "pr_number": 14, "checks": [{"passed": True}]}}).raise_for_status()
    with Session(engine) as db:
        db.add(PublicationAttempt(job_id=claim["id"], ticket_id=claim["ticket"]["id"], repository="example/project", branch=retired_branch, sha="b" * 40, state="RECONCILED"))
        db.commit()

    async def late(self, repo, branch):
        raise RuntimeError("retired branch appeared")

    monkeypatch.setattr(api.GitHubClient, "publication_clear", late)
    assert client.post("/reconcile-publications", headers=admin).json()[retired_branch] == "LATE_EFFECT"

    async def no_issues(self, repo):
        return []

    async def merged(self, repo, number, expected, branch):
        return branch == current_branch and expected == sha

    monkeypatch.setattr(api.GitHubClient, "list_issues", no_issues)
    monkeypatch.setattr(api.GitHubClient, "merged_exact", merged)
    client.post(f"/repositories/{repo_id}/poll", headers=admin).raise_for_status()
    assert client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()["state"] == "PUBLICATION_REVIEW"

    async def cleared(self, repo, branch):
        assert branch == retired_branch
        return {"branch_absent": True, "closed_unmerged_prs": []}

    monkeypatch.setattr(api.GitHubClient, "publication_clear", cleared)
    client.post("/control/pause", headers=admin).raise_for_status()
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    retired_id = next(x["id"] for x in detail["publication_attempts"] if x["branch"] == retired_branch)
    resolved = client.post(f"/publication-attempts/{retired_id}/resolve-late", headers=admin, json={"worker_isolation_reset": True, "explanation": "Restarted VM and cleaned late branch"})
    assert resolved.json()["ticket_state"] == "MERGED"


def test_expired_remote_capable_claim_quarantines_without_intent(control):
    client, engine = control
    admin, worker_auth, _, claim = setup_claim(client)
    engineer_claim(engine, claim)
    with Session(engine) as db:
        job = db.get(Job, claim["id"])
        job.lease_expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json() is None
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert detail["jobs"][0]["state"] == "PUBLICATION_REVIEW"
    client.post("/control/pause", headers=admin).raise_for_status()
    release = client.post(f"/jobs/{claim['id']}/reconcile-publication", headers=admin, json={"worker_isolation_reset": True, "explanation": "Restarted the old worker VM before retry"})
    assert release.json()["job_state"] == "QUEUED"


@pytest.mark.asyncio
async def test_github_publication_clear_checks_ref_and_all_pr_states(monkeypatch):
    from adp.github_auth import tokens

    async def test_token(override=None):
        return "test"

    monkeypatch.setattr(tokens, "get", test_token)
    branch = attempt_branch(7, "b179880d-f859-4707-8b87-e9a9795383ef", 1)

    def response(request):
        if "/git/ref/heads/" in request.url.path:
            assert "%2F" in str(request.url)
            return httpx.Response(404)
        return httpx.Response(200, json=[{"number": 9, "state": "closed", "merged_at": None, "head": {"ref": branch}}])

    evidence = await GitHubClient(transport=httpx.MockTransport(response)).publication_clear("example/project", branch)
    assert evidence == {"branch_absent": True, "closed_unmerged_prs": [9]}

    def open_pr(request):
        if "/git/ref/heads/" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(200, json=[{"number": 9, "state": "open", "merged_at": None, "head": {"ref": branch}}])

    with pytest.raises(RuntimeError, match="open or merged"):
        await GitHubClient(transport=httpx.MockTransport(open_pr)).publication_clear("example/project", branch)


@pytest.mark.asyncio
@pytest.mark.parametrize("loss_at", [3, 7])
async def test_remote_success_followed_by_claim_loss_is_quarantined(control, tmp_path, monkeypatch, loss_at):
    client, engine = control
    admin, worker_auth, _, claim = setup_claim(client)
    engineer_claim(engine, claim)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    (repo / "README.md").write_text("base")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)

    class Runtime:
        name = "codex"

        async def validate_environment(self):
            return {"available": True}

        async def execute(self, prompt, cwd, timeout=900, writable=False):
            (cwd / "change.txt").write_text("work")
            return RuntimeResult("codex", "succeeded", json.dumps({"summary": "implemented"}), {})

    monkeypatch.setattr(worker, "candidate_runtimes", lambda policy, stage: [Runtime()])

    async def checks(cwd, commands, image=None):
        return [{"passed": True}]

    monkeypatch.setattr(worker, "_checks", checks)
    remote_calls = []

    async def remote(argv, prompt, cwd, timeout, env=None):
        remote_calls.append(argv)
        if "list" in argv:
            return 0, "[]", ""
        if "create" in argv:
            return 0, "https://github.com/example/project/pull/14", ""
        return 0, "", ""

    monkeypatch.setattr(worker, "_run", remote)
    count = 0

    async def guard():
        nonlocal count
        count += 1
        if count == loss_at:
            raise worker.ClaimLost("lease expired after remote success")

    async def intent(kind, repository, branch, sha):
        response = client.post(f"/jobs/{claim['id']}/publication-intent", headers=worker_auth, json={"worker_id": "w1", "fencing_token": claim["fencing_token"], "kind": kind, "repository": repository, "branch": branch, "sha": sha})
        response.raise_for_status()

    job = {**claim, "stage": "engineer", "repository": {"full_name": "example/project", "policy": {"delivery_enabled": True, "required_checks": [["true"]]}}}
    config = {"repositories": {"example/project": {"path": str(repo), "worktrees": str(tmp_path / "worktrees")}}}
    with pytest.raises(worker.ClaimLost):
        await worker.execute_job(job, config, guard=guard, publish_intent=intent)
    assert any("push" in argv for argv in remote_calls)
    assert any("create" in argv for argv in remote_calls) == (loss_at == 7)
    with Session(engine) as db:
        db.get(Job, claim["id"]).lease_expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert client.post("/jobs/claim", headers=worker_auth, json={"worker_id": "w1"}).json() is None
    detail = client.get(f"/tickets/{claim['ticket']['id']}", headers=admin).json()
    assert detail["state"] == "PUBLICATION_REVIEW"
    assert detail["publication_attempts"][0]["state"] == "ACTIVE"


@pytest.mark.asyncio
async def test_issue_worktree_is_exclusive_for_whole_attempt(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    (repo / "README.md").write_text("base")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    started = asyncio.Event()

    async def busy(job, config, guard, publish_intent):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(worker, "_execute_job_inner", busy)
    job = {"repository": {"full_name": "example/project"}, "ticket": {"number": 7}}
    config = {"repositories": {"example/project": {"path": str(repo), "worktrees": str(tmp_path / "worktrees")}}}
    first = asyncio.create_task(worker.execute_job(job, config))
    await asyncio.wait_for(started.wait(), timeout=5)
    with pytest.raises(ValueError, match="still owns"):
        await worker.execute_job(job, config)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
