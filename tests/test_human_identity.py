from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp import cli
from adp.db import Approval, AuditEvent, Base, Repository, Ticket


def test_human_identity_binds_admin_and_review_decisions(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(api.settings, "control_token", "control-secret")
    monkeypatch.setattr(api.settings, "human_identity_required", True)
    monkeypatch.setattr(api.settings, "human_operator_ids", "64413370")
    monkeypatch.setattr(api.settings, "human_reviewer_ids", "64413370")

    def github_user(url, *, headers, timeout, follow_redirects):
        assert url == "https://api.github.com/user"
        token = headers["Authorization"]
        if token == "Bearer owner-token":
            return httpx.Response(200, json={"id": 64413370, "login": "Bturbs"})
        if token == "Bearer other-token":
            return httpx.Response(200, json={"id": 1234, "login": "other"})
        return httpx.Response(401)

    monkeypatch.setattr(api.httpx, "get", github_user)
    api.app.dependency_overrides[api.db_session] = get_db
    control = {"Authorization": "Bearer control-secret"}
    owner = {**control, "X-Human-Authorization": "Bearer owner-token"}
    try:
        with TestClient(api.app) as client:
            assert client.post("/control/resume", headers=control).status_code == 401
            assert client.post("/control/resume", headers={**control, "X-Human-Authorization": "Bearer control-secret"}).status_code == 401
            assert client.post("/control/resume", headers={**control, "X-Human-Authorization": "Bearer bad-token"}).status_code == 401
            assert client.post("/control/resume", headers={**control, "X-Human-Authorization": "Bearer other-token"}).status_code == 403
            assert client.post("/control/pause", headers=owner).json() == {"paused": True, "running_jobs": 0}
            registered = client.post("/repositories", headers=owner, json={"full_name": "example/project"})
            registered.raise_for_status()
            repo_id = registered.json()["id"]
            with Session(engine) as db:
                ticket = Ticket(repository_id=repo_id, number=1, title="Review me", state="WAITING_SECURITY_APPROVAL", design_revision=2, threat_revision="model-revision", verification_passed=True, findings=[], artifacts={})
                db.add(ticket)
                db.commit()
                ticket_id = ticket.id
            path = f"/tickets/{ticket_id}/approve-security"
            payload = {"actor": "someone-else", "justification": "Reviewed the exact design and model"}
            monkeypatch.setattr(api.settings, "human_reviewer_ids", "1234")
            assert client.post(path, headers=owner, json={"justification": payload["justification"]}).status_code == 403
            monkeypatch.setattr(api.settings, "human_reviewer_ids", "64413370")
            assert client.post(path, headers=owner, json=payload).status_code == 403
            approved = client.post(path, headers=owner, json={"justification": payload["justification"]})
            assert approved.status_code == 200
            with Session(engine) as db:
                approval = db.scalar(select(Approval).where(Approval.ticket_id == ticket_id))
                assert approval.actor == "github:64413370:Bturbs"
                assert approval.revision == 2 and approval.ref == "model-revision"
                actions = {event.action: event.detail for event in db.scalars(select(AuditEvent))}
                assert actions["global_pause_changed"]["actor"] == approval.actor
                assert actions["repository_registered"]["actor"] == approval.actor
                assert actions["security_design_approved"]["actor"] == approval.actor
    finally:
        api.app.dependency_overrides.clear()


def test_human_identity_fails_closed_when_role_or_api_unavailable(monkeypatch):
    monkeypatch.setattr(api.settings, "control_token", "control-secret")
    monkeypatch.setattr(api.settings, "human_identity_required", True)
    monkeypatch.setattr(api.settings, "human_operator_ids", "")
    monkeypatch.setattr(api.settings, "human_reviewer_ids", "64413370")
    headers = {"Authorization": "Bearer control-secret", "X-Human-Authorization": "Bearer owner-token"}
    with TestClient(api.app) as client:
        assert client.post("/control/pause", headers=headers).status_code == 503
        monkeypatch.setattr(api.settings, "human_operator_ids", "64413370")
        monkeypatch.setattr(api.httpx, "get", lambda *args, **kwargs: httpx.Response(503))
        assert client.post("/control/pause", headers=headers).status_code == 503


def test_operator_cli_passes_separate_human_token(monkeypatch):
    monkeypatch.setenv("CONTROL_TOKEN", "control-secret")
    monkeypatch.setenv("ADP_HUMAN_GITHUB_TOKEN", "owner-token")
    with cli._control_client("http://127.0.0.1:8000", "CONTROL_TOKEN") as client:
        assert client.headers["Authorization"] == "Bearer control-secret"
        assert client.headers["X-Human-Authorization"] == "Bearer owner-token"
