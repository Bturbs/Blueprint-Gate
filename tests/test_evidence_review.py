from fastapi.testclient import TestClient
import httpx
import subprocess
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import AuditEvent, Base, Repository, Ticket
from adp.workflow import complete_stage
from adp.threat_models import committed_model_revision, model_revision


def test_security_approval_requires_exact_review_evidence(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(api.settings, "control_token", "control-secret")
    monkeypatch.setattr(api.settings, "human_identity_required", True)
    monkeypatch.setattr(api.settings, "human_reviewer_ids", "64413370")
    monkeypatch.setattr(api.settings, "human_operator_ids", "64413370")
    monkeypatch.setattr(api.httpx, "get", lambda *args, **kwargs: httpx.Response(200, json={"id": 64413370, "login": "Bturbs"}))
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with Session(engine) as db:
            repo = Repository(full_name="example/project", policy={})
            db.add(repo)
            db.flush()
            repo_id = repo.id
            ticket = Ticket(repository_id=repo.id, number=1, title="Review model", state="WAITING_SECURITY_APPROVAL", design_revision=2, threat_revision="model-sha", verification_passed=True, findings=[], artifacts={"in_place_controls": ["root.yaml:AUTH", "root.yaml:BACKUP"]})
            db.add(ticket)
            db.commit()
            ticket_id = ticket.id
        owner = {"Authorization": "Bearer control-secret", "X-Human-Authorization": "Bearer owner-token"}
        path = f"/tickets/{ticket_id}/approve-security"
        base = {"justification": "Reviewed design and model evidence"}
        current = {**base, "reviewed_design_revision": 2, "reviewed_threat_revision": "model-sha", "reviewed_boundaries": ["Issue to worker boundary"], "control_evidence": {"root.yaml:AUTH": "source: auth.py at commit abc", "root.yaml:BACKUP": "staging: restored backup on 2026-10-18"}}
        with TestClient(api.app) as client:
            assert client.post(f"/repositories/{repo_id}/require-evidence-review", headers=owner).status_code == 409
            client.post("/control/pause", headers=owner).raise_for_status()
            assert client.post(f"/repositories/{repo_id}/require-evidence-review", headers={"Authorization": "Bearer control-secret"}).status_code == 401
            enabled = client.post(f"/repositories/{repo_id}/require-evidence-review", headers=owner)
            assert enabled.status_code == 200 and enabled.json()["evidence_review_required"] is True
            assert client.post(path, headers={"Authorization": "Bearer control-secret"}, json=current).status_code == 401
            assert client.post(path, headers=owner, json=base).status_code == 409
            assert client.post(path, headers=owner, json={**current, "reviewed_design_revision": 1}).status_code == 409
            assert client.post(path, headers=owner, json={**current, "reviewed_threat_revision": "old-model"}).status_code == 409
            assert client.post(path, headers=owner, json={**current, "reviewed_boundaries": []}).status_code == 422
            assert client.post(path, headers=owner, json={**current, "control_evidence": {"root.yaml:AUTH": "source: auth.py at commit abc"}}).status_code == 422
            accepted = client.post(path, headers=owner, json=current)
            assert accepted.status_code == 200
        with Session(engine) as db:
            reviewed = db.scalar(select(AuditEvent).where(AuditEvent.ticket_id == ticket_id, AuditEvent.action == "security_evidence_reviewed"))
            assert reviewed.detail["actor"] == "github:64413370:Bturbs"
            assert reviewed.detail["design_revision"] == 2
            assert reviewed.detail["threat_revision"] == "model-sha"
            assert set(reviewed.detail["control_evidence"]) == {"root.yaml:AUTH", "root.yaml:BACKUP"}
            policy_event = db.scalar(select(AuditEvent).where(AuditEvent.action == "evidence_review_required"))
            assert policy_event.detail["actor"] == "github:64413370:Bturbs"
    finally:
        api.app.dependency_overrides.clear()


def test_model_stage_records_manifest_and_design_change_invalidates_it():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        repo = Repository(full_name="example/project", policy={"evidence_review_required": True})
        ticket = Ticket(repository=repo, number=1, title="Review model", state="DESIGN_READY", design_revision=1, findings=[], artifacts={"design": "old", "tasks": "old"})
        db.add(ticket)
        db.flush()
        result = {"verification_passed": True, "threat_revision": "model-sha", "findings": [], "mitigation_requirements": []}
        try:
            complete_stage(db, ticket, "threat_modeler", result)
        except ValueError as exc:
            assert "control manifest" in str(exc)
        else:
            raise AssertionError("Missing control manifest was accepted")
        complete_stage(db, ticket, "threat_modeler", {**result, "in_place_controls": ["root.yaml:AUTH"]})
        assert ticket.artifacts["in_place_controls"] == ["root.yaml:AUTH"]
        complete_stage(db, ticket, "architect", {"design": "updated design", "tasks": "updated tasks"})
        assert "in_place_controls" not in ticket.artifacts


def test_verified_model_digest_matches_immutable_commit(tmp_path):
    model = tmp_path / "models" / "Example" / "Example.yaml"
    model.parent.mkdir(parents=True)
    model.write_text("title: reviewed\n")
    for args in (["init"], ["config", "user.email", "test@example.com"], ["config", "user.name", "Test"], ["add", "."], ["commit", "-m", "baseline"]):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()
    assert committed_model_revision(tmp_path, model.parent, sha) == model_revision(model)
    model.write_text("title: changed after verification\n")
    assert committed_model_revision(tmp_path, model.parent, sha) != model_revision(model)
