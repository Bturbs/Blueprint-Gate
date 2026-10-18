import hashlib
import hmac
import json

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import Base


def test_signed_webhook_reconciles_once(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    calls = []

    async def fake_issues(self, repo):
        calls.append(repo)
        return [{"number": 2, "title": "Ticket", "body": "Do it", "labels": []}]

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "github_webhook_secret", "hook-secret")
    monkeypatch.setattr(api.GitHubClient, "list_issues", fake_issues)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            client.post("/repositories", headers={"Authorization": "Bearer admin"}, json={"full_name": "example/project"}).raise_for_status()
            raw = json.dumps({"repository": {"full_name": "example/project"}, "action": "opened"}).encode()
            signature = "sha256=" + hmac.new(b"hook-secret", raw, hashlib.sha256).hexdigest()
            headers = {"X-Hub-Signature-256": signature, "X-GitHub-Delivery": "delivery-1", "X-GitHub-Event": "issues"}
            assert client.post("/webhooks/github", content=raw, headers={**headers, "X-Hub-Signature-256": "wrong"}).status_code == 401
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"accepted": True}
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"duplicate": True}
            assert calls == ["example/project"]
    finally:
        api.app.dependency_overrides.clear()
