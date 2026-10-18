import hashlib
import hmac
import json
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp import api
from adp.db import Base, WebhookDelivery, now


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
    monkeypatch.setattr(api.settings, "github_webhook_previous_secret", "")
    monkeypatch.setattr(api.settings, "github_webhook_previous_until", None)
    monkeypatch.setattr(api.GitHubClient, "list_issues", fake_issues)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            client.post("/repositories", headers={"Authorization": "Bearer admin"}, json={"full_name": "example/project"}).raise_for_status()
            raw = json.dumps({"repository": {"full_name": "example/project"}, "issue": {"number": 2}, "action": "opened"}).encode()
            signature = "sha256=" + hmac.new(b"hook-secret", raw, hashlib.sha256).hexdigest()
            headers = {"X-Hub-Signature-256": signature, "X-GitHub-Delivery": "delivery-1", "X-GitHub-Event": "issues"}
            assert client.post("/webhooks/github", content=raw, headers={**headers, "X-Hub-Signature-256": "wrong"}).status_code == 401
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"accepted": True}
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"duplicate": True}
            assert client.post("/webhooks/github", content=raw, headers={**headers, "X-GitHub-Delivery": "attacker-changed-id"}).json() == {"duplicate": True}
            assert client.post("/webhooks/github", content=raw, headers={**headers, "X-GitHub-Delivery": "changed-event", "X-GitHub-Event": "pull_request"}).status_code == 422
            comment = json.dumps({"action": "created", "repository": {"full_name": "example/project"}, "issue": {"number": 2}, "comment": {"id": 1}}).encode()
            comment_signature = "sha256=" + hmac.new(b"hook-secret", comment, hashlib.sha256).hexdigest()
            assert client.post("/webhooks/github", content=comment, headers={"X-Hub-Signature-256": comment_signature, "X-GitHub-Delivery": "comment-relabel", "X-GitHub-Event": "issues"}).status_code == 422
            review = json.dumps({"action": "submitted", "repository": {"full_name": "example/project"}, "pull_request": {"number": 1}, "review": {"id": 1}}).encode()
            review_signature = "sha256=" + hmac.new(b"hook-secret", review, hashlib.sha256).hexdigest()
            assert client.post("/webhooks/github", content=review, headers={"X-Hub-Signature-256": review_signature, "X-GitHub-Delivery": "review-relabel", "X-GitHub-Event": "pull_request"}).status_code == 422
            assert calls == ["example/project"]
    finally:
        api.app.dependency_overrides.clear()


def test_reconciliation_rollback_keeps_webhook_dedup(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    async def unavailable_projects(self, project_id, full_name):
        raise RuntimeError("GitHub Projects unavailable")

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "github_webhook_secret", "hook-secret")
    monkeypatch.setattr(api.settings, "github_webhook_previous_secret", "")
    monkeypatch.setattr(api.GitHubProjectsClient, "issue_items", unavailable_projects)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            client.post("/repositories", headers={"Authorization": "Bearer admin"}, json={"full_name": "example/project", "policy": {"project_id": "P", "project_status_field_id": "F"}}).raise_for_status()
            raw = b'{"action":"edited","projects_v2_item":{"id":123}}'
            signature = "sha256=" + hmac.new(b"hook-secret", raw, hashlib.sha256).hexdigest()
            headers = {"X-Hub-Signature-256": signature, "X-GitHub-Event": "projects_v2_item", "X-GitHub-Delivery": "first"}
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"accepted": True}
            assert client.post("/webhooks/github", content=raw, headers={**headers, "X-GitHub-Delivery": "second"}).json() == {"duplicate": True}
            with Session(engine) as db:
                assert db.get(WebhookDelivery, "first") is not None
                assert db.get(WebhookDelivery, "second") is None
    finally:
        api.app.dependency_overrides.clear()


def test_failed_webhook_reconciliation_can_retry(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    calls = 0

    async def issues_after_recovery(self, repo):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary GitHub failure")
        return []

    monkeypatch.setattr(api.settings, "control_token", "admin")
    monkeypatch.setattr(api.settings, "github_webhook_secret", "hook-secret")
    monkeypatch.setattr(api.settings, "github_webhook_previous_secret", "")
    monkeypatch.setattr(api.GitHubClient, "list_issues", issues_after_recovery)
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            client.post("/repositories", headers={"Authorization": "Bearer admin"}, json={"full_name": "example/project"}).raise_for_status()
            raw = b'{"action":"opened","repository":{"full_name":"example/project"},"issue":{"number":3}}'
            signature = "sha256=" + hmac.new(b"hook-secret", raw, hashlib.sha256).hexdigest()
            headers = {"X-Hub-Signature-256": signature, "X-GitHub-Event": "issues", "X-GitHub-Delivery": "retry-after-failure"}
            assert client.post("/webhooks/github", content=raw, headers=headers).status_code == 502
            assert client.post("/webhooks/github", content=raw, headers=headers).json() == {"accepted": True}
            assert calls == 2
    finally:
        api.app.dependency_overrides.clear()


def test_webhook_secret_rotation_overlap_and_expiry(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def get_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(api.settings, "github_webhook_secret", "new-secret")
    monkeypatch.setattr(api.settings, "github_webhook_previous_secret", "old-secret")
    monkeypatch.setattr(api.settings, "github_webhook_previous_until", now() + timedelta(minutes=15))
    api.app.dependency_overrides[api.db_session] = get_db
    try:
        with TestClient(api.app) as client:
            raw = b'{"action":"created","projects_v2_item":{"id":1}}'

            def signed(secret, delivery, body=raw):
                return {"X-Hub-Signature-256": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(), "X-GitHub-Delivery": delivery, "X-GitHub-Event": "projects_v2_item"}

            assert client.post("/webhooks/github", content=raw, headers=signed("old-secret", "before-cutover")).json() == {"accepted": True}
            assert client.post("/webhooks/github", content=raw, headers=signed("new-secret", "after-cutover")).json() == {"duplicate": True}
            fresh = b'{"action":"edited","projects_v2_item":{"id":2}}'
            assert client.post("/webhooks/github", content=fresh, headers=signed("new-secret", "new-secret-works", fresh)).json() == {"accepted": True}
            monkeypatch.setattr(api.settings, "github_webhook_previous_until", now() - timedelta(seconds=1))
            assert client.post("/webhooks/github", content=raw, headers=signed("old-secret", "expired-old")).status_code == 401
            assert client.post("/webhooks/github", content=fresh, headers=signed("new-secret", "new-after-expiry", fresh)).json() == {"duplicate": True}
    finally:
        api.app.dependency_overrides.clear()
