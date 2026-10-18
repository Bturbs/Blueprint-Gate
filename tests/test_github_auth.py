from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from adp.github_auth import GitHubTokenProvider
from adp.github import GitHubClient
from adp.merge import GitHubMergeClient
from adp.projects import GitHubProjectsClient
from adp.settings import settings
from adp.settings import Settings
from adp.threat_review import ThreatReviewClient


@pytest.mark.asyncio
async def test_github_app_token_is_signed_and_cached(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path / "app.pem"
    path.write_bytes(private)
    monkeypatch.setattr(settings, "github_token", "")
    monkeypatch.setattr(settings, "hybrid_mode", True)
    monkeypatch.setattr(settings, "github_app_id", "123")
    monkeypatch.setattr(settings, "github_installation_id", "456")
    monkeypatch.setattr(settings, "github_private_key_path", str(path))
    calls = []

    def handler(request):
        claims = jwt.decode(request.headers["Authorization"].split(" ", 1)[1], key.public_key(), algorithms=["RS256"], options={"verify_aud": False})
        assert claims["iss"] == "123"
        calls.append(request.url.path)
        return httpx.Response(201, json={"token": "installation-token", "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})

    provider = GitHubTokenProvider(transport=httpx.MockTransport(handler))
    assert await provider.get() == "installation-token"
    assert await provider.get() == "installation-token"
    assert calls == ["/app/installations/456/access_tokens"]


@pytest.mark.asyncio
async def test_hybrid_control_rejects_personal_token(monkeypatch):
    monkeypatch.setattr(settings, "hybrid_mode", True)
    monkeypatch.setattr(settings, "github_token", "broad-personal-token")
    monkeypatch.setattr(settings, "github_app_id", "")
    monkeypatch.setattr(settings, "github_installation_id", "")
    monkeypatch.setattr(settings, "github_private_key_path", "")
    with pytest.raises(RuntimeError, match="personal GitHub token"):
        await GitHubTokenProvider().get()


@pytest.mark.asyncio
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("client_name", ["issues", "merge", "projects", "threat_review"])
async def test_hybrid_clients_reject_personal_tokens_before_request(monkeypatch, explicit, client_name):
    monkeypatch.setattr(settings, "hybrid_mode", True)
    monkeypatch.setattr(settings, "github_token", "" if explicit else "configured-personal-token")
    monkeypatch.setattr(settings, "github_app_id", "")
    monkeypatch.setattr(settings, "github_installation_id", "")
    monkeypatch.setattr(settings, "github_private_key_path", "")
    calls = []

    def handler(request):
        calls.append(request)
        raise AssertionError("GitHub request should not be sent")

    kwargs = {"token": "explicit-personal-token" if explicit else None, "transport": httpx.MockTransport(handler)}
    if client_name == "issues":
        operation = GitHubClient(**kwargs).list_issues("example/project")
    elif client_name == "merge":
        operation = GitHubMergeClient(**kwargs).reconcile(None, SimpleNamespace(pr_number=3))
    elif client_name == "projects":
        operation = GitHubProjectsClient(**kwargs).set_status("project", "item", "field", "option")
    else:
        operation = ThreatReviewClient(**kwargs).review_state({"repository": "example/models", "number": 3, "head_sha": "abc"})
    with pytest.raises(RuntimeError, match="personal GitHub token"):
        await operation
    assert calls == []


@pytest.mark.asyncio
async def test_app_and_personal_token_conflict_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "hybrid_mode", False)
    monkeypatch.setattr(settings, "github_token", "configured-personal-token")
    monkeypatch.setattr(settings, "github_app_id", "123")
    monkeypatch.setattr(settings, "github_installation_id", "456")
    monkeypatch.setattr(settings, "github_private_key_path", "/not/read.pem")
    with pytest.raises(RuntimeError, match="GitHub App control must not use a personal GitHub token"):
        await GitHubTokenProvider().get()


@pytest.mark.asyncio
async def test_local_personal_token_remains_available_without_app(monkeypatch):
    monkeypatch.setattr(settings, "hybrid_mode", False)
    monkeypatch.setattr(settings, "github_token", "local-token")
    monkeypatch.setattr(settings, "github_app_id", "")
    monkeypatch.setattr(settings, "github_installation_id", "")
    monkeypatch.setattr(settings, "github_private_key_path", "")
    assert await GitHubTokenProvider().get() == "local-token"


def test_hybrid_settings_reject_personal_token_at_startup():
    with pytest.raises(ValueError, match="must not have GITHUB_TOKEN"):
        Settings(_env_file=None, hybrid_mode=True, github_token="personal-token")
