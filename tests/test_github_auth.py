from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from adp.github_auth import GitHubTokenProvider
from adp.settings import settings


@pytest.mark.asyncio
async def test_github_app_token_is_signed_and_cached(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path / "app.pem"
    path.write_bytes(private)
    monkeypatch.setattr(settings, "github_token", "")
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
