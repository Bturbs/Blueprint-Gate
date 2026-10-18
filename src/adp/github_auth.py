"""GitHub App installation token broker; private key stays on the control plane."""
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt

from adp.settings import settings


class GitHubTokenProvider:
    def __init__(self, transport=None):
        self.transport = transport
        self._cached: tuple[str, datetime] | None = None
        self._lock = asyncio.Lock()

    async def get(self, override: str | None = None) -> str:
        app_fields = (settings.github_app_id, settings.github_installation_id, settings.github_private_key_path)
        if settings.hybrid_mode and (settings.github_token or override):
            raise RuntimeError("Hybrid control must not use a personal GitHub token")
        if (settings.github_token or override) and any(app_fields):
            raise RuntimeError("GitHub App control must not use a personal GitHub token")
        if any(app_fields) and not all(app_fields):
            raise RuntimeError("Complete GitHub App configuration required")
        if override:
            return override
        if settings.github_token:
            return settings.github_token
        if not all(app_fields):
            raise RuntimeError("Complete GitHub App configuration required in hybrid mode" if settings.hybrid_mode else "GitHub token or complete GitHub App configuration required")
        async with self._lock:
            if self._cached and self._cached[1] > datetime.now(timezone.utc) + timedelta(minutes=5):
                return self._cached[0]
            key = Path(settings.github_private_key_path).read_text(encoding="utf-8")
            issued = datetime.now(timezone.utc)
            bearer = jwt.encode({"iat": int((issued - timedelta(seconds=60)).timestamp()), "exp": int((issued + timedelta(minutes=9)).timestamp()), "iss": settings.github_app_id}, key, algorithm="RS256")
            async with httpx.AsyncClient(base_url=settings.github_api_url, transport=self.transport, timeout=30) as client:
                response = await client.post(
                    f"/app/installations/{settings.github_installation_id}/access_tokens",
                    headers={"Authorization": f"Bearer {bearer}", "Accept": "application/vnd.github+json"},
                )
                response.raise_for_status()
                payload = response.json()
            expiry = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
            self._cached = (payload["token"], expiry)
            return payload["token"]


tokens = GitHubTokenProvider()
