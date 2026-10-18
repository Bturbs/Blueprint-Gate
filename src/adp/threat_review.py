"""Reconcile independent threat-model PR review and merge state."""
import httpx

from adp.github_auth import tokens
from adp.settings import settings


class ThreatReviewClient:
    def __init__(self, token: str | None = None, transport=None):
        self.token = token
        self.transport = transport

    async def review_state(self, artifact: dict) -> dict:
        token = await tokens.get(self.token)
        repository = artifact["repository"]
        number = artifact["number"]
        expected = artifact["head_sha"]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(base_url=settings.github_api_url, headers=headers, transport=self.transport, timeout=30) as client:
            pr = await client.get(f"/repos/{repository}/pulls/{number}")
            pr.raise_for_status()
            data = pr.json()
            if data.get("head", {}).get("sha") != expected:
                return {"approved": False, "merged": False}
            author = (data.get("user") or {}).get("login")
            if not author:
                return {"approved": False, "merged": bool(data.get("merged"))}
            reviews = []
            for page in range(1, 101):
                response = await client.get(f"/repos/{repository}/pulls/{number}/reviews", params={"per_page": 100, "page": page})
                response.raise_for_status()
                batch = response.json()
                reviews.extend(batch)
                if len(batch) < 100:
                    break
            else:
                raise RuntimeError("Threat-model review pagination limit exceeded")
            latest = {}
            for review in reviews:
                if review.get("commit_id") == expected and review.get("user", {}).get("login") and review["user"]["login"] != author and review["user"].get("type") != "Bot":
                    latest[review["user"]["login"]] = review.get("state")
            return {"approved": "APPROVED" in latest.values(), "merged": bool(data.get("merged"))}
