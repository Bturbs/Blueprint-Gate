"""GitHub REST polling. Token stays in the control plane and is never sent to workers."""
import re
import httpx
from adp.settings import settings
from adp.github_auth import tokens

DEPENDENCY = re.compile(r"(?im)^\s*(?:depends on|blocked by)\s*:?[ \t]*#(\d+)\s*$")


def dependencies(body: str) -> list[int]:
    return sorted({int(x) for x in DEPENDENCY.findall(body or "")})


class GitHubClient:
    def __init__(self, token: str | None = None, transport=None):
        self.token = token
        self.transport = transport

    async def list_issues(self, repo: str) -> list[dict]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Invalid repository name")
        token = await tokens.get(self.token)
        issues: list[dict] = []
        async with httpx.AsyncClient(base_url=settings.github_api_url, transport=self.transport, timeout=30) as client:
            for page in range(1, 101):
                response = await client.get(
                    f"/repos/{repo}/issues",
                    params={"state": "open", "per_page": 100, "page": page},
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                )
                response.raise_for_status()
                batch = [x for x in response.json() if "pull_request" not in x]
                issues.extend(batch)
                if len(response.json()) < 100:
                    break
            else:
                raise RuntimeError("GitHub issue pagination limit exceeded")
        return issues
