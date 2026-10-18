"""GitHub REST polling. Token stays in the control plane and is never sent to workers."""
import re
from urllib.parse import quote
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

    async def publication_clear(self, repo: str, branch: str) -> dict:
        """Confirm an attempt ref is gone and none of its PRs can still land."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"adp/issue-[0-9]+/job-[0-9a-f]{32}-f[0-9]+", branch):
            raise ValueError("Invalid publication identity")
        token = await tokens.get(self.token)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        matching: list[dict] = []
        async with httpx.AsyncClient(base_url=settings.github_api_url, transport=self.transport, timeout=30) as client:
            ref = await client.get(f"/repos/{repo}/git/ref/heads/{quote(branch, safe='')}", headers=headers)
            if ref.status_code != 404:
                ref.raise_for_status()
                raise RuntimeError("Publication branch still exists")
            for page in range(1, 101):
                response = await client.get(f"/repos/{repo}/pulls", params={"state": "all", "per_page": 100, "page": page}, headers=headers)
                response.raise_for_status()
                batch = response.json()
                matching.extend({"number": pr["number"], "state": pr["state"], "merged_at": pr.get("merged_at")} for pr in batch if pr.get("head", {}).get("ref") == branch)
                if len(batch) < 100:
                    break
            else:
                raise RuntimeError("GitHub PR pagination limit exceeded")
        if any(pr["state"] != "closed" or pr["merged_at"] for pr in matching):
            raise RuntimeError("Publication PR is open or merged")
        return {"branch_absent": True, "closed_unmerged_prs": [pr["number"] for pr in matching]}

    async def merged_exact(self, repo: str, number: int, sha: str, branch: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or number < 1 or not re.fullmatch(r"[0-9a-f]{40,64}", sha) or not re.fullmatch(r"adp/issue-[0-9]+/job-[0-9a-f]{32}-f[0-9]+", branch):
            raise ValueError("Invalid PR identity")
        token = await tokens.get(self.token)
        async with httpx.AsyncClient(base_url=settings.github_api_url, transport=self.transport, timeout=30) as client:
            response = await client.get(f"/repos/{repo}/pulls/{number}", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
            response.raise_for_status()
            pr = response.json()
        return bool(pr.get("merged_at") and pr.get("head", {}).get("sha") == sha and pr["head"].get("ref") == branch and (pr["head"].get("repo") or {}).get("full_name") == repo)
