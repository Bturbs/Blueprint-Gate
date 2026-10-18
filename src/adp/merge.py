"""Fail-closed GitHub merge eligibility and protected merge operation."""
import fnmatch
import re

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from adp.db import Approval, AuditEvent, PublicationAttempt, Repository, Ticket
from adp.github import GitHubClient
from adp.settings import settings
from adp.github_auth import tokens
from adp.workflow import dependencies_ready, security_gate

DEFAULT_HIGH_RISK = [
    "auth*", "**/*auth*", "security/**", "**/security/**", "**/*crypt*", "**/*key*",
    "migrations/**", "**/migrations/**", ".github/workflows/**",
    "terraform/**", "**/terraform/**", "infra/**", "**/infra/**",
    "policy/**", "**/policy/**", "**/*policy*",
]


def eligibility(db: Session, ticket: Ticket, pr: dict, checks: list[dict], paths: list[str]) -> list[str]:
    repo = ticket.repository
    reasons = []
    if not repo.auto_merge:
        reasons.append("automatic merging disabled")
    if ticket.state != "READY_TO_MERGE":
        reasons.append("QA or security review incomplete")
    if not security_gate(db, ticket):
        reasons.append("security design approval stale or absent")
    if not dependencies_ready(db, ticket):
        reasons.append("ticket dependencies not merged")
    if not pr.get("head", {}).get("sha") or pr["head"]["sha"] != ticket.artifacts.get("commit_sha"):
        reasons.append("PR head differs from validated commit")
    if pr.get("state") != "open" or pr.get("mergeable") is not True or pr.get("mergeable_state") != "clean":
        reasons.append("PR is not cleanly mergeable")
    expected_base = repo.policy.get("base_branch")
    if expected_base and pr.get("base", {}).get("ref") != expected_base:
        reasons.append("PR targets the wrong base branch")
    if not re.search(rf"(?i)\b(?:closes|fixes|resolves)\s+#{ticket.number}\b", pr.get("body") or ""):
        reasons.append("PR is not linked to ticket")
    passing = {x.get("name") for x in checks if x.get("status") == "completed" and x.get("conclusion") == "success"}
    missing = set(repo.policy.get("required_ci_checks", [])) - passing
    if not repo.policy.get("required_ci_checks") or missing:
        reasons.append("required CI checks missing or failed")
    forbidden = repo.policy.get("forbidden_paths", ["AGENTS.md", "**/AGENTS.md"])
    if any(fnmatch.fnmatch(path, pattern) for path in paths for pattern in forbidden):
        reasons.append("prohibited path changed")
    high_risk = repo.policy.get("high_risk_paths", DEFAULT_HIGH_RISK)
    if any(fnmatch.fnmatch(path, pattern) for path in paths for pattern in high_risk):
        approved = db.scalar(select(Approval).where(Approval.ticket_id == ticket.id, Approval.kind == "high_risk_merge", Approval.revision == ticket.design_revision, Approval.ref == pr.get("head", {}).get("sha")))
        if not approved:
            reasons.append("high-risk change needs human approval")
    if repo.policy.get("threat_model_pr_required") and not ticket.artifacts.get("threat_model_pr_merged"):
        reasons.append("threat model PR not merged")
    return reasons


class GitHubMergeClient:
    def __init__(self, token: str | None = None, transport=None):
        self.token = token
        self.transport = transport

    async def _get_pages(self, client, path):
        items = []
        for page in range(1, 101):
            response = await client.get(path, params={"per_page": 100, "page": page})
            response.raise_for_status()
            batch = response.json()
            items.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise RuntimeError("GitHub pagination limit exceeded")
        return items

    async def reconcile(self, db: Session, ticket: Ticket) -> dict:
        if not ticket.pr_number:
            return {"merged": False, "reasons": ["PR missing"]}
        token = await tokens.get(self.token)
        repo = ticket.repository.full_name
        number = ticket.pr_number
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
        async with httpx.AsyncClient(base_url=settings.github_api_url, headers=headers, transport=self.transport, timeout=30) as client:
            pr_response = await client.get(f"/repos/{repo}/pulls/{number}")
            pr_response.raise_for_status()
            pr = pr_response.json()
            if ticket.state == "MERGE_SUBMITTED":
                if pr.get("merged") and pr.get("head", {}).get("sha") == ticket.artifacts.get("commit_sha"):
                    ticket.state = "MERGED"
                    db.add(AuditEvent(ticket_id=ticket.id, action="merged", detail={"pr": number, "sha": ticket.artifacts["commit_sha"]}))
                    db.commit()
                    return {"merged": True}
                if pr.get("merged"):
                    ticket.state = "MERGE_UNKNOWN"
                    db.add(AuditEvent(ticket_id=ticket.id, action="merge_head_mismatch", detail={"pr": number}))
                    db.commit()
                    return {"merged": False, "state": "MERGE_UNKNOWN"}
                request_id = ticket.artifacts.get("merge_request_uuid")
                if request_id:
                    status_response = await client.get(f"/repos/{repo}/pulls/{number}/merge-async/{request_id}")
                    if status_response.status_code == 404:
                        ticket.state = "MERGE_UNKNOWN"
                    else:
                        status_response.raise_for_status()
                        if status_response.json().get("status") == "failed":
                            ticket.state = "MERGE_FAILED"
                    if ticket.state != "MERGE_SUBMITTED":
                        db.add(AuditEvent(ticket_id=ticket.id, action="merge_reconciliation_failed", detail={"state": ticket.state}))
                        db.commit()
                return {"merged": False, "state": ticket.state}
            sha = pr.get("head", {}).get("sha", "")
            checks_response = await client.get(f"/repos/{repo}/commits/{sha}/check-runs", params={"per_page": 100})
            checks_response.raise_for_status()
            checks = checks_response.json().get("check_runs", [])
            if checks_response.json().get("total_count", len(checks)) > len(checks):
                return {"merged": False, "reasons": ["CI check results are incomplete"]}
            paths = [x["filename"] for x in await self._get_pages(client, f"/repos/{repo}/pulls/{number}/files")]
            if pr.get("changed_files", len(paths)) > len(paths):
                return {"merged": False, "reasons": ["PR changed-file list is incomplete"]}
            reasons = eligibility(db, ticket, pr, checks, paths)
            retired = db.scalars(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.state.in_(["RECONCILED", "LATE_EFFECT"]))).all()
            for attempt in retired:
                if attempt.state == "LATE_EFFECT":
                    reasons.append("Late publication effect requires operator review")
                    continue
                try:
                    await GitHubClient(token=token, transport=self.transport).publication_clear(attempt.repository, attempt.branch)
                except Exception:
                    reasons.append("Retired publication attempt is not confirmed clear")
            if reasons:
                return {"merged": False, "reasons": reasons}
            response = await client.put(f"/repos/{repo}/pulls/{number}/merge-async", json={"sha": sha, "merge_method": ticket.repository.policy.get("merge_method", "squash"), "merge_action": "default"})
            if response.status_code not in {200, 202} or response.json().get("status") not in {"pending", "enqueued", "merged"}:
                return {"merged": False, "reasons": [f"GitHub rejected merge: HTTP {response.status_code}"]}
            ticket.state = "MERGE_SUBMITTED"
            request_id = response.json().get("details", {}).get("uuid")
            ticket.artifacts = {**ticket.artifacts, "merge_request_uuid": request_id, "merge_requested_sha": sha}
        db.add(AuditEvent(ticket_id=ticket.id, action="merge_submitted", detail={"pr": number, "sha": sha, "request_id": request_id}))
        db.commit()
        return {"merged": False, "state": "MERGE_SUBMITTED", "sha": sha}
