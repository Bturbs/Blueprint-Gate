from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
import httpx
import pytest

from adp.db import Approval, Base, Repository, Ticket
from adp.merge import GitHubMergeClient, eligibility


def test_merge_requires_exact_head_ci_and_high_risk_approval():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        repo = Repository(full_name="example/project", auto_merge=True, policy={"required_ci_checks": ["tests"]})
        ticket = Ticket(repository=repo, number=1, title="Add auth", state="READY_TO_MERGE", design_revision=1, security_approved_revision=1, verification_passed=True, threat_revision="tm1", artifacts={"commit_sha": "abc"})
        db.add_all([repo, ticket])
        db.flush()
        db.add(Approval(ticket_id=ticket.id, kind="security_design", revision=1, ref="tm1", actor="owner", justification="reviewed"))
        db.flush()
        pr = {"head": {"sha": "abc"}, "state": "open", "mergeable": True, "mergeable_state": "clean", "body": "Closes #1"}
        checks = [{"name": "tests", "status": "completed", "conclusion": "success"}]
        assert eligibility(db, ticket, pr, checks, ["src/feature.py"]) == []
        assert "high-risk change needs human approval" in eligibility(db, ticket, pr, checks, ["src/auth/permissions.py"])
        db.add(Approval(ticket_id=ticket.id, kind="high_risk_merge", revision=1, ref="abc", actor="owner", justification="reviewed risky change"))
        db.flush()
        assert eligibility(db, ticket, pr, checks, ["src/auth/permissions.py"]) == []
        pr["head"]["sha"] = "changed"
        assert "PR head differs from validated commit" in eligibility(db, ticket, pr, checks, ["src/feature.py"])
        assert "required CI checks missing or failed" in eligibility(db, ticket, pr, [], ["src/feature.py"])


@pytest.mark.asyncio
async def test_github_merge_only_after_policy_passes():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    calls = []
    merged = False

    def handler(request):
        nonlocal merged
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/pulls/3") and request.method == "GET":
            return httpx.Response(200, json={"head": {"sha": "abc"}, "state": "closed" if merged else "open", "merged": merged, "mergeable": True, "mergeable_state": "clean", "body": "Closes #1"})
        if request.url.path.endswith("/check-runs"):
            return httpx.Response(200, json={"check_runs": [{"name": "tests", "status": "completed", "conclusion": "success"}]})
        if request.url.path.endswith("/files"):
            return httpx.Response(200, json=[{"filename": "src/feature.py"}])
        if request.url.path.endswith("/merge-async"):
            return httpx.Response(202, json={"status": "pending", "details": {"uuid": "request-1"}})
        raise AssertionError(request.url)

    with Session(engine) as db:
        repo = Repository(full_name="example/project", auto_merge=False, policy={"required_ci_checks": ["tests"]})
        ticket = Ticket(repository=repo, number=1, title="Feature", state="READY_TO_MERGE", design_revision=1, security_approved_revision=1, verification_passed=True, threat_revision="tm1", artifacts={"commit_sha": "abc"}, pr_number=3)
        db.add_all([repo, ticket])
        db.flush()
        db.add(Approval(ticket_id=ticket.id, kind="security_design", revision=1, ref="tm1", actor="owner", justification="reviewed"))
        db.flush()
        client = GitHubMergeClient(token="test", transport=httpx.MockTransport(handler))
        result = await client.reconcile(db, ticket)
        assert not result["merged"]
        assert not any(method == "PUT" for method, _ in calls)
        repo.auto_merge = True
        result = await client.reconcile(db, ticket)
        assert not result["merged"]
        assert ticket.state == "MERGE_SUBMITTED"
        merged = True
        result = await client.reconcile(db, ticket)
        assert result["merged"]
        assert ticket.state == "MERGED"
        assert sum(method == "PUT" for method, _ in calls) == 1
