import pytest
from datetime import timedelta
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from adp.db import Base, Job, Repository, RiskAcceptance, Ticket, now
from adp.workflow import approve_security, complete_stage, enqueue, security_gate, unresolved_blockers


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_security_design_gate_and_invalidation(db):
    repo = Repository(full_name="example/project", policy={})
    ticket = Ticket(repository=repo, number=1, title="Add endpoint", body="")
    db.add_all([repo, ticket])
    db.flush()
    enqueue(db, ticket, "product_owner")
    complete_stage(db, ticket, "product_owner", {"requirements": "Requirements"})
    complete_stage(db, ticket, "architect", {"design": "Design", "tasks": "Tasks"})
    assert ticket.state == "DESIGN_READY"
    assert db.scalar(select(Job).where(Job.stage == "threat_modeler")) is not None
    with pytest.raises(ValueError):
        enqueue(db, ticket, "engineer")
    complete_stage(db, ticket, "threat_modeler", {"verification_passed": True, "threat_revision": "abc", "findings": []})
    assert ticket.state == "WAITING_SECURITY_APPROVAL"
    approve_security(db, ticket, "owner", "I reviewed the proposed design")
    assert ticket.state == "SECURITY_DESIGN_APPROVED"
    assert security_gate(db, ticket)
    ticket.threat_revision = "changed"
    assert not security_gate(db, ticket)
    ticket.threat_revision = "abc"
    complete_stage(db, ticket, "architect", {"design": "Changed design", "tasks": "Changed tasks"})
    assert not security_gate(db, ticket)
    with pytest.raises(ValueError):
        enqueue(db, ticket, "engineer")


def test_blocking_findings_remediate_then_escalate(db):
    repo = Repository(full_name="example/project", policy={"max_remediation_iterations": 2})
    ticket = Ticket(repository=repo, number=2, title="Sensitive change", body="")
    db.add_all([repo, ticket])
    db.flush()
    finding = {"finding_id": "TM-001", "threat_id": "UNAUTHORISED_ACCESS", "severity": "high", "status": "open", "blocking": False, "affected_assets": [], "recommended_mitigations": [], "linked_design_revision": 1}
    enqueue(db, ticket, "architect")
    complete_stage(db, ticket, "architect", {"design": "v1", "tasks": "tasks"})
    complete_stage(db, ticket, "threat_modeler", {"verification_passed": True, "threat_revision": "a", "findings": [finding]})
    assert ticket.state == "BLOCKED_FINDINGS"
    assert len(db.scalars(select(Job).where(Job.stage == "architect")).all()) == 2
    complete_stage(db, ticket, "architect", {"design": "v2", "tasks": "tasks"})
    db.flush()
    finding["linked_design_revision"] = 2
    complete_stage(db, ticket, "threat_modeler", {"verification_passed": True, "threat_revision": "b", "findings": [finding]})
    assert ticket.state == "ESCALATED_SECURITY"


def test_risk_acceptance_is_revision_bound_and_expires(db):
    repo = Repository(full_name="example/project", policy={"allow_risk_acceptance": True})
    finding = {"finding_id": "TM-1", "threat_id": "ACCESS", "severity": "high", "status": "open", "blocking": False}
    ticket = Ticket(repository=repo, number=3, title="Risky change", body="", design_revision=2, threat_revision="tm2", findings=[finding])
    db.add_all([repo, ticket])
    db.flush()
    assert unresolved_blockers(ticket, db) == [finding]
    acceptance = RiskAcceptance(ticket_id=ticket.id, threat_id="ACCESS", design_revision=2, threat_revision="tm2", actor="owner", justification="Accepted for test", residual_risk="Access may be abused", scope="Test deployment", expires_at=now() + timedelta(days=1))
    db.add(acceptance)
    db.flush()
    assert unresolved_blockers(ticket, db) == []
    acceptance.expires_at = now() - timedelta(days=1)
    db.flush()
    assert unresolved_blockers(ticket, db) == [finding]


def test_failed_qa_returns_to_engineer_until_limit(db):
    repo = Repository(full_name="example/project", policy={"max_code_iterations": 2})
    ticket = Ticket(repository=repo, number=4, title="Fix", state="PR_OPEN", design_revision=1, security_approved_revision=1, verification_passed=True, threat_revision="tm", artifacts={"commit_sha": "abc"})
    db.add_all([repo, ticket])
    db.flush()
    from adp.db import Approval
    db.add(Approval(ticket_id=ticket.id, kind="security_design", revision=1, ref="tm", actor="owner", justification="reviewed"))
    db.flush()
    enqueue(db, ticket, "engineer")
    complete_stage(db, ticket, "qa", {"checks": [{"passed": False}], "evidence": "test failed", "passed": False})
    assert ticket.state == "QA_FAILED"
    assert len(db.scalars(select(Job).where(Job.stage == "engineer")).all()) == 2
    complete_stage(db, ticket, "qa", {"checks": [{"passed": False}], "evidence": "still failing", "passed": False})
    assert ticket.state == "ESCALATED_QA"


def test_threat_pr_timing_and_mitigation_check_gate(db):
    repo = Repository(full_name="example/project", policy={"threat_model_pr_required": True, "threat_model_merge_timing": "before_final_merge", "required_checks": [["pytest", "-q"]]})
    ticket = Ticket(repository=repo, number=5, title="Auth", design_revision=1, artifacts={})
    db.add_all([repo, ticket])
    db.flush()
    result = {"verification_passed": True, "threat_revision": "tm", "findings": [], "threat_model_pr": {"repository": "example/models", "number": 4, "head_sha": "abc"}, "mitigation_requirements": [{"threat_id": "AUTH", "countermeasure_id": "CM-1", "check_command": ["pytest", "-q"]}]}
    complete_stage(db, ticket, "threat_modeler", result)
    assert ticket.state == "WAITING_THREAT_PR"
    ticket.artifacts = {**ticket.artifacts, "threat_model_pr_approved": True}
    ticket.state = "WAITING_SECURITY_APPROVAL"
    approve_security(db, ticket, "owner", "Reviewed model and design")
    assert security_gate(db, ticket)
    complete_stage(db, ticket, "security_engineer", {"passed": True, "checks": [{"command": ["pytest", "-q"], "passed": True}], "evidence": ["reviewed"]})
    assert ticket.state == "SECURITY_FAILED"
    complete_stage(db, ticket, "security_engineer", {"passed": True, "checks": [{"command": ["pytest", "-q"], "passed": True}], "evidence": ["reviewed"], "mitigation_evidence": [{"threat_id": "AUTH", "countermeasure_id": "CM-1", "code_paths": ["src/auth.py"], "test_evidence": ["negative test"]}]})
    assert ticket.state == "READY_TO_MERGE"
