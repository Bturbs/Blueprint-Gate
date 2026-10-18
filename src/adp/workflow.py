"""Deterministic ticket lifecycle and security gate."""
from sqlalchemy import select
from sqlalchemy.orm import Session
from adp.db import Approval, AuditEvent, Job, RiskAcceptance, Ticket, now

STAGES = ("product_owner", "architect", "threat_modeler", "engineer", "qa", "security_engineer")
NEXT = {"product_owner": "architect", "architect": "threat_modeler", "engineer": "qa", "qa": "security_engineer"}


def audit(db: Session, ticket: Ticket, action: str, detail: dict | None = None):
    db.add(AuditEvent(ticket_id=ticket.id, action=action, detail=detail or {}))


def enqueue(db: Session, ticket: Ticket, stage: str) -> Job:
    if stage not in STAGES:
        raise ValueError("Invalid stage")
    if stage == "engineer" and not security_gate(db, ticket):
        raise ValueError("Security design gate is not satisfied")
    revision = 1 + (db.scalar(select(Job.revision).where(Job.ticket_id == ticket.id, Job.stage == stage).order_by(Job.revision.desc()).limit(1)) or 0)
    job = Job(ticket_id=ticket.id, stage=stage, revision=revision)
    db.add(job)
    audit(db, ticket, "job_queued", {"stage": stage, "revision": revision})
    return job


def dependencies_ready(db: Session, ticket: Ticket) -> bool:
    for number in ticket.dependencies:
        predecessor = db.scalar(select(Ticket).where(Ticket.repository_id == ticket.repository_id, Ticket.number == number))
        if predecessor is None or predecessor.state != "MERGED":
            return False
    return True


def unresolved_blockers(ticket: Ticket, db: Session | None = None) -> list[dict]:
    block_low = ticket.repository.policy.get("block_low_findings", False)
    accepted: set[str] = set()
    if db and ticket.repository.policy.get("allow_risk_acceptance", False):
        accepted = {
            x.threat_id for x in db.scalars(select(RiskAcceptance).where(
                RiskAcceptance.ticket_id == ticket.id,
                RiskAcceptance.design_revision == ticket.design_revision,
                RiskAcceptance.threat_revision == ticket.threat_revision,
                RiskAcceptance.expires_at > now(),
            ))
        }
    return [
        f for f in ticket.findings
        if f.get("status") == "open" and f.get("threat_id") not in accepted and (
            f.get("severity") in {"medium", "high", "critical"}
            or (block_low and f.get("severity") == "low")
            or f.get("blocking") is True
        )
    ]


def validate_findings(ticket: Ticket, findings: list[dict]) -> None:
    if not isinstance(findings, list):
        raise ValueError("Findings must be a list")
    seen = set()
    for finding in findings:
        if not isinstance(finding, dict) or not all(finding.get(key) for key in ("finding_id", "threat_id", "severity", "status")):
            raise ValueError("Finding is missing required identity or classification")
        if finding["finding_id"] in seen:
            raise ValueError("Duplicate finding ID")
        seen.add(finding["finding_id"])
        if finding["severity"] not in {"low", "medium", "high", "critical"} or finding["status"] not in {"open", "resolved"}:
            raise ValueError("Invalid finding severity or status")
        if finding.get("linked_design_revision") != ticket.design_revision:
            raise ValueError("Finding is not linked to the current design revision")
        if not isinstance(finding.get("affected_assets"), list) or not isinstance(finding.get("recommended_mitigations"), list):
            raise ValueError("Finding assets and mitigations must be lists")


def validate_mitigations(requirements: list[dict]) -> None:
    if not isinstance(requirements, list):
        raise ValueError("Mitigation requirements must be a list")
    seen = set()
    for item in requirements:
        if not isinstance(item, dict) or not all(item.get(key) for key in ("threat_id", "countermeasure_id", "check_command")):
            raise ValueError("Mitigation requirement needs threat, countermeasure, and check command")
        if not isinstance(item["check_command"], list) or not all(isinstance(x, str) and x for x in item["check_command"]):
            raise ValueError("Mitigation check command must be an argv list")
        identity = (item["threat_id"], item["countermeasure_id"])
        if identity in seen:
            raise ValueError("Duplicate mitigation requirement")
        seen.add(identity)


def security_gate(db: Session, ticket: Ticket) -> bool:
    if not ticket.verification_passed or not ticket.threat_revision or unresolved_blockers(ticket, db):
        return False
    if ticket.repository.policy.get("threat_model_pr_required"):
        if not ticket.artifacts.get("threat_model_pr_approved"):
            return False
        if ticket.repository.policy.get("threat_model_merge_timing", "before_engineering") == "before_engineering" and not ticket.artifacts.get("threat_model_pr_merged"):
            return False
    approval = db.scalar(select(Approval).where(Approval.ticket_id == ticket.id, Approval.kind == "security_design", Approval.revision == ticket.design_revision, Approval.ref == ticket.threat_revision).order_by(Approval.created_at.desc()).limit(1))
    return approval is not None and ticket.security_approved_revision == ticket.design_revision


def complete_stage(db: Session, ticket: Ticket, stage: str, result: dict) -> None:
    if stage == "product_owner":
        if not isinstance(result.get("requirements"), str) or not result["requirements"].strip():
            raise ValueError("Requirements artifact required")
        ticket.spec_revision += 1
        ticket.artifacts = {**ticket.artifacts, "requirements": result["requirements"]}
        ticket.state = "REQUIREMENTS_READY"
    elif stage == "architect":
        if not all(isinstance(result.get(key), str) and result[key].strip() for key in ("design", "tasks")):
            raise ValueError("Design and tasks artifacts required")
        ticket.design_revision += 1
        ticket.security_approved_revision = None
        ticket.verification_passed = False
        ticket.threat_revision = None
        ticket.findings = []
        ticket.artifacts = {k: v for k, v in ticket.artifacts.items() if k not in {"threat_model_pr", "threat_model_pr_approved", "threat_model_pr_merged"}}
        ticket.artifacts = {**ticket.artifacts, "design": result["design"], "tasks": result["tasks"]}
        ticket.state = "DESIGN_READY"
    elif stage == "threat_modeler":
        if not result.get("verification_passed") or not result.get("threat_revision"):
            raise ValueError("Root threat-model verification and revision required")
        validate_findings(ticket, result.get("findings", []))
        validate_mitigations(result.get("mitigation_requirements", []))
        allowed_checks = ticket.repository.policy.get("required_checks", [])
        if any(item["check_command"] not in allowed_checks for item in result.get("mitigation_requirements", [])):
            raise ValueError("Mitigation check is not in repository required_checks allowlist")
        ticket.verification_passed = True
        ticket.threat_revision = result["threat_revision"]
        ticket.findings = result.get("findings", [])
        ticket.artifacts = {**ticket.artifacts, "mitigation_requirements": result.get("mitigation_requirements", [])}
        if ticket.repository.policy.get("threat_model_pr_required"):
            pr = result.get("threat_model_pr")
            if not isinstance(pr, dict) or not all(pr.get(k) for k in ("repository", "number", "head_sha")):
                raise ValueError("Separate threat-model PR evidence is required")
            ticket.artifacts = {**ticket.artifacts, "threat_model_pr": pr, "threat_model_pr_approved": False, "threat_model_pr_merged": False}
        ticket.state = "BLOCKED_FINDINGS" if unresolved_blockers(ticket, db) else "WAITING_SECURITY_APPROVAL"
        if ticket.state == "WAITING_SECURITY_APPROVAL" and ticket.repository.policy.get("threat_model_pr_required"):
            ticket.state = "WAITING_THREAT_PR"
        if ticket.state == "BLOCKED_FINDINGS":
            prior = db.scalar(select(Job.revision).where(Job.ticket_id == ticket.id, Job.stage == "architect").order_by(Job.revision.desc()).limit(1)) or 0
            maximum = int(ticket.repository.policy.get("max_remediation_iterations", 3))
            if prior < maximum:
                enqueue(db, ticket, "architect")
            else:
                ticket.state = "ESCALATED_SECURITY"
    elif stage == "engineer":
        if not result.get("commit_sha") or not result.get("pr_number"):
            raise ValueError("Commit and PR required")
        if not result.get("checks") or not all(c.get("passed") for c in result["checks"]):
            raise ValueError("Required local checks must pass")
        ticket.pr_number = result["pr_number"]
        ticket.artifacts = {**ticket.artifacts, "commit_sha": result["commit_sha"]}
        ticket.state = "PR_OPEN"
    elif stage == "qa":
        if not result.get("checks") or not result.get("evidence"):
            raise ValueError("QA requires checks and review evidence")
        passed = result.get("passed") is True and all(c.get("passed") for c in result["checks"])
        ticket.artifacts = {**ticket.artifacts, "qa_review": {"passed": passed, "evidence": result["evidence"], "checks": result["checks"]}}
        ticket.state = "QA_PASSED" if passed else "QA_FAILED"
        if not passed:
            _remediate_code(db, ticket, "QA")
            return
    elif stage == "security_engineer":
        if not result.get("checks") or not result.get("evidence"):
            raise ValueError("Security review requires checks and evidence")
        passed = result.get("passed") is True and all(c.get("passed") for c in result["checks"])
        required = {(x["threat_id"], x["countermeasure_id"]): x for x in ticket.artifacts.get("mitigation_requirements", [])}
        evidence = {(x.get("threat_id"), x.get("countermeasure_id")): x for x in result.get("mitigation_evidence", []) if isinstance(x, dict)}
        for identity, requirement in required.items():
            item = evidence.get(identity)
            checked = any(c.get("command") == requirement["check_command"] and c.get("passed") for c in result["checks"])
            if not item or not item.get("code_paths") or not item.get("test_evidence") or not checked:
                passed = False
        ticket.artifacts = {**ticket.artifacts, "security_review": {"passed": passed, "evidence": result["evidence"], "checks": result["checks"]}}
        if result.get("mitigation_evidence"):
            ticket.artifacts = {**ticket.artifacts, "mitigation_evidence": result["mitigation_evidence"]}
        ticket.state = "READY_TO_MERGE" if passed else "SECURITY_FAILED"
        if not passed:
            _remediate_code(db, ticket, "SECURITY")
            return
    else:
        raise ValueError("Unknown stage")
    audit(db, ticket, "stage_complete", {"stage": stage, "state": ticket.state})
    next_stage = NEXT.get(stage)
    if next_stage:
        enqueue(db, ticket, next_stage)


def _remediate_code(db: Session, ticket: Ticket, source: str):
    prior = db.scalar(select(Job.revision).where(Job.ticket_id == ticket.id, Job.stage == "engineer").order_by(Job.revision.desc()).limit(1)) or 0
    if prior < int(ticket.repository.policy.get("max_code_iterations", 3)):
        enqueue(db, ticket, "engineer")
    else:
        ticket.state = f"ESCALATED_{source}"
    audit(db, ticket, "code_review_failed", {"source": source, "state": ticket.state})


def approve_security(db: Session, ticket: Ticket, actor: str, justification: str):
    if ticket.state != "WAITING_SECURITY_APPROVAL" or unresolved_blockers(ticket, db) or not ticket.verification_passed or (ticket.repository.policy.get("threat_model_pr_required") and not ticket.artifacts.get("threat_model_pr_approved")):
        raise ValueError("Design is not eligible for security approval")
    db.add(Approval(ticket_id=ticket.id, kind="security_design", revision=ticket.design_revision, ref=ticket.threat_revision, actor=actor, justification=justification))
    ticket.security_approved_revision = ticket.design_revision
    ticket.state = "SECURITY_DESIGN_APPROVED"
    audit(db, ticket, "security_design_approved", {"actor": actor, "design_revision": ticket.design_revision, "threat_revision": ticket.threat_revision})
    enqueue(db, ticket, "engineer")
