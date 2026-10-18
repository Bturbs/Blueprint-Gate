"""Authenticated control plane API. Workers never receive provider or GitHub secrets."""
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import json
import secrets
import httpx
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from adp.db import AuditEvent, ControlState, Job, Repository, RiskAcceptance, SessionLocal, Ticket, WebhookDelivery, WorkerCredential, now
from adp.github import GitHubClient, dependencies
from adp.merge import GitHubMergeClient
from adp.projects import GitHubProjectsClient
from adp.threat_review import ThreatReviewClient
from adp.scheduler import order
from adp.settings import settings
from adp.workflow import approve_security, complete_stage, dependencies_ready, enqueue, security_gate, unresolved_blockers

app = FastAPI(title="Autonomous Development Platform", version="0.1.0")


def db_session():
    with SessionLocal() as db:
        yield db


def authorized(authorization: Annotated[str | None, Header()] = None):
    if not settings.control_token or not hmac.compare_digest(authorization or "", f"Bearer {settings.control_token}"):
        raise HTTPException(401, "Invalid control token")


def worker_authorized(authorization: Annotated[str | None, Header()] = None, db: Session = Depends(db_session)):
    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(401, "Invalid worker token")
    raw = authorization[len(prefix):]
    digest = hashlib.sha256(raw.encode()).hexdigest()
    credential = db.scalar(select(WorkerCredential).where(WorkerCredential.token_hash == digest))
    if credential:
        expiry = credential.expires_at
        if credential.disabled or (expiry and expiry.replace(tzinfo=expiry.tzinfo or timezone.utc) <= now()):
            raise HTTPException(401, "Worker credential disabled or expired")
        credential.last_seen_at = now()
        db.commit()
        return credential
    if not settings.hybrid_mode and settings.worker_token and hmac.compare_digest(raw, settings.worker_token):
        db.commit()
        return None
    raise HTTPException(401, "Invalid worker token")


class RepositoryIn(BaseModel):
    full_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    policy: dict = Field(default_factory=dict)
    auto_merge: bool = False


class ClaimIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=100)
    capabilities: list[str] = Field(default_factory=list)


class CompleteIn(BaseModel):
    worker_id: str
    fencing_token: int
    result: dict
    succeeded: bool = True


class YieldIn(BaseModel):
    worker_id: str
    fencing_token: int


class ApprovalIn(BaseModel):
    actor: str = Field(min_length=2)
    justification: str = Field(min_length=10)


class RiskAcceptanceIn(BaseModel):
    threat_id: str = Field(min_length=1)
    actor: str = Field(min_length=2)
    justification: str = Field(min_length=10)
    residual_risk: str = Field(min_length=10)
    scope: str = Field(min_length=3)
    expires_at: datetime


class WorkerCredentialIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=100)
    repositories: list[str] = Field(min_length=1)
    capabilities: list[str] = Field(min_length=1)
    expires_at: datetime | None = None


@app.post("/workers/credentials", dependencies=[Depends(authorized)])
def issue_worker_credential(data: WorkerCredentialIn, db: Session = Depends(db_session)):
    if db.scalar(select(WorkerCredential).where(WorkerCredential.worker_id == data.worker_id)):
        raise HTTPException(409, "Worker ID already exists")
    known = {x.full_name for x in db.scalars(select(Repository))}
    if not set(data.repositories).issubset(known):
        raise HTTPException(422, "Worker repository is not registered")
    raw = secrets.token_urlsafe(48)
    expiry = data.expires_at
    if expiry and expiry.replace(tzinfo=expiry.tzinfo or timezone.utc) <= now():
        raise HTTPException(422, "Expiry must be in the future")
    credential = WorkerCredential(worker_id=data.worker_id, token_hash=hashlib.sha256(raw.encode()).hexdigest(), repositories=sorted(set(data.repositories)), capabilities=sorted(set(data.capabilities)), expires_at=expiry)
    db.add(credential)
    db.add(AuditEvent(action="worker_credential_issued", detail={"worker_id": data.worker_id, "repositories": credential.repositories}))
    db.commit()
    return {"id": credential.id, "worker_id": credential.worker_id, "token": raw}


@app.post("/workers/credentials/{credential_id}/revoke", dependencies=[Depends(authorized)])
def revoke_worker_credential(credential_id: str, db: Session = Depends(db_session)):
    credential = db.get(WorkerCredential, credential_id)
    if not credential:
        raise HTTPException(404, "Worker credential not found")
    credential.disabled = True
    db.add(AuditEvent(action="worker_credential_revoked", detail={"worker_id": credential.worker_id}))
    db.commit()
    return {"revoked": True}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/control", dependencies=[Depends(authorized)])
def control_state(db: Session = Depends(db_session)):
    state = db.get(ControlState, 1)
    running = db.scalar(select(func.count()).select_from(Job).where(Job.state == "RUNNING")) or 0
    return {"paused": state.paused if state else False, "running_jobs": running}


@app.post("/control/{action}", dependencies=[Depends(authorized)])
def set_control_state(action: str, db: Session = Depends(db_session)):
    if action not in {"pause", "resume"}:
        raise HTTPException(404, "Unknown action")
    state = db.get(ControlState, 1)
    if state is None:
        state = ControlState(id=1, paused=False)
        db.add(state)
    state.paused = action == "pause"
    db.add(AuditEvent(action="global_pause_changed", detail={"paused": state.paused}))
    db.commit()
    running = db.scalar(select(func.count()).select_from(Job).where(Job.state == "RUNNING")) or 0
    return {"paused": state.paused, "running_jobs": running}


@app.post("/repositories", dependencies=[Depends(authorized)])
def add_repository(data: RepositoryIn, db: Session = Depends(db_session)):
    existing = db.scalar(select(Repository).where(Repository.full_name == data.full_name))
    if existing:
        raise HTTPException(409, "Repository already exists")
    repo = Repository(full_name=data.full_name, policy=data.policy, auto_merge=data.auto_merge)
    db.add(repo)
    db.commit()
    return {"id": repo.id, "full_name": repo.full_name}


@app.get("/repositories", dependencies=[Depends(authorized)])
def list_repositories(db: Session = Depends(db_session)):
    return [{"id": r.id, "full_name": r.full_name, "paused": r.paused, "auto_merge": r.auto_merge, "policy": r.policy} for r in db.scalars(select(Repository))]


@app.post("/repositories/{repo_id}/control/{action}", dependencies=[Depends(authorized)])
def set_repository_state(repo_id: str, action: str, db: Session = Depends(db_session)):
    if action not in {"pause", "resume"}:
        raise HTTPException(404, "Unknown action")
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    repo.paused = action == "pause"
    db.add(AuditEvent(action="repository_pause_changed", detail={"repository": repo.full_name, "paused": repo.paused}))
    db.commit()
    running = db.scalar(select(func.count()).select_from(Job).join(Ticket, Ticket.id == Job.ticket_id).where(Job.state == "RUNNING", Ticket.repository_id == repo_id)) or 0
    global_state = db.get(ControlState, 1)
    return {"paused": repo.paused, "global_paused": global_state.paused if global_state else False, "running_jobs": running}


@app.get("/repositories/{repo_id}/control", dependencies=[Depends(authorized)])
def repository_control_state(repo_id: str, db: Session = Depends(db_session)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    running = db.scalar(select(func.count()).select_from(Job).join(Ticket, Ticket.id == Job.ticket_id).where(Job.state == "RUNNING", Ticket.repository_id == repo_id)) or 0
    global_state = db.get(ControlState, 1)
    return {"paused": repo.paused, "global_paused": global_state.paused if global_state else False, "running_jobs": running}


@app.post("/repositories/{repo_id}/poll", dependencies=[Depends(authorized)])
async def poll(repo_id: str, db: Session = Depends(db_session)):
    repo = db.get(Repository, repo_id)
    if not repo or not repo.enabled:
        raise HTTPException(404, "Repository not found")
    try:
        issues = await GitHubClient().list_issues(repo.full_name)
        project_id = repo.policy.get("project_id")
        project_items = await GitHubProjectsClient().issue_items(project_id, repo.full_name) if project_id else {}
        if project_id:
            issues = [issue for issue in issues if issue["number"] in project_items]
    except Exception as exc:
        raise HTTPException(502, f"GitHub poll failed: {type(exc).__name__}") from exc
    created = 0
    replanned = 0
    visible = set()
    for issue in issues:
        number = issue["number"]
        visible.add(number)
        ticket = db.scalar(select(Ticket).where(Ticket.repository_id == repo.id, Ticket.number == number))
        labels = {x["name"].lower() for x in issue.get("labels", []) if isinstance(x, dict) and "name" in x}
        priority = 3 if "priority:critical" in labels else 2 if "priority:high" in labels else 1 if "priority:medium" in labels else 0
        provider_labels = {x.split(":", 1)[1] for x in labels if x.startswith("provider:")}
        if len(provider_labels) > 1:
            raise HTTPException(409, f"Issue #{number} has conflicting provider labels")
        override = next(iter(provider_labels), None)
        if override and override not in repo.policy.get("routing", {}).get("allowed_providers", ["codex"]):
            raise HTTPException(409, f"Issue #{number} requests an unapproved provider")
        new_body = issue.get("body") or ""
        new_dependencies = dependencies(new_body)
        if ticket:
            changed = (ticket.title, ticket.body, ticket.dependencies, ticket.priority, ticket.provider_override) != (issue["title"], new_body, new_dependencies, priority, override)
            if changed and ticket.state != "MERGED":
                active_jobs = db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING"])).with_for_update(of=Job)).all()
                ticket.title, ticket.body, ticket.dependencies, ticket.priority, ticket.provider_override = issue["title"], new_body, new_dependencies, priority, override
                for job in active_jobs:
                    job.state = "CANCELLED"
                ticket.state = "NEEDS_REPLAN"
                ticket.security_approved_revision = None
                ticket.verification_passed = False
                ticket.threat_revision = None
                ticket.findings = []
                ticket.artifacts = {"project_item_id": project_items[number]} if project_id else {}
                enqueue(db, ticket, "product_owner")
                db.add(AuditEvent(ticket_id=ticket.id, action="issue_replanned", detail={"number": number}))
                replanned += 1
            continue
        ticket = Ticket(repository_id=repo.id, number=number, title=issue["title"], body=new_body, dependencies=new_dependencies, priority=priority, provider_override=override, artifacts={"project_item_id": project_items[number]} if project_id else {})
        db.add(ticket)
        db.flush()
        enqueue(db, ticket, "product_owner")
        created += 1
    tickets = db.scalars(select(Ticket).where(Ticket.repository_id == repo.id)).all()
    for ticket in tickets:
        if ticket.number not in visible and ticket.state not in {"MERGED", "OUT_OF_SCOPE"}:
            for job in db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING"])).with_for_update(of=Job)):
                job.state = "CANCELLED"
            ticket.state = "OUT_OF_SCOPE"
            db.add(AuditEvent(ticket_id=ticket.id, action="issue_out_of_scope", detail={"number": ticket.number}))
    try:
        order({t.number: t.dependencies for t in tickets}, {t.number: t.priority for t in tickets})
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return {"discovered": len(issues), "created": created, "replanned": replanned}


@app.post("/reconcile-projects", dependencies=[Depends(authorized)])
async def reconcile_projects(db: Session = Depends(db_session)):
    results = {}
    for repo in db.scalars(select(Repository).where(Repository.enabled == True, Repository.paused == False)):
        project_id = repo.policy.get("project_id")
        field_id = repo.policy.get("project_status_field_id")
        options = repo.policy.get("project_status_options", {})
        if not project_id or not field_id:
            continue
        try:
            items = await GitHubProjectsClient().issue_items(project_id, repo.full_name)
            for ticket in db.scalars(select(Ticket).where(Ticket.repository_id == repo.id)):
                option = options.get(ticket.state)
                item_id = items.get(ticket.number)
                if not option or not item_id:
                    continue
                marker = f"{ticket.state}:{option}:{item_id}"
                if ticket.artifacts.get("project_status_marker") == marker:
                    continue
                await GitHubProjectsClient().set_status(project_id, item_id, field_id, option)
                ticket.artifacts = {**ticket.artifacts, "project_item_id": item_id, "project_status_marker": marker}
                db.add(AuditEvent(ticket_id=ticket.id, action="project_status_synced", detail={"state": ticket.state}))
                results[ticket.id] = ticket.state
            db.commit()
        except Exception as exc:
            db.rollback()
            results[repo.id] = {"error": type(exc).__name__}
    return results


@app.get("/tickets", dependencies=[Depends(authorized)])
def list_tickets(db: Session = Depends(db_session)):
    return [{"id": t.id, "repository": t.repository.full_name, "number": t.number, "state": t.state, "dependencies": t.dependencies, "provider_override": t.provider_override, "pr_number": t.pr_number} for t in db.scalars(select(Ticket).order_by(Ticket.number))]


@app.get("/tickets/{ticket_id}", dependencies=[Depends(authorized)])
def ticket_detail(ticket_id: str, db: Session = Depends(db_session)):
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    jobs = db.scalars(select(Job).where(Job.ticket_id == ticket_id).order_by(Job.created_at, Job.id)).all()
    return {
        "id": ticket.id, "repository": ticket.repository.full_name, "number": ticket.number,
        "title": ticket.title, "body": ticket.body, "state": ticket.state,
        "provider_override": ticket.provider_override,
        "spec_revision": ticket.spec_revision, "design_revision": ticket.design_revision,
        "threat_revision": ticket.threat_revision, "verification_passed": ticket.verification_passed,
        "security_approved_revision": ticket.security_approved_revision,
        "findings": ticket.findings, "artifacts": ticket.artifacts,
        "jobs": [{"id": j.id, "stage": j.stage, "revision": j.revision, "state": j.state, "claimed_by": j.claimed_by, "provider": j.provider, "result": j.result} for j in jobs],
        "risk_acceptances": [
            {"threat_id": x.threat_id, "design_revision": x.design_revision, "threat_revision": x.threat_revision, "actor": x.actor, "justification": x.justification, "residual_risk": x.residual_risk, "scope": x.scope, "expires_at": x.expires_at}
            for x in db.scalars(select(RiskAcceptance).where(RiskAcceptance.ticket_id == ticket.id))
        ],
    }


@app.post("/jobs/claim")
def claim(data: ClaimIn, credential: WorkerCredential | None = Depends(worker_authorized), db: Session = Depends(db_session)):
    if credential and data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    allowed_repositories = set(credential.repositories) if credential else None
    trusted_capabilities = set(credential.capabilities) if credential else set(data.capabilities)
    db.commit()
    with db.begin():
        global_state = db.get(ControlState, 1)
        if global_state and global_state.paused:
            return None
        candidates = db.scalars(
            select(Job).join(Ticket, Ticket.id == Job.ticket_id).where(or_(
                (Job.state == "QUEUED") & (or_(Job.claimed_by.is_(None), Job.claimed_by == data.worker_id)),
                (Job.state == "RUNNING") & (Job.lease_expires_at < now()),
            ))
            .order_by(Ticket.priority.desc(), Job.created_at, Job.id).with_for_update(of=Job, skip_locked=True).limit(100)
        ).all()
        for job in candidates:
            ticket = db.get(Ticket, job.ticket_id)
            repo = ticket.repository
            if allowed_repositories is not None and repo.full_name not in allowed_repositories:
                continue
            if repo.paused or not repo.enabled or not dependencies_ready(db, ticket):
                continue
            if job.stage == "engineer" and not security_gate(db, ticket):
                continue
            required = set(repo.policy.get("required_worker_capabilities", []))
            if not required.issubset(trusted_capabilities):
                continue
            job.state = "RUNNING"
            job.claimed_by = data.worker_id
            job.fencing_token += 1
            job.lease_expires_at = now() + timedelta(minutes=20)
            job.started_at = now()
            db.add(AuditEvent(ticket_id=ticket.id, action="job_claimed", detail={"job": job.id, "worker": data.worker_id, "fence": job.fencing_token}))
            return {"id": job.id, "stage": job.stage, "revision": job.revision, "fencing_token": job.fencing_token, "ticket": {"id": ticket.id, "number": ticket.number, "title": ticket.title, "body": ticket.body, "state": ticket.state, "provider_override": ticket.provider_override, "artifacts": ticket.artifacts, "findings": ticket.findings, "design_revision": ticket.design_revision, "threat_revision": ticket.threat_revision}, "repository": {"full_name": repo.full_name, "policy": repo.policy}}
    return None


def _locked_claim(db: Session, job_id: str, worker_id: str, fencing_token: int) -> Job:
    """Serialize claim mutations with reclaim and reject an expired lease."""
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True))
    expiry = job.lease_expires_at if job else None
    if (not job or job.state != "RUNNING" or job.claimed_by != worker_id
            or job.fencing_token != fencing_token or not expiry
            or expiry.replace(tzinfo=expiry.tzinfo or timezone.utc) <= now()):
        raise HTTPException(409, "Stale job claim")
    return job


@app.post("/jobs/{job_id}/heartbeat")
def heartbeat(job_id: str, data: ClaimIn, fencing_token: int, credential: WorkerCredential | None = Depends(worker_authorized), db: Session = Depends(db_session)):
    if credential and data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    job = _locked_claim(db, job_id, data.worker_id, fencing_token)
    job.lease_expires_at = now() + timedelta(minutes=20)
    ticket = db.get(Ticket, job.ticket_id)
    global_state = db.get(ControlState, 1)
    pause_requested = bool((global_state and global_state.paused) or ticket.repository.paused)
    db.commit()
    return {"ok": True, "pause_requested": pause_requested}


@app.post("/jobs/{job_id}/yield")
def yield_job(job_id: str, data: YieldIn, credential: WorkerCredential | None = Depends(worker_authorized), db: Session = Depends(db_session)):
    if credential and data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    job = _locked_claim(db, job_id, data.worker_id, data.fencing_token)
    job.state = "QUEUED"
    # Keep claimed_by as worker affinity so a different host cannot discard partial files.
    job.lease_expires_at = None
    job.started_at = None
    db.add(AuditEvent(ticket_id=job.ticket_id, action="job_yielded", detail={"job": job.id, "worker": data.worker_id, "revision": job.revision}))
    db.commit()
    return {"queued": True, "job_id": job.id}


@app.post("/jobs/{job_id}/release-affinity", dependencies=[Depends(authorized)])
def release_job_affinity(job_id: str, db: Session = Depends(db_session)):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True))
    if not job or job.state != "QUEUED" or not job.claimed_by:
        raise HTTPException(409, "Job is not a yielded claim")
    previous_worker = job.claimed_by
    job.claimed_by = None
    job.fencing_token += 1
    db.add(AuditEvent(ticket_id=job.ticket_id, action="job_affinity_released", detail={"job": job.id, "previous_worker": previous_worker}))
    db.commit()
    return {"queued": True, "job_id": job.id, "previous_worker": previous_worker}


@app.post("/jobs/{job_id}/complete")
def complete(job_id: str, data: CompleteIn, credential: WorkerCredential | None = Depends(worker_authorized), db: Session = Depends(db_session)):
    if credential and data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    job = _locked_claim(db, job_id, data.worker_id, data.fencing_token)
    ticket = db.get(Ticket, job.ticket_id)
    if data.succeeded:
        try:
            complete_stage(db, ticket, job.stage, data.result)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    else:
        ticket.state = "JOB_FAILED"
    job.state = "SUCCEEDED" if data.succeeded else "FAILED"
    job.result = data.result
    job.provider = data.result.get("provider")
    job.finished_at = now()
    job.lease_expires_at = None
    db.add(AuditEvent(ticket_id=ticket.id, action="job_completed", detail={"job": job.id, "state": job.state}))
    db.commit()
    return {"ticket_state": ticket.state}


@app.post("/jobs/{job_id}/retry", dependencies=[Depends(authorized)])
def retry_failed_job(job_id: str, db: Session = Depends(db_session)):
    job = db.get(Job, job_id)
    if not job or job.state != "FAILED":
        raise HTTPException(409, "Job is not failed")
    ticket = db.get(Ticket, job.ticket_id)
    if ticket.state != "JOB_FAILED":
        raise HTTPException(409, "Ticket has moved on")
    attempts = db.scalar(select(Job.revision).where(Job.ticket_id == ticket.id, Job.stage == job.stage).order_by(Job.revision.desc()).limit(1)) or 0
    if attempts >= int(ticket.repository.policy.get("max_job_attempts", 3)):
        raise HTTPException(409, "Job retry limit reached")
    try:
        queued = enqueue(db, ticket, job.stage)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    ticket.state = "RETRY_QUEUED"
    db.commit()
    return {"job_id": queued.id, "revision": queued.revision}


@app.post("/tickets/{ticket_id}/approve-security", dependencies=[Depends(authorized)])
def approve(ticket_id: str, data: ApprovalIn, db: Session = Depends(db_session)):
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    try:
        approve_security(db, ticket, data.actor, data.justification)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return {"state": ticket.state, "design_revision": ticket.design_revision}


@app.post("/tickets/{ticket_id}/accept-risk", dependencies=[Depends(authorized)])
def accept_risk(ticket_id: str, data: RiskAcceptanceIn, db: Session = Depends(db_session)):
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if not ticket.repository.policy.get("allow_risk_acceptance", False) or ticket.state != "ESCALATED_SECURITY":
        raise HTTPException(409, "Risk acceptance is not allowed at this stage")
    expiry = data.expires_at if data.expires_at.tzinfo else data.expires_at.replace(tzinfo=timezone.utc)
    if expiry <= now():
        raise HTTPException(422, "Expiry must be in the future")
    if data.threat_id not in {f.get("threat_id") for f in ticket.findings if f.get("status") == "open"}:
        raise HTTPException(404, "Open threat finding not found")
    db.add(RiskAcceptance(
        ticket_id=ticket.id, threat_id=data.threat_id, design_revision=ticket.design_revision,
        threat_revision=ticket.threat_revision, actor=data.actor, justification=data.justification,
        residual_risk=data.residual_risk, scope=data.scope, expires_at=expiry,
    ))
    db.flush()
    if not unresolved_blockers(ticket, db):
        ticket.state = "WAITING_THREAT_PR" if ticket.repository.policy.get("threat_model_pr_required") and not ticket.artifacts.get("threat_model_pr_approved") else "WAITING_SECURITY_APPROVAL"
    db.add(AuditEvent(ticket_id=ticket.id, action="risk_accepted", detail={"threat_id": data.threat_id, "actor": data.actor, "expiry": expiry.isoformat()}))
    db.commit()
    return {"state": ticket.state, "threat_id": data.threat_id, "expires_at": expiry}


@app.post("/tickets/{ticket_id}/approve-high-risk-merge", dependencies=[Depends(authorized)])
def approve_high_risk(ticket_id: str, data: ApprovalIn, db: Session = Depends(db_session)):
    from adp.db import Approval
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.state != "READY_TO_MERGE" or not ticket.artifacts.get("commit_sha") or not ticket.pr_number:
        raise HTTPException(409, "PR and independent reviews must be complete before approval")
    db.add(Approval(ticket_id=ticket.id, kind="high_risk_merge", revision=ticket.design_revision, ref=ticket.artifacts["commit_sha"], actor=data.actor, justification=data.justification))
    db.commit()
    return {"approved": True}


@app.post("/reconcile-threat-reviews", dependencies=[Depends(authorized)])
async def reconcile_threat_reviews(db: Session = Depends(db_session)):
    results = {}
    for ticket in db.scalars(select(Ticket).where(Ticket.state.notin_(["MERGED", "OUT_OF_SCOPE", "MERGE_SUBMITTED"]))):
        if not ticket.repository.policy.get("threat_model_pr_required"):
            continue
        artifact = ticket.artifacts.get("threat_model_pr")
        if not artifact:
            continue
        try:
            review = await ThreatReviewClient().review_state(artifact)
            timing = ticket.repository.policy.get("threat_model_merge_timing", "before_engineering")
            ready = review["approved"] and (review["merged"] or timing == "before_final_merge")
            if not review["approved"] and ticket.artifacts.get("threat_model_pr_approved"):
                ticket.security_approved_revision = None
                ticket.state = "WAITING_THREAT_PR"
            ticket.artifacts = {**ticket.artifacts, "threat_model_pr_approved": review["approved"], "threat_model_pr_merged": review["merged"]}
            if ticket.state == "WAITING_THREAT_PR" and ready and not unresolved_blockers(ticket, db):
                ticket.state = "WAITING_SECURITY_APPROVAL"
                db.add(AuditEvent(ticket_id=ticket.id, action="threat_model_pr_reviewed", detail={**artifact, **review}))
            db.commit()
            results[ticket.id] = review
        except Exception as exc:
            results[ticket.id] = {"error": type(exc).__name__}
    return results


@app.post("/reconcile-merges", dependencies=[Depends(authorized)])
async def reconcile_merges(db: Session = Depends(db_session)):
    global_state = db.get(ControlState, 1)
    results = {}
    for ticket in db.scalars(select(Ticket).where(Ticket.state.in_(["READY_TO_MERGE", "MERGE_SUBMITTED"]))):
        submitted = ticket.state == "MERGE_SUBMITTED"
        if submitted or (ticket.repository.auto_merge and not ticket.repository.paused and not (global_state and global_state.paused)):
            try:
                results[ticket.id] = await GitHubMergeClient().reconcile(db, ticket)
            except httpx.HTTPError as exc:
                results[ticket.id] = {"merged": False, "reasons": [f"GitHub error: {type(exc).__name__}"]}
    return results


@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(db_session)):
    if not settings.github_webhook_secret:
        raise HTTPException(404, "GitHub webhooks are disabled")
    raw = await request.body()
    if len(raw) > 1024 * 1024:
        raise HTTPException(413, "Webhook payload too large")
    expected = "sha256=" + hmac.new(settings.github_webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(request.headers.get("x-hub-signature-256", ""), expected):
        raise HTTPException(401, "Invalid webhook signature")
    delivery = request.headers.get("x-github-delivery", "")
    event = request.headers.get("x-github-event", "")
    if not delivery or len(delivery) > 100 or not event:
        raise HTTPException(422, "Missing webhook headers")
    if db.get(WebhookDelivery, delivery):
        return {"duplicate": True}
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(422, "Invalid JSON payload") from exc
    if event == "issues":
        repo_name = (payload.get("repository") or {}).get("full_name")
        repo = db.scalar(select(Repository).where(Repository.full_name == repo_name)) if repo_name else None
        if repo:
            await poll(repo.id, db)
    elif event == "pull_request":
        await reconcile_threat_reviews(db)
        await reconcile_merges(db)
    elif event == "projects_v2_item":
        await reconcile_projects(db)
    db.add(WebhookDelivery(id=delivery, event=event))
    db.commit()
    return {"accepted": True}
