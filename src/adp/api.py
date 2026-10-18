"""Authenticated control plane API. Workers never receive provider or GitHub secrets."""
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import hmac
import hashlib
import json
import secrets
import httpx
from urllib.parse import urlsplit
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from adp.db import AuditEvent, ControlState, Job, PublicationAttempt, Repository, RiskAcceptance, SessionLocal, Ticket, WebhookDelivery, WorkerCredential, now
from adp.github import GitHubClient, dependencies
from adp.merge import GitHubMergeClient
from adp.projects import GitHubProjectsClient
from adp.publication import attempt_branch
from adp.threat_review import ThreatReviewClient
from adp.scheduler import order
from adp.settings import settings
from adp.workflow import approve_security, complete_stage, dependencies_ready, enqueue, security_gate, unresolved_blockers

app = FastAPI(title="Autonomous Development Platform", version="0.1.0")


@dataclass(frozen=True)
class WorkerPrincipal:
    id: str
    worker_id: str
    token_hash: str
    repositories: tuple[str, ...]
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class HumanPrincipal:
    github_id: int
    login: str

    @property
    def actor(self) -> str:
        return f"github:{self.github_id}:{self.login}"


def db_session():
    with SessionLocal() as db:
        yield db


def _unsettled_publication_jobs(db: Session, ticket: Ticket) -> list[Job]:
    jobs = db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.stage.in_(["engineer", "threat_modeler"]), Job.state.in_(["FAILED", "PUBLICATION_REVIEW", "SUCCEEDED"])).with_for_update(of=Job)).all()
    unsettled = []
    for job in jobs:
        intent = (job.result or {}).get("_publication_intent")
        if job.state == "PUBLICATION_REVIEW" or (job.state == "FAILED" and intent):
            unsettled.append(job)
        elif job.state == "SUCCEEDED" and intent:
            if job.stage == "engineer" and ticket.artifacts.get("commit_sha") == intent["sha"] and ticket.state != "MERGED":
                unsettled.append(job)
            elif job.stage == "threat_modeler" and not ticket.artifacts.get("threat_model_pr_merged") and ticket.threat_revision == (job.result or {}).get("threat_revision"):
                unsettled.append(job)
    return unsettled


async def _recognize_external_merge(db: Session, ticket: Ticket) -> bool:
    if ticket.state == "PUBLICATION_REVIEW" or db.scalar(select(PublicationAttempt.id).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.state == "LATE_EFFECT").limit(1)):
        return False
    sha = ticket.artifacts.get("commit_sha")
    if not ticket.pr_number or not sha:
        return False
    attempt = db.scalar(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.repository == ticket.repository.full_name, PublicationAttempt.sha == sha, PublicationAttempt.state == "PUBLISHED").order_by(PublicationAttempt.created_at.desc()).limit(1))
    if not attempt or not await GitHubClient().merged_exact(ticket.repository.full_name, ticket.pr_number, sha, attempt.branch):
        return False
    ticket.state = "MERGED"
    db.add(AuditEvent(ticket_id=ticket.id, action="external_merge_recognized", detail={"pr": ticket.pr_number, "sha": sha}))
    return True


def _require_distinct_service_tokens():
    if settings.control_token and settings.worker_token and hmac.compare_digest(settings.control_token, settings.worker_token):
        raise HTTPException(503, "Administrator and worker credentials must be different")


def authorized(authorization: Annotated[str | None, Header()] = None):
    _require_distinct_service_tokens()
    if not settings.control_token or not hmac.compare_digest(authorization or "", f"Bearer {settings.control_token}"):
        raise HTTPException(401, "Invalid control token")


def human_authenticated(
    human_authorization: Annotated[str | None, Header(alias="X-Human-Authorization")] = None,
    _control: None = Depends(authorized),
) -> HumanPrincipal | None:
    if not settings.human_identity_required:
        return None
    if not settings.human_reviewer_ids.strip() or not settings.human_operator_ids.strip():
        raise HTTPException(503, "Human role IDs are not configured")
    prefix = "Bearer "
    if not human_authorization or not human_authorization.startswith(prefix):
        raise HTTPException(401, "Authenticated human token required")
    token = human_authorization[len(prefix):]
    if not token or hmac.compare_digest(token, settings.control_token):
        raise HTTPException(401, "Invalid human token")
    base = settings.github_api_url.rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(503, "GitHub identity API must use HTTPS")
    try:
        response = httpx.get(f"{base}/user", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}, timeout=5, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise HTTPException(503, "GitHub identity check unavailable") from exc
    if response.status_code in {401, 403}:
        raise HTTPException(401, "Invalid human token")
    if response.status_code != 200:
        raise HTTPException(503, "GitHub identity check unavailable")
    try:
        user = response.json()
        github_id = int(user["id"])
        login = user["login"]
        if github_id <= 0 or not isinstance(login, str) or not login:
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(503, "Invalid GitHub identity response") from exc
    return HumanPrincipal(github_id, login)


def _human_role(principal: HumanPrincipal | None, allowed: str) -> HumanPrincipal | None:
    if principal is not None and str(principal.github_id) not in {item.strip() for item in allowed.split(",") if item.strip()}:
        raise HTTPException(403, "Human role not permitted")
    return principal


def human_reviewer(principal: HumanPrincipal | None = Depends(human_authenticated)) -> HumanPrincipal | None:
    return _human_role(principal, settings.human_reviewer_ids)


def human_operator(principal: HumanPrincipal | None = Depends(human_authenticated)) -> HumanPrincipal | None:
    return _human_role(principal, settings.human_operator_ids)


def _decision_actor(principal: HumanPrincipal | None, claimed: str | None) -> str:
    if principal is None:
        if not claimed or len(claimed) < 2:
            raise HTTPException(422, "Actor is required")
        return claimed
    if claimed and claimed not in {principal.login, principal.actor}:
        raise HTTPException(403, "Actor does not match authenticated human")
    return principal.actor


def worker_authorized(authorization: Annotated[str | None, Header()] = None, db: Session = Depends(db_session)):
    _require_distinct_service_tokens()
    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(401, "Invalid worker token")
    raw = authorization[len(prefix):]
    digest = hashlib.sha256(raw.encode()).hexdigest()
    credential = db.scalar(select(WorkerCredential).where(WorkerCredential.token_hash == digest))
    if credential:
        expiry = credential.expires_at
        if credential.disabled or not expiry or expiry.replace(tzinfo=expiry.tzinfo or timezone.utc) <= now():
            raise HTTPException(401, "Worker credential disabled or expired")
        return WorkerPrincipal(credential.id, credential.worker_id, digest, tuple(credential.repositories), tuple(credential.capabilities))
    raise HTTPException(401, "Invalid worker token")


def _lock_worker_credential(db: Session, principal: WorkerPrincipal) -> None:
    credential = db.scalar(select(WorkerCredential).where(WorkerCredential.id == principal.id).with_for_update().execution_options(populate_existing=True))
    expiry = credential.expires_at if credential else None
    if not credential or credential.token_hash != principal.token_hash or credential.disabled or not expiry or expiry.replace(tzinfo=expiry.tzinfo or timezone.utc) <= now():
        raise HTTPException(401, "Worker credential disabled, expired, or rotated")
    credential.last_seen_at = now()


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


class PublicationIntentIn(BaseModel):
    worker_id: str
    fencing_token: int
    kind: str
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    branch: str
    sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")


class PublicationReconcileIn(BaseModel):
    worker_isolation_reset: bool
    explanation: str = Field(min_length=10)


class ApprovalIn(BaseModel):
    actor: str | None = Field(default=None, min_length=2)
    justification: str = Field(min_length=10)


class RiskAcceptanceIn(BaseModel):
    threat_id: str = Field(min_length=1)
    actor: str | None = Field(default=None, min_length=2)
    justification: str = Field(min_length=10)
    residual_risk: str = Field(min_length=10)
    scope: str = Field(min_length=3)
    expires_at: datetime


class WorkerCredentialIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=100)
    repositories: list[str] = Field(min_length=1)
    capabilities: list[str] = Field(min_length=1)
    expires_at: datetime


class WorkerCredentialRotateIn(BaseModel):
    expires_at: datetime


def _worker_expiry(expiry: datetime) -> datetime:
    expiry = expiry.replace(tzinfo=timezone.utc) if not expiry.tzinfo else expiry
    current = now()
    if expiry <= current or expiry > current + timedelta(days=30):
        raise HTTPException(422, "Worker credential expiry must be within 30 days")
    return expiry


@app.post("/workers/credentials")
def issue_worker_credential(data: WorkerCredentialIn, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    if db.scalar(select(WorkerCredential).where(WorkerCredential.worker_id == data.worker_id)):
        raise HTTPException(409, "Worker ID already exists")
    known = {x.full_name for x in db.scalars(select(Repository))}
    if not set(data.repositories).issubset(known):
        raise HTTPException(422, "Worker repository is not registered")
    raw = secrets.token_urlsafe(48)
    expiry = _worker_expiry(data.expires_at)
    credential = WorkerCredential(worker_id=data.worker_id, token_hash=hashlib.sha256(raw.encode()).hexdigest(), repositories=sorted(set(data.repositories)), capabilities=sorted(set(data.capabilities)), expires_at=expiry)
    db.add(credential)
    db.add(AuditEvent(action="worker_credential_issued", detail={"worker_id": data.worker_id, "repositories": credential.repositories, "actor": principal.actor if principal else None}))
    db.commit()
    return {"id": credential.id, "worker_id": credential.worker_id, "token": raw, "expires_at": expiry}


@app.post("/workers/credentials/{credential_id}/rotate")
def rotate_worker_credential(credential_id: str, data: WorkerCredentialRotateIn, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    credential = db.scalar(select(WorkerCredential).where(WorkerCredential.id == credential_id).with_for_update())
    if not credential:
        raise HTTPException(404, "Worker credential not found")
    state = db.scalar(select(ControlState).where(ControlState.id == 1).with_for_update())
    if not state or not state.paused:
        raise HTTPException(409, "Pause all workers before rotating a credential")
    running = db.scalar(select(func.count()).select_from(Job).where(Job.state == "RUNNING", Job.claimed_by == credential.worker_id)) or 0
    if running:
        raise HTTPException(409, "Worker has an active job; wait for it to yield")
    expiry = _worker_expiry(data.expires_at)
    raw = secrets.token_urlsafe(48)
    credential.token_hash = hashlib.sha256(raw.encode()).hexdigest()
    credential.expires_at = expiry
    credential.disabled = False
    db.add(AuditEvent(action="worker_credential_rotated", detail={"worker_id": credential.worker_id, "credential_id": credential.id, "expires_at": expiry.isoformat(), "actor": principal.actor if principal else None}))
    db.commit()
    return {"id": credential.id, "worker_id": credential.worker_id, "token": raw, "expires_at": expiry}


@app.post("/workers/credentials/{credential_id}/revoke")
def revoke_worker_credential(credential_id: str, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    credential = db.scalar(select(WorkerCredential).where(WorkerCredential.id == credential_id).with_for_update())
    if not credential:
        raise HTTPException(404, "Worker credential not found")
    credential.disabled = True
    db.add(AuditEvent(action="worker_credential_revoked", detail={"worker_id": credential.worker_id, "actor": principal.actor if principal else None}))
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


@app.post("/control/{action}")
def set_control_state(action: str, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    if action not in {"pause", "resume"}:
        raise HTTPException(404, "Unknown action")
    state = db.scalar(select(ControlState).where(ControlState.id == 1).with_for_update())
    if state is None:
        state = ControlState(id=1, paused=False)
        db.add(state)
    state.paused = action == "pause"
    db.add(AuditEvent(action="global_pause_changed", detail={"paused": state.paused, "actor": principal.actor if principal else None}))
    db.commit()
    running = db.scalar(select(func.count()).select_from(Job).where(Job.state == "RUNNING")) or 0
    return {"paused": state.paused, "running_jobs": running}


@app.post("/repositories")
def add_repository(data: RepositoryIn, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    existing = db.scalar(select(Repository).where(Repository.full_name == data.full_name))
    if existing:
        raise HTTPException(409, "Repository already exists")
    repo = Repository(full_name=data.full_name, policy=data.policy, auto_merge=data.auto_merge)
    db.add(repo)
    policy_hash = hashlib.sha256(json.dumps(repo.policy, sort_keys=True).encode()).hexdigest()
    db.add(AuditEvent(action="repository_registered", detail={"repository": repo.full_name, "policy_sha256": policy_hash, "auto_merge": repo.auto_merge, "actor": principal.actor if principal else None}))
    db.commit()
    return {"id": repo.id, "full_name": repo.full_name}


@app.get("/repositories", dependencies=[Depends(authorized)])
def list_repositories(db: Session = Depends(db_session)):
    return [{"id": r.id, "full_name": r.full_name, "paused": r.paused, "auto_merge": r.auto_merge, "policy": r.policy} for r in db.scalars(select(Repository))]


@app.post("/repositories/{repo_id}/control/{action}")
def set_repository_state(repo_id: str, action: str, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    if action not in {"pause", "resume"}:
        raise HTTPException(404, "Unknown action")
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    repo.paused = action == "pause"
    db.add(AuditEvent(action="repository_pause_changed", detail={"repository": repo.full_name, "paused": repo.paused, "actor": principal.actor if principal else None}))
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
                try:
                    if await _recognize_external_merge(db, ticket):
                        continue
                except Exception as exc:
                    raise HTTPException(502, f"PR merge verification failed: {type(exc).__name__}") from exc
                active_jobs = db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING"])).with_for_update(of=Job)).all()
                pending_publications = _unsettled_publication_jobs(db, ticket)
                ticket.title, ticket.body, ticket.dependencies, ticket.priority, ticket.provider_override = issue["title"], new_body, new_dependencies, priority, override
                publication_jobs = [job for job in active_jobs if job.stage in {"engineer", "threat_modeler"} and job.state == "RUNNING"]
                if publication_jobs or pending_publications or ticket.state == "PUBLICATION_REVIEW":
                    for job in publication_jobs + pending_publications:
                        _quarantine_publication(db, job, ticket, "issue changed during remote-capable job")
                        job.result = {**(job.result or {}), "_publication_replan": True}
                    for job in active_jobs:
                        if job not in publication_jobs:
                            job.state = "CANCELLED"
                    ticket.state = "PUBLICATION_REVIEW"
                    db.add(AuditEvent(ticket_id=ticket.id, action="publication_review_required", detail={"reason": "issue edited during publication"}))
                    continue
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
            try:
                if await _recognize_external_merge(db, ticket):
                    continue
            except Exception as exc:
                raise HTTPException(502, f"PR merge verification failed: {type(exc).__name__}") from exc
            active_jobs = db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING"])).with_for_update(of=Job)).all()
            pending_publications = _unsettled_publication_jobs(db, ticket)
            publication_jobs = [job for job in active_jobs if job.stage in {"engineer", "threat_modeler"} and job.state == "RUNNING"]
            if publication_jobs or pending_publications or ticket.state == "PUBLICATION_REVIEW":
                for job in publication_jobs + pending_publications:
                    _quarantine_publication(db, job, ticket, "issue disappeared during remote-capable job")
                    job.result = {**(job.result or {}), "_publication_out_of_scope": True}
                for job in active_jobs:
                    if job not in publication_jobs:
                        job.state = "CANCELLED"
                ticket.state = "PUBLICATION_REVIEW"
                continue
            for job in active_jobs:
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
        "publication_attempts": [
            {"id": attempt.id, "job_id": attempt.job_id, "repository": attempt.repository, "branch": attempt.branch, "sha": attempt.sha, "state": attempt.state, "last_checked_at": attempt.last_checked_at}
            for attempt in db.scalars(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id).order_by(PublicationAttempt.created_at))
        ],
        "risk_acceptances": [
            {"threat_id": x.threat_id, "design_revision": x.design_revision, "threat_revision": x.threat_revision, "actor": x.actor, "justification": x.justification, "residual_risk": x.residual_risk, "scope": x.scope, "expires_at": x.expires_at}
            for x in db.scalars(select(RiskAcceptance).where(RiskAcceptance.ticket_id == ticket.id))
        ],
    }


@app.post("/jobs/claim")
def claim(data: ClaimIn, credential: WorkerPrincipal = Depends(worker_authorized), db: Session = Depends(db_session)):
    if data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    allowed_repositories = set(credential.repositories)
    trusted_capabilities = set(credential.capabilities)
    db.commit()
    with db.begin():
        _lock_worker_credential(db, credential)
        global_state = db.scalar(select(ControlState).where(ControlState.id == 1).with_for_update())
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
            if repo.full_name not in allowed_repositories:
                continue
            if job.state == "RUNNING" and job.stage in {"engineer", "threat_modeler"}:
                _quarantine_publication(db, job, ticket, "claim expired before remote effects were reconciled")
                continue
            if repo.paused or not repo.enabled or not dependencies_ready(db, ticket):
                continue
            if ticket.state == "PUBLICATION_REVIEW":
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
            job.result = {**(job.result or {}), "_claim_ticket_state": ticket.state}
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


def _quarantine_publication(db: Session, job: Job, ticket: Ticket, reason: str) -> None:
    job.state = "PUBLICATION_REVIEW"
    job.lease_expires_at = None
    ticket.state = "PUBLICATION_REVIEW"
    db.add(AuditEvent(ticket_id=ticket.id, action="publication_review_required", detail={"job": job.id, "reason": reason, "intent": (job.result or {}).get("_publication_intent")}))


@app.post("/reconcile-publications", dependencies=[Depends(authorized)])
async def inspect_reconciled_publications(db: Session = Depends(db_session)):
    """Keep retired attempt refs under observation for delayed GitHub effects."""
    attempts = db.scalars(select(PublicationAttempt).where(PublicationAttempt.state == "RECONCILED").order_by(PublicationAttempt.created_at)).all()
    results = {}
    for attempt in attempts:
        try:
            await GitHubClient().publication_clear(attempt.repository, attempt.branch)
        except RuntimeError as exc:
            ticket = db.scalar(select(Ticket).where(Ticket.id == attempt.ticket_id).with_for_update())
            attempt.review_context = {"ticket_state": ticket.state}
            active_jobs = db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING"])).with_for_update(of=Job)).all()
            for job in active_jobs:
                job.state = "PUBLICATION_REVIEW" if job.state == "RUNNING" and job.stage in {"engineer", "threat_modeler"} and (job.result or {}).get("_publication_intent") else "CANCELLED"
                job.lease_expires_at = None
            ticket.state = "PUBLICATION_REVIEW"
            ticket.repository.paused = True
            attempt.state = "LATE_EFFECT"
            attempt.last_checked_at = now()
            db.add(AuditEvent(ticket_id=ticket.id, action="late_publication_detected", detail={"branch": attempt.branch, "repository": attempt.repository, "reason": str(exc)}))
            results[attempt.branch] = "LATE_EFFECT"
            db.commit()
        except Exception as exc:
            db.rollback()
            raise HTTPException(502, f"Publication observation failed: {type(exc).__name__}") from exc
        else:
            attempt.last_checked_at = now()
            results[attempt.branch] = "CLEAR"
            db.commit()
    return results


@app.post("/publication-attempts/{attempt_id}/resolve-late")
async def resolve_late_publication(attempt_id: str, data: PublicationReconcileIn, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    if not data.worker_isolation_reset:
        raise HTTPException(422, "Confirm the old worker isolation environment was reset")
    global_state = db.get(ControlState, 1)
    if not global_state or not global_state.paused:
        raise HTTPException(409, "Pause all workers before resolving a late effect")
    attempt = db.scalar(select(PublicationAttempt).where(PublicationAttempt.id == attempt_id).with_for_update())
    if not attempt or attempt.state != "LATE_EFFECT":
        raise HTTPException(409, "Attempt is not awaiting late-effect review")
    ticket = db.scalar(select(Ticket).where(Ticket.id == attempt.ticket_id).with_for_update())
    if ticket.state != "PUBLICATION_REVIEW" or not ticket.repository.paused:
        raise HTTPException(409, "Ticket and repository must remain in publication review")
    affected = db.scalars(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.state.in_(["LATE_EFFECT", "ACTIVE", "PUBLISHED"])).with_for_update()).all()
    previously_merged = any((item.review_context or {}).get("ticket_state") == "MERGED" for item in affected)
    current_merged = None
    if ticket.pr_number and ticket.artifacts.get("commit_sha"):
        current = next((item for item in affected if item.state == "PUBLISHED" and item.repository == ticket.repository.full_name and item.sha == ticket.artifacts["commit_sha"]), None)
        if current:
            try:
                if await GitHubClient().merged_exact(current.repository, ticket.pr_number, current.sha, current.branch):
                    current_merged = current
                    previously_merged = True
            except Exception as exc:
                raise HTTPException(409, f"Current merge cannot be verified: {type(exc).__name__}") from exc
    evidence = {}
    for item in affected:
        if item is current_merged:
            item.state = "MERGED"
            continue
        try:
            evidence[item.branch] = await GitHubClient().publication_clear(item.repository, item.branch)
        except Exception as exc:
            raise HTTPException(409, f"Publication is not clear: {type(exc).__name__}: {exc}") from exc
        item.state = "RECONCILED"
        item.reconciled_at = now()
        item.last_checked_at = now()
    for job in db.scalars(select(Job).where(Job.ticket_id == ticket.id, Job.state.in_(["QUEUED", "RUNNING", "PUBLICATION_REVIEW"])).with_for_update(of=Job)):
        job.state = "CANCELLED"
        job.lease_expires_at = None
    if previously_merged:
        next_state = "MERGED"
    else:
        ticket.security_approved_revision = None
        ticket.verification_passed = False
        ticket.threat_revision = None
        ticket.findings = []
        ticket.pr_number = None
        ticket.artifacts = {k: ticket.artifacts[k] for k in ("project_item_id",) if k in ticket.artifacts}
        enqueue(db, ticket, "product_owner")
        next_state = "NEEDS_REPLAN"
    ticket.state = next_state
    db.add(AuditEvent(ticket_id=ticket.id, action="late_publication_resolved", detail={"attempt": attempt.id, "remote_evidence": evidence, "worker_isolation_reset": True, "explanation": data.explanation, "next_state": next_state, "actor": principal.actor if principal else None}))
    db.commit()
    return {"ticket_state": next_state, "repository_paused": ticket.repository.paused}


@app.post("/jobs/{job_id}/reconcile-publication")
async def reconcile_publication(job_id: str, data: PublicationReconcileIn, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    if not data.worker_isolation_reset:
        raise HTTPException(422, "Confirm the old worker isolation environment was reset")
    global_state = db.scalar(select(ControlState).where(ControlState.id == 1).with_for_update())
    if not global_state or not global_state.paused:
        raise HTTPException(409, "Pause all workers before reconciling publication")
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True))
    if not job or job.stage not in {"engineer", "threat_modeler"} or job.state not in {"PUBLICATION_REVIEW", "FAILED", "RUNNING"}:
        raise HTTPException(409, "Job has no publication to reconcile")
    if job.state == "RUNNING" and job.lease_expires_at and job.lease_expires_at.replace(tzinfo=job.lease_expires_at.tzinfo or timezone.utc) > now():
        raise HTTPException(409, "Job lease is still active")
    ticket = db.scalar(select(Ticket).where(Ticket.id == job.ticket_id).with_for_update())
    if job.state == "FAILED" and not (job.result or {}).get("_publication_intent"):
        raise HTTPException(409, "Failed job has no publication intent")
    intent = (job.result or {}).get("_publication_intent")
    sibling_incident = db.scalar(select(PublicationAttempt.id).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.state == "LATE_EFFECT", PublicationAttempt.branch != (intent or {}).get("branch", "")).limit(1))
    if sibling_incident:
        raise HTTPException(409, "Resolve the ticket's late publication incident first")
    evidence = {}
    attempt = db.scalar(select(PublicationAttempt).where(PublicationAttempt.branch == intent["branch"]).with_for_update()) if intent else None
    if intent and (not attempt or attempt.job_id != job.id or attempt.state not in {"ACTIVE", "PUBLISHED"}):
        raise HTTPException(409, "Publication attempt record is missing or already reconciled")
    if intent:
        try:
            evidence = await GitHubClient().publication_clear(intent["repository"], intent["branch"])
        except Exception as exc:
            raise HTTPException(409, f"Remote publication is not clear: {type(exc).__name__}: {exc}") from exc
    original_state = (job.result or {}).get("_claim_ticket_state")
    if not original_state:
        raise HTTPException(409, "Claim origin state is missing")
    replan = bool((job.result or {}).get("_publication_replan"))
    out_of_scope = bool((job.result or {}).get("_publication_out_of_scope"))
    retry_code = bool((job.result or {}).get("_publication_retry"))
    resume_state = (job.result or {}).get("_publication_resume_state")
    job.fencing_token += 1
    job.lease_expires_at = None
    job.started_at = None
    job.claimed_by = None
    job.result = {}
    if attempt:
        attempt.state = "RECONCILED"
        attempt.reconciled_at = now()
        attempt.last_checked_at = now()
    if out_of_scope:
        job.state = "CANCELLED"
        ticket.state = "OUT_OF_SCOPE"
        ticket.pr_number = None
    elif replan:
        job.state = "CANCELLED"
        ticket.state = "NEEDS_REPLAN"
        ticket.pr_number = None
        ticket.security_approved_revision = None
        ticket.verification_passed = False
        ticket.threat_revision = None
        ticket.findings = []
        ticket.artifacts = {k: ticket.artifacts[k] for k in ("project_item_id",) if k in ticket.artifacts}
        enqueue(db, ticket, "product_owner")
    elif retry_code:
        job.state = "CANCELLED"
        ticket.state = resume_state or "QA_FAILED"
        ticket.pr_number = None
        ticket.artifacts = {k: v for k, v in ticket.artifacts.items() if k != "commit_sha"}
    else:
        job.state = "QUEUED"
        ticket.state = original_state
    db.add(AuditEvent(ticket_id=ticket.id, action="publication_reconciled", detail={"job": job.id, "old_intent": intent, "remote_evidence": evidence, "worker_isolation_reset": True, "explanation": data.explanation, "next_state": ticket.state, "actor": principal.actor if principal else None}))
    db.commit()
    return {"job_state": job.state, "ticket_state": ticket.state, "remote_evidence": evidence}


@app.post("/jobs/{job_id}/publication-intent")
def record_publication_intent(job_id: str, data: PublicationIntentIn, credential: WorkerPrincipal = Depends(worker_authorized), db: Session = Depends(db_session)):
    if data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    _lock_worker_credential(db, credential)
    job = _locked_claim(db, job_id, data.worker_id, data.fencing_token)
    ticket = db.get(Ticket, job.ticket_id)
    if job.stage != data.kind or job.stage not in {"engineer", "threat_modeler"}:
        raise HTTPException(409, "Job stage cannot publish this intent")
    if data.branch != attempt_branch(ticket.number, job.id, job.fencing_token):
        raise HTTPException(409, "Publication branch does not match the live claim")
    if job.stage == "engineer" and data.repository != ticket.repository.full_name:
        raise HTTPException(409, "Implementation repository does not match ticket")
    if job.stage == "threat_modeler" and data.repository != ticket.repository.policy.get("threat_model_repository"):
        raise HTTPException(409, "Threat-model repository does not match registered policy")
    prior_publication = db.scalar(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.repository == data.repository, PublicationAttempt.job_id != job.id, PublicationAttempt.state.in_(["ACTIVE", "PUBLISHED", "LATE_EFFECT"])).limit(1))
    if prior_publication:
        raise HTTPException(409, "Prior publication for this ticket and repository requires reconciliation")
    intent = {"kind": data.kind, "repository": data.repository, "branch": data.branch, "sha": data.sha, "job_id": job.id, "job_revision": job.revision, "fencing_token": job.fencing_token, "design_revision": ticket.design_revision, "threat_revision": ticket.threat_revision}
    prior = (job.result or {}).get("_publication_intent")
    if prior and prior != intent:
        raise HTTPException(409, "Publication intent is immutable for this claim")
    if not prior:
        db.add(PublicationAttempt(job_id=job.id, ticket_id=ticket.id, repository=data.repository, branch=data.branch, sha=data.sha, state="ACTIVE"))
    job.result = {**(job.result or {}), "_publication_intent": intent}
    db.add(AuditEvent(ticket_id=ticket.id, action="publication_intent_recorded", detail=intent))
    db.commit()
    return {"recorded": True, "branch": data.branch}


@app.post("/jobs/{job_id}/heartbeat")
def heartbeat(job_id: str, data: ClaimIn, fencing_token: int, credential: WorkerPrincipal = Depends(worker_authorized), db: Session = Depends(db_session)):
    if data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    _lock_worker_credential(db, credential)
    job = _locked_claim(db, job_id, data.worker_id, fencing_token)
    job.lease_expires_at = now() + timedelta(minutes=20)
    ticket = db.get(Ticket, job.ticket_id)
    global_state = db.get(ControlState, 1)
    pause_requested = bool((global_state and global_state.paused) or ticket.repository.paused)
    db.commit()
    return {"ok": True, "pause_requested": pause_requested}


@app.post("/jobs/{job_id}/yield")
def yield_job(job_id: str, data: YieldIn, credential: WorkerPrincipal = Depends(worker_authorized), db: Session = Depends(db_session)):
    if data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    _lock_worker_credential(db, credential)
    job = _locked_claim(db, job_id, data.worker_id, data.fencing_token)
    if (job.result or {}).get("_publication_intent"):
        _quarantine_publication(db, job, db.get(Ticket, job.ticket_id), "claim yielded after remote publication began")
    else:
        job.state = "QUEUED"
        # Keep claimed_by as worker affinity so a different host cannot discard partial files.
        job.lease_expires_at = None
        job.started_at = None
        db.add(AuditEvent(ticket_id=job.ticket_id, action="job_yielded", detail={"job": job.id, "worker": data.worker_id, "revision": job.revision}))
    db.commit()
    return {"queued": job.state == "QUEUED", "publication_review": job.state == "PUBLICATION_REVIEW", "job_id": job.id}


@app.post("/jobs/{job_id}/release-affinity")
def release_job_affinity(job_id: str, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True))
    if not job or job.state != "QUEUED" or not job.claimed_by:
        raise HTTPException(409, "Job is not a yielded claim")
    previous_worker = job.claimed_by
    job.claimed_by = None
    job.fencing_token += 1
    db.add(AuditEvent(ticket_id=job.ticket_id, action="job_affinity_released", detail={"job": job.id, "previous_worker": previous_worker, "actor": principal.actor if principal else None}))
    db.commit()
    return {"queued": True, "job_id": job.id, "previous_worker": previous_worker}


@app.post("/jobs/{job_id}/complete")
def complete(job_id: str, data: CompleteIn, credential: WorkerPrincipal = Depends(worker_authorized), db: Session = Depends(db_session)):
    if data.worker_id != credential.worker_id:
        raise HTTPException(403, "Worker identity mismatch")
    _lock_worker_credential(db, credential)
    job = _locked_claim(db, job_id, data.worker_id, data.fencing_token)
    ticket = db.get(Ticket, job.ticket_id)
    intent = (job.result or {}).get("_publication_intent")
    if data.succeeded and job.stage == "engineer" and (not intent or data.result.get("commit_sha") != intent["sha"] or data.result.get("publication_branch") != intent["branch"]):
        raise HTTPException(422, "Implementation result does not match durable publication intent")
    if data.succeeded and job.stage == "threat_modeler" and data.result.get("threat_model_pr") and (not intent or data.result["threat_model_pr"].get("head_sha") != intent["sha"] or data.result.get("publication_branch") != intent["branch"]):
        raise HTTPException(422, "Threat-model result does not match durable publication intent")
    if data.succeeded:
        try:
            complete_stage(db, ticket, job.stage, data.result)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if job.stage in {"qa", "security_engineer"} and ticket.state in {"QA_FAILED", "SECURITY_FAILED", "ESCALATED_QA", "ESCALATED_SECURITY"}:
            prior_engineer = db.scalar(select(Job).where(Job.ticket_id == ticket.id, Job.stage == "engineer", Job.state == "SUCCEEDED").order_by(Job.revision.desc()).limit(1).with_for_update())
            prior_intent = (prior_engineer.result or {}).get("_publication_intent") if prior_engineer else None
            if prior_intent and ticket.artifacts.get("commit_sha") == prior_intent["sha"]:
                resume_state = ticket.state
                _quarantine_publication(db, prior_engineer, ticket, "code review requested another publication")
                prior_engineer.result = {**prior_engineer.result, "_publication_retry": True, "_publication_resume_state": resume_state}
    else:
        ticket.state = "JOB_FAILED"
    job.state = "SUCCEEDED" if data.succeeded else "FAILED"
    if intent and data.succeeded:
        attempt = db.scalar(select(PublicationAttempt).where(PublicationAttempt.branch == intent["branch"]).with_for_update())
        if not attempt:
            raise HTTPException(409, "Publication attempt record is missing")
        attempt.state = "PUBLISHED"
    job.result = {**data.result, **({"_publication_intent": intent, "_claim_ticket_state": (job.result or {}).get("_claim_ticket_state")} if intent else {})}
    if data.succeeded and job.stage == "threat_modeler" and intent and ticket.state in {"BLOCKED_FINDINGS", "ESCALATED_SECURITY"}:
        resume_state = ticket.state
        _quarantine_publication(db, job, ticket, "threat findings require a new model publication")
        job.result = {**job.result, "_publication_retry": True, "_publication_resume_state": resume_state}
    job.provider = data.result.get("provider")
    job.finished_at = now()
    job.lease_expires_at = None
    db.add(AuditEvent(ticket_id=ticket.id, action="job_completed", detail={"job": job.id, "state": job.state}))
    db.commit()
    return {"ticket_state": ticket.state}


@app.post("/jobs/{job_id}/retry")
def retry_failed_job(job_id: str, principal: HumanPrincipal | None = Depends(human_operator), db: Session = Depends(db_session)):
    job = db.get(Job, job_id)
    if not job or job.state != "FAILED":
        raise HTTPException(409, "Job is not failed")
    if (job.result or {}).get("_publication_intent"):
        raise HTTPException(409, "Remote publication must be reconciled before retry")
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


@app.post("/tickets/{ticket_id}/approve-security")
def approve(ticket_id: str, data: ApprovalIn, principal: HumanPrincipal | None = Depends(human_reviewer), db: Session = Depends(db_session)):
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    try:
        approve_security(db, ticket, _decision_actor(principal, data.actor), data.justification)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return {"state": ticket.state, "design_revision": ticket.design_revision}


@app.post("/tickets/{ticket_id}/accept-risk")
def accept_risk(ticket_id: str, data: RiskAcceptanceIn, principal: HumanPrincipal | None = Depends(human_reviewer), db: Session = Depends(db_session)):
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
    actor = _decision_actor(principal, data.actor)
    db.add(RiskAcceptance(
        ticket_id=ticket.id, threat_id=data.threat_id, design_revision=ticket.design_revision,
        threat_revision=ticket.threat_revision, actor=actor, justification=data.justification,
        residual_risk=data.residual_risk, scope=data.scope, expires_at=expiry,
    ))
    db.flush()
    if not unresolved_blockers(ticket, db):
        ticket.state = "WAITING_THREAT_PR" if ticket.repository.policy.get("threat_model_pr_required") and not ticket.artifacts.get("threat_model_pr_approved") else "WAITING_SECURITY_APPROVAL"
    db.add(AuditEvent(ticket_id=ticket.id, action="risk_accepted", detail={"threat_id": data.threat_id, "actor": actor, "expiry": expiry.isoformat()}))
    db.commit()
    return {"state": ticket.state, "threat_id": data.threat_id, "expires_at": expiry}


@app.post("/tickets/{ticket_id}/approve-high-risk-merge")
def approve_high_risk(ticket_id: str, data: ApprovalIn, principal: HumanPrincipal | None = Depends(human_reviewer), db: Session = Depends(db_session)):
    from adp.db import Approval
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.state != "READY_TO_MERGE" or not ticket.artifacts.get("commit_sha") or not ticket.pr_number:
        raise HTTPException(409, "PR and independent reviews must be complete before approval")
    actor = _decision_actor(principal, data.actor)
    db.add(Approval(ticket_id=ticket.id, kind="high_risk_merge", revision=ticket.design_revision, ref=ticket.artifacts["commit_sha"], actor=actor, justification=data.justification))
    db.add(AuditEvent(ticket_id=ticket.id, action="high_risk_merge_approved", detail={"actor": actor, "sha": ticket.artifacts["commit_sha"]}))
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
            if review["merged"]:
                attempt = db.scalar(select(PublicationAttempt).where(PublicationAttempt.ticket_id == ticket.id, PublicationAttempt.repository == artifact["repository"], PublicationAttempt.sha == artifact["head_sha"], PublicationAttempt.state == "PUBLISHED").order_by(PublicationAttempt.created_at.desc()).limit(1))
                if attempt:
                    attempt.state = "MERGED"
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
            except (httpx.HTTPError, RuntimeError) as exc:
                results[ticket.id] = {"merged": False, "reasons": [f"GitHub error: {type(exc).__name__}"]}
    return results


@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(db_session)):
    if not settings.github_webhook_secret:
        raise HTTPException(404, "GitHub webhooks are disabled")
    raw = await request.body()
    if len(raw) > 1024 * 1024:
        raise HTTPException(413, "Webhook payload too large")
    accepted_secrets = [settings.github_webhook_secret]
    previous_until = settings.github_webhook_previous_until
    if (settings.github_webhook_previous_secret and previous_until
            and previous_until.replace(tzinfo=previous_until.tzinfo or timezone.utc) > now()):
        accepted_secrets.append(settings.github_webhook_previous_secret)
    signature = request.headers.get("x-hub-signature-256", "")
    if not any(hmac.compare_digest(signature, "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()) for secret in accepted_secrets):
        raise HTTPException(401, "Invalid webhook signature")
    delivery = request.headers.get("x-github-delivery", "")
    event = request.headers.get("x-github-event", "")
    if not delivery or len(delivery) > 100 or not event:
        raise HTTPException(422, "Missing webhook headers")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(422, "Invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(422, "Invalid webhook payload")
    expected_key = {"issues": "issue", "pull_request": "pull_request", "projects_v2_item": "projects_v2_item"}.get(event)
    if not expected_key:
        return {"ignored": True}
    signed_shapes = {key for key in ("issue", "pull_request", "projects_v2_item") if isinstance(payload.get(key), dict)}
    if signed_shapes != {expected_key} or not isinstance(payload.get("action"), str):
        raise HTTPException(422, "Webhook event does not match payload")
    if event in {"issues", "pull_request"} and ("comment" in payload or "review" in payload):
        raise HTTPException(422, "Webhook event does not match payload")
    if event in {"issues", "pull_request"} and not isinstance(payload.get("repository"), dict):
        raise HTTPException(422, "Webhook repository is missing")
    # The delivery header is not covered by GitHub's payload signature. The
    # payload digest also rejects a captured body replayed with a new ID.
    digest = hashlib.sha256(raw).hexdigest()
    bind = db.get_bind()
    # Reconciliation helpers commit or roll back their own Session. Reserve in
    # a separate transaction so those operations cannot erase dedup evidence.
    with Session(bind) as reservation:
        reservation.add(WebhookDelivery(id=delivery, event=event, payload_hash=digest))
        try:
            reservation.commit()
        except IntegrityError:
            reservation.rollback()
            return {"duplicate": True}
    try:
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
        db.commit()
    except Exception:
        with Session(bind) as reservation:
            reservation.execute(delete(WebhookDelivery).where(WebhookDelivery.id == delivery, WebhookDelivery.payload_hash == digest))
            reservation.commit()
        raise
    return {"accepted": True}
