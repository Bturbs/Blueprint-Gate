from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from adp.settings import settings


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    full_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    local_path: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_merge: Mapped[bool] = mapped_column(Boolean, default=False)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    github_etag: Mapped[str | None] = mapped_column(String(255))
    tickets: Mapped[list["Ticket"]] = relationship(back_populates="repository")


class Ticket(Base):
    __tablename__ = "tickets"
    __table_args__ = (UniqueConstraint("repository_id", "number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    provider_override: Mapped[str | None] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(40), default="NEW", index=True)
    dependencies: Mapped[list] = mapped_column(JSON, default=list)
    spec_revision: Mapped[int] = mapped_column(Integer, default=0)
    design_revision: Mapped[int] = mapped_column(Integer, default=0)
    threat_revision: Mapped[str | None] = mapped_column(String(80))
    verification_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    security_approved_revision: Mapped[int | None] = mapped_column(Integer)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict)
    pr_number: Mapped[int | None] = mapped_column(Integer)
    repository: Mapped[Repository] = relationship(back_populates="tickets")


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (UniqueConstraint("ticket_id", "stage", "revision"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    stage: Mapped[str] = mapped_column(String(40))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(30), default="QUEUED", index=True)
    provider: Mapped[str | None] = mapped_column(String(40))
    claimed_by: Mapped[str | None] = mapped_column(String(100))
    fencing_token: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    revision: Mapped[int] = mapped_column(Integer)
    ref: Mapped[str | None] = mapped_column(String(80))
    actor: Mapped[str] = mapped_column(String(255))
    justification: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ticket_id: Mapped[str | None] = mapped_column(ForeignKey("tickets.id"), index=True)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ControlState(Base):
    __tablename__ = "control_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    threat_id: Mapped[str] = mapped_column(String(255))
    design_revision: Mapped[int] = mapped_column(Integer)
    threat_revision: Mapped[str] = mapped_column(String(80))
    justification: Mapped[str] = mapped_column(Text)
    residual_risk: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class WorkerCredential(Base):
    __tablename__ = "worker_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    worker_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    repositories: Mapped[list] = mapped_column(JSON, default=list)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
