"""Protocol and policy checks for the disposable job boundary.

This module deliberately contains no local-process fallback.  A worker host is
not an acceptable boundary for issue-controlled commands: it can only submit a
bounded envelope to a configured VM supervisor.  The supervisor is responsible
for creating the VM, applying the policy, and destroying it before returning a
result.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GRANT = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
MAX_ENVELOPE_BYTES = 256 * 1024
MAX_RESULT_BYTES = 1024 * 1024
MAX_CHECKPOINT_BYTES = 256 * 1024 * 1024


class IsolationError(ValueError):
    """The worker must not start a job because its boundary is not trustworthy."""


def _canonical(value: Any, limit: int, label: str) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError) as exc:
        raise IsolationError(f"{label} is not JSON serializable") from exc
    if len(encoded) > limit:
        raise IsolationError(f"{label} exceeds {limit} bytes")
    return encoded


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IsolationError(f"{label} must be an object")
    return value


def _require_string(value: Any, label: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise IsolationError(f"{label} must be a non-empty string no longer than {limit} characters")
    return value


def _https_url(value: Any, label: str) -> str:
    url = _require_string(value, label)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IsolationError(f"{label} must be a simple HTTPS origin")
    if parsed.path not in {"", "/"}:
        raise IsolationError(f"{label} must not contain a path")
    return url.rstrip("/")


def _destination(value: Any) -> str:
    destination = _require_string(value, "egress destination", 255).lower()
    # Host names only.  CIDRs, URLs, ports, IP literals, and wildcard domains
    # make a deny-by-default proxy policy ambiguous.
    if not _HOST.fullmatch(destination) or "." not in destination or ".." in destination:
        raise IsolationError("egress destinations must be concrete DNS host names")
    if destination.startswith(("localhost.", "localhost-")) or destination == "localhost":
        raise IsolationError("egress destination must not be localhost")
    return destination


@dataclass(frozen=True)
class StageIsolationProfile:
    egress_allowlist: tuple[str, ...]
    credential_grants: tuple[str, ...]


@dataclass(frozen=True)
class IsolationPolicy:
    version: int
    guest_image_digest: str
    supervisor_url: str
    proxy_url: str
    resource_limits: dict[str, int]
    stages: dict[str, StageIsolationProfile]
    digest: str

    @classmethod
    def from_config(cls, value: Any) -> "IsolationPolicy":
        config = _require_mapping(value, "isolation policy")
        if config.get("version") != 1:
            raise IsolationError("isolation policy version 1 is required")
        if config.get("backend") != "vm":
            raise IsolationError("isolation backend must be vm")
        digest = _require_string(config.get("guest_image_digest"), "guest_image_digest", 80)
        if not _DIGEST.fullmatch(digest):
            raise IsolationError("guest_image_digest must be a pinned sha256 digest")
        if config.get("mount_manifest") != []:
            raise IsolationError("mount_manifest must be an empty list")
        network = _require_mapping(config.get("network"), "network")
        if network.get("direct_route") is not False:
            raise IsolationError("guest direct network route must be disabled")
        proxy_url = _https_url(network.get("proxy_url"), "network.proxy_url")
        limits = _require_mapping(config.get("resource_limits"), "resource_limits")
        required_limits = {"cpu", "memory_mb", "disk_mb", "pids", "runtime_seconds", "checkpoint_mb"}
        if set(limits) != required_limits or any(not isinstance(limits[k], int) or limits[k] <= 0 for k in required_limits):
            raise IsolationError("resource_limits must contain positive cpu, memory_mb, disk_mb, pids, runtime_seconds, checkpoint_mb")
        if limits["checkpoint_mb"] * 1024 * 1024 > MAX_CHECKPOINT_BYTES:
            raise IsolationError("checkpoint limit exceeds the platform maximum")
        stages_value = _require_mapping(config.get("stages"), "isolation stages")
        profiles: dict[str, StageIsolationProfile] = {}
        for stage, profile_value in stages_value.items():
            if not isinstance(stage, str) or not _GRANT.fullmatch(stage):
                raise IsolationError("isolation stage names are invalid")
            profile = _require_mapping(profile_value, f"isolation stage {stage}")
            destinations = profile.get("egress_allowlist")
            grants = profile.get("credential_grants")
            if not isinstance(destinations, list) or not destinations:
                raise IsolationError(f"isolation stage {stage} needs a non-empty egress allowlist")
            if not isinstance(grants, list) or not grants:
                raise IsolationError(f"isolation stage {stage} needs credential grant identifiers")
            parsed_destinations = tuple(sorted({_destination(item) for item in destinations}))
            parsed_grants = tuple(sorted({_require_string(item, "credential grant", 64) for item in grants}))
            if any(not _GRANT.fullmatch(item) for item in parsed_grants):
                raise IsolationError("credential grants must be identifiers, not credentials")
            profiles[stage] = StageIsolationProfile(parsed_destinations, parsed_grants)
        if not profiles:
            raise IsolationError("isolation stages must not be empty")
        supervisor_url = _https_url(config.get("supervisor_url"), "supervisor_url")
        policy_without_secrets = dict(config)
        for key in policy_without_secrets:
            if ("secret" in key.lower() or "token" in key.lower() or "password" in key.lower()) and key != "supervisor_token_env":
                raise IsolationError("isolation policy must reference credentials by identifier, not contain secret values")
        return cls(
            version=1,
            guest_image_digest=digest,
            supervisor_url=supervisor_url,
            proxy_url=proxy_url,
            resource_limits=dict(limits),
            stages=profiles,
            digest="sha256:" + hashlib.sha256(_canonical(config, MAX_ENVELOPE_BYTES, "isolation policy")).hexdigest(),
        )

    def profile_for(self, stage: str) -> StageIsolationProfile:
        try:
            return self.stages[stage]
        except KeyError as exc:
            raise IsolationError(f"isolation policy has no profile for stage {stage}") from exc


@dataclass(frozen=True)
class JobEnvelope:
    job_id: str
    ticket_id: str
    ticket_number: int
    stage: str
    revision: int
    fencing_token: int
    repository: str
    policy_digest: str
    guest_image_digest: str
    egress_allowlist: tuple[str, ...]
    credential_grants: tuple[str, ...]
    task: dict[str, Any]

    @classmethod
    def create(cls, job: dict[str, Any], policy: IsolationPolicy) -> "JobEnvelope":
        ticket = _require_mapping(job.get("ticket"), "job.ticket")
        repository = _require_mapping(job.get("repository"), "job.repository")
        stage = _require_string(job.get("stage"), "job.stage", 64)
        profile = policy.profile_for(stage)
        ticket_number = ticket.get("number")
        revision, fence = job.get("revision", 1), job.get("fencing_token")
        if not isinstance(ticket_number, int) or ticket_number < 1 or not isinstance(revision, int) or revision < 1 or not isinstance(fence, int) or fence < 1:
            raise IsolationError("job number, revision, and fencing token must be positive integers")
        task = {
            "title": _require_string(ticket.get("title"), "ticket title", 16 * 1024),
            "body": ticket.get("body", ""),
            "artifacts": ticket.get("artifacts", {}),
            "findings": ticket.get("findings", []),
            "repository_policy": repository.get("policy", {}),
            "provider_override": ticket.get("provider_override"),
        }
        _canonical(task, MAX_ENVELOPE_BYTES, "job task data")
        if not isinstance(task["body"], str):
            raise IsolationError("ticket body must be a string")
        envelope = cls(
            job_id=_require_string(job.get("id"), "job.id", 128),
            ticket_id=_require_string(ticket.get("id"), "ticket.id", 128),
            ticket_number=ticket_number,
            stage=stage,
            revision=revision,
            fencing_token=fence,
            repository=_require_string(repository.get("full_name"), "repository.full_name", 255),
            policy_digest=policy.digest,
            guest_image_digest=policy.guest_image_digest,
            egress_allowlist=profile.egress_allowlist,
            credential_grants=profile.credential_grants,
            task=task,
        )
        _canonical(envelope.as_dict(), MAX_ENVELOPE_BYTES, "job envelope")
        return envelope

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id, "ticket_id": self.ticket_id, "ticket_number": self.ticket_number,
            "stage": self.stage, "revision": self.revision, "fencing_token": self.fencing_token,
            "repository": self.repository, "policy_digest": self.policy_digest,
            "guest_image_digest": self.guest_image_digest, "egress_allowlist": list(self.egress_allowlist),
            "credential_grants": list(self.credential_grants), "task": self.task,
        }


@dataclass(frozen=True)
class GuestResult:
    result: dict[str, Any]
    boundary_id: str
    checkpoint_digest: str | None

    @classmethod
    def from_response(cls, value: Any, envelope: JobEnvelope) -> "GuestResult":
        response = _require_mapping(value, "guest response")
        for key, expected in (("job_id", envelope.job_id), ("ticket_id", envelope.ticket_id), ("stage", envelope.stage), ("revision", envelope.revision), ("fencing_token", envelope.fencing_token), ("policy_digest", envelope.policy_digest)):
            if response.get(key) != expected:
                raise IsolationError(f"guest response {key} does not match the claimed job")
        result = _require_mapping(response.get("result"), "guest result")
        _canonical(result, MAX_RESULT_BYTES, "guest result")
        boundary_id = _require_string(response.get("boundary_id"), "guest boundary_id", 128)
        checkpoint = response.get("checkpoint_digest")
        if checkpoint is not None and (not isinstance(checkpoint, str) or not _DIGEST.fullmatch(checkpoint)):
            raise IsolationError("guest checkpoint_digest must be a sha256 digest")
        return cls(result=result, boundary_id=boundary_id, checkpoint_digest=checkpoint)


class VmSupervisorClient:
    """Submit a job to a pre-provisioned VM supervisor, never to a shell."""

    def __init__(self, policy: IsolationPolicy, token_env: str):
        if not _ENV_NAME.fullmatch(token_env):
            raise IsolationError("supervisor_token_env must be a safe environment variable name")
        self.policy = policy
        self.token_env = token_env
        self.envelope: JobEnvelope | None = None

    async def run(self, job: dict[str, Any]) -> dict[str, Any]:
        token = os.environ.get(self.token_env, "")
        if not token:
            raise IsolationError("VM supervisor credential is not configured")
        envelope = JobEnvelope.create(job, self.policy)
        self.envelope = envelope
        headers = {"Authorization": f"Bearer {token}", "X-ADP-Fencing-Token": str(envelope.fencing_token)}
        started = datetime.now(timezone.utc).isoformat()
        try:
            async with httpx.AsyncClient(base_url=self.policy.supervisor_url, headers=headers, timeout=self.policy.resource_limits["runtime_seconds"] + 30) as client:
                response = await client.post("/v1/disposable-jobs", json=envelope.as_dict())
                response.raise_for_status()
                guest = GuestResult.from_response(response.json(), envelope)
        except httpx.HTTPError as exc:
            raise IsolationError(f"VM supervisor did not complete isolated job: {type(exc).__name__}") from exc
        record = {
            "boundary_id": guest.boundary_id,
            "policy_digest": self.policy.digest,
            "guest_image_digest": self.policy.guest_image_digest,
            "mount_manifest_digest": "sha256:" + hashlib.sha256(b"[]").hexdigest(),
            "egress_profile": list(envelope.egress_allowlist),
            "credential_grant_ids": list(envelope.credential_grants),
            "checkpoint_digest": guest.checkpoint_digest,
            "started_at": started,
            "teardown_verified": False,
        }
        return {**guest.result, "isolation": record}

    async def teardown(self) -> bool:
        if self.envelope is None:
            return True
        token = os.environ.get(self.token_env, "")
        if not token:
            return False
        headers = {"Authorization": f"Bearer {token}", "X-ADP-Fencing-Token": str(self.envelope.fencing_token)}
        try:
            async with httpx.AsyncClient(base_url=self.policy.supervisor_url, headers=headers, timeout=15) as client:
                response = await client.delete(f"/v1/disposable-jobs/{self.envelope.job_id}")
                if response.status_code not in {200, 204, 404, 409}:
                    response.raise_for_status()
                return response.status_code in {200, 204}
        except httpx.HTTPError:
            # The job result is never accepted as evidence of teardown.  The
            # supervisor's out-of-band reconciliation must retry this revoke.
            return False


def isolated_supervisor(config: dict[str, Any]) -> VmSupervisorClient:
    isolation = _require_mapping(config.get("isolation"), "isolation")
    token_env = isolation.get("supervisor_token_env")
    return VmSupervisorClient(IsolationPolicy.from_config(isolation), _require_string(token_env, "supervisor_token_env", 64))
