import pytest

from adp.isolation import GuestResult, IsolationError, IsolationPolicy, JobEnvelope, isolated_supervisor
from adp import worker


def _policy(**overrides):
    value = {
        "version": 1,
        "backend": "vm",
        "guest_image_digest": "sha256:" + "a" * 64,
        "supervisor_url": "https://vm-supervisor.example",
        "supervisor_token_env": "ADP_VM_SUPERVISOR_TOKEN",
        "mount_manifest": [],
        "network": {"direct_route": False, "proxy_url": "https://egress-proxy.example"},
        "resource_limits": {"cpu": 2, "memory_mb": 2048, "disk_mb": 8192, "pids": 256, "runtime_seconds": 900, "checkpoint_mb": 64},
        "stages": {"engineer": {"egress_allowlist": ["api.openai.com", "github.com", "api.github.com"], "credential_grants": ["codex", "github_repo"]}},
    }
    value.update(overrides)
    return value


def _job():
    return {
        "id": "job-1", "stage": "engineer", "revision": 3, "fencing_token": 7,
        "repository": {"full_name": "example/project", "policy": {"required_checks": [["pytest", "-q"]]}},
        "ticket": {"id": "ticket-1", "number": 1, "title": "Fix isolation", "body": "untrusted", "artifacts": {}, "findings": []},
    }


def test_isolation_policy_rejects_host_mount_direct_network_and_secret_values():
    for change in (
        {"mount_manifest": ["/home"]},
        {"network": {"direct_route": True, "proxy_url": "https://egress-proxy.example"}},
        {"provider_token": "not-a-reference"},
    ):
        with pytest.raises(IsolationError):
            IsolationPolicy.from_config(_policy(**change))


def test_isolation_policy_requires_concrete_stage_profile():
    policy = IsolationPolicy.from_config(_policy())
    with pytest.raises(IsolationError, match="no profile"):
        JobEnvelope.create({**_job(), "stage": "qa"}, policy)


def test_guest_result_is_bound_to_job_policy_and_fencing_token():
    policy = IsolationPolicy.from_config(_policy())
    envelope = JobEnvelope.create(_job(), policy)
    response = {
        "job_id": envelope.job_id, "ticket_id": envelope.ticket_id, "stage": envelope.stage,
        "revision": envelope.revision, "fencing_token": envelope.fencing_token,
        "policy_digest": envelope.policy_digest, "boundary_id": "vm-123", "result": {"summary": "done"},
        "checkpoint_digest": "sha256:" + "b" * 64,
    }
    assert GuestResult.from_response(response, envelope).boundary_id == "vm-123"
    response["fencing_token"] = 8
    with pytest.raises(IsolationError, match="fencing_token"):
        GuestResult.from_response(response, envelope)


def test_missing_isolation_policy_fails_closed_before_any_job_is_started():
    with pytest.raises(IsolationError, match="isolation"):
        isolated_supervisor({})


@pytest.mark.asyncio
async def test_public_worker_entrypoint_has_no_local_execution_fallback():
    with pytest.raises(IsolationError, match="isolation"):
        await worker.execute_job(_job(), {})
