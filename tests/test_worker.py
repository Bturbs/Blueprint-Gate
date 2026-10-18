import asyncio
import json
import subprocess

import pytest
import yaml

from adp import worker
from adp.runtimes import RuntimeResult
from adp.control_url import control_origin


class FakeRuntime:
    name = "codex"

    async def validate_environment(self):
        return {"available": True}

    async def execute(self, prompt, cwd, timeout=900, writable=False):
        if "Refine the issue" in prompt:
            output = {"requirements": "# Requirements\nThe feature works."}
        else:
            output = {"design": "# Design\nUse a service.", "tasks": "# Tasks\nImplement service."}
        return RuntimeResult("codex", "succeeded", json.dumps(output), {})


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000@attacker.example",
    "http://localhost:8000@attacker.example",
    "http://attacker.example:8000",
    "https://user:secret@example.com",
    "https://example.com/jobs/claim",
    "https://example.com?token=secret",
])
@pytest.mark.asyncio
async def test_worker_rejects_unsafe_control_origin_before_sending_token(tmp_path, monkeypatch, url):
    monkeypatch.setenv("ADP_WORKER_TOKEN", "worker-secret")
    config = tmp_path / "worker.yaml"
    config.write_text(yaml.safe_dump({"control_url": url, "worker_token_env": "ADP_WORKER_TOKEN"}))
    with pytest.raises(ValueError):
        await worker.run_worker(config, once=True)


def test_control_origin_preserves_valid_local_and_tls_urls():
    assert control_origin("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert control_origin("http://localhost:8000") == "http://localhost:8000"
    assert control_origin("https://gate.example:8443/") == "https://gate.example:8443"
    assert control_origin("http://control:8000", allow_container_control=True) == "http://control:8000"
    with pytest.raises(ValueError):
        control_origin("http://control:8000")
    with pytest.raises(ValueError):
        control_origin("http://control.attacker.example:8000", allow_container_control=True)


def test_provider_prompt_uses_only_stage_context():
    sentinel = "UNRELATED_PRIVATE_VALUE"
    job = {
        "repository": {"full_name": "example/project", "policy": {"required_checks": [["pytest", "-q"]]}},
        "ticket": {
            "number": 5,
            "title": "Feature",
            "body": f"Issue-only details {sentinel}",
            "artifacts": {
                "requirements": "Required behavior",
                "design": "Approved design",
                "tasks": "Implementation tasks",
                "mitigation_requirements": [{"threat_id": "T1", "countermeasure_id": "C1", "check_command": ["pytest", "-q"]}],
                "qa_review": {"evidence": "QA feedback", "checks": [{"output": sentinel}]},
                "security_review": {"evidence": "Security feedback", "checks": [{"output": sentinel}]},
                "project_item_id": sentinel,
                "merge_request_uuid": sentinel,
            },
            "findings": [{"threat_id": "T1", "note": "Repair boundary"}],
        },
    }
    product_owner = worker._prompt({**job, "stage": "product_owner"})
    assert "Issue-only details" in product_owner
    assert "Required behavior" not in product_owner
    assert "Repair boundary" not in product_owner
    architect = worker._prompt({**job, "stage": "architect"})
    assert "Required behavior" in architect
    assert "Approved design" in architect
    assert "Implementation tasks" in architect
    assert "Repair boundary" in architect
    assert sentinel not in architect
    engineer = worker._prompt({**job, "stage": "engineer"})
    assert "Issue-only details" not in engineer
    assert "Required behavior" in engineer
    assert "Approved design" in engineer
    assert "Implementation tasks" in engineer
    assert "QA feedback" in engineer
    assert "Security feedback" in engineer
    assert "Repair boundary" in engineer
    assert sentinel not in engineer
    security = worker._prompt({**job, "stage": "security_engineer"})
    assert "QA feedback" in security
    assert "Security feedback" in security
    assert sentinel not in security
    qa = worker._prompt({**job, "stage": "qa"})
    assert "QA feedback" in qa
    assert "Security feedback" in qa
    assert sentinel not in qa


@pytest.mark.asyncio
async def test_worker_creates_reusable_issue_worktree_and_specs(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "README.md").write_text("Test")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    monkeypatch.setattr(worker, "candidate_runtimes", lambda policy, stage: [FakeRuntime()])
    config = {"repositories": {"example/project": {"path": str(repo), "worktrees": str(tmp_path / "worktrees")}}}
    base = {"repository": {"full_name": "example/project", "policy": {}}, "ticket": {"number": 5, "title": "Feature", "body": "Do work", "artifacts": {}, "findings": []}}
    requirements = await worker.execute_job({**base, "stage": "product_owner"}, config)
    assert requirements["requirements"].startswith("# Requirements")
    design = await worker.execute_job({**base, "stage": "architect"}, config)
    assert design["tasks"].startswith("# Tasks")
    spec = tmp_path / "worktrees" / "issue-5" / "specs" / "ISSUE-5"
    assert (spec / "requirements.md").exists()
    assert (spec / "design.md").exists()
    assert (spec / "tasks.md").exists()
