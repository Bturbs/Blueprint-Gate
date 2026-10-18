import asyncio
import json
import subprocess

import pytest

from adp import worker
from adp.runtimes import RuntimeResult


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

