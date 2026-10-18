import json
import os
import subprocess
import sys

import pytest

from adp import worker
from adp.process_env import child_environment
from adp.runtimes import _run


_ENV_PROBE = """import json, os
print(json.dumps({name: os.environ.get(name) for name in (
    'PATH', 'HOME', 'CONTROL_TOKEN', 'ADP_WORKER_TOKEN',
    'GH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'UNRELATED_SECRET'
)}))
"""


@pytest.mark.asyncio
async def test_agent_and_repository_checks_do_not_inherit_service_secrets(tmp_path, monkeypatch):
    for name in ("CONTROL_TOKEN", "ADP_WORKER_TOKEN", "GH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "UNRELATED_SECRET"):
        monkeypatch.setenv(name, f"secret-for-{name}")
    argv = [sys.executable, "-c", _ENV_PROBE]

    rc, out, err = await _run(argv, "", tmp_path, 10)
    assert (rc, err) == (0, "")
    runtime_env = json.loads(out)
    checks = await worker._checks(tmp_path, [argv])
    assert checks[0]["passed"]
    check_env = json.loads(checks[0]["output"])
    for child_env in (runtime_env, check_env):
        assert child_env["PATH"] and child_env["HOME"]
        assert all(child_env[name] is None for name in (
            "CONTROL_TOKEN", "ADP_WORKER_TOKEN", "GH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN", "UNRELATED_SECRET",
        ))


def test_git_delivery_keeps_its_credential_but_not_worker_or_admin_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_TOKEN", "admin-secret")
    monkeypatch.setenv("ADP_WORKER_TOKEN", "worker-secret")
    monkeypatch.setenv("GH_TOKEN", "github-secret")
    monkeypatch.setenv("UNRELATED_SECRET", "unrelated-secret")
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv[0], kwargs["env"]))
        return subprocess.CompletedProcess(argv, 0, "ok")

    monkeypatch.setattr(worker.subprocess, "run", fake_run)
    assert worker._git(tmp_path, "status") == "ok"
    assert worker._git(tmp_path, "push", "origin", "test") == "ok"
    assert worker._gh(tmp_path, "auth", "status") == "ok"
    for (name, child_env), expect_github_token in zip(seen, (False, False, True)):
        assert name in {"git", "gh"}
        assert child_env.get("GH_TOKEN") == ("github-secret" if expect_github_token else None)
        assert "CONTROL_TOKEN" not in child_env
        assert "ADP_WORKER_TOKEN" not in child_env
        assert "UNRELATED_SECRET" not in child_env


def test_worker_git_ignores_repository_hooks(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    marker = tmp_path / "hook-ran"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\nprintf '%s' \"$GH_TOKEN\" > '{marker}'\n")
    hook.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(hooks)], check=True)
    monkeypatch.setenv("GH_TOKEN", "github-secret")
    (repo / "README.md").write_text("work")
    worker._git(repo, "add", "README.md")
    worker._git(repo, "commit", "-m", "work")
    assert not marker.exists()


def test_git_local_preserves_configured_author_identity(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    home = tmp_path / "home"
    home.mkdir()
    git_config = tmp_path / "gitconfig"
    git_config.write_text("[user]\n name = Configured User\n email = configured@example.com\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(git_config))
    (repo / "README.md").write_text("work")
    worker._git(repo, "add", "README.md")
    worker._git(repo, "commit", "-m", "work")
    assert worker._git(repo, "show", "-s", "--format=%an <%ae>") == "Configured User <configured@example.com>"


def test_git_push_does_not_pass_github_api_token_to_ssh_command(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "README.md").write_text("work")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "work"], check=True)
    marker = tmp_path / "ssh-env"
    ssh = tmp_path / "fake-ssh"
    ssh.write_text(f"#!/bin/sh\nprintf '%s' \"${{GH_TOKEN:-}}\" > '{marker}'\nexit 1\n")
    ssh.chmod(0o755)
    subprocess.run(["git", "-C", str(repo), "config", "core.sshCommand", str(ssh)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "ssh://example.invalid/repo"], check=True)
    monkeypatch.setenv("GH_TOKEN", "github-secret")
    with pytest.raises(subprocess.CalledProcessError):
        worker._git(repo, "push", "origin", "HEAD")
    assert marker.read_text() == ""


@pytest.mark.asyncio
async def test_direct_worker_launch_removes_service_tokens_before_claim(tmp_path, monkeypatch):
    config = tmp_path / "worker.yaml"
    config.write_text("control_url: http://127.0.0.1:8000\nworker_token_env: ADP_WORKER_TOKEN\n")
    monkeypatch.setenv("CONTROL_TOKEN", "admin-secret")
    monkeypatch.setenv("ADP_WORKER_TOKEN", "worker-secret")

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["headers"] == {"Authorization": "Bearer worker-secret"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, *_args, **_kwargs):
            assert "CONTROL_TOKEN" not in os.environ
            assert "ADP_WORKER_TOKEN" not in os.environ
            return self

        def raise_for_status(self):
            return None

        def json(self):
            return None

    monkeypatch.setattr(worker.httpx, "AsyncClient", FakeClient)
    await worker.run_worker(config, once=True)


@pytest.mark.asyncio
async def test_direct_worker_rejects_admin_token_reused_as_worker_token(tmp_path, monkeypatch):
    config = tmp_path / "worker.yaml"
    config.write_text("control_url: http://127.0.0.1:8000\nworker_token_env: ADP_WORKER_TOKEN\n")
    monkeypatch.setenv("CONTROL_TOKEN", "same-secret")
    monkeypatch.setenv("ADP_WORKER_TOKEN", "same-secret")
    with pytest.raises(ValueError, match="must be different"):
        await worker.run_worker(config, once=True)


@pytest.mark.asyncio
async def test_direct_worker_rejects_inline_token(tmp_path):
    config = tmp_path / "worker.yaml"
    config.write_text("control_url: http://127.0.0.1:8000\nworker_token: file-secret\n")
    with pytest.raises(ValueError, match="worker_token_env"):
        await worker.run_worker(config, once=True)


def test_authenticated_proxy_credentials_are_not_inherited_by_untrusted_commands(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://person:proxy-secret@proxy.example:8443")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    env = child_environment("check")
    assert "HTTPS_PROXY" not in env
    assert env["HTTP_PROXY"] == "http://proxy.example:8080"
