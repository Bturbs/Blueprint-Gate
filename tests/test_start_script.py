import os
import shutil
import subprocess
import sys
from pathlib import Path


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    (root / "scripts").mkdir(parents=True)
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / "bin").mkdir()
    script = root / "scripts" / "start.sh"
    shutil.copyfile(Path(__file__).parents[1] / "scripts" / "start.sh", script)
    script.chmod(0o755)
    (root / ".venv" / "bin" / "python").symlink_to(sys.executable)
    (root / ".env").write_text("CONTROL_TOKEN=admin-secret\nWORKER_TOKEN=worker-secret\n")
    (root / "worker.yaml").write_text("control_url: http://127.0.0.1:8000\nworker_token_env: ADP_WORKER_TOKEN\nworker_id: host-1\n")
    (root / ".venv" / "bin" / "adp").write_text("""#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  control-status) [[ "${CONTROL_TOKEN:-}" == admin-secret ]]; printf '{"paused":%s}\\n' "$(cat "$TEST_STATUS")" ;;
  resume) [[ "${CONTROL_TOKEN:-}" == admin-secret ]]; echo false > "$TEST_STATUS"; echo resume >> "$TEST_LOG" ;;
  worker)
    [[ "${ADP_WORKER_TOKEN:-}" == worker-secret ]]
    [[ -z "${CONTROL_TOKEN:-}" && -z "${GITHUB_TOKEN:-}" && -z "${GITHUB_APP_ID:-}" ]]
    [[ -z "${GITHUB_INSTALLATION_ID:-}" && -z "${GITHUB_PRIVATE_KEY_PATH:-}" && -z "${GITHUB_WEBHOOK_SECRET:-}" && -z "${GITHUB_WEBHOOK_PREVIOUS_SECRET:-}" ]]
    echo worker >> "$TEST_LOG" ;;
esac
""")
    (root / ".venv" / "bin" / "adp").chmod(0o755)
    for name, body in {
        "docker": 'echo "docker $*" >> "$TEST_LOG"',
        "curl": 'echo health >> "$TEST_LOG"',
    }.items():
        path = root / "bin" / name
        path.write_text(f"#!/usr/bin/env bash\n{body}\n")
        path.chmod(0o755)
    return script, root


def _run(script: Path, root: Path, *args: str, paused: bool = False) -> subprocess.CompletedProcess:
    status = root / "status"
    status.write_text("true" if paused else "false")
    env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}", TEST_STATUS=str(status), TEST_LOG=str(root / "calls"))
    env.pop("CONTROL_TOKEN", None)
    env.pop("ADP_WORKER_TOKEN", None)
    return subprocess.run([str(script), *args], cwd=root, env=env, text=True, capture_output=True, timeout=10)


def test_start_keeps_saved_pause_and_resumes_only_when_requested(tmp_path):
    script, root = _fixture(tmp_path)
    paused = _run(script, root, paused=True)
    assert paused.returncode == 0, paused.stderr
    assert "still paused" in paused.stdout
    assert "worker" not in (root / "calls").read_text()

    (root / "calls").unlink()
    resumed = _run(script, root, "--resume", paused=True)
    assert resumed.returncode == 0, resumed.stderr
    assert (root / "calls").read_text().splitlines()[-2:] == ["resume", "worker"]


def test_start_reuses_database_and_runs_host_worker(tmp_path):
    script, root = _fixture(tmp_path)
    result = _run(script, root)
    assert result.returncode == 0, result.stderr
    calls = (root / "calls").read_text()
    assert "docker compose up --build -d" in calls
    assert "worker" in calls
    assert "resume" not in calls


def test_worker_only_does_not_require_local_docker_or_database(tmp_path):
    script, root = _fixture(tmp_path)
    (root / ".env").unlink()
    status = root / "status"
    status.write_text("false")
    env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}", TEST_STATUS=str(status), TEST_LOG=str(root / "calls"), ADP_WORKER_TOKEN="worker-secret", CONTROL_TOKEN="admin-secret", GITHUB_TOKEN="control-github-token", GITHUB_APP_ID="123", GITHUB_INSTALLATION_ID="456", GITHUB_PRIVATE_KEY_PATH="/tmp/app.pem", GITHUB_WEBHOOK_SECRET="webhook-secret", GITHUB_WEBHOOK_PREVIOUS_SECRET="old-webhook-secret")
    result = subprocess.run([str(script), "--worker-only"], cwd=root, env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert (root / "calls").read_text().splitlines() == ["worker"]


def test_start_selects_app_and_tls_overlays_on_restart(tmp_path):
    script, root = _fixture(tmp_path)
    app_key = root / "app.pem"
    app_key.write_text("test-only-key")
    (root / "compose.local-tls.yaml").write_text("services: {}\n")
    with (root / ".env").open("a") as config:
        config.write(f"GITHUB_APP_PRIVATE_KEY_FILE={app_key}\nBLUEPRINT_LOCAL_TLS=true\n")
    result = _run(script, root, "--control-only")
    assert result.returncode == 0, result.stderr
    assert "docker compose -f compose.yaml -f compose.github-app.yaml -f compose.local-tls.yaml up --build -d" in (root / "calls").read_text()


def test_start_rejects_missing_app_key_before_docker(tmp_path):
    script, root = _fixture(tmp_path)
    with (root / ".env").open("a") as config:
        config.write(f"GITHUB_APP_PRIVATE_KEY_FILE={root / 'missing.pem'}\n")
    result = _run(script, root, "--control-only")
    assert result.returncode == 1
    assert "GitHub App private key file is missing" in result.stderr
    assert not (root / "calls").exists()


def test_resume_checks_worker_config_before_clearing_pause(tmp_path):
    script, root = _fixture(tmp_path)
    (root / "worker.yaml").unlink()
    result = _run(script, root, "--resume", paused=True)
    assert result.returncode == 1
    assert "Missing worker config" in result.stderr
    assert not (root / "calls").exists()
