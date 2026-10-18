#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mode="${1:---local}"
if [[ "$#" -gt 1 || ( "$mode" != "--local" && "$mode" != "--resume" && "$mode" != "--control-only" && "$mode" != "--worker-only" ) ]]; then
  echo "Usage: scripts/start.sh [--local|--resume|--control-only|--worker-only]" >&2
  exit 2
fi
resume=false
if [[ "$mode" == "--resume" ]]; then
  resume=true
  mode=--local
fi

adp="$ROOT/.venv/bin/adp"
python="$ROOT/.venv/bin/python"
if [[ ! -x "$adp" || ! -x "$python" ]]; then
  echo "Install the local CLI first: uv sync --extra test --no-editable" >&2
  exit 1
fi

read_dotenv() {
  "$python" - "$ROOT/.env" "$1" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.exists():
    for line in path.read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key.strip() == sys.argv[2]:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            sys.stdout.write(value)
            break
PY
}

if [[ "$mode" != "--worker-only" && ! -f "$ROOT/.env" ]]; then
  echo "Missing .env; copy .env.example and configure credentials first." >&2
  exit 1
fi
if [[ "$mode" != "--control-only" ]]; then
  config="${WORKER_CONFIG:-$ROOT/worker.yaml}"
  if [[ ! -f "$config" ]]; then
    echo "Missing worker config: $config. Copy worker.example.yaml to worker.yaml and set its paths." >&2
    exit 1
  fi
fi
if [[ "$mode" == "--local" ]]; then
  if [[ -z "${ADP_WORKER_TOKEN:-}" || "$ADP_WORKER_TOKEN" == replace-with* ]]; then
    echo "Export an issued scoped token as ADP_WORKER_TOKEN before starting the worker." >&2
    exit 1
  fi
fi

if [[ "$mode" != "--worker-only" ]]; then
  export CONTROL_TOKEN="${CONTROL_TOKEN:-$(read_dotenv CONTROL_TOKEN)}"
  if [[ -z "$CONTROL_TOKEN" || "$CONTROL_TOKEN" == replace-with* ]]; then
    echo "Set a real CONTROL_TOKEN in .env or the environment." >&2
    exit 1
  fi
  if [[ "$mode" == "--local" && "$ADP_WORKER_TOKEN" == "$CONTROL_TOKEN" ]]; then
    echo "The worker and administrator credentials must be different." >&2
    exit 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is not installed or is not on PATH." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "Starting Docker Desktop..."
      open -a Docker
    else
      echo "Start the Docker daemon, then rerun this script." >&2
      exit 1
    fi
    for _ in {1..60}; do
      if docker info >/dev/null 2>&1; then break; fi
      sleep 2
    done
    if ! docker info >/dev/null 2>&1; then
      echo "Docker did not become ready within two minutes." >&2
      exit 1
    fi
  fi

  echo "Starting PostgreSQL, control plane, and scheduler..."
  docker compose up --build -d
  for _ in {1..60}; do
    if curl --fail --silent --output /dev/null http://127.0.0.1:8000/health; then break; fi
    sleep 2
  done
  if ! curl --fail --silent --output /dev/null http://127.0.0.1:8000/health; then
    echo "Control plane did not become healthy within two minutes. Check docker compose logs control." >&2
    exit 1
  fi

  if [[ "$resume" == true ]]; then
    "$adp" resume http://127.0.0.1:8000
  fi
  status="$("$adp" control-status http://127.0.0.1:8000)"
  if printf '%s' "$status" | "$python" -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["paused"] else 1)'; then
    echo "Control plane is still paused. Run 'scripts/start.sh --resume' when ready."
    exit 0
  fi
  echo "Control plane is ready. Registered repositories and jobs were retained in PostgreSQL."
fi

if [[ "$mode" == "--control-only" ]]; then exit 0; fi

if [[ -n "${CONTROL_TOKEN:-}" && "${ADP_WORKER_TOKEN:-}" == "$CONTROL_TOKEN" ]]; then
  echo "The worker and administrator credentials must be different." >&2
  exit 1
fi
echo "Starting host worker in this terminal. Press Ctrl-C once to yield its active job safely."
unset CONTROL_TOKEN
exec "$adp" worker --config "$config"
