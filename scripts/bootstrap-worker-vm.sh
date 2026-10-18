#!/usr/bin/env bash
set -euo pipefail

# Run inside the plain-mode Lima VM from a trusted Blueprint Gate checkout.
if [[ "$(uname -s)" != Linux ]] || ! systemd-detect-virt --vm --quiet || [[ -e /.dockerenv ]]; then
  echo "Bootstrap requires a dedicated Linux VM." >&2
  exit 1
fi
if mount | grep -Eq ' type (virtiofs|9p|nfs|nfs4|cifs|smb3|fuse|fuse\.[^ ]+) '; then
  echo "Worker VM has a host directory mount." >&2
  exit 1
fi
sudo -n true || { echo "Worker supervisor needs noninteractive sudo for identity switching." >&2; exit 1; }
docker info --format '{{json .SecurityOptions}}' | grep -q rootless || { echo "Worker VM needs its own rootless Docker daemon." >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_home="$HOME"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq acl bubblewrap git gh nodejs npm python3-venv python3-pip >/dev/null
sudo groupadd -f blueprint-work
if ! getent passwd blueprint-agent >/dev/null; then
  sudo useradd --create-home --shell /bin/bash blueprint-agent
fi
sudo usermod -aG blueprint-work "$(id -un)"
sudo usermod -aG blueprint-work blueprint-agent
sudo chmod 700 "$worker_home" /home/blueprint-agent
sudo install -d -m 700 -o blueprint-agent -g blueprint-agent /home/blueprint-agent/.codex /home/blueprint-agent/.claude
sudo -n -u blueprint-agent -- git config --global --replace-all safe.directory '/srv/blueprint-gate/worktrees/*'
sudo install -d -m 700 -o "$(id -un)" -g "$(id -gn)" "$worker_home/.config/blueprint-gate"
for directory in /srv/blueprint-gate /srv/blueprint-gate/repos /srv/blueprint-gate/worktrees /srv/blueprint-gate/tools; do
  sudo install -d -m 2755 -o "$(id -un)" -g blueprint-work "$directory"
done
for directory in /srv/blueprint-gate/worktrees/Blueprint-Gate /srv/blueprint-gate/worktrees/Threat-Models; do
  sudo install -d -m 2755 -o "$(id -un)" -g blueprint-work "$directory"
done

clone_if_missing() {
  local url="$1" target="$2" exposure="${3:-metadata}"
  if [[ ! -d "$target/.git" ]]; then
    if ! git clone --quiet "$url" "$target"; then
      echo "Cannot clone $url. Provision a repository-scoped GitHub credential in the VM or copy a credential-free checkout there, then rerun bootstrap." >&2
      exit 1
    fi
  fi
  # The agent needs Git metadata to inspect its linked worktree, not the base
  # checkout's source files. The verifier tool is a separate readable case.
  sudo chgrp -R blueprint-work "$target"
  if [[ "$exposure" == metadata ]]; then
    sudo find "$target" -type d -exec chmod g-r,g-w,g+x,o-rwx {} +
    sudo find "$target" -type f -exec chmod go-rwx {} +
    sudo chmod -R g+rX,g-w "$target/.git"
  else
    sudo chmod -R g+rX,g-w "$target"
  fi
}

clone_if_missing https://github.com/Bturbs/Blueprint-Gate.git /srv/blueprint-gate/repos/Blueprint-Gate
clone_if_missing https://github.com/Bturbs/Threat-Models.git /srv/blueprint-gate/repos/Threat-Models
clone_if_missing https://github.com/Bturbs/TM-Tool.git /srv/blueprint-gate/tools/threat-model-tool tool
(cd /srv/blueprint-gate/tools/threat-model-tool && npm ci --ignore-scripts)
sudo chgrp -R blueprint-work /srv/blueprint-gate/tools/threat-model-tool
sudo chmod -R g+rX,g-w /srv/blueprint-gate/tools/threat-model-tool

python3 -m venv "$worker_home/.venvs/blueprint-gate"
"$worker_home/.venvs/blueprint-gate/bin/pip" install --quiet "$repo_root"
sudo npm install --global @openai/codex@0.155.0-alpha.16
docker build --quiet -f "$repo_root/deploy/worker-vm/Dockerfile.checks" -t blueprint-gate-checks:local "$repo_root" >/dev/null
image_id="$(docker image inspect blueprint-gate-checks:local --format '{{.Id}}')"

"$worker_home/.venvs/blueprint-gate/bin/python" - "$worker_home/worker.yaml" "$worker_home" "$image_id" <<'PY'
import sys
from pathlib import Path
import yaml

destination, home, image = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
config = {
    "control_url": "http://127.0.0.1:8000",
    "worker_token_env": "ADP_WORKER_TOKEN",
    "worker_id": "local-staging-worker",
    "untrusted_user": "blueprint-agent",
    "untrusted_group": "blueprint-work",
    "untrusted_sandbox": True,
    "capabilities": ["git", "codex"],
    "poll_seconds": 5,
    "threat_tool_root": "/srv/blueprint-gate/tools/threat-model-tool",
    "repositories": {
        "Bturbs/Blueprint-Gate": {
            "path": "/srv/blueprint-gate/repos/Blueprint-Gate",
            "worktrees": "/srv/blueprint-gate/worktrees/Blueprint-Gate",
            "check_image": image,
            "threat_repository": {
                "full_name": "Bturbs/Threat-Models",
                "path": "/srv/blueprint-gate/repos/Threat-Models",
                "worktrees": "/srv/blueprint-gate/worktrees/Threat-Models",
                "root_model": "threatModels/BlueprintGate/BlueprintGate.yaml",
            },
        }
    },
}
destination.write_text(yaml.safe_dump(config, sort_keys=False))
destination.chmod(0o600)
PY
echo "VM prepared. Configure scoped gh and Codex logins inside the VM before starting its worker."
