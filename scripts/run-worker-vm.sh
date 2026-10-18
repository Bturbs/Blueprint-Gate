#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]] || ! systemd-detect-virt --vm --quiet || [[ -e /.dockerenv ]]; then
  echo "Run this command only inside the dedicated worker VM." >&2
  exit 1
fi
# Lima's long-lived SSH connection can retain pre-bootstrap supplementary
# groups. Start a fresh supervisor process with the worktree group before any
# checkout is created; otherwise a late chgrp fails halfway through publish.
if [[ " $(id -nG) " != *" blueprint-work "* ]]; then
  exec sudo -n -u "$(id -un)" -g blueprint-work -- "$0" "$@"
fi
worker_home="$HOME"
token_file="$worker_home/.config/blueprint-gate/staging-worker.json"
config="$worker_home/worker.yaml"
if [[ ! -f "$token_file" || ! -f "$config" ]]; then
  echo "Worker token and configuration must be provisioned in the VM." >&2
  exit 1
fi
if [[ "$(stat -c %a "$token_file")" != 600 ]]; then
  echo "Worker token file must have mode 0600." >&2
  exit 1
fi
export ADP_WORKER_TOKEN="$(python3 - "$token_file" "$config" <<'PY'
import json,sys,yaml
token = json.load(open(sys.argv[1]))
config = yaml.safe_load(open(sys.argv[2]))
if token['worker_id'] != config['worker_id']:
    raise SystemExit('Worker ID does not match credential')
print(token['token'])
PY
)"
exec "$worker_home/.venvs/blueprint-gate/bin/adp" worker --config "$config" "$@"
