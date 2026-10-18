#!/usr/bin/env bash
set -euo pipefail

# Run inside the provisioned VM. This creates only disposable fixture files.
[[ "$(uname -s)" == Linux ]] && systemd-detect-virt --vm --quiet
[[ ! -e /.dockerenv ]]
if mount | grep -Eq ' type (virtiofs|9p|nfs|nfs4|cifs|smb3|fuse|fuse\.[^ ]+) '; then
  echo "Host directory mount found in worker VM" >&2
  exit 1
fi
docker info --format '{{json .SecurityOptions}}' | grep -q rootless

supervisor_home="$HOME"
sentinel="$supervisor_home/.config/blueprint-gate/isolation-fixture"
install -d -m 700 "$supervisor_home/.config/blueprint-gate"
printf 'supervisor-only\n' > "$sentinel"
chmod 600 "$sentinel"
if sudo -n -u blueprint-agent -- cat "$sentinel" >/dev/null 2>&1; then
  echo "Agent could read the supervisor credential directory" >&2
  exit 1
fi
fixture=/srv/blueprint-gate/isolation-fixture
install -d -m 2775 "$fixture"
chgrp blueprint-work "$fixture"
sudo -n -u blueprint-agent -- sh -c 'printf normal-ticket > /srv/blueprint-gate/isolation-fixture/result.txt'
[[ "$(cat "$fixture/result.txt")" == normal-ticket ]]

image="$(python3 - "$supervisor_home/worker.yaml" <<'PY'
import sys,yaml
print(yaml.safe_load(open(sys.argv[1]))['repositories']['Bturbs/Blueprint-Gate']['check_image'])
PY
)"
docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user 65534:65534 \
  --mount "type=bind,src=$fixture,dst=/workspace,readonly" --workdir /workspace \
  --env "SUPERVISOR_SENTINEL=$sentinel" --entrypoint python "$image" -c 'from pathlib import Path; import os,socket; assert Path("result.txt").read_text()=="normal-ticket"; assert not Path(os.environ["SUPERVISOR_SENTINEL"]).exists(); s=socket.socket(); assert s.connect_ex(("1.1.1.1",443)) != 0; print("isolated-check-passed")'
echo "Worker VM identity, file, check-container, and network fixtures passed."
