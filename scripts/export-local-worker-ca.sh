#!/usr/bin/env bash
set -euo pipefail

destination="${1:-${XDG_CONFIG_HOME:-$HOME/.config}/blueprint-gate/local-worker-ca.crt}"
directory="$(dirname "$destination")"
if [[ ! -d "$directory" ]]; then
  install -d -m 700 "$directory"
fi
temporary="$(mktemp "$directory/.local-worker-ca-XXXXXXXX")"
trap 'rm -f "$temporary"' EXIT

container="$(docker compose -f compose.yaml -f compose.local-tls.yaml ps -q worker_tls)"
if [[ -z "$container" ]]; then
  echo "Local TLS proxy is not running" >&2
  exit 1
fi
docker cp "$container:/data/caddy/pki/authorities/local/root.crt" "$temporary" >/dev/null
chmod 644 "$temporary"
mv "$temporary" "$destination"
trap - EXIT
echo "$destination"
