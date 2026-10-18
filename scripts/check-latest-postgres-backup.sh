#!/usr/bin/env bash
set -euo pipefail

backup_dir="${BACKUP_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/blueprint-gate/backups}"
shopt -s nullglob
backups=("$backup_dir"/blueprint-gate-*.dump)
if [[ "${#backups[@]}" -eq 0 ]]; then
  echo "No Blueprint Gate backup found" >&2
  exit 1
fi
latest="$(printf '%s\n' "${backups[@]}" | sort | tail -n 1)"
max_age_hours="${BACKUP_MAX_AGE_HOURS:-24}"
if [[ ! "$max_age_hours" =~ ^[1-9][0-9]*$ ]]; then
  echo "BACKUP_MAX_AGE_HOURS must be a positive integer" >&2
  exit 2
fi
age_seconds="$(($(date +%s) - $(stat -f %m "$latest")))"
if (( age_seconds > max_age_hours * 3600 )); then
  echo "Latest Blueprint Gate backup exceeds the freshness target" >&2
  exit 1
fi
"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-postgres-restore.sh" "$latest"
