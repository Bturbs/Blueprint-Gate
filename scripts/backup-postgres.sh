#!/usr/bin/env bash
set -euo pipefail

umask 077

container="${BLUEPRINT_GATE_DB_CONTAINER:-aiworkflow-db-1}"
backup_dir="${BACKUP_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/blueprint-gate/backups}"
retention_days="${BACKUP_RETENTION_DAYS:-14}"
if [[ ! "$retention_days" =~ ^[1-9][0-9]*$ ]]; then
  echo "BACKUP_RETENTION_DAYS must be a positive integer" >&2
  exit 2
fi
if [[ -L "$backup_dir" ]]; then
  echo "Backup directory must not be a symlink" >&2
  exit 2
fi
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"

temporary="$(mktemp "$backup_dir/.blueprint-gate-XXXXXXXX")"
trap 'rm -f "$temporary"' EXIT
docker exec "$container" pg_dump -U adp -Fc adp > "$temporary"
docker exec -i "$container" pg_restore --file=/dev/null < "$temporary"

suffix="${temporary##*/.blueprint-gate-}"
backup="$backup_dir/blueprint-gate-$(date -u +%Y%m%dT%H%M%SZ)-$suffix.dump"
mv "$temporary" "$backup"
trap - EXIT
find "$backup_dir" -maxdepth 1 -type f -name 'blueprint-gate-*.dump' -mtime "+$retention_days" -delete
echo "$backup"
