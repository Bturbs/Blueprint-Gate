#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! -f "$1" ]]; then
  echo "Usage: scripts/test-postgres-restore.sh BACKUP.dump" >&2
  exit 2
fi

backup="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
container="${BLUEPRINT_GATE_DB_CONTAINER:-aiworkflow-db-1}"
database="adp_restore_$(date -u +%Y%m%d%H%M%S)_$RANDOM"
cleanup() {
  docker exec "$container" dropdb -U adp --if-exists "$database" > /dev/null
}
docker exec "$container" createdb -U adp "$database"
trap cleanup EXIT
docker exec -i "$container" pg_restore -U adp --no-owner --no-acl --exit-on-error --single-transaction -d "$database" < "$backup"

for table in repositories tickets jobs approvals audit_events risk_acceptances worker_credentials control_state; do
  count="$(docker exec "$container" psql -U adp -d "$database" -At -c "SELECT count(*) FROM $table")"
  if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    echo "Invalid restored count for $table" >&2
    exit 1
  fi
  echo "$table=$count"
  if [[ "${COMPARE_LIVE:-0}" == 1 ]]; then
    query="SELECT md5(coalesce(string_agg(row_to_json(t)::text, E'\\n' ORDER BY t.id), '')) FROM $table t"
    live_digest="$(docker exec "$container" psql -U adp -d adp -At -c "$query")"
    restored_digest="$(docker exec "$container" psql -U adp -d "$database" -At -c "$query")"
    if [[ "$live_digest" != "$restored_digest" ]]; then
      echo "Restored rows differ from the paused live database for $table" >&2
      exit 1
    fi
  fi
done
trap - EXIT
if ! cleanup; then
  echo "Could not remove the temporary restore database" >&2
  exit 1
fi
if [[ "${COMPARE_LIVE:-0}" == 1 ]]; then
  echo "Restored backup in a separate database; core table rows match the paused live database."
else
  echo "Restored backup in a separate database and validated core tables."
fi
