# Operations

## Start and observe

For local mode, set `.env` then run `docker compose up --build -d`. Use `docker compose ps`, `docker compose logs control`, and `docker compose logs scheduler` for process health. `GET /health` only reports API availability; also check scheduler logs and recent ticket/job states through `GET /tickets`.

After a computer restart, export the issued scoped `ADP_WORKER_TOKEN` and run `./scripts/start.sh` from the repository. It starts Docker Desktop on macOS if necessary, runs `docker compose up --build -d`, waits for control health, checks the saved pause flag, and starts the host worker in the foreground. Keep that terminal open; one Ctrl-C asks the worker to yield its active job. The script uses `CONTROL_TOKEN` from `.env` for the status check. It does not register repositories again or replace the PostgreSQL `postgres_data` volume. The scheduler rereads open GitHub issues and Project membership every 60 seconds; jobs, approvals, policy, and pause state come from the existing database. The script is a manual startup command, not a login item.

The script removes `CONTROL_TOKEN` before starting the worker and refuses to reuse it as `ADP_WORKER_TOKEN`. A directly launched worker also removes its service tokens from its process environment after reading them. Coding CLIs, repository checks, the model verifier, and Git/GitHub commands receive purpose-specific environment variables. This limits inherited credential exposure; these processes still run as the host user and can read files that user can access.

If startup reports a saved pause, run `./scripts/start.sh --resume` when ready. That explicitly clears the global pause before starting the worker. `./scripts/start.sh --control-only` starts the local services without a worker. On a hybrid worker host, export its scoped worker token and run `./scripts/start.sh --worker-only`; this mode does not start Docker or load local `.env` credentials. Keep its `worker_id` and checkout paths stable. The script expects an installed `.venv/bin/adp` and a configured `worker.yaml` for modes that start a worker.

For a fresh local instance, start with `./scripts/start.sh --control-only`, register the intended repository, and issue a worker credential with a future `expires_at` through the admin API. Save the one-time returned token in the host's secret store outside the repository, export it as `ADP_WORKER_TOKEN`, then start the worker. For rotation, run `adp pause http://127.0.0.1:8000` and confirm `running_jobs` is zero, call `POST /workers/credentials/{id}/rotate` with a new `expires_at`, replace the stored token, then resume and restart the worker with the same `worker_id` and checkout paths. The old token stops working immediately. If a token expires or is revoked during a job, the worker stops code execution, but cannot authenticate its yield; the job remains leased until expiry (up to 20 minutes) before recovery. In-flight job mutations recheck and lock the credential in their transaction, so a rotation or revocation waits for a mutation already using that credential to finish.

For hybrid mode, terminate HTTPS at a trusted reverse proxy, set `HYBRID_MODE=true`, configure a GitHub App installation and webhook secret, then issue a distinct worker credential for each worker. Workers connect outbound to the HTTPS URL. The scheduler keeps GitHub state reconciled and jobs queued while workers are offline.

## Webhook secret rotation and incident response

Generate a new, unique 32-byte-or-longer random webhook secret in the host's protected secret store; do not put it in Git, shell history, PR text, or command arguments. Set the service's current `GITHUB_WEBHOOK_SECRET` to the new value, `GITHUB_WEBHOOK_PREVIOUS_SECRET` to the old value, and `GITHUB_WEBHOOK_PREVIOUS_UNTIL` to a near-term UTC deadline (for example 15 minutes ahead). Restart the control service and verify its health while GitHub still signs with the old secret. Change the secret in the GitHub App or repository webhook settings to the new value, then send a test event and verify a new signed delivery is accepted once. Remove the previous secret and deadline from service configuration and restart. A test signed with the old secret must now receive HTTP 401; a fresh event signed with the new secret must be accepted. Signature verification stays enabled throughout. Keep scheduler polling active during the cutover.

If compromise is suspected, set a short deadline, change GitHub to a new secret promptly, inspect recent webhook delivery IDs and reconciliation audit events, then remove the old secret immediately after confirming the new delivery. A stolen signed body may be replayed with altered headers, so review unexpected reconciliation activity even when signature checks passed. If the old secret itself was exposed, do not use an overlap; coordinate a direct cutover and rely on scheduled polling for events during the restart. Local staging on a loopback-only Mac can exercise signatures and rotation, but it cannot receive GitHub deliveries without an authenticated HTTPS endpoint.
### Local HTTPS worker-channel exercise

On a Mac staging host, keep the control API on its existing loopback port and start the optional TLS proxy with `docker compose -f compose.yaml -f compose.local-tls.yaml up -d worker_tls`. The proxy listens only on `127.0.0.1:8443` and forwards `/jobs/claim`, worker heartbeat/yield/complete routes, and `/health`; it returns 404 for administrative routes. It uses Caddy's private local CA for this loopback exercise. Export only the public root certificate with `./scripts/export-local-worker-ca.sh`, then set `SSL_CERT_FILE` to that path for a test worker using `https://127.0.0.1:8443`. Do not disable certificate verification or add this test CA to system-wide trust. Store the worker credential separately from the admin token.

Confirm that a request with the exported CA succeeds, the same request without it fails certificate validation, cleartext remote URLs are rejected before a worker sends its token, and an administrative endpoint returns 404 through the proxy. This loopback proxy is staging evidence only. A remote worker deployment needs a DNS name and trusted certificate, network allowlisting, `HYBRID_MODE=true`, an issued scoped worker credential, and a claim/completion exercise through that exact external route. Keep the API's direct admin port private.

For backlog planning, run `$github-spec-workflow` from a Codex session in the target checkout. The skill reads existing issues before writing and uses that host's `gh` login. Check the proposed ticket map in chat. If the repository is already registered, a new visible issue is picked up on the next poll. Editing an unmerged issue cancels queued/running work, clears its security design approval, and starts requirements replanning. If the repository uses `project_id`, confirm new issues are in the Project; an issue outside it will not be ingested.

## Pause and recover

For a local worker, press Ctrl-C once; a normal SIGTERM follows the same path. The worker asks its CLI process group to terminate, gives it five seconds to close files, then stops it if necessary. It releases the current job back to `QUEUED` with the same stage and revision and leaves the issue worktree in place. Restart with the same `worker_id` and checkout to continue. A yielded job keeps that worker affinity, preventing a different hybrid host from claiming work whose partial files it cannot see. Completed stages stay in the database. An interrupted stage reruns using existing worktree files; an incomplete model response is not a durable checkpoint.

For all workers or one repository, export `CONTROL_TOKEN` in the shell and use the CLI:

```bash
adp pause http://127.0.0.1:8000
adp control-status http://127.0.0.1:8000
adp resume http://127.0.0.1:8000
```

Append `--repository-id ID` to scope any of these commands. Repository status also reports `global_paused`; a global pause still applies if the repository's own `paused` flag is false. Remote control URLs must use HTTPS. `pause` blocks new claims and merge submissions, signals running workers through their heartbeat, and waits up to 30 seconds for `running_jobs` to reach zero. It exits with status 2 when work has not drained. A merge request already submitted to GitHub may still complete while paused; inspect its PR if a full delivery halt is needed. After `resume`, restart any workers that exited on pause. The equivalent admin API endpoints are `POST /control/{pause|resume}`, `GET /control`, and their `/repositories/{id}/control` forms. A worker with a matching lease can release a job through `POST /jobs/{id}/yield`; stale fencing tokens are rejected.

If the worker process or network disappears before it can yield, the job remains leased for up to 20 minutes. Once the lease expires and dispatch resumes, a worker can reclaim that same job with a new fencing token. Inspect `GET /tickets/{id}` before retrying a genuinely failed job through `POST /jobs/{id}/retry`; retry limits are configured by `max_job_attempts`. If an asynchronous merge reaches `MERGE_FAILED` or `MERGE_UNKNOWN`, inspect GitHub and the PR before taking further action.

If a yielded worker host is permanently unavailable, an admin can inspect the job in `GET /tickets/{id}` and call `POST /jobs/{job_id}/release-affinity` after ensuring the old process has stopped. The next eligible worker may then claim the job from the last completed stage; partial files on the old host will not follow it. The release increments the fencing token and is recorded in the audit log.

## Database backup

Back up PostgreSQL before upgrades and regularly. On the local macOS staging host, `scripts/backup-postgres.sh` writes a verified custom-format dump under `~/.local/share/blueprint-gate/backups` with directory mode 0700 and file mode 0600. It retains dumps for 14 days by default. `BACKUP_DIR` and `BACKUP_RETENTION_DAYS` can be set for a different location and retention. The scripts target the local `aiworkflow-db-1` container by default; set `BLUEPRINT_GATE_DB_CONTAINER` if the Compose project uses another name. Run one backup and a separate database restore exercise manually:

```bash
backup="$(scripts/backup-postgres.sh)"
scripts/test-postgres-restore.sh "$backup"
```

To compare every restored core row with the live database, pause dispatch and stop the scheduler first, take a fresh backup, then run `COMPARE_LIVE=1 scripts/test-postgres-restore.sh "$backup"`. This requires writes to remain stopped during the comparison. The restore exercise creates a temporary PostgreSQL database, verifies the restored tables, and removes it. A normal restore check verifies schema and readability without assuming the live database has stayed unchanged since the dump.

On macOS, `python3 scripts/install-local-backups.py` copies the scripts to `~/.local/share/blueprint-gate/bin` and installs launchd jobs for a daily 02:00 backup and Sunday 03:00 restore exercise. The copied scripts run from outside `Documents`, where macOS privacy controls can prevent a background launchd job from entering this checkout. The weekly check fails if the newest backup is older than 24 hours (`BACKUP_MAX_AGE_HOURS` can override this). Logs are under `~/.local/share/blueprint-gate/logs`. Inspect them after a missed run or failure. The staging recovery target is at most 24 hours of data loss from the last successful daily run and two hours to restore service, assuming this Mac and Docker remain available. Confirm the last successful timestamp; sleep, shutdown, or a failed run can exceed that target. Keep a verified copy on separately protected storage before relying on backups against host loss or a compromised host user. Mode 0700 local storage alone does not protect against either.

For primary recovery, stop workers, control, and scheduler; retain the failed volume for investigation; create a fresh `adp` database; restore the selected dump with `pg_restore --exit-on-error --no-owner --no-acl`; then restart control and scheduler and inspect ticket, job, approval, audit, and exception state before resuming dispatch. Always perform the separate database restore exercise before replacing a primary database. Keep the GitHub App private key, webhook secret, admin token, and worker tokens in a separate secret store; database backups do not contain provider CLI credentials or raw worker tokens.

## Worker isolation

Each worker runs repository commands and coding CLIs under its host user. Use a dedicated disposable VM or account per trust domain, keep production credentials off that host, and do not let two workers share a checkout/worktree root. Required checks should be reviewed argv commands. `AGENTS.md` and other repo content are untrusted input to coding agents.
