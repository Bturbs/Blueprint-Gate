# Operations

## Start and observe

For local mode, set `.env` then run `docker compose up --build -d`. Use `docker compose ps`, `docker compose logs control`, and `docker compose logs scheduler` for process health. `GET /health` only reports API availability; also check scheduler logs and recent ticket/job states through `GET /tickets`.

For hybrid mode, terminate HTTPS at a trusted reverse proxy, set `HYBRID_MODE=true`, configure a GitHub App installation and webhook secret, then issue a distinct worker credential for each worker. Workers connect outbound to the HTTPS URL. The scheduler keeps GitHub state reconciled and jobs queued while workers are offline.

## Pause and recover

Use `POST /control/pause` or `POST /repositories/{id}/control/pause` with the admin token to stop new claims and merges. Inspect `GET /tickets/{id}` before retrying a failed job through `POST /jobs/{id}/retry`. Retry limits are configured by `max_job_attempts`. A stale worker lease is fenced by a new claim; the old worker cannot complete its job. If an asynchronous merge reaches `MERGE_FAILED` or `MERGE_UNKNOWN`, inspect GitHub and the PR before taking further action.

## Database backup

Back up PostgreSQL before upgrades and regularly in production. For a local Compose installation, use a host shell with protected backup storage:

```bash
docker compose exec -T db pg_dump -U adp -Fc adp > adp-backup.dump
```

Test restores on a separate database. Stop control and scheduler writes before restoring a primary database. Keep the GitHub App private key, webhook secret, admin token, and worker tokens in a separate secret store; database backups do not contain provider CLI credentials or raw worker tokens.

## Worker isolation

Each worker runs repository commands and coding CLIs under its host user. Use a dedicated disposable VM or account per trust domain, keep production credentials off that host, and do not let two workers share a checkout/worktree root. Required checks should be reviewed argv commands. `AGENTS.md` and other repo content are untrusted input to coding agents.
