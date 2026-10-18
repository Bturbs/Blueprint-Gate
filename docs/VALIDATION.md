# Validation evidence

Checked on 2026-10-18:

- `pytest -q`: 20 passed, 2 skipped. The skipped tests require PostgreSQL and an explicitly configured staging GitHub repository/token; the PostgreSQL test runs in the supplied GitHub Actions workflow.
- `alembic upgrade head`: reached revision `0006` using the local SQLite development database. A fresh SQLite migration also succeeded. PostgreSQL migration execution is configured in CI but could not be run locally because the Docker daemon is unavailable.
- `docker compose config --quiet`: passed with placeholder tokens. Container startup was not verified because the Docker daemon is unavailable.
- `CodexCLIRuntime` executed a read-only JSON smoke prompt through the installed authenticated `codex exec` CLI and returned a parsed result with usage metrics.
- `corda/threat-model-tool` was installed in a temporary checkout. Its `init` script created a schema-version-2 fixture; `adp.threat_models.verify` invoked the real `verify-threat-model.ts` script and received a success result.
- Claude Code is not installed locally. Its adapter follows the [official Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference), but has not been exercised against a real CLI or subscription.
- GitHub issue polling, Projects V2 GraphQL, GitHub App JWT/token cache, signed webhooks, threat PR review, and asynchronous merge submission were tested with mocks. They have not been run against a dedicated test repository.

Separate threat-model repository Git operations, real GitHub App/Projects/merge queue, remote workers, and Claude execution remain unverified in a live environment. The worker's host-level execution isolation and production backup/monitoring are deployment responsibilities.
