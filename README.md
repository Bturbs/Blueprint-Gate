# Autonomous Development Platform

Local-first, policy-gated GitHub issue delivery. It runs a FastAPI/PostgreSQL control plane in Docker and Codex or Claude Code workers on the host. It supports GitHub Projects, separate threat-model PRs, asynchronous merge requests, and scoped outbound hybrid workers. See [implementation status and validation limits](docs/IMPLEMENTATION_PLAN.md).

## Start locally

Requires Docker, Python 3.12+, Git, GitHub CLI, and at least one authenticated coding CLI. A configured root threat-model YAML and local `corda/threat-model-tool` checkout with `npm install` are required for security design approval.

```bash
cp .env.example .env
# Set distinct random CONTROL_TOKEN and WORKER_TOKEN values, plus GITHUB_TOKEN.
docker compose up --build -d
uv sync --extra test --no-editable
.venv/bin/adp doctor
```

Register a repository with the control API, then poll it. Replace the placeholder values:

```bash
curl -X POST http://127.0.0.1:8000/repositories \
  -H "Authorization: Bearer $CONTROL_TOKEN" -H 'Content-Type: application/json' \
  -d '{"full_name":"example/project","policy":{"routing":{"default_provider":"codex","allowed_providers":["codex"]},"required_checks":[["python","-m","pytest"]],"delivery_enabled":false}}'
.venv/bin/adp poll http://127.0.0.1:8000 "$CONTROL_TOKEN" REPOSITORY_ID
```

Copy `worker.example.yaml` to `worker.yaml`, set absolute local paths, export `ADP_WORKER_TOKEN`, then run `.venv/bin/adp worker --config worker.yaml`. This worker uses only outbound HTTP. For a remote control plane, use HTTPS and an issued worker credential. The worker creates `adp/issue-N` worktrees in the configured directory. `delivery_enabled` must be explicitly enabled before it will commit, push, and open an implementation PR.

The control API has `GET /tickets` and `GET /tickets/{id}` for review. When a ticket enters `WAITING_SECURITY_APPROVAL`, a human with the separate control token can approve the current design revision via `POST /tickets/{id}/approve-security` with JSON `{"actor":"name","justification":"Reviewed design and threat model"}`. Blocking findings trigger up to three Architect revisions, then escalation. Issue dependencies use lines such as `Depends on #12` in the issue body. An issue label such as `provider:claude` overrides routing only if that provider is approved by the repository policy. `POST /control/pause` pauses new claims and merges; `POST /repositories/{id}/control/pause` pauses one repository.

When `allow_risk_acceptance` is explicitly enabled, a human can record a scoped, expiring exception for an escalated finding through `POST /tickets/{id}/accept-risk`. The request requires `threat_id`, `actor`, `justification`, `residual_risk`, `scope`, and `expires_at`. Expired exceptions or exceptions for a previous design/model revision do not satisfy the security gate. An exception never changes a threat-model control to `inPlace: true`.

To opt a repository into automatic merging, set `auto_merge: true` when registering it and configure nonempty `required_ci_checks`. The control plane compares the PR head with the validated commit and submits GitHub's asynchronous merge request only if all policy checks pass. It records `MERGED` after GitHub confirms the final state. GitHub branch protection must be configured separately. High-risk changed paths require `POST /tickets/{id}/approve-high-risk-merge` after QA and security review; that approval is tied to the exact commit.

CLI subscriptions have limits and are distinct from API billing. This version never falls back to a paid API. Each CLI must be installed and authenticated separately on the worker host. The control plane stores only the selected provider name and reported usage metadata.

For hybrid deployment, host the control service behind HTTPS, set `HYBRID_MODE=true`, and issue each worker a scoped credential. Signed GitHub webhooks can trigger faster reconciliation while scheduled polling remains active. See [configuration](docs/CONFIGURATION.md) and [operations](docs/OPERATIONS.md).

## Development

```bash
uv sync --extra test --no-editable
.venv/bin/pytest
```

After changing source code, rebuild the non-editable local package before running the installed `adp` CLI: `uv sync --extra test --no-editable --reinstall-package autonomous-dev-platform`.

No live GitHub or Claude execution was performed during repository development. A read-only Codex CLI smoke test succeeded; the tests use mocks and local fixtures. Do not point the worker at a production repository until you have reviewed its policy, isolation, GitHub permissions, branch protection, and required checks. See [validation evidence](docs/VALIDATION.md).
