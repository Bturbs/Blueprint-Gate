# Blueprint Gate

Blueprint Gate turns GitHub issues into policy-gated software delivery. It runs a FastAPI/PostgreSQL control plane in Docker and Codex or Claude Code workers on the host. It supports GitHub Projects, separate threat-model PRs, asynchronous merge requests, and scoped outbound hybrid workers. See [implementation status and validation limits](docs/IMPLEMENTATION_PLAN.md).

## Plan work with one skill

In Codex chat, use `$github-spec-workflow` and describe what you want to build. The skill reviews current GitHub tickets, discusses overlaps and missing decisions, updates tickets that already cover the idea, and creates tickets for new aspects. You can use the same skill later to refine `specs/ISSUE-N/{requirements,design,tasks}.md` for manual work and prepare a PR handoff. For example: “Use `$github-spec-workflow` for Bturbs/Blueprint-Gate. I want to build ... Review the tickets and update the backlog.” See the [workflow guide](docs/SPEC_WORKFLOW.md) and [skill instructions](.agents/skills/github-spec-workflow/SKILL.md).

The skill runs in a human-driven Codex session using the host's authenticated GitHub CLI. The automated worker still uses its role profiles and security gate. If the target repository is registered with the control plane, the next poll can queue a new issue's Product Owner stage; editing an unmerged issue invalidates prior design approval and queues replanning. If repository policy filters intake by a GitHub Project, add new issues to that Project before expecting the worker to ingest them.

The skill is repository scoped. To plan work in another repository, copy `.agents/skills/github-spec-workflow` into that checkout's `.agents/skills/` and add an equivalent trigger to its `AGENTS.md`. Keep the `gh` login on the host; do not put tokens in prompts or committed files.

## Start locally

Requires Docker, Python 3.12+, Git, GitHub CLI, and at least one authenticated coding CLI. A configured root threat-model YAML and local `corda/threat-model-tool` checkout with `npm install` are required for security design approval.

```bash
cp .env.example .env
# Set a random CONTROL_TOKEN and a GitHub credential for the control plane.
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

Issue a scoped worker credential through `POST /workers/credentials` with a future `expires_at` (up to 30 days), then copy `worker.example.yaml` to `worker.yaml`, set absolute local paths, export the returned token as `ADP_WORKER_TOKEN`, and run `.venv/bin/adp worker --config worker.yaml`. The raw token is returned once. This worker uses only outbound HTTP. For a remote control plane, use HTTPS. The worker creates `adp/issue-N` worktrees in the configured directory. `delivery_enabled` must be explicitly enabled before it will commit, push, and open an implementation PR.

After setup, export the issued `ADP_WORKER_TOKEN` and restart the local stack and worker with `./scripts/start.sh`. It starts Docker Desktop on macOS if needed, waits for the control service, and runs the worker in the foreground. A saved pause remains in force; use `./scripts/start.sh --resume` only when you intend to resume work. Use `./scripts/start.sh --control-only` to start the services without a worker, or `./scripts/start.sh --worker-only` on a hybrid worker host with its scoped token already exported. See [reboot steps](docs/OPERATIONS.md).

### Stop and resume safely

Press **Ctrl-C once** in a local worker terminal to stop its active CLI, return the unfinished job to the queue, and exit. A normal SIGTERM from a process manager follows the same path. Restart with the same `worker_id` and checkout to pick up the yielded job; another host cannot claim it accidentally. Completed stages remain recorded, and files already written in the issue worktree remain available. An interrupted model response itself starts again, so only completed stages and saved files are durable checkpoints.

To pause the whole system, export the existing `CONTROL_TOKEN` in your shell, then run:

```bash
.venv/bin/adp pause http://127.0.0.1:8000
.venv/bin/adp control-status http://127.0.0.1:8000
# When ready to continue:
.venv/bin/adp resume http://127.0.0.1:8000
.venv/bin/adp worker --config worker.yaml
```

`pause` stops new claims and merge submissions, asks active workers to yield, and waits up to 30 seconds for `running_jobs` to reach zero. Use `--repository-id ID` to pause one registered repository. If active jobs remain, the command exits with status 2; check again before shutting down. For hybrid mode, use the HTTPS control URL. [Recovery details](docs/OPERATIONS.md).

The control API has `GET /tickets` and `GET /tickets/{id}` for review. When a ticket enters `WAITING_SECURITY_APPROVAL`, a human with the separate control token can approve the current design revision via `POST /tickets/{id}/approve-security` with JSON `{"actor":"name","justification":"Reviewed design and threat model"}`. Blocking findings trigger up to three Architect revisions, then escalation. Issue dependencies use lines such as `Depends on #12` in the issue body. An issue label such as `provider:claude` overrides routing only if that provider is approved by the repository policy. `POST /control/pause` and `POST /repositories/{id}/control/pause` stop new claims and merge submissions and request active workers to yield.

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

No live GitHub writes or Claude execution were performed during repository development. GitHub repository lookup and issue listing were read-only; a read-only Codex CLI smoke test succeeded. The automated tests use mocks and local fixtures. Do not point the worker at a production repository until you have reviewed its policy, isolation, GitHub permissions, branch protection, and required checks. See [validation evidence](docs/VALIDATION.md).
