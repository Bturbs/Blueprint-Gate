# Implementation plan and status

1. **Lifecycle:** FastAPI, PostgreSQL migrations, GitHub issue polling, Projects V2 filtering/status sync, issue-edit invalidation, durable tickets/jobs, bounded remediation, local worker, Codex/Claude CLI adapters, worktrees, specifications, verified root threat models, revision-bound approval, checks, and PR creation.
2. **Delivery:** Opt-in merge eligibility checks validated head, issue link, CI, path policy, and risk approval. GitHub's asynchronous merge API preserves merge-queue behavior and reconciles eventual merged state. Failed jobs have bounded manual retries.
3. **Threat models:** The verifier adapter checks a configured root YAML. Separate repository worktrees and PRs are supported. An exact-head independent review and merged threat-model PR are required before engineering when policy enables this. Human risk acceptance records are revision-bound and expiring.
4. **Hybrid:** Outbound HTTPS workers use individually issued, repository-scoped tokens and server-side capabilities. The control plane supports GitHub App installation token brokerage and signed, deduplicated GitHub webhooks with polling fallback. Production deployment still needs HTTPS termination, backups, monitoring, and worker-host isolation.
5. **Interactive planning:** The repo-scoped `$github-spec-workflow` skill lets a Codex conversation inspect current issues, reconcile overlapping scope, create missing tickets, and maintain linked specs. This is a human-driven entry point; the platform's automated Product Owner, Architect, and security stages remain separate.

The service rejects engineering dispatch until the current design revision has a passed verification result, no open blocking findings, and a human security-design approval. A changed design resets that gate. Automatic merging defaults to disabled and is only available with repository opt-in.

## Validation limits

This repository was tested with local fixtures and mocked GitHub responses. Docker/PostgreSQL integration could not run on this host because its Docker daemon was unavailable. Claude CLI was absent. No live GitHub App, Projects, PR review, merge queue, or remote worker was exercised. A staging rollout should use real repositories, branch protection, HTTPS, and scoped credentials before production use.

The worker runs repository checks and coding CLIs with its host user's privileges. Use a dedicated disposable account or VM for untrusted repositories. A lost lease can leave Git side effects; fencing blocks stale completion and branch/PR creation is reusable, but workers sharing one checkout should not run concurrently.
