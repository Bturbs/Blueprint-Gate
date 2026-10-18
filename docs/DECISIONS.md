# Architectural decisions

- PostgreSQL is the durable state store and queue. Jobs are claimed with row locks and fencing tokens; a later claim invalidates stale completion.
- GitHub Issues are ingested by outbound REST polling. Signed, deduplicated webhooks can reduce latency in hybrid mode; polling remains the recovery path.
- The control plane stores no Codex or Claude credentials. CLI execution takes place in a host worker; routing is per repository and role.
- Automated specifications are generated into an issue worktree and are committed with the eventual application PR. The security-design approval is recorded in the control plane before engineering.
- A single repo-scoped Codex skill handles human-driven idea discovery, GitHub backlog reconciliation, specification refinement, and PR handoff. It uses host `gh` credentials; automated workers keep their existing role prompts and security gate.
- Threat modelling uses the repository's configured root YAML and the real `corda/threat-model-tool` verifier. Separate model repositories use isolated branches and PRs with exact-head review checks. The `Bturbs/Threat-Models` checkout inspected on 2026-10-18 contains no YAML models, so onboarding must supply or create a reviewed model before this stage can pass.
- Security approval is bound to a design revision. The system deliberately does not infer that a syntactically valid YAML model is a secure design.
- Workers do not merge PRs. PR creation requires `delivery_enabled: true`; the control plane submits asynchronous merges only after explicit `auto_merge: true` repository opt-in and deterministic policy checks, then reconciles GitHub's final merged state.
- Hybrid workers receive scoped bearer credentials. The control plane holds GitHub App credentials; CLI/Git credentials stay on each worker host.
