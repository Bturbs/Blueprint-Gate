# Repository policy examples

The `policy` object supplied to `POST /repositories` chooses CLI routing. The examples below assume the corresponding CLI is installed and authenticated on the worker host. No API-billed provider fallback is implemented.

## Codex only

```json
{
  "routing": {"default_provider": "codex", "allowed_providers": ["codex"]},
  "required_checks": [["python", "-m", "pytest"]],
  "required_ci_checks": ["tests"],
  "delivery_enabled": false
}
```

## Claude only

```json
{
  "routing": {"default_provider": "claude", "allowed_providers": ["claude"]},
  "required_checks": [["python", "-m", "pytest"]],
  "required_ci_checks": ["tests"],
  "delivery_enabled": false
}
```

## Split roles with approved fallback

```json
{
  "data_classification": "internal",
  "routing": {
    "default_provider": "codex",
    "roles": {"architect": "claude", "threat_modeler": "claude", "qa": "claude"},
    "allowed_providers": ["codex", "claude"],
    "provider_classifications": {"codex": ["public", "internal"], "claude": ["public", "internal"]},
    "fallback": {"enabled": true, "order": ["codex", "claude"]}
  },
  "required_checks": [["python", "-m", "pytest"]],
  "required_ci_checks": ["tests"],
  "delivery_enabled": false
}
```

Each worker maps the GitHub repository to a **local** checkout in `worker.yaml`. The root model can live in that worktree or a separate repository configured under `threat_repository` with `full_name`, `path`, `worktrees`, and `root_model`. Set `threat_model_pr_required: true` in policy to require a separate PR approved on the exact model commit. The default `threat_model_merge_timing` is `before_engineering`; `before_final_merge` permits engineering after PR approval, while the final application merge still waits for the model PR to merge. If the model or verifier is missing, the threat stage fails closed. The worker rejects newly marked `inPlace: true` controls during design review.

Local and hybrid workers both require individual scoped credentials. Register the repository first, then issue a credential through `POST /workers/credentials` with a JSON body such as `{"worker_id":"host-1","repositories":["example/project"],"capabilities":["git","codex"],"expires_at":"2026-11-01T12:00:00Z"}`. Choose an expiry in the future and no more than 30 days away. The raw token is returned once; keep it outside the checkout and provide it through `worker_token_env` (the example uses `ADP_WORKER_TOKEN`). Inline `worker_token` in worker YAML is rejected. The server no longer accepts a shared `WORKER_TOKEN`. For hybrid deployment, host the control image and PostgreSQL behind HTTPS, set `HYBRID_MODE=true`, and point the worker's `control_url` at that URL. Revoke a credential through `POST /workers/credentials/{id}/revoke`. Rotation uses `POST /workers/credentials/{id}/rotate` with a new `expires_at`; pause all workers and wait for that worker's active job to yield first. Rotation preserves its ID, scope, capabilities, and worktree affinity, and invalidates the previous token immediately.

The worker heartbeat checks the global and repository pause flags every ten seconds while a job runs. The host CLI uses its existing `CONTROL_TOKEN` environment variable to request `pause`, `resume`, or `control-status`; this admin credential remains separate from the worker token. A paused worker yields its unfinished job and exits. Keep its `worker_id` and checkout path stable when restarting so it can reclaim its partial worktree. See [operations](OPERATIONS.md).

Set `GITHUB_TOKEN` for local control-plane GitHub operations, or set `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_PRIVATE_KEY_PATH`. Mount the private key outside the repository into the control container. Worker hosts keep their own `gh`/Git credentials for branch pushes and PR creation. `project_id` in policy limits discovery to issues in a GitHub Project; `project_status_field_id` and `project_status_options` map internal ticket states to GitHub single-select option IDs.

The interactive `$github-spec-workflow` skill uses the local host's authenticated `gh` session to read, create, and edit issues. It does not use or receive the control plane's `GITHUB_TOKEN` or GitHub App private key. Install the skill in the target repository checkout. If `project_id` limits automated discovery, ensure newly created issues join that Project; a GitHub issue outside it will not become a platform ticket. The skill can plan work before the repository is registered, but automated jobs begin only after registration and polling.

Set a unique random `GITHUB_WEBHOOK_SECRET` to enable `POST /webhooks/github`, and configure the same secret on the GitHub App or repository webhook. Keep it in host secret storage, outside the repository, readable only by the service account. The endpoint verifies `X-Hub-Signature-256`, checks the event against the signed payload shape, and atomically rejects repeated delivery IDs or identical signed payloads even when the delivery ID changes. It reconciles issue, pull-request, and Projects item events. Polling remains the fallback. `GITHUB_WEBHOOK_PREVIOUS_SECRET` is accepted only before `GITHUB_WEBHOOK_PREVIOUS_UNTIL` (UTC ISO 8601); use both only during a short rotation overlap.

`delivery_enabled` controls implementation PR creation. `auto_merge` is a separate explicit repository opt-in requiring `required_ci_checks`. Merge requests use GitHub's async API with `merge_action: default`; the ticket becomes `MERGED` only after reconciliation confirms GitHub's merged state. `MERGE_FAILED` and `MERGE_UNKNOWN` require operator inspection. Configure `max_code_iterations` and `max_job_attempts` for bounded review remediation and failed-job retries.
