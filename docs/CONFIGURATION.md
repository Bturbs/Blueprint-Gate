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

For hybrid deployment, host the control image and PostgreSQL behind HTTPS, set `HYBRID_MODE=true`, and point the local worker's `control_url` at that URL. Issue an individual credential through `POST /workers/credentials` with a JSON body such as `{"worker_id":"host-1","repositories":["example/project"],"capabilities":["git","codex"]}`. The raw token is returned once; store it on that worker and reference it with `worker_token_env`. Revoke it through `POST /workers/credentials/{id}/revoke`. Hybrid mode refuses the shared `WORKER_TOKEN`.

Set `GITHUB_TOKEN` for local control-plane GitHub operations, or set `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_PRIVATE_KEY_PATH`. Mount the private key outside the repository into the control container. Worker hosts keep their own `gh`/Git credentials for branch pushes and PR creation. `project_id` in policy limits discovery to issues in a GitHub Project; `project_status_field_id` and `project_status_options` map internal ticket states to GitHub single-select option IDs.

The interactive `$github-spec-workflow` skill uses the local host's authenticated `gh` session to read, create, and edit issues. It does not use or receive the control plane's `GITHUB_TOKEN` or GitHub App private key. Install the skill in the target repository checkout. If `project_id` limits automated discovery, ensure newly created issues join that Project; a GitHub issue outside it will not become a platform ticket. The skill can plan work before the repository is registered, but automated jobs begin only after registration and polling.

Set `GITHUB_WEBHOOK_SECRET` to enable `POST /webhooks/github` in hybrid deployments, and configure the same secret on the GitHub App/webhook. The endpoint verifies `X-Hub-Signature-256`, rejects duplicate delivery IDs, and reconciles issue, pull-request, and Projects item events. Polling remains the fallback.

`delivery_enabled` controls implementation PR creation. `auto_merge` is a separate explicit repository opt-in requiring `required_ci_checks`. Merge requests use GitHub's async API with `merge_action: default`; the ticket becomes `MERGED` only after reconciliation confirms GitHub's merged state. `MERGE_FAILED` and `MERGE_UNKNOWN` require operator inspection. Configure `max_code_iterations` and `max_job_attempts` for bounded review remediation and failed-job retries.
