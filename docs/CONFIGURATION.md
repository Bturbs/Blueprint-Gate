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

The worker heartbeat checks the global and repository pause flags every ten seconds while a job runs. The host CLI uses its existing `CONTROL_TOKEN` environment variable to request `pause`, `resume`, or `control-status`; this admin credential remains separate from the worker token. A paused worker yields its unfinished job and exits. Keep its `worker_id` and checkout path stable when restarting so it can reclaim its partial worktree. See [operations](OPERATIONS.md).

Set `GITHUB_TOKEN` only for local control-plane GitHub operations. Hybrid mode requires `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_PRIVATE_KEY_PATH` and rejects a personal token, including explicit client overrides. Do not set App credentials and `GITHUB_TOKEN` together. Install the App only on repositories that the control plane must read or update and grant only the corresponding GitHub permissions. Mount its private key outside the repository into the control container; rotate the key through the GitHub App settings and replace the mount when needed. The App installation token is fetched by the control API and cached only until shortly before expiry. Worker hosts keep their own `gh`/Git credentials for branch pushes and PR creation. `project_id` in policy limits discovery to issues in a GitHub Project; `project_status_field_id` and `project_status_options` map internal ticket states to GitHub single-select option IDs.

For a Compose deployment using the App, set `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_APP_PRIVATE_KEY_FILE` (an absolute host path to the PEM file), leave `GITHUB_TOKEN` empty, and run `docker compose -f compose.yaml -f compose.github-app.yaml up -d --build`. The overlay sets hybrid mode, removes the personal token from the control container environment, and mounts the PEM read-only at `GITHUB_PRIVATE_KEY_PATH`. Keep the PEM outside repository checkouts and readable only by the operator and control container.

For restarts through `scripts/start.sh`, set `GITHUB_APP_PRIVATE_KEY_FILE` in `.env` or the shell; the script selects the App overlay automatically. If using the separate local TLS overlay, set `BLUEPRINT_LOCAL_TLS=true` as well. The script rejects a missing PEM or TLS overlay before starting Compose.

For a GitHub App installation, select only the application and threat-model repositories registered with Blueprint Gate. Use this permission budget and remove conditional permissions when the corresponding feature is disabled:

| Process | Permission | When required |
| --- | --- | --- |
| Control App | Metadata: read; Issues: read | Repository discovery and issue polling. |
| Control App | Pull requests: read | Threat-model review and engineering PR reconciliation. |
| Control App | Pull requests: write; Checks: read | Automatic merge is explicitly enabled for a repository. |
| Control App | Organization or repository Projects: read/write | Only when Projects status reconciliation is configured; read is enough for membership-only discovery. |
| Worker Git/`gh` identity | Contents: write; Pull requests: write | Only for repositories where `delivery_enabled` permits branch pushes and PR creation. |

Store each worker's Git/`gh` identity on that worker host with access only to its assigned repositories. Do not mount the control App key or token on worker hosts. For rotation, create a replacement App private key, update the control mount, restart the control process, and verify an authenticated poll before deleting the old key. Revoke a compromised App installation or remove affected repositories from its installation immediately; rotate worker Git/`gh` credentials at their issuer and replace them on the affected host. Recheck branch and PR operations with the replacement worker credential. Record the installed repositories, granted permissions, and last rotation in the deployment runbook. GitHub's [App permission reference](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps) and [installation token guide](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) are the source of truth when configuring the installation.

`scripts/start.sh` removes control-plane credentials from its environment before launching the host worker. Authenticate the worker's own `gh`/Git identity on that host; do not rely on the control plane's `GITHUB_TOKEN` for worker branch or PR operations.

The interactive `$github-spec-workflow` skill uses the local host's authenticated `gh` session to read, create, and edit issues. It does not use or receive the control plane's `GITHUB_TOKEN` or GitHub App private key. Install the skill in the target repository checkout. If `project_id` limits automated discovery, ensure newly created issues join that Project; a GitHub issue outside it will not become a platform ticket. The skill can plan work before the repository is registered, but automated jobs begin only after registration and polling.

Set `GITHUB_WEBHOOK_SECRET` to enable `POST /webhooks/github` in hybrid deployments, and configure the same secret on the GitHub App/webhook. The endpoint verifies `X-Hub-Signature-256`, rejects duplicate delivery IDs, and reconciles issue, pull-request, and Projects item events. Polling remains the fallback.

`delivery_enabled` controls implementation PR creation. `auto_merge` is a separate explicit repository opt-in requiring `required_ci_checks`. Merge requests use GitHub's async API with `merge_action: default`; the ticket becomes `MERGED` only after reconciliation confirms GitHub's merged state. `MERGE_FAILED` and `MERGE_UNKNOWN` require operator inspection. Configure `max_code_iterations` and `max_job_attempts` for bounded review remediation and failed-job retries.
