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

The worker sends the issue body only to the product-owner stage. Later stages receive selected approved artifacts and security findings needed for their role; project metadata, unrelated artifact keys, and raw prior check output are omitted from the automatic prompt. This reduces prompt disclosure but does not constrain files that a provider CLI can read from its checkout. Classify the repository and approve each provider in `routing.provider_classifications` before using a worker with sensitive source. Put secret-bearing files outside provider-visible worktrees and use worker-host filesystem isolation where a provider must not read a data class.

Set each repository's local `check_image` to a preloaded Docker image pinned by SHA-256 digest before running engineer, QA, or security checks. The image must include the required command and dependencies. Checks run as an unprivileged user with only the current issue worktree mounted read-only, no network, and a small temporary filesystem; they cannot use host virtual environments, write artifacts back into the worktree, or follow a linked worktree's `.git` pointer to host metadata. Select check commands that work within that boundary. Missing images or Docker cause checks to fail closed. Provider CLIs, the threat-model verifier, and Git delivery still run on the worker host, so this check boundary does not replace a disposable worker host.

Local and hybrid workers both require individual scoped credentials. Register the repository first, then issue a credential through `POST /workers/credentials` with a JSON body such as `{"worker_id":"host-1","repositories":["example/project"],"capabilities":["git","codex"],"expires_at":"2026-11-01T12:00:00Z"}`. Choose an expiry in the future and no more than 30 days away. The raw token is returned once; keep it outside the checkout and provide it through `worker_token_env` (the example uses `ADP_WORKER_TOKEN`). Inline `worker_token` in worker YAML is rejected. The server no longer accepts a shared `WORKER_TOKEN`. For hybrid deployment, host the control image and PostgreSQL behind HTTPS, set `HYBRID_MODE=true`, and point the worker's `control_url` at that URL. Revoke a credential through `POST /workers/credentials/{id}/revoke`. Rotation uses `POST /workers/credentials/{id}/rotate` with a new `expires_at`; pause all workers and wait for that worker's active job to yield first. Rotation preserves its ID, scope, capabilities, and worktree affinity, and invalidates the previous token immediately.

Worker and admin clients require a control URL containing only an origin. HTTP is accepted for the exact loopback hostnames `127.0.0.1` and `localhost`; all remote hosts require HTTPS. The in-container scheduler has one explicit exception for `http://control:8000` on the private Compose network. A private staging CA must be supplied to the worker's HTTP client through `SSL_CERT_FILE` or `SSL_CERT_DIR`. The local TLS proxy example in [operations](OPERATIONS.md) exposes only worker job routes and keeps administration on loopback.

The worker heartbeat checks the global and repository pause flags every ten seconds while a job runs. The host CLI uses its existing `CONTROL_TOKEN` environment variable to request `pause`, `resume`, or `control-status`; this admin credential remains separate from the worker token. A paused worker yields its unfinished job and exits. Keep its `worker_id` and checkout path stable when restarting so it can reclaim its partial worktree. See [operations](OPERATIONS.md).

Set `GITHUB_TOKEN` only for local control-plane GitHub operations. Hybrid mode requires `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_PRIVATE_KEY_PATH` and rejects a personal token, including explicit client overrides. Do not set App credentials and `GITHUB_TOKEN` together. Install the App only on repositories that the control plane must read or update and grant only the corresponding GitHub permissions. Mount its private key outside the repository into the control container; rotate the key through the GitHub App settings and replace the mount when needed. The App installation token is fetched by the control API and cached only until shortly before expiry. Worker hosts keep their own `gh`/Git credentials for branch pushes and PR creation. `project_id` in policy limits discovery to issues in a GitHub Project; `project_status_field_id` and `project_status_options` map internal ticket states to GitHub single-select option IDs.

For a Compose deployment using the App, set `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, and `GITHUB_APP_PRIVATE_KEY_FILE` (an absolute host path to the PEM file), leave `GITHUB_TOKEN` empty, and run `docker compose -f compose.yaml -f compose.github-app.yaml up -d --build`. The overlay sets hybrid mode, removes the personal token from the control container environment, and mounts the PEM read-only at `GITHUB_PRIVATE_KEY_PATH`. Keep the PEM outside repository checkouts and readable only by the operator and control container.

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

Set a unique random `GITHUB_WEBHOOK_SECRET` to enable `POST /webhooks/github`, and configure the same secret on the GitHub App or repository webhook. Keep it in host secret storage, outside the repository, readable only by the service account. The endpoint verifies `X-Hub-Signature-256`, checks the event against the signed payload shape, and atomically rejects repeated delivery IDs or identical signed payloads even when the delivery ID changes. It reconciles issue, pull-request, and Projects item events. Polling remains the fallback. `GITHUB_WEBHOOK_PREVIOUS_SECRET` is accepted only before `GITHUB_WEBHOOK_PREVIOUS_UNTIL` (UTC ISO 8601); use both only during a short rotation overlap.

`delivery_enabled` controls implementation PR creation. `auto_merge` is a separate explicit repository opt-in requiring `required_ci_checks`. Merge requests use GitHub's async API with `merge_action: default`; the ticket becomes `MERGED` only after reconciliation confirms GitHub's merged state. `MERGE_FAILED` and `MERGE_UNKNOWN` require operator inspection. Configure `max_code_iterations` and `max_job_attempts` for bounded review remediation and failed-job retries.
