# Learning log

- 2026-10-18: Local Codex CLI is 0.155.0-alpha.16 and supports `codex exec --json --sandbox`; Claude CLI is absent locally, so its adapter is implemented from official CLI documentation and needs live validation.
- 2026-10-18: On this macOS setup, Python skipped a `uv` editable-install `.pth` file with the filesystem `hidden` flag. Clearing that flag restored `adp` imports. The packaged wheel includes all role profiles and avoids that editable-install dependency.
- 2026-10-18: The real threat-model verifier accepted a generated schema-version-2 fixture through the adapter; a syntactically valid fixture does not establish a secure design.
- 2026-10-18: Keep conversational backlog planning in one repo-scoped Codex skill. A GitHub issue edit to an unmerged ticket triggers control-plane replanning, and `project_id` filters out new issues until they join the configured Project.
- 2026-10-18: Safe stop uses a fenced worker yield: unfinished jobs return to the queue at the same revision, while completed stages and issue worktrees supply durable resume points. Yielded jobs retain worker affinity because partial files are host-local; abrupt loss relies on lease expiry and manual affinity release is available for permanent host loss.
- 2026-10-18: Local startup is a manual, one-command script that reuses the Compose PostgreSQL volume, preserves a saved pause by default, and runs the host worker in the foreground. Explicit `--resume` is required to clear a global pause; hybrid workers can use `--worker-only` without local Docker.
