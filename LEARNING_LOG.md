# Learning log

- 2026-10-18: Local Codex CLI is 0.155.0-alpha.16 and supports `codex exec --json --sandbox`; Claude CLI is absent locally, so its adapter is implemented from official CLI documentation and needs live validation.
- 2026-10-18: On this macOS setup, Python skipped a `uv` editable-install `.pth` file with the filesystem `hidden` flag. Clearing that flag restored `adp` imports. The packaged wheel includes all role profiles and avoids that editable-install dependency.
- 2026-10-18: The real threat-model verifier accepted a generated schema-version-2 fixture through the adapter; a syntactically valid fixture does not establish a secure design.
