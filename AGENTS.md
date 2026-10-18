# Repository conventions

- Keep control-plane provider-independent; add new model CLIs only behind `AgentRuntime`.
- Keep provider CLI credentials and repository checkouts on worker hosts.
- All code dispatch must pass the current revision's security gate.
- Never claim a threat control is in place without implementation evidence.
- Never add an automatic merge path without an explicit repository opt-in and GitHub protection checks.

## Spec workflow skill

- In human-driven Codex sessions, use `$github-spec-workflow` to discuss a build idea, reconcile existing GitHub tickets, create missing tickets, refine specifications, or prepare a spec-driven PR handoff.
- This skill does not replace the platform's threat-model verification, revision-bound security approval, or merge policy.
