# Issue #1 — Isolate work driven by untrusted issues and repositories

## Business context

Blueprint Gate runs coding CLIs and repository commands for GitHub issues. An issue author can place hostile instructions in an issue or checkout. Prompt instructions label that content untrusted, but the worker currently runs commands with its host user's access. The desired outcome is an enforced execution boundary that limits the effects of a successful prompt injection. The referenced threat is `ISSUE_PROMPT_INJECTION` in the [Blueprint Gate threat model](https://github.com/Bturbs/Threat-Models/blob/main/threatModels/BlueprintGate/BlueprintGate.yaml).

## Functional requirements

- **FR-1:** Run every issue or repository driven CLI, Git command, required check, verifier, and child process inside a dedicated disposable worker identity or VM. Provide access to the active checkout and only the temporary files needed for that job. Preserve valid interrupted work through an explicit, bounded recovery mechanism.
- **FR-2:** Enforce filesystem and process isolation so the job cannot read or change sibling checkouts, host home directories, control-plane data, administrator secrets, or other workers' processes. Apply the boundary to subprocesses and to both supported CLI providers.
- **FR-3:** Deny outbound connections by default. Permit only documented destinations needed for the approved model provider, scoped worker control channel, and authorized repository operations; block arbitrary internet, private-network, and host-service access.
- **FR-4:** Supply only the credentials required for the active job, scoped to its repository and role where supported. Keep control-plane administrator credentials and unrelated provider or GitHub credentials outside the boundary. Remove job credentials and disposable state when the job ends.
- **FR-5:** Fail closed when isolation, mounts, credential scoping, or outbound policy cannot be established. Record which boundary and policy were applied to each job without logging secret values.
- **FR-6:** Preserve the provider-independent control plane, `AgentRuntime` boundary, current-revision security gate, and existing repository opt-in and GitHub protection checks for any merge path.
- **FR-7:** Link implementation, deployment configuration, and verification evidence to this issue. Reconcile its `ticketLink` and control status in the Threat-Models repository, run root-model verification, and set `fullyMitigated: true` only after the deployed control is evidenced and no material gap remains.

## Non-functional requirements

- The boundary must hold against commands initiated by the model, build or test scripts, and other descendants of the job process.
- Isolation must be observable and repeatable in the intended deployment, including after worker restart or job retry. Documentation alone is insufficient evidence.
- Legitimate issue processing must remain usable through the normal security approval, validation, and PR workflow.
- Logs and test artifacts must avoid exposing credentials or unrelated host data.

## Assumptions

- The deployment may choose a disposable VM or an equivalently enforced disposable identity, provided the acceptance tests demonstrate the same boundary.
- Provider and GitHub access may require outbound connections and job-scoped credentials; their exact destinations and credential mechanism will be documented during design.
- The existing `MARK_UNTRUSTED_INPUT` source-baseline entry does not establish that `ISOLATE_UNTRUSTED_WORK` is deployed or effective. The current repository documentation describes worker-host isolation as a deployment responsibility.

## Exclusions

- Eliminating all misleading model output or guaranteeing that generated code is correct.
- Granting automatic merge permission or bypassing revision-bound security approval.
- Marking controls implemented solely because a configuration example or operating instruction exists.

## Testable acceptance criteria

- **AC-1:** Deployment evidence shows an issue job and every command it launches running in a dedicated disposable boundary with access to the active checkout only; restart and retry behavior preserves authorized progress without exposing another job's files.
- **AC-2:** A hostile issue and repository fixture attempts to read host canaries, a sibling checkout, administrator credentials, and another worker's process data. Each attempt fails, and the canaries remain unchanged.
- **AC-3:** The same fixture attempts outbound access to an unapproved internet endpoint, a private-network service, and a host service. Each attempt fails; documented approved destinations remain usable.
- **AC-4:** A missing or invalid isolation policy prevents job execution and produces a reviewable failure record without disclosing secrets.
- **AC-5:** A normal ticket completes its approved stages, required checks, and PR handoff within the boundary while the current-revision security gate and merge protections remain enforced.
- **AC-6:** This issue links the deployed configuration, implementation, hostile-fixture results, and normal-ticket results. The Threat-Models repository records the correct `ticketLink`, evidence-backed control status, residual risks, and a passing root-model verification. `fullyMitigated` remains false if any material boundary gap remains.