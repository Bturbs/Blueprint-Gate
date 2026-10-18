# Issue #1 threat assessment handoff

Design source: `specs/ISSUE-1/design.md`, SHA-256 `832657bbebc4aaed2d79b454f2217e664c188ef68510bf29d6b52949e622a275`.

Model source: `Bturbs/Threat-Models/threatModels/BlueprintGate/BlueprintGate.yaml`, local SHA-256 `26b18158c039b80a1fdbb1fa2c027b86aa688381b027103672f98a6b28e16619`. The authoritative checkout is outside this worker's writable root. The incremental update is in `threatModels/BlueprintGate/BlueprintGate.yaml` here, with an apply-ready `BlueprintGate-model.patch` and one proposed-flow sequence diagram. The patch passed `git apply --check` against the source checkout. The updated root passed the threat-model-tool verifier: 5 objectives, 24 assets, 4 attackers, 15 threats, 33 countermeasures.

The existing model records partial staging isolation: a dedicated Lima VM and constrained agent filesystem view, while provider egress remains unrestricted and no normal issue job has completed there. The design proposes a new per-claim guest, trusted supervisor, fenced egress proxy, temporary provider and repository grants, and checkpoint recovery. No proposed control was marked in place; `ISSUE_PROMPT_INJECTION`, `GUEST_EGRESS_BYPASS`, and `GUEST_OUTPUT_BOUNDARY` remain `fullyMitigated: false`.

## Boundaries and findings

| ID | Threat | Assessment | Required engineering control |
| --- | --- | --- | --- |
| TM-ISSUE-1-01 | `ISSUE_PROMPT_INJECTION` | The design covers the host escape path, but existing host commands and incomplete staging remain a critical exposure until every CLI, Git operation, verifier, check, and descendant is proven to run in the disposable guest. The guest must not receive administrator or worker-control secrets. | `ENFORCE_DISPOSABLE_GUEST`, `RESTRICT_JOB_CREDENTIALS` |
| TM-ISSUE-1-02 | `GUEST_EGRESS_BYPASS` | The proposed proxy is the new network trust boundary. It must block direct routes, private and host services, DNS/redirect/port bypasses, and stale-fence traffic across both provider routes. | `ENFORCE_FENCED_EGRESS` |
| TM-ISSUE-1-03 | `GUEST_OUTPUT_BOUNDARY` | Guest results and checkpoints are attacker-controlled data crossing back to supervisor authority. Authentication, schema/size limits, revision/fence binding, and safe same-lineage restore are required; isolation records must be supervisor-created. | `VALIDATE_GUEST_PROTOCOL`, `BOUND_CHECKPOINT_RECOVERY` |

The existing `CONFIDENTIALITY`, `INTEGRITY`, and `AUTHORIZED_DISPATCH` objectives and `ISSUE_AUTHOR` attacker are reused. Changed assets are `HOST_WORKER`, `ISOLATED_JOB_GUEST`, `JOB_EGRESS_PROXY`, `GUEST_JOB_CHANNEL`, `JOB_EGRESS`, `JOB_CHECKPOINT`, `ISOLATION_RECORD`, and `JOB_CREDENTIAL_GRANT`. The guest-to-supervisor, proxy-to-provider/GitHub, and checkpoint-to-new-guest flows are proposed, not deployed.

## Acceptance blocker

The job prompt supplies `Allowed required checks: []`. `complete_stage` rejects every mitigation requirement whose `check_command` is absent from that policy allowlist. The requested nonempty `mitigation_requirements` therefore cannot be submitted validly until a policy owner approves at least one command, such as the documented `['python', '-m', 'pytest']`, and the relevant isolation tests are implemented. Deployment hostile-fixture and normal-ticket evidence remain necessary beyond unit tests. The current design revision number was not included in the prompt; `linked_design_revision` should use the ticket's actual database value when resuming.
