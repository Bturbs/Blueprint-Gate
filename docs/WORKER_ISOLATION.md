# Disposable worker isolation

The worker dispatcher will not execute an issue-controlled command, Git command, required check, verifier, or provider CLI on its own host. A valid `isolation` block is required in `worker.yaml`; otherwise dispatch fails before an envelope is sent or a checkout is touched.

The configured VM supervisor receives a bounded job envelope containing the job ID, ticket ID, stage, revision, fencing token, active repository identity, policy digest, image digest, stage-specific destination names, credential-grant identifiers, and bounded task data. It must create one guest VM for that claim and run all repository work there. The guest response is rejected unless its job, stage, revision, fence, and policy digest match the envelope.

The dispatcher accepts only a version-1 policy with all of the following:

- `backend: vm`, a pinned SHA-256 guest image, and an empty mount manifest;
- no direct guest route, an HTTPS egress proxy, and a nonempty concrete-DNS allowlist per stage;
- positive CPU, memory, disk, process, runtime, and checkpoint limits;
- credential grant identifiers only. Tokens, passwords, and secret values are rejected from policy files.

The supervisor must enforce those settings rather than relying on guest cooperation: no host mounts or sockets, a separate kernel/process tree and writable job disk, proxy-only egress, metadata/private/host-service denial, and grant revocation before VM teardown. It must bind proxy grants to the job and fence and reject stale guests. It must keep administrator, control-plane, unrelated GitHub, and unrelated provider credentials out of the guest.

The worker calls `DELETE /v1/disposable-jobs/{job_id}` when a job returns, is cancelled, loses its claim, or is paused. A successful completion stores an `isolation_records` row with supervisor-produced boundary, policy/image/mount digests, egress profile, credential-grant identifiers, checkpoint digest, and teardown result. No secret values or guest command output are stored there.

Checkpoints are opaque data handled by the supervisor. Restore only after it has checked ticket, repository, stage/revision lineage, digest, size, and retention; never unpack or execute a checkpoint on the dispatcher host. A teardown failure is recorded as unverified and requires supervisor reconciliation before it can be used as mitigation evidence.

Before deployment, populate the allowlists from staging observations and run the hostile fixture: attempts to read host/sibling/admin/process canaries and to reach arbitrary, private, link-local, and host destinations must fail. Also run pause/retry/fallback and a normal approved ticket through required checks and PR handoff. These deployment results, image/policy/proxy digests, and the supervisor teardown evidence are required before marking `ISOLATE_UNTRUSTED_WORK` effective or setting the related threat model to fully mitigated.
