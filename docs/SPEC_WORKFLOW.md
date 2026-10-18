# Conversational GitHub specification workflow

Describe what you want to build in Codex chat and invoke `$github-spec-workflow`. You can start with a rough idea. The same skill handles backlog planning, later specification work, and PR handoff; it does not force all stages into one conversation.

For example: “Use `$github-spec-workflow` in `OWNER/REPO`. I want to build [idea]. Review the existing tickets, update overlaps, and create tickets for missing parts.”

The skill is stored at `.agents/skills/github-spec-workflow/SKILL.md` in this repository. For another target repository, copy that directory to its `.agents/skills/` and add an equivalent trigger to its `AGENTS.md`. Use the target repository's checkout for the conversation so issue lookup and local specifications refer to the same project.

## Ticket reconciliation

The skill reads open and closed issues in the target repository, searches for related work, and checks likely matches in detail. It discusses the desired outcome and missing product decisions with you, then maps each part of the idea to an existing ticket to extend, a new ticket to create, delivered work, or an unresolved decision. It prepares a concise change map and full issue bodies before editing GitHub. When you have asked it to organize the backlog, it applies the edits and creates the missing tickets after material scope questions are resolved. A brainstorm or draft request leaves GitHub unchanged.

Existing issue intent and discussion stay intact. The skill rereads tickets before editing to catch concurrent changes, and it checks returned URLs to avoid duplicate creates on retries. Ticket bodies include testable `AC-*` criteria and `Depends on #N` lines where the platform needs dependencies. GitHub Issues remain the requested-scope record; Project membership and status change only when requested or required by established repository workflow.

If control-plane policy has a `project_id`, its poller only ingests issues present in that GitHub Project. The skill must verify that newly created issues are added before claiming they entered the automated queue. When a registered repository is polled, a new visible issue queues Product Owner work. An edit to an unmerged issue cancels queued or running jobs, clears prior security approval, and queues a new Product Owner stage. Coordinate edits to active tickets when timing matters.

## Specs and delivery

For a ticket ready to refine, the skill writes `specs/ISSUE-N/requirements.md`, then `design.md` and `tasks.md` when the requirements are settled. Requirements record the issue URL and `updatedAt` so later work can detect scope drift. Design maps each `AC-*` criterion to a decision; tasks use stable `T-*` IDs, dependencies, and verification evidence. At implementation handoff, the skill compares issue, specs, PR diff, checks, and acceptance evidence.

The automated worker already produces files with these names through its Product Owner and Architect stages. When a worker owns the ticket, update the GitHub issue and let that worker regenerate specs in its issue worktree. For manual work, use the skill to refine specs in the relevant branch or worktree. The skill does not call control-plane approval or merge APIs; its GitHub edits can trigger replanning on the next poll. Root threat-model verification, revision-bound security approval, code dispatch, CI, and merge eligibility remain enforced by the platform.

## Local and hybrid use

Use `gh auth status` and `gh repo view --json nameWithOwner,url` in the target checkout to verify host access. Install the skill in each target repository checkout where a Codex session will run, including a remote worker host if you use Codex interactively there. Keep GitHub and Git credentials on that host. The remote control plane does not need the CLI credentials. Claude Code workers continue to use the platform role profiles; this Codex skill is not assumed to load in Claude Code.
