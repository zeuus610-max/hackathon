# Agent collaboration workflow

This repository coordinates work across Codex Desktop, Antigravity, and OpenCode. The repository is the shared source of truth; it does not launch or synchronize desktop agents by itself.

## Agent roles

| Agent | Default responsibility |
| --- | --- |
| Codex Desktop | Coordinate issue scope, split work, and integrate reviewed changes. |
| Antigravity | Take an implementation issue and deliver it on an isolated branch. |
| OpenCode | Review another agent's pull request or take an explicitly assigned implementation issue. |

Any agent can implement or review when the issue names it as owner or reviewer. Keep one implementation owner per issue; the other agents can review or take separate, non-overlapping issues.

## Start and hand off work

1. Create a GitHub issue with context, acceptance criteria, affected areas, and dependencies. Record the owner as `Codex Desktop`, `Antigravity`, or `OpenCode` in the issue.
2. Each agent uses its own clone or worktree. Before editing, fetch the latest `main` and create a branch such as `agent/opencode/issue-12-add-login`.
3. Keep one issue per branch. If another agent is already changing the same area, coordinate in the issue and wait or choose a separate task.
4. Commit focused changes, push the branch, and open a pull request that links the issue. The pull request description records the agent/tool, summary, affected areas, and validation.
5. A different agent reviews the pull request and leaves findings there. The implementation owner addresses them, then the project owner merges the reviewed pull request.
6. Start follow-up work from the updated `main`; do not copy unmerged changes between agents' checkouts.

## Working agreement

- Keep decisions, blockers, and task status in the GitHub issue or pull request so all three tools can see them.
- Avoid concurrent edits to the same branch or checkout. Use separate branches even when multiple tools run on one machine.
- Do not push directly to `main`, force-push shared branches, or merge your own pull request without an explicit project decision.
- Report what changed and what was or was not verified. Until project commands are documented in `README.md`, do not claim builds or tests passed.
- Never put credentials, API keys, or private user data in issues, commits, or pull request text.
