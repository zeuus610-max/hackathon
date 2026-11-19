# Agent instructions

## Shared workflow

- Read `docs/agent-workflow.md` before starting project work.
- Work from an issue with acceptance criteria and a single named owner agent.
- Use a separate checkout and branch per agent. Never have two agents edit the same checkout or work directly on `main`.
- Keep changes within the issue scope. Coordinate overlapping work through the issue before editing shared files.
- Push your branch and open a pull request that links the issue; include the agent/tool name and validation performed.
- Review the current diff and report blockers or unverified behavior in the pull request.

## Project commands

- The application stack and canonical commands are not set yet. Read `README.md` and update it when the first implementation issue establishes them.
- Do not invent setup, lint, build, or test commands. Do not add or run tests unless the user asks.

## Key conventions

- Keep GitHub issues as the task source of truth and pull requests as the handoff record.
- Never commit secrets, local environment files, or generated credentials.
- Keep tool-specific behavior in the shared workflow unless a platform requires a small adapter.

## Commit attribution

AI-authored commits should include a `Co-Authored-By` trailer identifying the agent and model when supported.
