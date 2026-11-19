# Orbit

Orbit is a request-time gate concept for sensitive vendor bank changes. It checks identity and credential, permission for the specific vendor and field, Finance approval for the exact new details, and risk context. A failed check should hold the request, alert a reviewer, and preserve the linked evidence.

The CR-26-047 prototype demonstrates a read-only review of the supplied synthetic case. It does not modify a payment or vendor record, identify an attacker, or claim that funds moved.

## Start here

1. Open this repository in your coding tool and read [`AGENTS.md`](AGENTS.md) and [`docs/agent-workflow.md`](docs/agent-workflow.md).
2. Create or pick up a GitHub issue with clear acceptance criteria and one named agent owner.
3. Work on that issue from your own checkout and branch, then open a pull request.

## Stack and local setup

The app uses FastAPI and SQLite for the evidence API and a static HTML, CSS, and JavaScript interface.

```sh
python3 -m venv traceguard/.venv
source traceguard/.venv/bin/activate
python -m pip install -r traceguard/requirements.txt
python -m uvicorn server.main:app --app-dir traceguard --reload
```

Open `http://127.0.0.1:8000` for the Orbit landing page or `http://127.0.0.1:8000/review/` for the CR-26-047 case review. The server loads the evidence package from `evidence/` at startup and writes its local SQLite database to `traceguard/traceguard.db`.

No lint or test command is defined yet. Do not add or run tests unless the task asks for them.

## Collaboration

GitHub issues are the shared task board; branches and pull requests are the handoff and review trail. See [`docs/agent-workflow.md`](docs/agent-workflow.md) for the working agreement.
