# Orbit — CR-26-047 Defense Console

Orbit is a local demonstration of a zero-trust request gate for sensitive vendor changes, plus an evidence-led review of the supplied synthetic CR-26-047 case. It combines the existing FastAPI evidence service with a React/Vite investigation console and the Orbit presentation.

The detection console demonstrates request scoring, twin-record receipt checks, a deterministic legacy-key canary, clock uncertainty, and persistent evaluation history. It does not sit in a production API path, change vendor or payment records, or identify an attacker. Validation values are user-entered demonstration data unless independently measured.

## Architecture

- `traceguard/server/` — FastAPI routes, evidence ingestion, UTC/clock handling, detections, SQLAlchemy-backed SQLite persistence for interactive state, and request simulation.
- `traceguard/frontend/` — React, Vite, Tailwind CSS, Recharts, Framer Motion, and Lucide-based five-section console.
- `traceguard/web/` — static Orbit presentation and read-only historical review; Vite production output is built to `web/console/`.
- `evidence/` — source case records. Original timestamps and missing telemetry remain visible in the evidence model.
- `traceguard/supabase/schema.sql` — optional Supabase persistence schema.

## Prerequisites

- Python 3.11 or newer.
- Node.js 20 or newer and npm.

## Local development

Install and start the backend from the repository root:

```sh
python3 -m venv traceguard/.venv
source traceguard/.venv/bin/activate
python -m pip install -r traceguard/requirements.txt
python -m uvicorn server.main:app --app-dir traceguard --reload --port 8000
```

In another terminal, start the React console:

```sh
cd traceguard/frontend
npm install
npm run dev
```

Open `http://localhost:5173` for the five-section defense console. Vite proxies `/api` to the backend at `http://127.0.0.1:8000`.

The existing Orbit overview is at `http://localhost:8000/`; the read-only case review is at `http://localhost:8000/review/`.

## Production-style local build

```sh
cd traceguard/frontend
npm run build
cd ../..
traceguard/.venv/bin/python -m uvicorn server.main:app --app-dir traceguard --port 8000
```

The backend serves the built console at `http://localhost:8000/console/` when `npm run build` has created `traceguard/web/console/`.

## Persistence

SQLite is the default. The database is created at `traceguard/defense_engine.db`; override it with `TRACEGUARD_DB`. Evidence records are re-ingested from `evidence/` at startup while evaluation history, validation metrics, evidence references, and checklist state persist.

To enable Supabase, configure **both** variables in the backend environment:

```sh
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-server-side-service-role-key"
```

Run `traceguard/supabase/schema.sql` in the Supabase SQL editor first. The backend selects Supabase only at process startup when both variables are present. A configured Supabase failure is reported; the service does not silently fall back to SQLite. The key must remain server-side and must never be placed in frontend variables or bundles. Without both variables, SQLite is used.

`traceguard/.env.example` lists supported environment variables. FastAPI does not automatically load it; export variables in the backend process environment.

## API

Interactive documentation: `http://localhost:8000/docs`.

- `GET /api/health` — API time, last evidence ingest, database provider and connectivity.
- `GET /api/topology` — systems, links, ranges, credential state, blind spots.
- `GET /api/timeline?normalized=true|false&tolerance_s=900` — source records, UTC normalization, and E05 uncertainty.
- `POST /api/engine/evaluate` — validated request payload and PASS, QUARANTINE, or CRITICAL_CANARY result.
- `GET /api/engine/presets` and `GET /api/engine/history` — simulation payloads and persisted decisions.
- `GET /api/validation`, `POST /api/validation` — editable demonstration counts and evidence row IDs.
- `GET /api/evidence-references`, `POST /api/evidence-references` — editable case row references.
- `GET /api/checklist`, `POST /api/checklist` — evidence preservation checklist state.
- Existing read-only endpoints remain available for `/api/case`, `/api/evidence`, `/api/clocks`, `/api/events`, `/api/findings`, and `/api/audit`.

The simulation includes normal nightly sync, client downgrade plus cover-up, rogue agent on the vendor link, and legacy canary hit. The canary verdict takes precedence. A sensitive action without required receipt/correlation fields is quarantined as unverified; that is not a finding of malicious intent.

## Verification

```sh
traceguard/.venv/bin/python -m pytest traceguard/tests -q
cd traceguard/frontend && npm run build
```

The tests cover expected preset verdicts, missing twin-proof behavior, canary priority and persistence, validation metric calculation, SHA-256 evidence hashing, and API health/topology/timeline/history routes.

## Security limitations

This is a local demonstration with no analyst authentication. Do not expose it publicly. Supabase uses a backend-only service key and server-side calls; RLS is enabled without browser policies. The demo scoring thresholds are configurable in `traceguard/server/engine.py`, are not calibrated against a representative dataset, and are not validated production detection performance. Orbit’s real-time prevention claim is architectural: this prototype does not enforce requests against LedgerOne or any other production system.
