# Orbit — CR-26-047 Vendor Change Gate

Orbit has a request-time gate for vendor bank-detail changes. The gate authenticates the calling service or Finance user, checks vendor-specific scope and current employee status, and holds the request for independent Finance approval of the exact submitted details. It forwards only through a configured provider write path; QBO sandbox bank changes require a manual UI save and an audited Finance confirmation because the Vendor API did not persist the Bill Pay ACH fields in controlled sandbox checks.

**Live Netlify UI preview:** [Orbit landing page](https://orbit-vendor-protection.netlify.app/) · [Console](https://orbit-vendor-protection.netlify.app/console/)

The public Netlify deployment currently serves static files only; it does not host the FastAPI backend or SQLite database. Live status checks, attack drills, and Finance approval requests require the backend and are unavailable from this preview. Do not submit bank changes through the public preview.

The repository also contains the historical CR-26-047 evidence review and request-scoring console. The scoring/simulation routes are analysis tools; they do not enforce writes. Enforcement occurs only when callers send changes to `POST /api/gate/vendor-changes` and every write path to the finance system is restricted to Orbit. The local workspace has been used with an Intuit QuickBooks Online sandbox; production books are not connected.

## Architecture

- `traceguard/server/` — FastAPI request gate, evidence ingestion, UTC/clock handling, detections, and persistence.
- `traceguard/frontend/` — React, Vite, Tailwind CSS, Recharts, Framer Motion, and Lucide-based Orbit console for Overview, Finance approvals, and the Security Wall.
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

Open `http://localhost:5173` for the Orbit console. Vite proxies `/api` to the backend at `http://127.0.0.1:8000`.

The Security Wall shows a live posture score from the request-gate configuration, approval policy, audit-chain verification, provider result, browser response headers, and local deployment boundary. Its attack drill calls the analysis-only request scoring route; it never forwards a bank change to the finance provider. The score is a transparent configuration check, not a penetration-test result or security certification.

The existing Orbit overview is at `http://localhost:8000/`; the read-only case review is at `http://localhost:8000/review/`.

## Request-time bank-change gate

The gate is disabled by default. `GET /api/gate/status` reports whether gate secrets and the selected provider mode are configured. For QBO, it reports `can_forward: false`, `upstream_configured: false`, and `write_mode: "manual_qbo_ui"`; OAuth configuration, if present, does not enable an API write. Without the required gate keys, a bank-change request is rejected with `503`; no request is treated as safe by default.

Before enabling it, configure `ORBIT_GATE_CREDENTIALS_JSON`, `ORBIT_DATA_ENCRYPTION_KEY`, and `ORBIT_BANK_FIELD_HMAC_KEY` in the backend environment. Use token hashes in the JSON; raw caller tokens are held by the calling service and never stored by Orbit. A credential entry has this shape:

```json
[
  {
    "principal": "tallybridge-service",
    "role": "integration",
    "active": true,
    "credential_id": "key-tb-07",
    "token_sha256": "<sha256-of-caller-token>",
    "scopes": ["vendor:read"],
    "vendor_ids": ["*"]
  },
  {
    "principal": "finance-maker-1",
    "role": "finance_maker",
    "active": true,
    "employee_username": "n.ansari",
    "token_sha256": "<sha256-of-user-token>",
    "scopes": ["vendor:bank-change"],
    "vendor_ids": ["V-0412"]
  },
  {
    "principal": "finance-approver-1",
    "role": "finance_approver",
    "active": true,
    "employee_username": "a.desai",
    "token_sha256": "<sha256-of-approver-token>",
    "vendor_ids": ["V-0412"]
  }
]
```

Finance principals are checked against the imported employee status and termination date on every call. Integration principals are checked against the imported credential status. The case's `key-tb-07` broad scope does not grant `vendor:bank-change`; a request from it is recorded as `BLOCKED`. Any use of `key-tb-03` creates a `CRITICAL_CANARY` state. These records come from the supplied case package; a real installation must replace that identity source with its IdP/credential lifecycle feed.

The workflow is:

1. `POST /api/gate/vendor-changes` authenticates the caller and stores a request as `HELD` or `BLOCKED`. Bank details are encrypted at rest; audit events contain only a keyed fingerprint and last four characters.
2. A separate active Finance approver can inspect a held request with `GET /api/gate/requests/{id}` and approve only by resubmitting the exact bank details with `confirm_exact_details: true`. Mismatches, self-approval, expired identities, or out-of-scope vendors are rejected.
3. After approval, the default `generic` connector sends a `PATCH` to `{ORBIT_FINANCE_API_BASE_URL}/v2/vendors/{vendor_id}/bank-details`. For QBO, set `ORBIT_FINANCE_PROVIDER=qbo`. Orbit records the request as `MANUAL_ACTION_REQUIRED` and does not send a Vendor API write, because a controlled test against a blank QBO US sandbox vendor showed the API incremented `SyncToken` but did not populate the Bill Pay ACH fields visible in the vendor UI. A Finance approver must save the already-approved details in QBO, then confirm the masked suffix and routing number through Orbit's QBO UI confirmation endpoint. Orbit records that separate attestation as `APPLIED_MANUAL`, never as API-confirmed `APPLIED`.

### QuickBooks Online sandbox workflow

1. Create or select a QBO sandbox company. Do not use production credentials or a production realm ID.
2. Set `ORBIT_FINANCE_PROVIDER=qbo`. The manual workflow does not require Intuit OAuth credentials or a Vendor ID map; keep vendor-scope authorization on Orbit's vendor ID.
3. After an independent Finance approval, the request becomes `MANUAL_ACTION_REQUIRED`. The approver signs in to QBO, opens the matching vendor, and saves the approved bank details in the Bill Pay ACH section.
4. An active Finance approver other than the request maker confirms the UI's account suffix and routing number through Orbit. Orbit sets `APPLIED_MANUAL` after matching those values against the encrypted approval. This confirmation is an attestation; the endpoint does not inspect QBO.
5. Use only sandbox vendors and dummy bank values. The sandbox does not move funds. A production deployment also needs every vendor bank write routed through Orbit and direct QBO write access restricted, or callers can bypass the gate.

No Intuit credentials are included in this repository. A synthetic test ACH value was saved directly in the QBO vendor form and reappeared masked after save. A clean vendor test then showed that both full and sparse Orbit Vendor API updates returned HTTP 200 without populating Bill Pay ACH in the QBO UI; the sparse attempt did not advance `SyncToken`. Orbit now requires the manual UI step rather than reporting a successful API write. Do not use real bank details to work around sandbox validation.

For this QBO API limitation, a different authorized Finance approver can reconcile the manually saved vendor record with `POST /api/gate/requests/{id}/qbo-ui-confirmation`. Submit the observed account last four, routing number, and `confirm_vendor_ui_saved: true`. Orbit compares those values with the encrypted approved request, requires the same vendor scope, records an append-only audit event, and sets `APPLIED_MANUAL` to distinguish UI confirmation from API-confirmed `APPLIED`.

Generate fresh secrets in the deployment secret manager. Example local key generation:

```sh
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'import hashlib; print(hashlib.sha256(b"replace-with-a-random-caller-token").hexdigest())'
```

Only enable `vendor:bank-change` for the identities and vendors that need it. Do not expose the current local console publicly: its investigation endpoints are not protected by the gate's caller authentication. For production, place the finance API behind network controls that prevent callers from bypassing Orbit, replace the case roster with the organization's IdP, and use durable shared database storage and HTTPS ingress.

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
- `GET /api/gate/status` — gate and provider-mode status without returning secrets.
- `POST /api/gate/vendor-changes` — authenticated, encrypted, fail-closed bank-change request.
- `GET /api/gate/requests` and `GET /api/gate/requests/{id}` — Finance approval queue and protected review details.
- `POST /api/gate/requests/{id}/approvals` — exact-detail Finance approval; QBO requests transition to `MANUAL_ACTION_REQUIRED`.
- `POST /api/gate/requests/{id}/qbo-ui-confirmation` — independent Finance confirmation of a manually saved QBO vendor record.
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

The tests cover expected scoring verdicts, missing twin-proof behavior, canary priority, the CR-26-047 TallyBridge block, terminated-employee rejection, exact Finance approval, idempotency, encrypted storage, fail-closed configuration, upstream forwarding only after approval, provider failure handling, validation metrics, SHA-256 evidence hashing, and API routes.

## Security limitations

The request gate and QBO sandbox adapter are implemented and connected to a local Intuit sandbox app. The adapter is sandbox-pinned; Orbit API bank-field persistence remains unverified because Intuit omits the fields from API responses and readback. A manual UI entry did persist in the sandbox. Orbit only protects changes routed through its endpoint; direct finance API access would bypass it. The frontend and historical evidence endpoints have no analyst login and must stay private until organization SSO/RBAC is connected. Supplied roster and credential state are historical case data, not live identity state. Scoring thresholds are not calibrated production detection performance. Never route production traffic until the provider contract, identity source, key custody, direct-write lockout, database durability, and failure behavior have been verified.
