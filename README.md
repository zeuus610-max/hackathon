# Orbit — CR-26-047 Vendor Change Gate

Orbit has a request-time gate for vendor bank-detail changes. The gate authenticates the calling service or Finance user, checks vendor-specific scope and current employee status, holds the request for independent Finance approval of the exact submitted details, then forwards the approved change to a configured finance API. It never forwards before approval and fails closed if its security configuration or provider is missing.

The repository also contains the historical CR-26-047 evidence review and request-scoring console. The scoring/simulation routes are analysis tools; they do not enforce writes. Enforcement occurs only when callers send changes to `POST /api/gate/vendor-changes` and every write path to the finance system is restricted to Orbit. This workspace has a local-only connection to an Intuit QuickBooks Online sandbox; credentials are kept in ignored, permission-restricted local configuration and are not part of this repository.

## Architecture

- `traceguard/server/` — FastAPI request gate, evidence ingestion, UTC/clock handling, detections, and persistence.
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

## Request-time bank-change gate

The gate is disabled by default. `GET /api/gate/status` reports whether gate secrets and an upstream finance connector are present. Without the required gate keys, a bank-change request is rejected with `503`; no request is treated as safe by default.

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
3. After approval, Orbit sends the request through the selected server-side connector. The default `generic` connector sends a `PATCH` to `{ORBIT_FINANCE_API_BASE_URL}/v2/vendors/{vendor_id}/bank-details`. Set `ORBIT_FINANCE_PROVIDER=qbo` to use the fixed Intuit QuickBooks Online **sandbox** API instead. The QBO adapter refreshes OAuth credentials, reads the vendor's current `SyncToken`, then makes a full vendor update preserving existing fields and replacing only the approved bank fields. It encrypts rotated refresh tokens in the Orbit database. QBO's vendor bank detail schema has no bank institution field, so the approved account holder maps to `BankAccountName`, routing code maps to `BankBranchIdentifier`, account number maps to `BankAccountNumber`, and `bank_name` remains only in Orbit's encrypted approval record. An unconfigured connector or uncertain upstream response remains `APPROVED_PENDING_PROVIDER`; Orbit does not report success.

### QuickBooks Online sandbox setup

1. Create an Intuit developer account and app, enable the Accounting API scope, and authorize it against a sandbox company. Intuit supplies sandbox companies and app credentials through its developer portal.
2. Obtain the app's OAuth client ID, client secret, sandbox realm ID, and refresh token from the OAuth authorization flow. Do not use production credentials or a production realm ID; Orbit's QBO adapter is deliberately pinned to `https://sandbox-quickbooks.api.intuit.com`.
3. Set `ORBIT_FINANCE_PROVIDER=qbo`, `ORBIT_QBO_REALM_ID`, `ORBIT_QBO_CLIENT_ID`, `ORBIT_QBO_CLIENT_SECRET`, and `ORBIT_QBO_REFRESH_TOKEN` in the deployment's secret manager. The Orbit encryption key must also be configured to protect rotated refresh tokens.
4. Map each Orbit vendor ID to the corresponding QBO Vendor `Id` with `ORBIT_QBO_VENDOR_ID_MAP_JSON`, for example `{"V-0412":"58"}`. Keep authorization scopes on the Orbit vendor ID (`V-0412`); the connector resolves it to QBO's ID only after approval. It pins QBO minor version 75, reads the current Vendor and `SyncToken`, preserves the vendor's existing fields in the full update, then verifies the update response and, if needed, reads the vendor back. Because QBO may mask account numbers or omit bank fields from later reads, it confirms the account suffix with the account holder and routing fields before reporting `APPLIED`; otherwise the request remains pending.
5. Test only with a sandbox vendor and dummy bank values. Intuit's sandbox demonstrates accounting API writes; it does not move funds. A production deployment also needs every vendor bank write routed through Orbit and direct QBO write access restricted, or callers can bypass the gate.

The local sandbox connection does not connect production books or move funds. No Intuit credentials are included in this repository. A synthetic test ACH value was saved directly in the QBO vendor form and reappeared masked after save, confirming the UI record persists. Orbit API requests passed maker and separate-approver checks, but QBO omitted `VendorPaymentBankDetail` from the update response and vendor readback. Orbit keeps those requests at `APPROVED_PENDING_PROVIDER`; the UI test does not confirm the Orbit API write. Do not use real bank details to work around sandbox validation.

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
- `GET /api/gate/status` — gate configuration status without returning secrets.
- `POST /api/gate/vendor-changes` — authenticated, encrypted, fail-closed bank-change request.
- `GET /api/gate/requests` and `GET /api/gate/requests/{id}` — Finance approval queue and protected review details.
- `POST /api/gate/requests/{id}/approvals` — exact-detail Finance approval, followed by an upstream write only when configured.
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
