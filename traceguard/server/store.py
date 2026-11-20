import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id   TEXT PRIMARY KEY,
  filename      TEXT NOT NULL,
  kind          TEXT NOT NULL,
  system        TEXT NOT NULL,
  clock         TEXT NOT NULL,
  clock_rule    TEXT NOT NULL,
  groups        TEXT NOT NULL,
  rows          INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL,
  note          TEXT,
  fingerprint   TEXT,
  ingested_at   TEXT
);

CREATE TABLE IF NOT EXISTS events (
  id           INTEGER PRIMARY KEY,
  evidence_id  TEXT NOT NULL,
  system       TEXT NOT NULL,
  raw_ts       TEXT,
  ts_utc       TEXT NOT NULL,
  ts_ms        INTEGER NOT NULL,
  clock        TEXT NOT NULL,
  actor        TEXT,
  api_key_id   TEXT,
  source_ip    TEXT,
  src_24       TEXT,
  user_agent   TEXT,
  action       TEXT,
  endpoint     TEXT,
  method       TEXT,
  object_id    TEXT,
  records      INTEGER,
  result       TEXT,
  bytes        INTEGER,
  raw          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts      ON events (ts_ms);
CREATE INDEX IF NOT EXISTS events_evidence ON events (evidence_id);
CREATE INDEX IF NOT EXISTS events_key     ON events (api_key_id);
CREATE INDEX IF NOT EXISTS events_24      ON events (src_24);
CREATE INDEX IF NOT EXISTS events_actor   ON events (actor);

CREATE TABLE IF NOT EXISTS credentials (
  credential_id   TEXT PRIMARY KEY,
  integration     TEXT,
  system          TEXT,
  vendor          TEXT,
  scope           TEXT,
  owner           TEXT,
  created         TEXT,
  last_review     TEXT,
  ip_restricted   INTEGER,
  token_lifetime  INTEGER,
  last_used       TEXT,
  status          TEXT,
  observed_events INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS people (
  username         TEXT PRIMARY KEY,
  employee_id      TEXT,
  full_name        TEXT,
  department       TEXT,
  role             TEXT,
  status           TEXT,
  manager          TEXT,
  hire_date        TEXT,
  termination_date TEXT,
  notes            TEXT
);

CREATE TABLE IF NOT EXISTS indicators (
  indicator  TEXT PRIMARY KEY,
  type       TEXT,
  first_seen TEXT,
  last_seen  TEXT,
  confidence TEXT,
  vendor_note TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id           INTEGER PRIMARY KEY,
  run_id       TEXT NOT NULL,
  kind         TEXT NOT NULL,
  severity     TEXT NOT NULL,
  title        TEXT NOT NULL,
  detail       TEXT NOT NULL,
  caveat       TEXT,
  subject      TEXT,
  evidence_ids TEXT NOT NULL,
  occurred_utc TEXT,
  count        INTEGER NOT NULL DEFAULT 1,
  meta         TEXT,
  created_utc  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_run ON findings (run_id);

CREATE TABLE IF NOT EXISTS eval_history (
  evaluation_id TEXT PRIMARY KEY,
  created_utc TEXT NOT NULL,
  key_id TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  caller_ip TEXT NOT NULL,
  verdict TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  triggered_rules TEXT NOT NULL,
  canary INTEGER NOT NULL,
  payload TEXT NOT NULL,
  result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS eval_history_created ON eval_history (created_utc);
CREATE TABLE IF NOT EXISTS canary_alerts (
  id INTEGER PRIMARY KEY,
  evaluation_id TEXT NOT NULL,
  created_utc TEXT NOT NULL,
  key_id TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS validation_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  true_positives INTEGER NOT NULL DEFAULT 0,
  false_positives INTEGER NOT NULL DEFAULT 0,
  missed_detections INTEGER NOT NULL DEFAULT 0,
  evidence_row_ids TEXT NOT NULL DEFAULT '[]',
  metadata TEXT NOT NULL DEFAULT '{}',
  updated_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_references (
  evidence_id TEXT PRIMARY KEY,
  row_reference TEXT NOT NULL DEFAULT '',
  updated_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checklist_state (
  item_id TEXT PRIMARY KEY,
  checked INTEGER NOT NULL DEFAULT 0,
  updated_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gate_requests (
  gate_request_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL UNIQUE,
  vendor_id TEXT NOT NULL,
  requester TEXT NOT NULL,
  requester_employee TEXT,
  credential_id TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  bank_fingerprint TEXT NOT NULL,
  bank_details_ciphertext TEXT NOT NULL,
  account_last4 TEXT NOT NULL,
  status TEXT NOT NULL,
  reason_codes TEXT NOT NULL,
  upstream_status INTEGER,
  upstream_reference TEXT,
  created_utc TEXT NOT NULL,
  updated_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS gate_requests_created ON gate_requests (created_utc);
CREATE INDEX IF NOT EXISTS gate_requests_vendor ON gate_requests (vendor_id, created_utc);

CREATE TABLE IF NOT EXISTS gate_approvals (
  approval_id TEXT PRIMARY KEY,
  gate_request_id TEXT NOT NULL,
  approver TEXT NOT NULL,
  bank_fingerprint TEXT NOT NULL,
  created_utc TEXT NOT NULL,
  UNIQUE (gate_request_id, approver),
  FOREIGN KEY (gate_request_id) REFERENCES gate_requests(gate_request_id)
);

CREATE TABLE IF NOT EXISTS simulated_gate_requests (
  gate_request_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  vendor_id TEXT NOT NULL,
  requester TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('HELD', 'APPROVED_PENDING_PROVIDER', 'APPLIED')),
  bank_details_json TEXT NOT NULL,
  upstream_status INTEGER,
  upstream_reference TEXT,
  created_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq          INTEGER PRIMARY KEY,
  ts_utc       TEXT NOT NULL,
  actor        TEXT NOT NULL,
  action       TEXT NOT NULL,
  target       TEXT NOT NULL,
  meta         TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  entry_hash   TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_is_append_only_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is write-once'); END;

CREATE TRIGGER IF NOT EXISTS audit_is_append_only_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is write-once'); END;
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    """SQLite container for ingested evidence and derived findings.

    Event rows are re-derivable from source files, so re-ingest clears them.
    The audit ledger is not: triggers abort any UPDATE or DELETE against it.
    """

    def __init__(self, path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self._seed_simulated_gate_requests()
        self.conn.commit()

    def _seed_simulated_gate_requests(self):
        now = datetime.now(timezone.utc)
        scenarios = [
            ("sim-held-001", "SIM-2026-001", "V-0412", "Ops maker 01", "HELD", "1284", None, None),
            ("sim-held-002", "SIM-2026-002", "V-0537", "Ops maker 02", "HELD", "6731", None, None),
            ("sim-held-003", "SIM-2026-003", "V-0861", "Ops maker 03", "HELD", "4409", None, None),
            ("sim-followup-001", "SIM-2026-004", "V-0228", "Ops maker 04", "APPROVED_PENDING_PROVIDER", "9012", None, None),
            ("sim-followup-002", "SIM-2026-005", "V-0992", "Ops maker 05", "APPROVED_PENDING_PROVIDER", "3375", None, None),
            ("sim-applied-001", "SIM-2026-006", "V-0118", "Ops maker 06", "APPLIED", "5820", 200, "SIM-ZOHO-2048"),
        ]
        for offset, (gate_id, request_id, vendor_id, requester, status, suffix,
                     upstream_status, upstream_reference) in enumerate(scenarios):
            bank_details = {
                "bank_name": "Example Finance Bank",
                "account_holder": f"Orbit Simulation Vendor {offset + 1}",
                "account_number": f"00000000{suffix}",
                "routing_code": "000000000",
                "country": "IN",
            }
            created = (now - timedelta(minutes=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.conn.execute(
                "INSERT OR IGNORE INTO simulated_gate_requests "
                "(gate_request_id, request_id, vendor_id, requester, status, bank_details_json, "
                "upstream_status, upstream_reference, created_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (gate_id, request_id, vendor_id, requester, status,
                 json.dumps(bank_details, sort_keys=True), upstream_status,
                 upstream_reference, created),
            )

    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def write(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    def writemany(self, sql, seq):
        batch = list(seq)
        with self.lock:
            self.conn.executemany(sql, batch)
            self.conn.commit()
        return len(batch)

    def get_meta(self, key, default=None):
        row = self.one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_meta(self, key, value):
        self.write(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    def clear_evidence(self, evidence_id):
        with self.lock:
            self.conn.execute("DELETE FROM events WHERE evidence_id = ?", (evidence_id,))
            self.conn.commit()

    def audit(self, actor, action, target, meta=None):
        payload = json.dumps(meta or {}, sort_keys=True, separators=(",", ":"))
        with self.lock:
            prev = self.conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev["entry_hash"] if prev else "GENESIS"
            ts = utcnow()
            body = "|".join([prev_hash, ts, actor, action, target, payload])
            entry_hash = hashlib.sha256(body.encode()).hexdigest()
            self.conn.execute(
                "INSERT INTO audit_log (ts_utc, actor, action, target, meta, prev_hash, entry_hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, actor, action, target, payload, prev_hash, entry_hash),
            )
            self.conn.commit()
        return entry_hash

    def audit_tail(self, limit=12):
        return self.query(
            "SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)
        )

    def audit_verified(self):
        rows = self.query("SELECT * FROM audit_log ORDER BY seq ASC")
        prev = "GENESIS"
        for row in rows:
            body = "|".join(
                [
                    prev,
                    row["ts_utc"],
                    row["actor"],
                    row["action"],
                    row["target"],
                    row["meta"],
                ]
            )
            if hashlib.sha256(body.encode()).hexdigest() != row["entry_hash"]:
                return {"chain_length": len(rows), "intact": False, "broken_at": row["seq"]}
            prev = row["entry_hash"]
        return {"chain_length": len(rows), "intact": True, "broken_at": None}
