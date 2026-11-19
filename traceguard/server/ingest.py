"""Reads the CR-26-047 evidence package into normalized event rows."""

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import clocks
from .config import EVIDENCE_DIR


@dataclass
class Spec:
    evidence_id: str
    filename: str
    kind: str  # events | reference | document
    system: str
    groups: str
    note: str = ""


@dataclass
class Event:
    evidence_id: str
    system: str
    raw_ts: str
    actor: str = ""
    api_key_id: str = ""
    source_ip: str = ""
    user_agent: str = ""
    action: str = ""
    endpoint: str = ""
    method: str = ""
    object_id: str = ""
    records: int | None = None
    result: str = ""
    bytes: int | None = None
    extra: dict = field(default_factory=dict)


EVENT_COLUMNS = (
    "evidence_id system raw_ts ts_utc ts_ms clock actor api_key_id source_ip src_24 "
    "user_agent action endpoint method object_id records result bytes raw"
).split()

PLAN = [
    Spec("E01", "E01_ledgerone_api_access.csv", "events", "LedgerOne", "Finance, Integration",
         "Jun 3 - Aug 31 API access"),
    Spec("E02", "E02_helpdeskr_audit_log.csv", "events", "HelpDeskr", "Data Export",
         "Recorded in India wall time"),
    Spec("E03", "E03_sso_signin_log.csv", "events", "SSO", "Identity", "Staff sign-in"),
    Spec("E04", "E04_connected_software_register.json", "reference", "Register", "Integration",
         "Credential state, point in time"),
    Spec("E05", "E05_bluevault_access_log.csv", "events", "BlueVault", "File Access",
         "Unix epoch from an unattested clock"),
    Spec("E06", "E06_billing_alert_and_invoice.pdf", "document", "Billing", "Data Export"),
    Spec("E07", "E07_onboarding_review_file.pdf", "document", "Vendor Mgmt", "Integration"),
    Spec("E08", "E08_contract_excerpt.pdf", "document", "Legal", "Integration"),
    Spec("E09", "E09_risk_register_extract.xlsx", "document", "Risk", "Audit"),
    Spec("E10", "E10_it_security_policy_v2_1.pdf", "document", "Policy", "Identity, Audit"),
    Spec("E11", "E11_internal_audit_report_IA_2025_09.pdf", "document", "Audit", "Audit"),
    Spec("E12", "E12_email_notice.pdf", "document", "External", "Integration"),
    Spec("E13", "E13_support_team_chat_export.json", "events", "HelpDeskr", "Data Export",
         "Chat export, wall time"),
    Spec("E14", "E14_staff_roster.csv", "reference", "HR", "Identity"),
    Spec("E15", "E15_network_link_flow_log.csv", "events", "PrivateLink", "File Access, Integration"),
    Spec("E16", "E16_followup_email_notice.pdf", "document", "External", "Integration"),
    Spec("E17", "E17_indicator_list.csv", "reference", "Threat Intel", "Integration",
         "Vendor-supplied indicators, may be incomplete"),
    Spec("E18", "E18_ledgerone_api_access_1_to_7_sep.csv", "events", "LedgerOne", "Finance",
         "Sep 1 - 7 API access"),
    Spec("E19", "E19_vendor_master_change_log.csv", "events", "LedgerOne", "Finance",
         "Vendor master changes with approval refs"),
    Spec("E20", "E20_public_records_pack.pdf", "document", "External", "Integration"),
]
PLAN_BY_ID = {s.evidence_id: s for s in PLAN}


def src_24(ip: str) -> str:
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ""


def _read_csv(path: Path):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        yield from csv.DictReader(handle)


def _api_event(row, spec):
    return Event(
        evidence_id=spec.evidence_id,
        system=spec.system,
        raw_ts=row.get("ts_utc", ""),
        api_key_id=row.get("api_key_id", ""),
        source_ip=row.get("caller_ip", ""),
        user_agent=row.get("user_agent", ""),
        action="api.call",
        endpoint=row.get("endpoint", ""),
        method=row.get("method", ""),
        object_id=row.get("request_id", ""),
        records=int(row["records_returned"]) if row.get("records_returned") else None,
        result=row.get("status", ""),
    )


def _event_for(spec, row) -> Event:
    if spec.evidence_id in ("E01", "E18"):
        return _api_event(row, spec)
    if spec.evidence_id == "E02":
        return Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=row.get("ts_local", ""),
            actor=row.get("actor", ""), source_ip=row.get("source_ip", ""),
            action=row.get("action", ""), object_id=row.get("event_id", ""),
            result=row.get("result", ""), extra={"actor_type": row.get("actor_type", ""),
                                                 "target": row.get("object_id", ""),
                                                 "details": row.get("details", "")},
        )
    if spec.evidence_id == "E03":
        return Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=row.get("ts_utc", ""),
            actor=row.get("user", ""), source_ip=row.get("source_ip", ""),
            action=f"sso.{row.get('auth_method', 'unknown')}",
            object_id=row.get("event_id", ""), result=row.get("result", ""),
            extra={"city": row.get("city", ""), "mfa": row.get("mfa_result", ""),
                   "device_id": row.get("device_id", ""),
                   "failure_reason": row.get("failure_reason", "")},
        )
    if spec.evidence_id == "E05":
        return Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=row.get("epoch_s", ""),
            actor=row.get("principal", ""), source_ip=row.get("source_ip", ""),
            action=f"file.{row.get('action', '')}", object_id=row.get("event_id", ""),
            result=row.get("result", ""),
            bytes=int(row["bytes"]) if row.get("bytes") else None,
            extra={"path": row.get("path", "")},
        )
    if spec.evidence_id == "E15":
        return Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=row.get("ts_utc", ""),
            source_ip=row.get("src_ip", ""), action=f"flow.{row.get('result', '')}",
            object_id=row.get("flow_id", ""), result=row.get("result", ""),
            bytes=int(row["bytes_out"]) if row.get("bytes_out") else None,
            extra={"src_label": row.get("src_label", ""),
                   "dst_system": row.get("dst_system", ""),
                   "tunnel_id": row.get("tunnel_id", "")},
        )
    if spec.evidence_id == "E19":
        return Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=row.get("ts_utc", ""),
            actor=row.get("changed_by", ""), source_ip=row.get("source_ip", ""),
            action=f"vendor.{row.get('field', '')}", object_id=row.get("change_id", ""),
            result=row.get("channel", ""),
            extra={"vendor_id": row.get("vendor_id", ""), "vendor_name": row.get("vendor_name", ""),
                   "field": row.get("field", ""), "old_value": row.get("old_value", ""),
                   "new_value": row.get("new_value", ""), "approval_ref": row.get("approval_ref", ""),
                   "request_id": row.get("request_id", "")},
        )
    raise ValueError(f"no event reader for {spec.evidence_id}")


def _iter_chat_events(spec, payload):
    for message in payload.get("messages", []):
        yield Event(
            evidence_id=spec.evidence_id, system=spec.system, raw_ts=message.get("ts_local", ""),
            actor=message.get("author", ""), action="chat.message",
            object_id=message.get("channel", ""), result="ok",
            extra={"text": message.get("text", "")},
        )


def _fingerprint(path: Path) -> str:
    stat = path.stat()
    return f"{int(stat.st_mtime_ns)}:{stat.st_size}"


def _insert_events(store, spec, rows):
    pending, skipped = [], 0
    for row in rows:
        ts_ms, problem = clocks.to_utc_ms(spec.evidence_id, row.raw_ts)
        if ts_ms is None:
            skipped += 1
            continue
        clock = clocks.CLOCK_SPECS[spec.evidence_id]
        pending.append((
            spec.evidence_id, spec.system, row.raw_ts, clocks.iso(ts_ms), ts_ms, clock.kind,
            row.actor, row.api_key_id, row.source_ip, src_24(row.source_ip), row.user_agent,
            row.action, row.endpoint, row.method, row.object_id, row.records, row.result,
            row.bytes, json.dumps({**row.__dict__, "extra": row.extra}, default=str),
        ))
        if len(pending) >= 5000:
            store.writemany(
                f"INSERT INTO events ({', '.join(EVENT_COLUMNS)}) "
                f"VALUES ({', '.join('?' * len(EVENT_COLUMNS))})", pending)
            pending = []
    if pending:
        store.writemany(
            f"INSERT INTO events ({', '.join(EVENT_COLUMNS)}) "
            f"VALUES ({', '.join('?' * len(EVENT_COLUMNS))})", pending)
    return skipped


def _ingest_register(store, path: Path, spec):
    payload = json.loads(path.read_text())
    items = payload.get("integrations", [])
    store.writemany(
        "INSERT INTO credentials (credential_id, integration, system, vendor, scope, owner, created,"
        " last_review, ip_restricted, token_lifetime, last_used, status) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(credential_id) DO UPDATE SET "
        "scope=excluded.scope, owner=excluded.owner, last_review=excluded.last_review,"
        " ip_restricted=excluded.ip_restricted, token_lifetime=excluded.token_lifetime,"
        " last_used=excluded.last_used, status=excluded.status",
        [(i.get("credential_id", ""), i.get("integration", ""), i.get("system", ""),
          i.get("vendor", ""), i.get("scope", ""), i.get("owner", ""), i.get("created", ""),
          i.get("last_review", ""), int(bool(i.get("ip_restriction"))),
          i.get("token_lifetime_days"), i.get("last_used", ""), i.get("status", ""))
         for i in items],
    )
    store.set_meta("E04_export_generated", payload.get("export_generated", ""))
    return len(items), payload.get("note", "")


def _ingest_people(store, path: Path):
    rows = list(_read_csv(path))
    store.writemany(
        "INSERT INTO people (username, employee_id, full_name, department, role, status, manager,"
        " hire_date, termination_date, notes) VALUES (?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(username) DO UPDATE SET status=excluded.status,"
        " termination_date=excluded.termination_date, role=excluded.role",
        [(r.get("username", ""), r.get("employee_id", ""), r.get("full_name", ""),
          r.get("department", ""), r.get("role", ""), r.get("status", ""), r.get("manager", ""),
          r.get("hire_date", ""), r.get("termination_date", ""), r.get("notes", "")) for r in rows],
    )
    return len(rows)


def _ingest_indicators(store, path: Path):
    rows = list(_read_csv(path))
    store.writemany(
        "INSERT INTO indicators (indicator, type, first_seen, last_seen, confidence, vendor_note)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(indicator) DO UPDATE SET"
        " last_seen=excluded.last_seen, vendor_note=excluded.vendor_note",
        [(r.get("indicator", ""), r.get("type", ""), r.get("first_seen", ""),
          r.get("last_seen", ""), r.get("confidence", ""), r.get("vendor_note", "")) for r in rows],
    )
    return len(rows)


def ingest_one(store, spec: Spec, evidence_dir: Path = EVIDENCE_DIR, force=False) -> dict:
    path = evidence_dir / spec.filename
    record = {
        "evidence_id": spec.evidence_id, "filename": spec.filename, "kind": spec.kind,
        "system": spec.system, "groups": spec.groups, "note": spec.note,
    }
    if not path.exists():
        record.update(rows=0, status="missing", clock="n/a", clock_rule="no clock rule")
        _upsert_evidence(store, record)
        return record

    fingerprint = _fingerprint(path)
    existing = store.one("SELECT fingerprint, rows FROM evidence WHERE evidence_id = ?",
                         (spec.evidence_id,))
    if not force and existing and existing["fingerprint"] == fingerprint and existing["rows"] > 0:
        record.update(rows=existing["rows"], status="cached",
                      clock=clocks.CLOCK_SPECS.get(spec.evidence_id, clocks.ClockSpec(
                          "", "", "none", "", "", True)).kind,
                      clock_rule="unchanged since last ingest")
        return record

    if spec.kind == "document":
        record.update(rows=0, status="document", clock="n/a",
                      clock_rule="Not machine-parsed in this build.")
        _upsert_evidence(store, record)
        return record

    if spec.evidence_id == "E04":
        count, note = _ingest_register(store, path, spec)
        record.update(rows=count, status="reference", clock="point_in_time",
                      clock_rule=note or "Point-in-time state, no event timestamps.")
        _upsert_evidence(store, record, fingerprint)
        return record
    if spec.evidence_id == "E14":
        count = _ingest_people(store, path)
        record.update(rows=count, status="reference", clock="point_in_time",
                      clock_rule="Roster state; dates only.")
        _upsert_evidence(store, record, fingerprint)
        return record
    if spec.evidence_id == "E17":
        count = _ingest_indicators(store, path)
        record.update(rows=count, status="reference", clock="date_only",
                      clock_rule="Indicator dates, no time of day.")
        _upsert_evidence(store, record, fingerprint)
        return record

    clock = clocks.CLOCK_SPECS[spec.evidence_id]
    if path.suffix == ".json":
        payload = json.loads(path.read_text())
        if spec.evidence_id == "E13":
            rows = _iter_chat_events(spec, payload)
        else:
            rows = [_event_for(spec, r) for r in payload]
    else:
        rows = (_event_for(spec, r) for r in _read_csv(path))

    store.clear_evidence(spec.evidence_id)
    skipped = _insert_events(store, spec, rows)
    count = store.one("SELECT COUNT(*) AS n FROM events WHERE evidence_id = ?",
                      (spec.evidence_id,))["n"]
    record.update(rows=count, status="ingested", clock=clock.kind, clock_rule=clock.rule,
                  skipped=skipped)
    _upsert_evidence(store, record, fingerprint)
    return record


def _upsert_evidence(store, record, fingerprint=None):
    store.write(
        "INSERT INTO evidence (evidence_id, filename, kind, system, clock, clock_rule, groups,"
        " rows, status, note, fingerprint, ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(evidence_id) DO UPDATE SET filename=excluded.filename,"
        " kind=excluded.kind, system=excluded.system, clock=excluded.clock,"
        " clock_rule=excluded.clock_rule, groups=excluded.groups, rows=excluded.rows,"
        " status=excluded.status, note=excluded.note, fingerprint=excluded.fingerprint,"
        " ingested_at=excluded.ingested_at",
        (record["evidence_id"], record["filename"], record["kind"], record["system"],
         record.get("clock", "n/a"), record.get("clock_rule", ""), record["groups"],
         record.get("rows", 0), record["status"], record.get("note", ""), fingerprint,
         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
    )


def measure_drift(store) -> dict:
    """Bound BlueVault's clock against the UTC streams and record the result."""
    e5 = [r["ts_ms"] for r in store.query(
        "SELECT ts_ms FROM events WHERE evidence_id = 'E05'")]
    ref = [r["ts_ms"] for r in store.query(
        "SELECT ts_ms FROM events WHERE evidence_id IN ('E01','E03','E15')")]
    bound = clocks.bound_offset(e5, ref)
    bound["candidate_rows"] = len(e5)
    bound["reference_rows"] = len(ref)
    store.set_meta("E05_offset_verdict", bound["verdict"])
    store.set_meta("E05_indistinguishable_minutes", bound.get("indistinguishable_span_minutes") or "")
    return bound


def ingest_all(store, evidence_dir: Path = EVIDENCE_DIR, force=False) -> dict:
    # E05's clock is only checkable once the UTC streams it is compared to are loaded.
    order = [s for s in PLAN if s.evidence_id != "E05"] + [
        s for s in PLAN if s.evidence_id == "E05"]
    results = [ingest_one(store, spec, evidence_dir, force) for spec in order]
    drift = measure_drift(store)
    store.audit("system", "evidence.ingest", "evidence/",
                {"files": len(results), "events": sum(r["rows"] for r in results)})
    return {"results": results, "drift": drift}
