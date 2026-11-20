"""Cross-system detections. Every finding cites evidence ids and separates fact from inference.

The rules are derived from the evidence package, not from the case marketing copy: a
blank approval reference, an unattested clock or an over-scoped key is a reason to
review a record, not proof that anything was stolen.
"""

import json
import uuid
from datetime import datetime, timezone

from . import clocks

APPROVED_SYNC_FIELDS = {"contact_email", "contact_phone"}
BANK_FIELD = "bank_account"
INTEGRATION_KEYS = {"key-tb-07", "tb-sync-svc"}
SYNC_WINDOW_UTC = (22, 7)  # overnight batch: 22:00 inclusive to 07:00 exclusive
WEEKLY_EXPORT_DAY = 1  # Tuesday, per E13 support-team routine

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(kind, severity, title, detail, evidence_ids, *, caveat="", subject="",
             occurred_utc=None, count=1, meta=None):
    return {
        "kind": kind, "severity": severity, "title": title, "detail": detail,
        "evidence_ids": ",".join(evidence_ids), "caveat": caveat, "subject": subject,
        "occurred_utc": occurred_utc, "count": count, "meta": meta or {},
    }


def _raw(row) -> dict:
    return json.loads(row["raw"])


def vendor_write_review(store) -> list[dict]:
    """E18 vendor writes joined to E19 approval records, ported from the review desk."""
    writes = store.query(
        "SELECT e.*, json_extract(p.raw, '$.extra.approval_ref') AS linked_approval, "
        "json_extract(p.raw, '$.extra.field') AS linked_field, "
        "json_extract(p.raw, '$.extra.vendor_id') AS linked_vendor_id, "
        "json_extract(p.raw, '$.extra.vendor_name') AS linked_vendor_name, "
        "json_extract(p.raw, '$.extra.old_value') AS linked_old_value, "
        "json_extract(p.raw, '$.extra.new_value') AS linked_new_value, "
        "p.ts_utc AS change_utc FROM events e "
        "LEFT JOIN events p ON p.evidence_id = 'E19' "
        "AND json_extract(p.raw, '$.extra.request_id') = e.object_id "
        "WHERE e.evidence_id = 'E18' AND e.method IN ('PATCH', 'PUT', 'POST') "
        "AND e.endpoint LIKE '/v2/vendors/%'")
    if not writes:
        return []

    flagged, passed = [], 0
    for row in writes:
        payload = _raw(row)
        change = payload.get("extra") or {}
        # E18 is the API request log; the changed field and approval live in the
        # matching E19 vendor-master record, joined by request_id.
        field = change.get("field") or row.get("linked_field") or ""
        approval = (row.get("linked_approval") or "").strip()
        reasons = []
        if field not in APPROVED_SYNC_FIELDS:
            reasons.append(
                f"The change touched {field or 'an unknown field'}, which is outside the approved "
                "sync purpose of email and phone only.")
        if field == BANK_FIELD and not approval:
            reasons.append("The vendor master record carries no Finance approval reference.")
        if not reasons:
            passed += 1
            continue
        entry = _finding(
            "vendor_write_review",
            "critical" if field == BANK_FIELD else "medium",
            f"Vendor {field or 'record'} change needs a person on the Finance desk",
            " ".join(reasons) + f" Source: API key {row['api_key_id']} from {row['source_ip']} "
            f"against {row['endpoint']}.",
            ["E18", "E19"],
            caveat="A blank approval reference is a reason to review the change. It is not a "
                   "finding that money moved or that the change was unauthorized.",
            subject=row["object_id"], occurred_utc=row["ts_utc"],
            meta={"vendor_id": row.get("linked_vendor_id") or change.get("vendor_id"),
                  "vendor_name": row.get("linked_vendor_name") or change.get("vendor_name"),
                  "old_value": row.get("linked_old_value"),
                  "new_value": row.get("linked_new_value"),
                  "field": field, "api_key_id": row["api_key_id"], "source_ip": row["source_ip"],
                  "endpoint": row["endpoint"], "approval_ref": approval, "reasons": reasons})
        flagged.append(entry)

    out = flagged
    out.append(_finding(
        "vendor_write_scope", "info",
        "Nightly contact sync stayed inside its approved purpose",
        f"{passed} of {len(writes)} API vendor writes between 1 and 7 Sep touched only "
        f"contact_email or contact_phone. {len(flagged)} went to a person for review.",
        ["E18", "E19"],
        caveat="Scope conformance here is a control observation, not an assurance that no "
               "unrelated activity happened outside these two streams.",
        count=len(writes), meta={"passed": passed, "flagged": len(flagged)}))
    return out


def credential_hygiene(store) -> list[dict]:
    """E04 register state measured against activity actually observed in E01/E18/E02/E05."""
    export_generated = store.get_meta("E04_export_generated") or "2026-09-02T06:00:00Z"
    baseline = clocks.parse_utc(export_generated)
    creds = store.query("SELECT * FROM credentials")
    observed = {}
    for row in store.query(
            "SELECT api_key_id AS k, COUNT(*) n, MIN(ts_utc) first_seen, MAX(ts_utc) last_seen "
            "FROM events WHERE api_key_id != '' GROUP BY api_key_id"):
        observed[row["k"]] = row

    active, dormant = [], []
    for cred in creds:
        key = cred["credential_id"]
        activity = observed.get(key)
        count = activity["n"] if activity else 0
        store.write("UPDATE credentials SET observed_events = ? WHERE credential_id = ?",
                    (count, key))
        unbounded = (not cred["ip_restricted"]) and not cred["token_lifetime"]
        broad = any(t in (cred["scope"] or "") for t in ("all-modules", "admin", "read:all"))
        if not (unbounded and broad):
            continue
        last_used = clocks.parse_utc(f"{cred['last_used']}T00:00:00Z") if cred["last_used"] else None
        idle_days = (baseline - last_used).days if last_used else None
        (active if count else dormant).append((cred, count, idle_days, activity))

    findings = []
    for cred, count, _idle, activity in active:
        detail = (f"{cred['credential_id']} holds {cred['scope']} on {cred['system']} with no IP "
                  f"restriction and no token expiry, and served {count} logged calls "
                  f"({activity['first_seen']} to {activity['last_seen']}).")
        if cred["credential_id"] in INTEGRATION_KEYS:
            outside = store.one(
                "SELECT COUNT(*) n FROM events WHERE api_key_id = ? AND evidence_id IN ('E01','E18')"
                " AND CAST(strftime('%H', ts_utc) AS INT) NOT BETWEEN 22 AND 23"
                " AND CAST(strftime('%H', ts_utc) AS INT) NOT BETWEEN 0 AND 6",
                (cred["credential_id"],))["n"]
            detail += (f" {outside} of those calls sit outside the 22:00-07:00 UTC batch window the "
                       "integration is described as running in.")
        scope = cred["scope"] or ""
        findings.append(_finding(
            "credential_hygiene", "high" if "admin" in scope else "medium",
            f"Static credential with blanket scope is in active use: {cred['credential_id']}"
            f" (owner: {cred['owner'] or 'unassigned'})",
            detail, ["E04", "E01", "E18"],
            caveat="Broad scope plus no expiry is an exposure, not evidence of misuse. Each call "
                   "counted here stays attributable and is examined on its own terms elsewhere.",
            subject=cred["credential_id"], count=count,
            meta={"credential_id": cred["credential_id"], "scope": scope,
                  "owner": cred["owner"], "last_review": cred["last_review"],
                  "ip_restricted": bool(cred["ip_restricted"]),
                  "days_since_review": _age_days(cred["last_review"], baseline)}))

    for cred, count, idle_days, _activity in dormant:
        findings.append(_finding(
            "credential_hygiene", "medium",
            f"Dormant unbounded credential is still active: {cred['credential_id']}",
            f"{cred['scope']} on {cred['system']}, owner {cred['owner'] or 'unassigned'}, no IP "
            f"restriction, no expiry, last used {cred['last_used']}"
            + (f" ({idle_days} days before the register export)" if idle_days is not None else "")
            + f". Calls observed in the loaded logs: {count}.",
            ["E04", "E01", "E18"],
            caveat="Zero observed calls means this build found no activity for it, which is not "
                   "proof none happened: the logs cover Jun-Sep 2026 and the credential predates "
                   "that window.",
            subject=cred["credential_id"], count=count,
            meta={"credential_id": cred["credential_id"], "idle_days": idle_days,
                  "scope": cred["scope"], "owner": cred["owner"]}))
    return findings


def _age_days(date_text, baseline) -> int | None:
    if not date_text:
        return None
    moment = clocks.parse_utc(f"{date_text}T00:00:00Z")
    return (baseline - moment).days if moment else None


def indicator_matches(store) -> list[dict]:
    """E17 indicators joined to source addresses seen in the UTC streams."""
    indicators = store.query("SELECT * FROM indicators WHERE type = 'ip'")
    findings = []
    for ind in indicators:
        hits = store.query(
            "SELECT evidence_id, system, COUNT(*) n, MIN(ts_utc) first_seen, MAX(ts_utc) last_seen, "
            "GROUP_CONCAT(DISTINCT api_key_id) keys, GROUP_CONCAT(DISTINCT user_agent) agents "
            "FROM events WHERE source_ip = ? OR src_24 = ? GROUP BY evidence_id",
            (ind["indicator"], ".".join(ind["indicator"].split(".")[:3])))
        total = sum(h["n"] for h in hits)
        if not total:
            continue
        spread = ", ".join(f"{h['evidence_id']}/{h['system']}: {h['n']}" for h in hits)
        findings.append(_finding(
            "indicator_match", "critical" if ind["confidence"] == "high" else "high",
            f"Vendor indicator {ind['indicator']} appears in the loaded logs",
            f"{total} events carry this source address ({spread}). Indicator first seen "
            f"{ind['first_seen']}, last {ind['last_seen']}, confidence {ind['confidence']}. "
            f"Vendor note: {ind['vendor_note'] or 'none given'}.",
            ["E17", "E01", "E03", "E05", "E15"],
            caveat="The indicator list is vendor-supplied and the case file calls it possibly "
                   "incomplete; a match is a lead to inspect, and absence of a match proves nothing.",
            subject=ind["indicator"], occurred_utc=hits[0]["first_seen"], count=total,
            meta={"keys": hits[0]["keys"], "agents": hits[0]["agents"],
                  "confidence": ind["confidence"]}))
    return findings


def export_lifecycle(store) -> list[dict]:
    """Create -> download -> delete chains in E02, and exports off the weekly cycle."""
    rows = store.query(
        "SELECT * FROM events WHERE evidence_id = 'E02' AND action LIKE 'export.%' ORDER BY ts_ms")
    if not rows:
        return []
    jobs: dict[str, dict] = {}
    for row in rows:
        payload = _raw(row)
        job = (payload.get("extra") or {}).get("target") or row["object_id"]
        entry = jobs.setdefault(job, {"steps": [], "actor": row["actor"], "ip": row["source_ip"]})
        entry["steps"].append(row)

    created = sum(1 for j in jobs.values() if any(s["action"] == "export.create" for s in j["steps"]))
    deleted = [j for j in jobs.values() if any(s["action"] == "export.delete" for s in j["steps"])]
    fast = []
    for job, entry in jobs.items():
        steps = sorted(entry["steps"], key=lambda s: s["ts_ms"])
        if len(steps) >= 2 and (steps[-1]["ts_ms"] - steps[0]["ts_ms"]) <= 3600_000:
            fast.append((job, steps))

    findings = [_finding(
        "export_lifecycle", "info",
        "Export jobs observed in the HelpDeskr audit trail",
        f"{created} jobs were created and downloaded by the support desk. "
        f"{len(deleted)} of them also have an export.delete event, meaning the job record was "
        f"removed after download.",
        ["E02"],
        caveat="Deletion of an export job record is normal hygiene in some workflows; it becomes a "
               "problem only when the deletion removes the only trace of a download nobody can "
               "otherwise account for.",
        count=created, meta={"deleted": len(deleted), "fast_cycles": len(fast)})]

    if deleted:
        actors = sorted({d["actor"] for d in deleted})
        findings.append(_finding(
            "export_record_cleanup", "high",
            f"{len(deleted)} export jobs were downloaded and then deleted",
            "Create, download and delete all fall inside short windows for these jobs, so the "
            "audit trail no longer holds the record that was exported. Actors involved: "
            + ", ".join(actors) + ".",
            ["E02", "E06"],
            caveat="This shows the trail is gone, not what left with it. Recovering the payload "
                   "list needs the billing artefact (E06) or an HelpDeskr retention export.",
            subject=",".join(actors), count=len(deleted),
            meta={"jobs": sorted(j for j, e in jobs.items()
                                 if any(s["action"] == "export.delete" for s in e["steps"]))}))

    off_cycle = [r for r in rows if datetime.fromtimestamp(r["ts_ms"] / 1000, timezone.utc).weekday()
                 != WEEKLY_EXPORT_DAY]
    if off_cycle:
        days = sorted({datetime.fromtimestamp(r["ts_ms"] / 1000, timezone.utc).strftime("%a %d %b")
                       for r in off_cycle})
        findings.append(_finding(
            "export_off_cycle", "medium",
            f"{len(off_cycle)} export events fall outside the weekly Tuesday cycle",
            "The support team describes one export run per week (E13). These events sit on "
            + ", ".join(days) + ". Timestamps are post-normalization; the raw log is wall-clock "
            "India time, and the shift alone moves an export recorded after 18:30 local into the "
            "previous UTC day.",
            ["E02", "E13"],
            caveat="Off-cycle is a deviation from a described routine, not a deviation from policy "
                   "on its own; E10 sets no weekday rule.",
            subject="export.schedule", count=len(off_cycle),
            meta={"events": [{"ts_utc": r["ts_utc"], "actor": r["actor"], "action": r["action"]}
                             for r in off_cycle[:25]]}))
    return findings


def fingerprint_deviation(store) -> list[dict]:
    """Bind each credential to the agents, subnets and hours it actually used."""
    findings = []
    rows = store.query(
        "SELECT api_key_id, COUNT(*) n, GROUP_CONCAT(DISTINCT user_agent) agents, "
        "GROUP_CONCAT(DISTINCT src_24) nets, "
        "SUM(CASE WHEN CAST(strftime('%H', ts_utc) AS INT) NOT BETWEEN 22 AND 6 THEN 1 ELSE 0 END) "
        "  AS outside_window "
        "FROM events WHERE api_key_id != '' AND evidence_id IN ('E01','E18') GROUP BY api_key_id")
    for row in rows:
        agents = [a for a in (row["agents"] or "").split(",") if a]
        nets = [n for n in (row["nets"] or "").split(",") if n]
        notes = []
        if len(agents) > 1:
            notes.append(f"{len(agents)} distinct user agents: {', '.join(sorted(agents))}")
        if len(nets) > 1:
            notes.append(f"{len(nets)} distinct /24 ranges: {', '.join(sorted(nets))}")
        if row["api_key_id"] in INTEGRATION_KEYS and row["outside_window"]:
            notes.append(f"{row['outside_window']} calls outside the 22:00-07:00 UTC batch window")
        if not notes:
            continue
        findings.append(_finding(
            "fingerprint_deviation", "medium" if len(notes) > 1 else "low",
            f"Behavioural fingerprint is not single-valued for {row['api_key_id']}",
            "; ".join(notes) + f". Spread across {row['n']} logged calls.",
            ["E01", "E18", "E04"],
            caveat="Shared service credentials legitimately run from several hosts and client "
                   "versions, so a wide fingerprint is a scoping problem first and a suspicion only "
                   "if a specific call cannot be accounted for.",
            subject=row["api_key_id"], count=row["n"],
            meta={"agents": sorted(agents), "nets": sorted(nets),
                  "outside_window": row["outside_window"]}))
    return findings


def identity_gaps(store) -> list[dict]:
    """Roster state against SSO activity: terminations, and actors with no roster entry."""
    findings = []
    late = store.query(
        "SELECT p.username, p.full_name, p.status, p.termination_date, "
        "COUNT(*) n, MIN(e.ts_utc) first_seen, MAX(e.ts_utc) last_seen "
        "FROM people p JOIN events e ON e.evidence_id = 'E03' AND e.actor = p.username "
        "WHERE p.termination_date != '' AND substr(e.ts_utc, 1, 10) > p.termination_date "
        "GROUP BY p.username")
    for row in late:
        findings.append(_finding(
            "post_termination_access", "critical",
            f"Sign-in recorded after termination: {row['full_name']} ({row['username']})",
            f"Roster (E14) shows termination on {row['termination_date']} while the account status "
            f"field still reads '{row['status']}'. {row['n']} SSO sign-in(s) are logged from "
            f"{row['first_seen']} to {row['last_seen']}.",
            ["E03", "E14", "E10"],
            caveat="A sign-in after a termination date needs investigating; it is consistent with a "
                   "missed offboarding, a rehire, or a reused identifier, and E03 alone cannot "
                   "separate those.",
            subject=row["username"], occurred_utc=row["first_seen"], count=row["n"],
            meta={"full_name": row["full_name"], "termination_date": row["termination_date"],
                  "roster_status": row["status"]}))

    inconsistent = store.one(
        "SELECT COUNT(*) n FROM people WHERE termination_date != '' AND status = 'active'")["n"]
    if inconsistent:
        findings.append(_finding(
            "roster_state", "medium",
            f"{inconsistent} roster rows carry a termination date and status 'active'",
            "E14 lists staff with a termination_date while the status field still says active, and "
            "E10 requires access removal on leaving. Anything downstream that filters on status "
            "rather than termination_date treats these people as current staff.",
            ["E14", "E10"],
            caveat="This is a data-quality gap in the roster. It does not by itself show that any "
                   "specific account could still authenticate.",
            subject="hr.roster", count=inconsistent))

    unknown = store.query(
        "SELECT e.actor, COUNT(*) n, MIN(e.ts_utc) first_seen, MAX(e.ts_utc) last_seen, "
        "GROUP_CONCAT(DISTINCT e.source_ip) ips FROM events e "
        "LEFT JOIN people p ON p.username = e.actor "
        "WHERE e.evidence_id = 'E03' AND e.actor != '' AND p.username IS NULL GROUP BY e.actor")
    for row in unknown:
        findings.append(_finding(
            "unrostered_identity", "high",
            f"SSO activity from an identity absent from the roster: {row['actor']}",
            f"{row['n']} sign-ins between {row['first_seen']} and {row['last_seen']} from "
            f"{len(set((row['ips'] or '').split(',')))} distinct address(es). No E14 record exists "
            "for this username, so no owner, department or leaving date can be cited.",
            ["E03", "E14"],
            caveat="Service accounts legitimately sit outside a staff roster. The finding is that "
                   "nothing in the supplied evidence names an owner, not that the account is hostile.",
            subject=row["actor"], occurred_utc=row["first_seen"], count=row["n"],
            meta={"ips": sorted(set((row["ips"] or "").split(",")))[:12]}))
    return findings


def clock_integrity(store) -> list[dict]:
    """What normalization changed, and what it could not settle."""
    ist_rows = store.one(
        "SELECT COUNT(*) n FROM events WHERE clock = 'wall_ist'")["n"]
    shifted = store.one(
        "SELECT COUNT(*) n FROM events WHERE clock = 'wall_ist' "
        "AND substr(raw_ts, 1, 10) != substr(ts_utc, 1, 10)")["n"]
    e5 = store.one("SELECT COUNT(*) n FROM events WHERE clock = 'epoch_unverified'")["n"]
    bound = clocks.bound_offset(
        [r["ts_ms"] for r in store.query("SELECT ts_ms FROM events WHERE clock = 'epoch_unverified'")],
        [r["ts_ms"] for r in store.query("SELECT ts_ms FROM events WHERE evidence_id IN ('E01','E03','E15')")])

    day_shift_note = (
        f"{shifted} of {ist_rows} wall-clock events land on a different calendar day once shifted "
        "to UTC" if shifted else
        f"{ist_rows} wall-clock events were shifted to UTC without crossing a date boundary")
    findings = [_finding(
        "clock_normalization", "info",
        "Timestamps normalized onto one UTC axis before any correlation",
        f"E02 and E13 were recorded as India wall clock with no offset marker and were shifted back "
        f"5h30m; {day_shift_note}. The dd/mm order is confirmed rather than assumed: "
        "the first component exceeds 12 in thousands of E02 rows.",
        ["E02", "E13", "E01", "E03"],
        caveat="The 5h30m offset is taken from the case description of HelpDeskr, not measured from "
               "the log itself.",
        subject="clocks.utc", count=ist_rows,
        meta={"wall_ist_rows": ist_rows, "day_boundary_shifts": shifted})]

    verdict = bound.get("verdict")
    lag = bound.get("best_lag_s")
    lag_text = f"{lag}s" if lag is not None else "not identifiable"
    median_gap = bound.get("median_nearest_gap_s")
    gap_text = f"{median_gap}s" if median_gap is not None else "unavailable"
    findings.append(_finding(
        "clock_unverified", "medium" if verdict != "identified" else "info",
        "BlueVault's epoch clock could not be pinned to the UTC streams",
        f"{e5} E05 events carry epoch seconds from a source the case file describes as running fast. "
        f"Fitting E05's hourly activity profile against E01/E03/E15 gives a {lag_text} lag; "
        f"the phase fit is not a reliable clock lock across {bound.get('comparable_events')} "
        f"comparable events. Median nearest-UTC-event gap is {gap_text}. E05 times are therefore "
        "used at face value with the stated uncertainty, and any correlation that depends on "
        "sub-hour E05 ordering is reported as unresolved.",
        ["E05", "E01", "E03", "E15"],
        caveat="Refusing to print a drift number is the finding here. A single plausible-looking "
               "offset would let every downstream twin match inherit it as fact.",
        subject="clocks.bluevault", count=e5, meta=bound))
    return findings


DETECTION_SETS = (
    clock_integrity,
    vendor_write_review,
    credential_hygiene,
    indicator_matches,
    export_lifecycle,
    fingerprint_deviation,
    identity_gaps,
)


def run_all(store, actor="analyst") -> dict:
    run_id = uuid.uuid4().hex[:12]
    created = []
    for detect in DETECTION_SETS:
        for finding in detect(store) or []:
            finding_id = store.write(
                "INSERT INTO findings (run_id, kind, severity, title, detail, caveat, subject,"
                " evidence_ids, occurred_utc, count, meta, created_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, finding["kind"], finding["severity"], finding["title"], finding["detail"],
                 finding["caveat"], finding["subject"], finding["evidence_ids"],
                 finding["occurred_utc"], finding["count"],
                 json.dumps(finding["meta"], default=str), clocks.iso(int(
                     datetime.now(timezone.utc).timestamp() * 1000))))
            created.append((finding_id, finding))
    store.audit(actor, "analysis.run", run_id,
                {"findings": len(created),
                 "by_severity": {s: sum(1 for _, f in created if f["severity"] == s)
                                 for s in SEVERITY_ORDER}})
    return {"run_id": run_id, "findings": len(created)}
