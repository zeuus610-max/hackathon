import json
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

from . import clocks, detections, ingest
from .config import CASE_ID, COMPANY, TRACK

router = APIRouter(prefix="/api")


def store_of(request: Request):
    return request.app.state.store


@router.get("/case")
def case_summary(request: Request):
    store = store_of(request)
    totals = store.one(
        "SELECT COUNT(*) events, MIN(ts_utc) first_event, MAX(ts_utc) last_event, "
        "COUNT(DISTINCT system) systems, COUNT(DISTINCT api_key_id) keys, "
        "COUNT(DISTINCT source_ip) addresses FROM events")
    evidence = store.query(
        "SELECT evidence_id, filename, kind, system, clock, rows, status, groups, note, ingested_at "
        "FROM evidence ORDER BY evidence_id")
    loaded = [e for e in evidence if e["status"] in ("ingested", "reference", "cached")]
    run = store.one("SELECT run_id, MAX(created_utc) at FROM findings GROUP BY run_id "
                    "ORDER BY at DESC LIMIT 1")
    severities = store.query(
        "SELECT severity, COUNT(*) n FROM findings WHERE run_id = ? GROUP BY severity",
        (run["run_id"],)) if run else []
    top_keys = store.query(
        "SELECT api_key_id k, COUNT(*) n FROM events WHERE api_key_id != '' "
        "GROUP BY api_key_id ORDER BY n DESC LIMIT 6")
    return {
        "case_id": CASE_ID,
        "company": COMPANY,
        "track": TRACK,
        "product": "Orbit",
        "subtitle": "Evidence-led vendor bank-change review",
        "events": totals["events"] or 0,
        "window": {"first": totals["first_event"], "last": totals["last_event"]},
        "systems": totals["systems"] or 0,
        "credentials": totals["keys"] or 0,
        "addresses": totals["addresses"] or 0,
        "evidence_total": len(evidence),
        "evidence_loaded": len(loaded),
        "document_only": len(evidence) - len(loaded),
        "streams": [{"evidence_id": e["evidence_id"], "system": e["system"], "rows": e["rows"],
                     "clock": e["clock"]} for e in loaded],
        "top_credentials": top_keys,
        "run": {"run_id": run["run_id"], "at": run["at"],
                "findings": sum(s["n"] for s in severities)} if run else None,
        "severity_counts": {s["severity"]: s["n"] for s in severities},
        "clocks": {
            "wall_ist": store.one("SELECT COUNT(*) n FROM events WHERE clock = 'wall_ist'")["n"],
            "utc": store.one("SELECT COUNT(*) n FROM events WHERE clock = 'utc'")["n"],
            "unverified": store.one(
                "SELECT COUNT(*) n FROM events WHERE clock = 'epoch_unverified'")["n"],
        },
        "audit": store.audit_verified(),
    }


@router.get("/evidence")
def evidence_list(request: Request):
    return {"evidence": store_of(request).query(
        "SELECT * FROM evidence ORDER BY evidence_id")}


@router.get("/clocks")
def clock_report(request: Request, tolerance: int = Query(900, ge=0, le=86_400)):
    store = store_of(request)
    spec_rows = []
    for evidence_id, spec in sorted(clocks.CLOCK_SPECS.items()):
        row = store.one(
            "SELECT COUNT(*) n, MIN(raw_ts) sample_raw, MIN(ts_utc) sample_utc FROM events "
            "WHERE evidence_id = ?", (evidence_id,))
        spec_rows.append({
            "evidence_id": evidence_id, "system": spec.system, "kind": spec.kind,
            "label": spec.label, "rule": spec.rule, "verifiable": spec.verifiable,
            "rows": row["n"] or 0, "sample_raw": row["sample_raw"], "sample_utc": row["sample_utc"],
        })

    day_boundary = store.one(
        "SELECT COUNT(*) n FROM events WHERE clock = 'wall_ist' "
        "AND substr(raw_ts, 1, 10) != substr(ts_utc, 1, 10)")["n"]
    dd_mm_proof = store.one(
        "SELECT COUNT(*) n FROM events WHERE evidence_id = 'E02' "
        "AND CAST(substr(raw_ts, 1, 2) AS INT) > 12")["n"]

    samples = store.query(
        "SELECT evidence_id, raw_ts, ts_utc, clock FROM events WHERE clock = 'wall_ist' "
        "AND substr(raw_ts, 1, 10) != substr(ts_utc, 1, 10) ORDER BY ts_ms LIMIT 4")

    e5 = [(r["ts_ms"], r["src_24"]) for r in store.query(
        "SELECT ts_ms, src_24 FROM events WHERE evidence_id = 'E05'")]
    e1 = [(r["ts_ms"], r["src_24"]) for r in store.query(
        "SELECT ts_ms, src_24 FROM events WHERE evidence_id IN ('E01','E18')")]
    bound = clocks.bound_offset([ms for ms, _ in e5], [ms for ms, _ in e1])
    offsets = list(range(-1800, 1801, 300))
    curve = clocks.fragility_curve(e5, e1, offsets)
    baseline = next(c["links"] for c in curve if c["offset_s"] == 0)
    peak = max(curve, key=lambda c: c["links"])

    return {
        "sources": spec_rows,
        "ist_offset_minutes": 330,
        "day_boundary_shifts": day_boundary,
        "dd_mm_evidence_rows": dd_mm_proof,
        "samples": samples,
        "drift_bound": bound,
        "fragility": {
            "tolerance_s": tolerance,
            "pairs_at_recorded_time": baseline,
            "peak_links": peak["links"],
            "peak_offset_s": peak["offset_s"],
            "curve": curve,
            "note": "Twin links between BlueVault file access and LedgerOne API calls, counted for "
                    "each assumed offset on the unattested clock. A link count that moves this much "
                    "with a 30-minute shift means sub-hour ordering cannot be trusted yet.",
        },
    }


@router.get("/events")
def events(request: Request, evidence: str | None = None, key: str | None = None,
           ip: str | None = None, system: str | None = None, action: str | None = None,
           since: str | None = None, until: str | None = None,
           limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    store = store_of(request)
    where, params = ["1=1"], []
    for column, value in (("evidence_id", evidence), ("system", system), ("api_key_id", key),
                          ("source_ip", ip), ("action", action)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if since:
        where.append("ts_utc >= ?")
        params.append(since)
    if until:
        where.append("ts_utc <= ?")
        params.append(until)
    clause = " AND ".join(where)
    total = store.one(f"SELECT COUNT(*) n FROM events WHERE {clause}", params)["n"]
    rows = store.query(
        f"SELECT id, evidence_id, system, raw_ts, ts_utc, clock, actor, api_key_id, source_ip, "
        f"user_agent, action, endpoint, method, object_id, records, result, bytes, raw FROM events "
        f"WHERE {clause} ORDER BY ts_ms LIMIT ? OFFSET ?", params + [limit, offset])
    for row in rows:
        row["extra"] = json.loads(row.pop("raw")).get("extra", {})
    return {"total": total, "limit": limit, "offset": offset, "events": rows}


@router.get("/findings")
def findings(request: Request, run: str | None = None, severity: str | None = None,
             kind: str | None = None):
    store = store_of(request)
    run_id = run or store.get_meta("last_run")
    if not run_id:
        return {"run_id": None, "findings": []}
    where, params = ["run_id = ?"], [run_id]
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if kind:
        where.append("kind = ?")
        params.append(kind)
    rows = store.query(
        f"SELECT * FROM findings WHERE {' AND '.join(where)} "
        f"ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        f"WHEN 'low' THEN 3 ELSE 4 END, count DESC", params)
    for row in rows:
        row["meta"] = json.loads(row["meta"] or "{}")
        row["evidence_ids"] = row["evidence_ids"].split(",")
    return {"run_id": run_id, "findings": rows}


@router.post("/analyze")
def analyze(request: Request, actor: str = Form("analyst")):
    store = store_of(request)
    result = detections.run_all(store, actor=actor)
    store.set_meta("last_run", result["run_id"])
    return result


@router.get("/audit")
def audit(request: Request, limit: int = Query(20, ge=1, le=200)):
    store = store_of(request)
    return {"verification": store.audit_verified(), "entries": store.audit_tail(limit)}


@router.post("/evidence/upload")
async def upload(request: Request, file: UploadFile = File(...),
                 evidence_id: str | None = Form(None)):
    store = store_of(request)
    name = Path(file.filename or "").name
    spec = None
    if evidence_id:
        spec = ingest.PLAN_BY_ID.get(evidence_id.upper())
        if spec is None:
            raise HTTPException(404, f"{evidence_id} is not a known evidence id")
    else:
        for candidate in ingest.PLAN:
            if candidate.filename == name or name.lower().startswith(candidate.evidence_id.lower()):
                spec = candidate
                break
    if spec is None:
        raise HTTPException(422, f"Cannot map {name or 'this upload'} to an evidence id")
    if spec.kind == "document":
        raise HTTPException(415, f"{spec.evidence_id} is a document artefact; "
                                "document parsing is not implemented in this build")

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / spec.filename  # canonical name, never the client's path
        with target.open("wb") as handle:
            shutil.copyfileobj(file.file, handle)
        result = ingest.ingest_one(store, spec, evidence_dir=Path(tmp), force=True)
    store.audit("analyst", "evidence.upload", spec.evidence_id,
                {"filename": name, "rows": result.get("rows"), "status": result.get("status")})
    detection = detections.run_all(store, actor="analyst")
    store.set_meta("last_run", detection["run_id"])
    return {"ingest": result, "analysis": detection}
