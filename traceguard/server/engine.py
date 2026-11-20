"""Transparent request-level scoring for the CR-26-047 demonstration."""

from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json
import os
import uuid

from .schemas import EvaluationRequest
from .store import utcnow

LEGACY_CANARY = "key-tb-03 (legacy)"
PRIVATE_LINK = "10.20.4.0/24"
WEIGHTS = {
    "key": max(0, min(100, int(os.getenv("TRACEGUARD_WEIGHT_KEY", "25")))),
    "user_agent": max(0, min(100, int(os.getenv("TRACEGUARD_WEIGHT_AGENT", "25")))),
    "network": max(0, min(100, int(os.getenv("TRACEGUARD_WEIGHT_NETWORK", "15")))),
    "behavior": max(0, min(100, int(os.getenv("TRACEGUARD_WEIGHT_BEHAVIOR", "35")))),
}
REQUEST_VOLUME_THRESHOLD = max(1, int(os.getenv("TRACEGUARD_REQUEST_VOLUME_THRESHOLD", "80")))
EXPORT_VOLUME_THRESHOLD = max(1, int(os.getenv("TRACEGUARD_EXPORT_VOLUME_THRESHOLD", "20")))
QUARANTINE_THRESHOLD = max(1, min(100, int(os.getenv("TRACEGUARD_QUARANTINE_THRESHOLD", "40"))))

PRESETS = {
    "normal": EvaluationRequest(key_id="key-tb-07", system="LedgerOne", endpoint="/vendors/sync", user_agent="TallyBridge-Sync 3.5.0", caller_ip="10.20.4.18", sync_window="expected", request_volume=18, export_volume=4, e02_receipt="present", e15_receipt="present", action_sequence=["nightly_sync"]),
    "downgrade": EvaluationRequest(key_id="key-tb-07", system="LedgerOne", endpoint="/exports/jobs", user_agent="TallyBridge-Sync 3.4.1", caller_ip="10.20.4.77", sync_window="outside", request_volume=140, export_volume=48, e02_receipt="missing", e15_receipt="present", action_sequence=["Create Job", "Download", "Delete Job"]),
    "rogue": EvaluationRequest(key_id="tb-sync-svc", system="LedgerOne", endpoint="/vendors/bank-details", user_agent="backup-agent 2.1", caller_ip="10.20.4.77", sync_window="outside", request_volume=110, export_volume=35, e02_receipt="unknown", e15_receipt="present", action_sequence=["bulk_export"]),
    "canary": EvaluationRequest(key_id=LEGACY_CANARY, system="LedgerOne", endpoint="/payments/search"),
}


def _network_score(raw_ip: str | None) -> tuple[int, str]:
    if not raw_ip:
        return 15, "Caller IP is missing; network context is unresolved."
    try:
        addr = ip_address(raw_ip)
    except ValueError:
        return 20, "Caller IP is not a valid address."
    if addr.version == 4 and addr in ip_network("10.20.4.0/24"):
        return 10, "The request came from the vendor private link; that range is not trusted by itself."
    if addr.version == 4 and addr in ip_network("172.16.0.0/16"):
        return 0, "The source is in the office/server range; network location is only one factor."
    return 12, "The caller is outside the documented office/server and vendor-link ranges."


def _has_twin_proof(payload: EvaluationRequest) -> tuple[bool, list[str]]:
    sensitive = any(part in payload.endpoint.lower() for part in ("payment", "bank"))
    if not sensitive:
        return True, []
    missing = []
    for label, receipt in (("E02 HelpDeskr audit", payload.e02_receipt), ("E15 network flow", payload.e15_receipt)):
        if receipt != "present":
            missing.append(label)
    if payload.request_id is None:
        missing.append("request ID correlation")
    if not payload.caller_ip:
        missing.append("caller IP correlation")
    if not payload.user_agent:
        missing.append("User-Agent correlation")
    if not payload.timestamp:
        missing.append("time-window correlation")
    return not missing, missing


def evaluate(payload: EvaluationRequest) -> dict:
    evaluation_id = str(uuid.uuid4())
    created_at = utcnow()
    if payload.key_id.casefold() in {"key-tb-03", LEGACY_CANARY.casefold()}:
        return {
            "evaluation_id": evaluation_id, "timestamp": created_at, "verdict": "CRITICAL_CANARY",
            "risk_score": 100, "factors": {"key": 100, "user_agent": 0, "network": 0, "behavior": 0},
            "baseline": "Canary identifiers are excluded from baseline scoring.",
            "twin_proof": {"status": "not_required_for_tripwire", "missing": []},
            "triggered_rules": ["legacy_key_canary"],
            "reasons": ["Use of the legacy key identifier is a deterministic tripwire condition."],
            "limitations": ["This verdict assumes the credential identifier is correctly attributed."],
            "recommended_response": "Isolate the alert, preserve request evidence, and investigate credential use.",
            "canary": True, "weights": WEIGHTS,
        }

    reasons, rules = [], []
    factors = {}
    key = payload.key_id.lower()
    if key == "key-tb-07":
        factors["key"] = 12
        reasons.append("key-tb-07 is documented as broad and without an IP restriction or expiry.")
    elif key == "tb-sync-svc":
        factors["key"] = 20
        reasons.append("tb-sync-svc has administrator scope on HelpDeskr.")
    else:
        factors["key"] = 18
        reasons.append("The key is not in the documented expected integration set.")

    agent = payload.user_agent.lower()
    if "3.4.1" in agent or "backup-agent" in agent:
        factors["user_agent"] = 25
        rules.append("client_fingerprint_anomaly")
        reasons.append("The client fingerprint differs from the expected TallyBridge-Sync 3.5.0.")
    elif "tallybridge-sync 3.5.0" in agent:
        factors["user_agent"] = 0
    elif not agent:
        factors["user_agent"] = 15
        reasons.append("User-Agent is missing, so client identity cannot be corroborated.")
    else:
        factors["user_agent"] = 12
        reasons.append("The client fingerprint is not the documented expected sync agent.")

    factors["network"], network_reason = _network_score(payload.caller_ip)
    reasons.append(network_reason)

    behavior = 0
    if payload.sync_window == "outside":
        behavior += 12
        reasons.append("The request is outside the documented sync window.")
    if payload.request_volume > REQUEST_VOLUME_THRESHOLD or payload.export_volume > EXPORT_VOLUME_THRESHOLD:
        behavior += 18
        rules.append("volume_anomaly")
        reasons.append("Request or export volume is above the configured demo threshold.")
    sequence = " ".join(payload.action_sequence).lower()
    if all(action in sequence for action in ("create", "download", "delete")):
        behavior += 20
        rules.append("export_download_delete_sequence")
        reasons.append("The action sequence matches the documented export/download/delete pattern.")
    factors["behavior"] = min(behavior, 35)

    has_twins, missing = _has_twin_proof(payload)
    if not has_twins:
        rules.append("twin_proof_missing")
        reasons.append("Sensitive activity is unverified because required corroborating records are missing.")

    weighted_factors = {name: min(score, WEIGHTS[name]) for name, score in factors.items()}
    total = min(100, sum(weighted_factors.values()))
    verdict = "QUARANTINE" if total >= QUARANTINE_THRESHOLD or not has_twins else "PASS"
    if not reasons:
        reasons.append("The request matches the configured normal nightly-sync profile.")
    return {
        "evaluation_id": evaluation_id, "timestamp": created_at, "verdict": verdict,
        "risk_score": total, "factors": weighted_factors, "weights": WEIGHTS, "baseline": "Compared with the documented nightly sync profile.",
        "twin_proof": {"status": "verified" if has_twins else "unverified", "missing": missing},
        "triggered_rules": rules, "reasons": reasons,
        "limitations": ["This is a demonstration score, not experimentally validated performance.",
                        "Signals classify request risk; they do not identify an actor or prove intent."],
        "recommended_response": "Allow the request to proceed under policy." if verdict == "PASS" else "Hold the request, alert a reviewer, and preserve linked evidence.",
        "canary": False,
    }


def persist(store, payload: EvaluationRequest, result: dict) -> None:
    store.write(
        "INSERT INTO eval_history (evaluation_id, created_utc, key_id, user_agent, caller_ip, verdict, risk_score, triggered_rules, canary, payload, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (result["evaluation_id"], result["timestamp"], payload.key_id, payload.user_agent,
         payload.caller_ip or "", result["verdict"], result["risk_score"],
         json.dumps(result["triggered_rules"]), int(result["canary"]),
         payload.model_dump_json(), json.dumps(result)),
    )
    if result["canary"]:
        store.write("INSERT INTO canary_alerts (evaluation_id, created_utc, key_id, payload) VALUES (?, ?, ?, ?)",
                    (result["evaluation_id"], result["timestamp"], payload.key_id, payload.model_dump_json()))
