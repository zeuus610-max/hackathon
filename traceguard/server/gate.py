"""Request-time enforcement for vendor bank-detail changes.

This gate fails closed. It only forwards a bank change after the caller is
authorized for that vendor and an independent active Finance approver confirms
the same normalized bank details.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request

from .schemas import (BankDetails, QBOUIConfirmation, VendorBankChangeApproval,
                      VendorBankChangeRequest)
from .store import Store, utcnow


@dataclass(frozen=True)
class Principal:
    principal: str
    role: str
    credential_id: str
    token_sha256: str
    scopes: frozenset[str]
    vendor_ids: frozenset[str]
    employee_username: str | None = None
    active: bool = False


def _read_credentials() -> list[Principal]:
    raw = os.getenv("ORBIT_GATE_CREDENTIALS_JSON", "")
    if not raw:
        raise HTTPException(503, "Request gate credentials are not configured")
    try:
        items = json.loads(raw)
        if not isinstance(items, list) or not items:
            raise ValueError("Expected a nonempty list")
        principals = []
        for item in items:
            token_hash = item["token_sha256"].lower()
            role = item["role"]
            if (not re.fullmatch(r"[0-9a-f]{64}", token_hash)
                    or role not in {"integration", "finance_maker", "finance_approver"}
                    or not isinstance(item.get("active"), bool)
                    or not isinstance(item.get("scopes", []), list)
                    or not isinstance(item.get("vendor_ids", []), list)):
                raise ValueError("Invalid credential record")
            principals.append(Principal(
                principal=item["principal"],
                role=role,
                credential_id=item.get("credential_id", item["principal"]),
                token_sha256=token_hash,
                scopes=frozenset(item.get("scopes", [])),
                vendor_ids=frozenset(item.get("vendor_ids", [])),
                employee_username=item.get("employee_username"),
                active=item["active"],
            ))
        if len({principal.token_sha256 for principal in principals}) != len(principals):
            raise ValueError("Duplicate credential hash")
        return principals
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "Request gate credentials are invalid") from exc


def _fernet() -> Fernet:
    key = os.getenv("ORBIT_DATA_ENCRYPTION_KEY", "")
    hmac_key = os.getenv("ORBIT_BANK_FIELD_HMAC_KEY", "")
    try:
        cipher = Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise HTTPException(503, "Request gate encryption is not configured")
    if len(hmac_key.encode()) < 32:
        raise HTTPException(503, "Request gate fingerprint key is not configured")
    return cipher


def _normalized(details: BankDetails) -> dict:
    value = details.model_dump()
    value["country"] = value["country"].upper()
    value["account_number"] = re.sub(r"[\s-]", "", value["account_number"]).upper()
    value["routing_code"] = re.sub(r"[\s-]", "", value["routing_code"]).upper()
    value["bank_name"] = " ".join(value["bank_name"].split())
    value["account_holder"] = " ".join(value["account_holder"].split())
    return value


def _fingerprint(vendor_id: str, details: BankDetails) -> str:
    key = os.environ["ORBIT_BANK_FIELD_HMAC_KEY"].encode()
    payload = json.dumps({"vendor_id": vendor_id, "bank_details": _normalized(details)},
                         sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _secret(details: BankDetails) -> str:
    return _fernet().encrypt(json.dumps(_normalized(details), sort_keys=True).encode()).decode()


def _unsecret(value: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(value.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "Stored bank-change payload cannot be decrypted") from exc


def _authenticate(request: Request, store: Store) -> Principal:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 512:
        raise HTTPException(401, "Bearer credentials required")
    supplied_hash = hashlib.sha256(token.encode()).hexdigest()
    principals = _read_credentials()
    principal = next((item for item in principals
                      if hmac.compare_digest(item.token_sha256, supplied_hash)), None)
    if principal is None:
        raise HTTPException(401, "Invalid credentials")
    if not principal.active:
        raise HTTPException(403, "Gate credential is disabled")

    if principal.role == "integration":
        credential = store.one("SELECT status FROM credentials WHERE credential_id = ?",
                               (principal.credential_id,))
        if not credential or credential["status"].lower() != "active":
            raise HTTPException(403, "Integration credential is inactive or unregistered")
        if principal.credential_id.casefold() == "key-tb-03":
            return principal
    else:
        if not principal.employee_username:
            raise HTTPException(403, "Finance principal is not mapped to an employee record")
        employee = store.one("SELECT status, termination_date FROM people WHERE username = ?",
                             (principal.employee_username,))
        if not employee or (employee["status"] or "").lower() != "active":
            raise HTTPException(403, "Finance identity is inactive")
        termination = employee["termination_date"]
        if termination:
            try:
                if datetime.fromisoformat(termination[:10]).date() < datetime.now(timezone.utc).date():
                    raise HTTPException(403, "Finance identity is past its termination date")
            except ValueError:
                raise HTTPException(403, "Finance identity termination data is invalid")
    return principal


def _public(row: dict, include_bank_details: bool = False) -> dict:
    result = {key: row[key] for key in (
        "gate_request_id", "request_id", "vendor_id", "requester", "credential_id",
        "source_ip", "user_agent", "account_last4", "status", "upstream_status",
        "upstream_reference", "created_utc", "updated_utc")}
    result["reason_codes"] = json.loads(row["reason_codes"] or "[]")
    result["bank_fingerprint"] = row["bank_fingerprint"]
    if include_bank_details:
        result["bank_details"] = _unsecret(row["bank_details_ciphertext"])
    return result


def gate_status() -> dict:
    try:
        _read_credentials()
        _fernet()
        configured = True
    except HTTPException:
        configured = False
    if os.getenv("ORBIT_FINANCE_PROVIDER", "generic").lower() == "qbo":
        qbo_oauth_configured = all(os.getenv(key) for key in (
            "ORBIT_QBO_REALM_ID", "ORBIT_QBO_CLIENT_ID", "ORBIT_QBO_CLIENT_SECRET",
            "ORBIT_QBO_REFRESH_TOKEN"))
        return {"configured": configured, "can_hold": configured,
                "can_forward": False,
                "upstream_configured": False,
                "oauth_configured": qbo_oauth_configured,
                "provider": "quickbooks_online_sandbox",
                "write_mode": "manual_qbo_ui",
                "manual_confirmation_available": configured,
                "enforcement": "deny unless active identity, vendor scope, and exact Finance approval pass"}
    raw_url = os.getenv("ORBIT_FINANCE_API_BASE_URL", "").rstrip("/")
    parsed = urlsplit(raw_url)
    upstream = bool(raw_url and os.getenv("ORBIT_FINANCE_API_TOKEN") and
                    (parsed.scheme == "https" or parsed.hostname in {"localhost", "127.0.0.1", "::1"})
                    and not (parsed.query or parsed.fragment or parsed.username or parsed.password))
    return {"configured": configured, "can_hold": configured,
            "can_forward": configured and upstream,
            "upstream_configured": upstream,
            "provider": "generic",
            "enforcement": "deny unless active identity, vendor scope, and exact Finance approval pass"}


def _require_role(principal: Principal, *roles: str) -> None:
    if principal.role not in roles:
        raise HTTPException(403, "This identity cannot perform that gate action")


def _vendor_allowed(principal: Principal, vendor_id: str) -> bool:
    return "*" in principal.vendor_ids or vendor_id in principal.vendor_ids


def _provider_url(vendor_id: str) -> str:
    raw = os.getenv("ORBIT_FINANCE_API_BASE_URL", "").rstrip("/")
    token = os.getenv("ORBIT_FINANCE_API_TOKEN", "")
    parsed = urlsplit(raw)
    if not raw or not token:
        raise HTTPException(503, "Finance write connector is not configured; no bank change was sent")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(503, "Finance connector must use HTTPS")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise HTTPException(503, "Finance connector URL is invalid")
    return f"{raw}/v2/vendors/{quote(vendor_id, safe='')}/bank-details"


async def submit_change(payload: VendorBankChangeRequest, request: Request) -> dict:
    store: Store = request.app.state.store
    principal = _authenticate(request, store)
    _require_role(principal, "integration", "finance_maker")
    fingerprint = _fingerprint(payload.vendor_id, payload.bank_details)
    existing = store.one("SELECT * FROM gate_requests WHERE idempotency_key = ?",
                         (payload.idempotency_key,))
    if existing:
        if existing["bank_fingerprint"] != fingerprint or existing["requester"] != principal.principal:
            raise HTTPException(409, "Idempotency key was already used for another request")
        return {**_public(existing), "idempotent_replay": True}
    existing_request = store.one("SELECT gate_request_id FROM gate_requests WHERE request_id = ?",
                                 (payload.request_id,))
    if existing_request:
        raise HTTPException(409, "Request ID was already processed")

    reasons = []
    canary = principal.credential_id.casefold() == "key-tb-03"
    if canary:
        reasons.append("legacy_key_canary")
    if "vendor:bank-change" not in principal.scopes:
        reasons.append("identity_not_authorized_for_bank_changes")
    if not _vendor_allowed(principal, payload.vendor_id):
        reasons.append("vendor_outside_identity_scope")
    reasons.append("exact_finance_approval_required")

    if canary:
        status = "CRITICAL_CANARY"
    elif any(code != "exact_finance_approval_required" for code in reasons):
        status = "BLOCKED"
    else:
        status = "HELD"

    caller_ip = request.client.host if request.client else "UNKNOWN"
    user_agent = request.headers.get("user-agent", "UNKNOWN")[:240]
    now = utcnow()
    gate_request_id = str(uuid.uuid4())
    details = _normalized(payload.bank_details)
    ciphertext = _secret(payload.bank_details)
    with store.lock:
        store.conn.execute(
            "INSERT INTO gate_requests (gate_request_id, request_id, idempotency_key, vendor_id, requester, requester_employee, credential_id, source_ip, user_agent, bank_fingerprint, bank_details_ciphertext, account_last4, status, reason_codes, created_utc, updated_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (gate_request_id, payload.request_id, payload.idempotency_key, payload.vendor_id,
             principal.principal, principal.employee_username, principal.credential_id, caller_ip, user_agent, fingerprint,
             ciphertext, details["account_number"][-4:], status, json.dumps(reasons), now, now),
        )
        store.conn.commit()
    store.audit(principal.principal, "vendor_bank_change.held", gate_request_id,
                {"vendor_id": payload.vendor_id, "credential_id": principal.credential_id,
                 "status": status, "reason_codes": reasons, "bank_fingerprint": fingerprint,
                 "account_last4": details["account_number"][-4:], "request_id": payload.request_id})
    row = store.one("SELECT * FROM gate_requests WHERE gate_request_id = ?", (gate_request_id,))
    return {**_public(row), "idempotent_replay": False}


def list_requests(request: Request, limit: int = 100) -> dict:
    store: Store = request.app.state.store
    principal = _authenticate(request, store)
    _require_role(principal, "finance_approver")
    rows = store.query("SELECT * FROM gate_requests ORDER BY created_utc DESC LIMIT ?", (limit,))
    rows = [row for row in rows if _vendor_allowed(principal, row["vendor_id"])]
    return {"requests": [_public(row) for row in rows]}


def get_request(gate_request_id: str, request: Request) -> dict:
    store: Store = request.app.state.store
    principal = _authenticate(request, store)
    _require_role(principal, "finance_approver")
    row = store.one("SELECT * FROM gate_requests WHERE gate_request_id = ?", (gate_request_id,))
    if not row:
        raise HTTPException(404, "Gate request not found")
    if not _vendor_allowed(principal, row["vendor_id"]):
        raise HTTPException(404, "Gate request not found")
    store.audit(principal.principal, "vendor_bank_change.review", gate_request_id,
                {"vendor_id": row["vendor_id"], "bank_fingerprint": row["bank_fingerprint"]})
    approvals = store.query("SELECT approver, created_utc FROM gate_approvals WHERE gate_request_id = ? ORDER BY created_utc",
                           (gate_request_id,))
    return {**_public(row, include_bank_details=True), "approvals": approvals}


async def approve_change(gate_request_id: str, payload: VendorBankChangeApproval,
                         request: Request) -> dict:
    store: Store = request.app.state.store
    approver = _authenticate(request, store)
    _require_role(approver, "finance_approver")
    row = store.one("SELECT * FROM gate_requests WHERE gate_request_id = ?", (gate_request_id,))
    if not row:
        raise HTTPException(404, "Gate request not found")
    if row["status"] != "HELD":
        raise HTTPException(409, "This request cannot be approved")
    if not payload.confirm_exact_details:
        raise HTTPException(422, "Finance must confirm the exact bank details shown for review")
    if (approver.principal == row["requester"] or
            (approver.employee_username and approver.employee_username == row["requester_employee"])):
        raise HTTPException(403, "The requester cannot approve their own change")
    if not _vendor_allowed(approver, row["vendor_id"]):
        raise HTTPException(403, "This Finance identity is not assigned to this vendor")
    candidate = _fingerprint(row["vendor_id"], payload.bank_details)
    if not hmac.compare_digest(candidate, row["bank_fingerprint"]):
        store.audit(approver.principal, "vendor_bank_change.approval_mismatch", gate_request_id,
                    {"vendor_id": row["vendor_id"], "submitted_fingerprint": candidate})
        raise HTTPException(409, "Approval details do not match the held request")

    approval_id = str(uuid.uuid4())
    now = utcnow()
    qbo_provider = os.getenv("ORBIT_FINANCE_PROVIDER", "generic").lower() == "qbo"
    approved_status = "MANUAL_ACTION_REQUIRED" if qbo_provider else "APPROVED_PENDING_PROVIDER"
    with store.lock:
        latest = store.conn.execute("SELECT status FROM gate_requests WHERE gate_request_id = ?",
                                    (gate_request_id,)).fetchone()
        if not latest or latest["status"] != "HELD":
            raise HTTPException(409, "This request has already left the approval queue")
        duplicate = store.conn.execute(
            "SELECT 1 FROM gate_approvals WHERE gate_request_id = ? AND approver = ?",
            (gate_request_id, approver.principal),
        ).fetchone()
        if duplicate:
            raise HTTPException(409, "This Finance identity already reviewed the request")
        store.conn.execute(
            "INSERT INTO gate_approvals (approval_id, gate_request_id, approver, bank_fingerprint, created_utc) VALUES (?, ?, ?, ?, ?)",
            (approval_id, gate_request_id, approver.principal, candidate, now),
        )
        store.conn.execute(
            "UPDATE gate_requests SET status = ?, updated_utc = ? WHERE gate_request_id = ?",
            (approved_status, now, gate_request_id),
        )
        store.conn.commit()

    if qbo_provider:
        return await _approve_qbo_change(store, approver, row, gate_request_id)

    try:
        provider_url = _provider_url(row["vendor_id"])
        secret = os.environ["ORBIT_FINANCE_API_TOKEN"]
    except HTTPException as exc:
        store.audit(approver.principal, "vendor_bank_change.approved_held", gate_request_id,
                    {"vendor_id": row["vendor_id"], "reason": "finance_connector_unconfigured"})
        return {"gate_request_id": gate_request_id, "status": "APPROVED_PENDING_PROVIDER",
                "detail": "Approval is recorded; no finance-system write was sent because the connector is not configured."}

    bank_details = _unsecret(row["bank_details_ciphertext"])
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=3.0)) as client:
            response = await client.patch(
                provider_url,
                headers={"Authorization": f"Bearer {secret}",
                         "Idempotency-Key": f"orbit-{gate_request_id}"},
                json=bank_details,
            )
    except httpx.HTTPError as exc:
        store.audit(approver.principal, "vendor_bank_change.forward_error", gate_request_id,
                    {"vendor_id": row["vendor_id"], "error_type": type(exc).__name__})
        return {"gate_request_id": gate_request_id, "status": "APPROVED_PENDING_PROVIDER",
                "detail": "Finance connector did not confirm the update. Check upstream state before retrying."}

    if not 200 <= response.status_code < 300:
        store.write("UPDATE gate_requests SET upstream_status = ?, updated_utc = ? WHERE gate_request_id = ?",
                    (response.status_code, utcnow(), gate_request_id))
        store.audit(approver.principal, "vendor_bank_change.forward_rejected", gate_request_id,
                    {"vendor_id": row["vendor_id"], "upstream_status": response.status_code})
        return {"gate_request_id": gate_request_id, "status": "APPROVED_PENDING_PROVIDER",
                "detail": "Finance system rejected the update. No success is reported."}

    upstream_reference = None
    try:
        result = response.json()
        upstream_reference = result.get("id") or result.get("reference")
    except (ValueError, AttributeError):
        pass
    store.write("UPDATE gate_requests SET status = 'APPLIED', upstream_status = ?, upstream_reference = ?, updated_utc = ? WHERE gate_request_id = ?",
                (response.status_code, str(upstream_reference)[:120] if upstream_reference else None,
                 utcnow(), gate_request_id))
    store.audit(approver.principal, "vendor_bank_change.applied", gate_request_id,
                {"vendor_id": row["vendor_id"], "bank_fingerprint": row["bank_fingerprint"],
                 "upstream_status": response.status_code, "upstream_reference": upstream_reference})
    return {"gate_request_id": gate_request_id, "status": "APPLIED",
            "upstream_status": response.status_code, "upstream_reference": upstream_reference}


async def _approve_qbo_change(store: Store, approver: Principal, row: dict,
                             gate_request_id: str) -> dict:
    """Hold QBO requests for UI completion; Vendor API does not update Bill Pay ACH."""
    store.audit(approver.principal, "vendor_bank_change.qbo_ui_required", gate_request_id,
                {"vendor_id": row["vendor_id"], "bank_fingerprint": row["bank_fingerprint"],
                 "reason": "vendor_api_did_not_persist_bill_pay_ach_in_sandbox"})
    return {"gate_request_id": gate_request_id, "status": "MANUAL_ACTION_REQUIRED",
            "detail": "Save the approved details in the QBO vendor Bill Pay ACH section, then confirm its masked account suffix and routing number through the QBO UI confirmation endpoint."}


def confirm_qbo_ui_change(gate_request_id: str, payload: QBOUIConfirmation,
                          request: Request) -> dict:
    """Record an independently authorized Finance check of a manual QBO UI write.

    QBO's US sandbox API may omit Bill Pay bank details from both update and
    read responses. This route records a Finance user's UI readback separately
    from API-confirmed application; it never implies the API performed the write.
    """
    store: Store = request.app.state.store
    confirmer = _authenticate(request, store)
    _require_role(confirmer, "finance_approver")
    if os.getenv("ORBIT_FINANCE_PROVIDER", "generic").lower() != "qbo":
        raise HTTPException(409, "Manual UI confirmation is only available for QBO")
    row = store.one("SELECT * FROM gate_requests WHERE gate_request_id = ?",
                    (gate_request_id,))
    if not row or not _vendor_allowed(confirmer, row["vendor_id"]):
        raise HTTPException(404, "Gate request not found")
    if row["status"] not in {"APPROVED_PENDING_PROVIDER", "MANUAL_ACTION_REQUIRED"}:
        raise HTTPException(409, "Only an approved pending QBO request can be confirmed")
    if row["requester"] == confirmer.principal or (
            row["requester_employee"] and
            row["requester_employee"] == confirmer.employee_username):
        raise HTTPException(403, "The requester cannot confirm their own provider update")
    if not payload.confirm_vendor_ui_saved:
        raise HTTPException(422, "Finance must confirm the saved QBO vendor UI details")

    details = _unsecret(row["bank_details_ciphertext"])
    expected_routing = re.sub(r"[\s-]", "", details["routing_code"]).upper()
    observed_routing = re.sub(r"[\s-]", "", payload.routing_code).upper()
    if (payload.account_last4 != row["account_last4"] or
            not hmac.compare_digest(expected_routing, observed_routing)):
        store.audit(confirmer.principal, "vendor_bank_change.qbo_ui_confirmation_mismatch",
                    gate_request_id, {"vendor_id": row["vendor_id"]})
        raise HTTPException(409, "QBO UI readback does not match the approved request")

    now = utcnow()
    with store.lock:
        current = store.conn.execute(
            "SELECT status FROM gate_requests WHERE gate_request_id = ?",
            (gate_request_id,),
        ).fetchone()
        if not current or current["status"] not in {
                "APPROVED_PENDING_PROVIDER", "MANUAL_ACTION_REQUIRED"}:
            raise HTTPException(409, "This request has already been reconciled")
        store.conn.execute(
            "UPDATE gate_requests SET status = 'APPLIED_MANUAL', upstream_reference = ?, updated_utc = ? WHERE gate_request_id = ?",
            ("qbo-ui-readback", now, gate_request_id),
        )
        store.conn.commit()
    store.audit(confirmer.principal, "vendor_bank_change.qbo_ui_confirmed",
                gate_request_id, {"vendor_id": row["vendor_id"],
                                  "account_last4": row["account_last4"],
                                  "bank_fingerprint": row["bank_fingerprint"]})
    return {"gate_request_id": gate_request_id, "status": "APPLIED_MANUAL",
            "detail": "Finance confirmed the saved QBO vendor UI values; the QBO API write remains unconfirmed."}
