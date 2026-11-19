from pathlib import Path
import hashlib
import json

from cryptography.fernet import Fernet

import pytest
from fastapi.testclient import TestClient

from traceguard.server import gate, main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test-defense.db")
    monkeypatch.setattr(main, "EVIDENCE_DIR", Path(__file__).resolve().parents[2] / "evidence")
    with TestClient(main.app) as test_client:
        yield test_client


def test_health_topology_and_raw_timeline(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["database_provider"] == "SQLITE LOCAL"
    assert health.json()["database_connected"] is True
    topology = client.get("/api/topology").json()
    assert {node["name"] for node in topology["systems"]} >= {"LedgerOne", "HelpDeskr", "BlueVault", "SSO"}
    assert any(item["cidr"] == "10.20.4.0/24" and not item["trusted_by_ip_alone"] for item in topology["network_ranges"])
    timeline = client.get("/api/timeline?normalized=false&limit=10").json()
    assert timeline["normalized"] is False
    assert timeline["events"]


def test_api_evaluation_history_and_validation(client):
    payload = {"key_id": "key-tb-03", "endpoint": "/payments/search"}
    result = client.post("/api/engine/evaluate", json=payload).json()
    assert result["verdict"] == "CRITICAL_CANARY"
    history = client.get("/api/engine/history").json()["evaluations"]
    assert history[0]["canary"] is True
    saved = client.post("/api/validation", json={"true_positives": 2, "false_positives": 1, "missed_detections": 1, "evidence_row_ids": ["E18:REQ-1"]}).json()
    assert saved["precision"] == saved["recall"] == 2 / 3
    assert client.get("/api/validation").json()["evidence_row_ids"] == ["E18:REQ-1"]


def test_evidence_hash_is_sha256_of_known_case_file(client):
    path = Path(__file__).resolve().parents[2] / "evidence" / "E01_ledgerone_api_access.csv"
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    response = client.post("/api/evidence/hash", json={"evidence_id": "E01"})
    assert response.status_code == 200
    assert response.json()["sha256"] == expected
    assert response.json()["algorithm"] == "SHA-256"
    assert client.post("/api/evidence/hash", json={"evidence_id": "E99"}).status_code == 404


def _gate_credential(token, principal, role, **extra):
    return {"principal": principal, "role": role,
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "active": True, **extra}


def _enable_gate(monkeypatch, credentials):
    monkeypatch.setenv("ORBIT_GATE_CREDENTIALS_JSON", json.dumps(credentials))
    monkeypatch.setenv("ORBIT_DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("ORBIT_BANK_FIELD_HMAC_KEY", "test-only-hmac-key-" + ("x" * 40))
    monkeypatch.delenv("ORBIT_FINANCE_API_BASE_URL", raising=False)
    monkeypatch.delenv("ORBIT_FINANCE_API_TOKEN", raising=False)


def _bank_change():
    return {"request_id": "req-5f61b0de8", "idempotency_key": "case-replay-0412-20260903",
            "vendor_id": "V-0412",
            "bank_details": {"bank_name": "Example Bank", "account_holder": "Coastal Packaging Ltd",
                             "account_number": "123456789083", "routing_code": "ABCD1234567",
                             "country": "IN"}}


def test_case_tallybridge_bank_write_is_blocked_before_forwarding(client, monkeypatch):
    _enable_gate(monkeypatch, [_gate_credential(
        "tallybridge-secret", "key-tb-07", "integration", credential_id="key-tb-07",
        scopes=["read:write all-modules"], vendor_ids=["*"]
    )])
    response = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer tallybridge-secret"}, json=_bank_change())
    assert response.status_code == 202
    result = response.json()
    assert result["status"] == "BLOCKED"
    assert "identity_not_authorized_for_bank_changes" in result["reason_codes"]
    assert "exact_finance_approval_required" in result["reason_codes"]
    assert result["account_last4"] == "9083"
    saved = client.app.state.store.one("SELECT * FROM gate_requests WHERE gate_request_id = ?",
                                       (result["gate_request_id"],))
    assert saved["status"] == "BLOCKED"
    assert "123456789083" not in saved["bank_details_ciphertext"]
    assert client.app.state.store.one("SELECT COUNT(*) n FROM gate_approvals WHERE gate_request_id = ?",
                                     (result["gate_request_id"],))["n"] == 0


def test_legacy_key_use_is_a_critical_canary_and_cannot_be_approved(client, monkeypatch):
    _enable_gate(monkeypatch, [_gate_credential(
        "legacy-secret", "key-tb-03", "integration", credential_id="key-tb-03",
        scopes=["vendor:bank-change"], vendor_ids=["*"]
    )])
    response = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer legacy-secret"}, json=_bank_change())
    assert response.status_code == 202
    result = response.json()
    assert result["status"] == "CRITICAL_CANARY"
    assert "legacy_key_canary" in result["reason_codes"]
    assert client.app.state.store.one(
        "SELECT status FROM gate_requests WHERE gate_request_id = ?",
        (result["gate_request_id"],))["status"] == "CRITICAL_CANARY"


def test_gate_idempotency_replay_does_not_create_second_request(client, monkeypatch):
    _enable_gate(monkeypatch, [_gate_credential(
        "tallybridge-secret", "key-tb-07", "integration", credential_id="key-tb-07",
        scopes=["read:write all-modules"], vendor_ids=["*"]
    )])
    headers = {"Authorization": "Bearer tallybridge-secret"}
    first = client.post("/api/gate/vendor-changes", headers=headers, json=_bank_change()).json()
    replay = client.post("/api/gate/vendor-changes", headers=headers, json=_bank_change()).json()
    assert replay["gate_request_id"] == first["gate_request_id"]
    assert replay["idempotent_replay"] is True
    assert client.app.state.store.one("SELECT COUNT(*) n FROM gate_requests")["n"] == 1


def test_only_exact_independent_finance_approval_can_forward_upstream(client, monkeypatch):
    _enable_gate(monkeypatch, [
        _gate_credential("maker-secret", "finance-maker-1", "finance_maker",
                         employee_username="n.ansari", scopes=["vendor:bank-change"],
                         vendor_ids=["V-0412"]),
        _gate_credential("approver-secret", "finance-approver-1", "finance_approver",
                         employee_username="a.desai", vendor_ids=["V-0412"]),
    ])
    monkeypatch.setenv("ORBIT_FINANCE_API_BASE_URL", "https://finance.example")
    monkeypatch.setenv("ORBIT_FINANCE_API_TOKEN", "server-only-finance-token")
    calls = []

    class UpstreamResponse:
        status_code = 200
        def json(self): return {"id": "finance-change-123"}

    class UpstreamClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def patch(self, url, *, headers, json):
            calls.append((url, headers, json))
            return UpstreamResponse()

    monkeypatch.setattr(gate.httpx, "AsyncClient", UpstreamClient)
    held = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer maker-secret"}, json=_bank_change()).json()
    assert held["status"] == "HELD"
    assert calls == []

    reviewer = {"Authorization": "Bearer approver-secret"}
    details = client.get(f"/api/gate/requests/{held['gate_request_id']}", headers=reviewer).json()
    assert details["bank_details"]["account_number"] == "123456789083"

    mismatched = _bank_change()["bank_details"] | {"account_number": "123456789084"}
    rejected = client.post(f"/api/gate/requests/{held['gate_request_id']}/approvals",
                           headers=reviewer,
                           json={"bank_details": mismatched, "confirm_exact_details": True})
    assert rejected.status_code == 409
    assert calls == []

    approved = client.post(f"/api/gate/requests/{held['gate_request_id']}/approvals",
                           headers=reviewer,
                           json={"bank_details": _bank_change()["bank_details"],
                                 "confirm_exact_details": True}).json()
    assert approved["status"] == "APPLIED"
    assert approved["upstream_reference"] == "finance-change-123"
    assert calls[0][0] == "https://finance.example/v2/vendors/V-0412/bank-details"
    assert calls[0][1]["Idempotency-Key"] == f"orbit-{held['gate_request_id']}"
    assert calls[0][1]["Authorization"] == "Bearer server-only-finance-token"
    assert calls[0][2]["account_number"] == "123456789083"


def test_approval_stays_pending_without_finance_connector(client, monkeypatch):
    _enable_gate(monkeypatch, [
        _gate_credential("maker-secret", "finance-maker-1", "finance_maker",
                         employee_username="n.ansari", scopes=["vendor:bank-change"],
                         vendor_ids=["V-0412"]),
        _gate_credential("approver-secret", "finance-approver-1", "finance_approver",
                         employee_username="a.desai", vendor_ids=["V-0412"]),
    ])
    held = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer maker-secret"}, json=_bank_change()).json()
    approved = client.post(f"/api/gate/requests/{held['gate_request_id']}/approvals",
                           headers={"Authorization": "Bearer approver-secret"},
                           json={"bank_details": _bank_change()["bank_details"],
                                 "confirm_exact_details": True}).json()
    assert approved["status"] == "APPROVED_PENDING_PROVIDER"
    assert "no finance-system write was sent" in approved["detail"]


def test_finance_provider_error_is_not_reported_as_applied(client, monkeypatch):
    _enable_gate(monkeypatch, [
        _gate_credential("maker-secret", "finance-maker-1", "finance_maker",
                         employee_username="n.ansari", scopes=["vendor:bank-change"],
                         vendor_ids=["V-0412"]),
        _gate_credential("approver-secret", "finance-approver-1", "finance_approver",
                         employee_username="a.desai", vendor_ids=["V-0412"]),
    ])
    monkeypatch.setenv("ORBIT_FINANCE_API_BASE_URL", "https://finance.example")
    monkeypatch.setenv("ORBIT_FINANCE_API_TOKEN", "server-only-finance-token")

    class UpstreamResponse:
        status_code = 503

    class UpstreamClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def patch(self, *args, **kwargs): return UpstreamResponse()

    monkeypatch.setattr(gate.httpx, "AsyncClient", UpstreamClient)
    held = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer maker-secret"}, json=_bank_change()).json()
    result = client.post(f"/api/gate/requests/{held['gate_request_id']}/approvals",
                         headers={"Authorization": "Bearer approver-secret"},
                         json={"bank_details": _bank_change()["bank_details"],
                               "confirm_exact_details": True}).json()
    assert result["status"] == "APPROVED_PENDING_PROVIDER"
    assert result["detail"] == "Finance system rejected the update. No success is reported."


def test_terminated_rohan_cannot_review_a_held_request(client, monkeypatch):
    _enable_gate(monkeypatch, [_gate_credential(
        "rohan-secret", "rohan", "finance_approver", employee_username="r.menon",
        vendor_ids=["*"]
    )])
    response = client.get("/api/gate/requests", headers={"Authorization": "Bearer rohan-secret"})
    assert response.status_code == 403
    assert "termination date" in response.json()["detail"]


def test_gate_fails_closed_when_secrets_or_caller_identity_are_missing(client, monkeypatch):
    for name in ("ORBIT_GATE_CREDENTIALS_JSON", "ORBIT_DATA_ENCRYPTION_KEY",
                 "ORBIT_BANK_FIELD_HMAC_KEY", "ORBIT_FINANCE_API_BASE_URL",
                 "ORBIT_FINANCE_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert client.get("/api/gate/status").json()["can_hold"] is False
    response = client.post("/api/gate/vendor-changes", headers={
        "Authorization": "Bearer caller-token"}, json=_bank_change())
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]
