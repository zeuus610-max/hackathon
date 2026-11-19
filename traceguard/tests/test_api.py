from pathlib import Path
import hashlib

import pytest
from fastapi.testclient import TestClient

from traceguard.server import main


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
