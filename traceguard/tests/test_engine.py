import json

from traceguard.server.engine import PRESETS, evaluate
from traceguard.server.persistence import SQLitePersistence
from traceguard.server.schemas import EvaluationRequest, ValidationUpdate
from traceguard.server.store import Store


def test_required_presets_return_expected_verdicts():
    expected = {
        "normal": "PASS",
        "downgrade": "QUARANTINE",
        "rogue": "QUARANTINE",
        "canary": "CRITICAL_CANARY",
    }
    assert {name: evaluate(payload)["verdict"] for name, payload in PRESETS.items()} == expected


def test_sensitive_request_without_twin_proof_is_quarantined():
    payload = EvaluationRequest(
        key_id="key-tb-07", endpoint="/vendors/V-0412/bank", caller_ip="10.20.4.18",
        user_agent="TallyBridge-Sync 3.5.0", e02_receipt="missing", e15_receipt="present",
        request_id="REQ-1",
    )
    result = evaluate(payload)
    assert result["verdict"] == "QUARANTINE"
    assert result["twin_proof"]["status"] == "unverified"
    assert "E02 HelpDeskr audit" in result["twin_proof"]["missing"]


def test_legacy_canary_overrides_normal_scoring_and_persists(tmp_path):
    store = Store(tmp_path / "defense.db")
    adapter = SQLitePersistence(store)
    payload = PRESETS["canary"]
    result = evaluate(payload)
    adapter.save_evaluation(payload, result)
    assert result["verdict"] == "CRITICAL_CANARY"
    assert result["risk_score"] == 100
    assert len(adapter.history(10)) == 1
    assert store.one("SELECT COUNT(*) AS n FROM canary_alerts")["n"] == 1
    store.conn.close()
    reopened = Store(tmp_path / "defense.db")
    assert len(SQLitePersistence(reopened).history(10)) == 1
    reopened.conn.close()


def test_validation_metrics_handle_zero_denominators_and_save(tmp_path):
    from traceguard.server.api import _validation_result

    store = Store(tmp_path / "validation.db")
    adapter = SQLitePersistence(store)
    empty = _validation_result(adapter.get_validation())
    assert (empty["precision"], empty["recall"], empty["f1"]) == (0.0, 0.0, 0.0)
    saved = adapter.save_validation(ValidationUpdate(true_positives=8, false_positives=2, missed_detections=2, evidence_row_ids=["E18:R1"]))
    result = _validation_result(saved)
    assert result["precision"] == 0.8
    assert result["recall"] == 0.8
    assert result["evidence_row_ids"] == ["E18:R1"]
    store.conn.close()
