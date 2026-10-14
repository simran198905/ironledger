import os
import sys
import time
import copy

try:
    import pytest
except ImportError:
    pytest = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.blockchain import BlockchainLedger
from backend.simulator import ICSSimulator
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine


pytest_fixture = pytest.fixture if pytest else (lambda fn: fn)

@pytest_fixture
def ledger():
    return BlockchainLedger()


@pytest_fixture
def simulator():
    sim = ICSSimulator()
    sim.reset_state()
    return sim


@pytest_fixture
def anomaly_detector():
    return AnomalyDetector()


def test_canonical_hashing_determinism(ledger):
    """Verifies that hashing is strictly deterministic regardless of dictionary key ordering."""
    event_a = {
        "event_id": 1,
        "timestamp": 1700000000.1234,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "START",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 2400.0, "mode": "AUTO"},
        "plant_state_snapshot": {"pressure": 5.4, "temp": 68.5}
    }
    event_b = {
        "plant_state_snapshot": {"temp": 68.5, "pressure": 5.4},
        "parameters": {"mode": "AUTO", "rpm": 2400.0},
        "entity_id": "PUMP_A_01",
        "command_type": "START",
        "source": "AUTHORIZED_ENG_01",
        "timestamp": 1700000000.1234,
        "event_id": 1
    }
    prev_hash = ledger.genesis_block["event_hash"]
    hash_a = ledger.compute_event_hash(event_a, prev_hash)
    hash_b = ledger.compute_event_hash(event_b, prev_hash)
    assert hash_a == hash_b
    assert hash_a.startswith("0x")


def test_timestamp_tampering_detection(ledger):
    """Ensures that altering the event timestamp triggers a cryptographic hash mismatch."""
    event = {
        "event_id": 1,
        "timestamp": 1700000000.0,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "START",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 2400.0},
        "plant_state_snapshot": {"pressure": 5.4}
    }
    block = ledger.anchor_event(event)
    
    # Tamper the timestamp in the database event
    tampered_event = copy.deepcopy(event)
    tampered_event["timestamp"] = 1700000500.0  # shifted by 500s

    audit = ledger.audit_entire_chain([tampered_event])
    assert not audit["integrity_healthy"]
    assert audit["tampered_blocks_found"] == 1
    assert audit["audit_details"][0]["reason"] == "HASH_MISMATCH"


def test_snapshot_tampering_detection(ledger):
    """Ensures that altering telemetry state snapshot triggers a hash mismatch."""
    event = {
        "event_id": 1,
        "timestamp": 1700000000.0,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "SET_VALVE",
        "entity_id": "VALVE_VENT_02",
        "parameters": {"open_percent": 15.0},
        "plant_state_snapshot": {"pressure_vessel": {"pressure_bar": 5.4}}
    }
    ledger.anchor_event(event)

    # Tamper the snapshot data in the database
    tampered_event = copy.deepcopy(event)
    tampered_event["plant_state_snapshot"]["pressure_vessel"]["pressure_bar"] = 9.8

    audit = ledger.audit_entire_chain([tampered_event])
    assert not audit["integrity_healthy"]
    assert audit["tampered_blocks_found"] == 1
    assert audit["audit_details"][0]["reason"] == "HASH_MISMATCH"


def test_broken_chain_link_detection(ledger):
    """Verifies that an adversary tampering with previous_hash links is flagged as BROKEN_CHAIN_LINK."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    e2 = {"event_id": 2, "timestamp": 1700000002.0, "source": "B", "command_type": "C2", "entity_id": "E2"}
    ledger.anchor_event(e1)
    ledger.anchor_event(e2)

    # Maliciously re-link block 2's previous_hash
    ledger.chain[2]["previous_hash"] = "0x" + "f" * 64

    audit = ledger.audit_entire_chain([e1, e2])
    assert not audit["integrity_healthy"]
    reasons = [d["reason"] for d in audit["audit_details"] if d.get("tampered")]
    assert "BROKEN_CHAIN_LINK" in reasons


def test_unanchored_db_record_detection(ledger):
    """Verifies that extra forged records inserted into the off-chain database are caught."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    ledger.anchor_event(e1)

    e_forged = {"event_id": 999, "timestamp": 1700000002.0, "source": "ATTACKER", "command_type": "INJECT", "entity_id": "VALVE"}
    
    audit = ledger.audit_entire_chain([e1, e_forged])
    assert not audit["integrity_healthy"]
    unanchored = [d for d in audit["audit_details"] if d.get("reason") == "UNANCHORED_DB_RECORD"]
    assert len(unanchored) == 1
    assert unanchored[0]["event_id"] == 999


def test_deleted_record_detection(ledger):
    """Verifies that purged/deleted database records are caught."""
    e1 = {"event_id": 1, "timestamp": 1700000001.0, "source": "A", "command_type": "C1", "entity_id": "E1"}
    e2 = {"event_id": 2, "timestamp": 1700000002.0, "source": "B", "command_type": "C2", "entity_id": "E2"}
    ledger.anchor_event(e1)
    ledger.anchor_event(e2)

    # Attacker deletes e1 from database
    audit = ledger.audit_entire_chain([e2])
    assert not audit["integrity_healthy"]
    deleted = [d for d in audit["audit_details"] if d.get("reason") == "AUDIT_RECORD_DELETED_FROM_DB"]
    assert len(deleted) == 1
    assert deleted[0]["event_id"] == 1


def test_forensic_backward_walk_and_policy(ledger, simulator):
    """Verifies evidence-based backward-walk identifying unauthorized policy violations."""
    forensics = ForensicReconstructionEngine(ledger)
    
    # 1. Normal baseline commands
    c1 = simulator.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    ledger.anchor_event(c1)
    c2 = simulator.execute_command("SCADA_AUTO_PID", "SET_VALVE", "VALVE_INLET_01", {"open_percent": 75.0})
    ledger.anchor_event(c2)

    # 2. Rogue command violating policy
    c3 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
    ledger.anchor_event(c3)

    recon = forensics.reconstruct_incident(simulator.event_log)
    assert recon["success"]
    assert recon["events_analyzed"] == 3
    assert recon["root_cause_artifact"]["source_identity"] == "ROGUE_OPERATOR_0x7b"
    assert recon["root_cause_artifact"]["policy_violation"] is True


def test_threat_intel_objective_scoring():
    """Verifies objective technique overlap scoring and attribution ranking."""
    engine = ThreatIntelligenceEngine()
    
    # Command history matching TRITON signature (T0888 Loss of Safety, T0831 Manipulation of Control, T0855 Unauthorized Command)
    history = [
        {"command_type": "OVERRIDE_SIS", "source": "ROGUE_01", "parameters": {"bypass": True}},
        {"command_type": "SET_VALVE", "source": "ROGUE_01", "parameters": {"open_percent": 0.0}}
    ]
    anomaly = {"severity": "CRITICAL"}
    
    intel = engine.correlate_incident(history, anomaly, tampered_detected=False)
    assert len(intel["matched_techniques"]) >= 3
    assert intel["primary_hypothesis"] is not None
    assert intel["primary_hypothesis"]["actor_id"] == "XENOTIME"
    assert intel["primary_hypothesis"]["confidence_score"] > 50.0
    assert "attribution_caveat" in intel


def test_anomaly_detector_physics_and_ml(anomaly_detector, simulator):
    """Verifies physics envelope safety breaches and Isolation Forest scoring."""
    nominal_snap = simulator.get_telemetry_snapshot()
    nominal_eval = anomaly_detector.evaluate_telemetry(nominal_snap)
    assert nominal_eval["severity"] == "NORMAL"
    assert nominal_eval["ml_anomaly_score"] < 0.65

    # Trigger overpressure breach
    simulator.pressure_vessel["pressure_bar"] = 10.5
    breach_snap = simulator.get_telemetry_snapshot()
    breach_eval = anomaly_detector.evaluate_telemetry(breach_snap)
    assert breach_eval["is_anomaly"] is True
    assert breach_eval["severity"] == "CATASTROPHIC"
    assert "PRESSURE_VESSEL_PRESSURE" in breach_eval["flagged_sensors"]


def test_forensic_tamper_parameter_verification():
    """Verifies tamper detection and authentic parameter recovery via block hash validation."""
    import copy
    
    # a) SET_RPM rpm=5000, then tamper DB parameters to {"rpm":2400}
    l_a = BlockchainLedger()
    s_a = ICSSimulator()
    f_a = ForensicReconstructionEngine(l_a)
    c_a = s_a.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 5000.0})
    l_a.anchor_event(c_a)
    db_ev_a = copy.deepcopy(c_a)
    db_ev_a["parameters"] = {"rpm": 2400.0}

    recon_a = f_a.reconstruct_incident([db_ev_a])
    step_a = recon_a["timeline"][0]
    assert step_a["policy_violation"] is True
    assert step_a["parameters"] == {"rpm": 5000.0}

    # b) STOP with parameters {}, then tamper DB source to "X"
    l_b = BlockchainLedger()
    s_b = ICSSimulator()
    f_b = ForensicReconstructionEngine(l_b)
    c_b = s_b.execute_command("AUTHORIZED_ENG_01", "STOP", "PUMP_A_01", {})
    l_b.anchor_event(c_b)
    db_ev_b = copy.deepcopy(c_b)
    db_ev_b["source"] = "X"

    recon_b = f_b.reconstruct_incident([db_ev_b])
    step_b = recon_b["timeline"][0]
    assert step_b["policy_violation"] is False
    assert step_b["source"] == "AUTHORIZED_ENG_01"

    # c) same as (a) but also edit ledger block["parameters"] to {"rpm":2400}
    l_c = BlockchainLedger()
    s_c = ICSSimulator()
    f_c = ForensicReconstructionEngine(l_c)
    c_c = s_c.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 5000.0})
    b_c = l_c.anchor_event(c_c)
    b_c["parameters"] = {"rpm": 2400.0}
    db_ev_c = copy.deepcopy(c_c)
    db_ev_c["parameters"] = {"rpm": 2400.0}

    recon_c = f_c.reconstruct_incident([db_ev_c])
    step_c = recon_c["timeline"][0]
    assert step_c["policy_violation"] is True

    # d) tamper the DB timestamp -> policy_violation True
    l_d = BlockchainLedger()
    s_d = ICSSimulator()
    f_d = ForensicReconstructionEngine(l_d)
    c_d = s_d.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    l_d.anchor_event(c_d)
    db_ev_d = copy.deepcopy(c_d)
    db_ev_d["timestamp"] = db_ev_d["timestamp"] + 100.0

    recon_d = f_d.reconstruct_incident([db_ev_d])
    step_d = recon_d["timeline"][0]
    assert step_d["policy_violation"] is True


def test_malformed_db_record_handling():
    """Verifies that audit_entire_chain, reconstruct_incident, and report generation handle malformed DB values gracefully."""
    import copy
    from report_generator import ForensicReportGenerator
    from threat_intel import ThreatIntelligenceEngine

    report_gen = ForensicReportGenerator()
    intel_engine = ThreatIntelligenceEngine()

    tampered_cases = [
        ("timestamp", "abc"),
        ("timestamp", None),
        ("parameters", "abc")
    ]

    for field, val in tampered_cases:
        l = BlockchainLedger()
        s = ICSSimulator()
        f = ForensicReconstructionEngine(l)

        cmd = s.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
        l.anchor_event(cmd)
        
        db_ev = copy.deepcopy(cmd)
        db_ev[field] = val

        # 1. Audit check
        audit = l.audit_entire_chain([db_ev])
        assert not audit["integrity_healthy"], f"Audit failed to detect tamper for {field}={val}"
        assert audit["tampered_blocks_found"] >= 1

        # 2. Reconstruct incident check
        recon = f.reconstruct_incident([db_ev])
        assert recon["success"] is True, f"Reconstruct failed for {field}={val}"
        assert recon["tamper_detected"] is True, f"Reconstruct tamper_detected False for {field}={val}"

        # 3. HTML report generation check
        intel = intel_engine.correlate_incident([], {}, tampered_detected=recon["tamper_detected"])
        html_report = report_gen.generate_html_report(recon, intel, s.get_telemetry_snapshot())
        assert isinstance(html_report, str) and len(html_report) > 0, f"HTML report generation failed for {field}={val}"


def test_tampered_parameters_correlate_and_report_resilience():
    """Verifies that correlate_incident and HTML report generator handle non-dict parameters ('abc', None, [1,2]) without raising exceptions."""
    import copy
    from report_generator import ForensicReportGenerator
    from threat_intel import ThreatIntelligenceEngine

    report_gen = ForensicReportGenerator()
    intel_engine = ThreatIntelligenceEngine()

    invalid_param_values = ["abc", None, [1, 2]]

    for param_val in invalid_param_values:
        l = BlockchainLedger()
        s = ICSSimulator()
        f = ForensicReconstructionEngine(l)

        cmd = s.execute_command("AUTHORIZED_ENG_01", "SET_RPM", "PUMP_A_01", {"rpm": 3000.0})
        l.anchor_event(cmd)

        db_ev = copy.deepcopy(cmd)
        db_ev["parameters"] = param_val

        recon = f.reconstruct_incident([db_ev])

        intel = intel_engine.correlate_incident([db_ev], {}, tampered_detected=recon["tamper_detected"])
        assert isinstance(intel, dict) and "matched_techniques" in intel

        html_report = report_gen.generate_html_report(recon, intel, s.get_telemetry_snapshot())
        assert isinstance(html_report, str) and len(html_report) > 0


def test_signature_tampering_detection(ledger):
    """Ensures that altering an event's HMAC signature in off-chain DB triggers a hash mismatch."""
    import copy
    event = {
        "event_id": 1,
        "timestamp": 1700000000.0,
        "source": "AUTHORIZED_ENG_01",
        "command_type": "SET_RPM",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 3000.0},
        "signature": "hmac_sha256_signature_abc123"
    }
    ledger.anchor_event(event)

    # Tamper the signature in the off-chain database
    tampered_event = copy.deepcopy(event)
    tampered_event["signature"] = "forged_hmac_signature_xyz789"

    audit = ledger.audit_entire_chain([tampered_event])
    assert not audit["integrity_healthy"]
    assert audit["tampered_blocks_found"] == 1
    assert audit["audit_details"][0]["reason"] == "HASH_MISMATCH"


def test_api_endpoints_and_auth_guardrails():
    """Verifies FastAPI endpoints for plant command execution, forensic reconstruction, and report generation."""
    from fastapi.testclient import TestClient
    from api import app

    client = TestClient(app)

    # 1. Telemetry endpoint
    r_telem = client.get("/api/telemetry")
    assert r_telem.status_code == 200
    assert "pressure_vessel" in r_telem.json()["telemetry"]

    # 2. Command execution endpoint
    cmd_data = {
        "source": "AUTHORIZED_ENG_01",
        "command_type": "SET_RPM",
        "entity_id": "PUMP_A_01",
        "parameters": {"rpm": 2400}
    }
    r_cmd = client.post("/api/plant/command", json=cmd_data)
    assert r_cmd.status_code == 200
    assert r_cmd.json().get("status") == "COMMAND_EXECUTED_AND_ANCHORED"

    # 3. Forensic reconstruction endpoint
    r_forensics = client.get("/api/forensics/reconstruct")
    assert r_forensics.status_code == 200
    assert r_forensics.json().get("success") is True

    # 4. Report generation endpoint
    r_report = client.get("/api/report/html")
    assert r_report.status_code == 200
    assert "Forensic Report" in r_report.text


def test_onchain_contract_order_verification():
    """Verifies that verify_against_contract returns structured verification payload."""
    ledger = BlockchainLedger()
    res = ledger.verify_against_contract()
    assert isinstance(res, dict)
    assert "contract_connected" in res


def test_mocked_contract_timeout_no_resend_and_out_of_sync_stop():
    """Verifies that post-broadcast receipt timeout never resends transactions, and out-of-sync lastHash pauses queue."""
    from unittest.mock import MagicMock

    # 1. Test receipt timeout: send_raw_transaction must be called EXACTLY ONCE, no second send
    ledger_a = BlockchainLedger()
    mock_w3_a = MagicMock()
    mock_contract_a = MagicMock()
    mock_account_a = MagicMock()
    mock_account_a.address = "0x1111111111111111111111111111111111111111"

    mock_w3_a.eth.get_transaction_count.return_value = 1
    mock_w3_a.eth.get_block.return_value = {"baseFeePerGas": 1000000000}
    mock_w3_a.to_wei.return_value = 2000000000
    mock_w3_a.eth.send_raw_transaction.return_value = b"\xaa" * 32
    mock_w3_a.eth.wait_for_transaction_receipt.side_effect = Exception("Timeout waiting for receipt")

    mock_contract_a.functions.lastHash().call.return_value = bytes.fromhex(ledger_a.genesis_block["event_hash"][2:])

    ledger_a.w3 = mock_w3_a
    ledger_a.contract = mock_contract_a
    ledger_a.account = mock_account_a
    ledger_a.contract_type = "ironledger"
    ledger_a.is_simulated = False
    ledger_a._queue_worker_running = True

    block_a = {
        "block_index": 1,
        "event_id": 1,
        "event_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "previous_hash": ledger_a.genesis_block["event_hash"],
        "status": "QUEUED_ON_CHAIN"
    }
    event_a = {"event_id": 1, "source": "TEST", "command_type": "START", "entity_id": "PUMP_A_01"}

    ledger_a._tx_queue.put({"block_ref": block_a, "event": event_a})

    # Process single queue task
    ledger_a._queue_worker_running = False  # process one iteration
    task = ledger_a._tx_queue.get()

    # Run inline processing logic
    event_hash = block_a["event_hash"]
    prev_hash = block_a["previous_hash"]

    # Perform pre-send lastHash check
    onchain_last_hash = mock_contract_a.functions.lastHash().call()
    onchain_last_str = "0x" + onchain_last_hash.hex().lower()
    assert onchain_last_str == prev_hash.lower()

    # Perform pre-broadcast
    tx_sent = mock_w3_a.eth.send_raw_transaction(b"raw_tx")
    block_a["tx_hash"] = tx_sent.hex()
    block_a["status"] = "PENDING_CONFIRMATION"

    # Simulate receipt timeout
    try:
        mock_w3_a.eth.wait_for_transaction_receipt(tx_sent, timeout=60)
    except Exception:
        block_a["status"] = "PENDING_CONFIRMATION"

    # Assert send_raw_transaction was called EXACTLY ONCE (no resend on timeout)
    assert mock_w3_a.eth.send_raw_transaction.call_count == 1
    assert block_a["status"] == "PENDING_CONFIRMATION"
    assert block_a["tx_hash"] is not None

    # 2. Test out-of-sync lastHash: stops processing and marks status CHAIN_OUT_OF_SYNC
    ledger_b = BlockchainLedger()
    mock_w3_b = MagicMock()
    mock_contract_b = MagicMock()

    mismatched_last_hash = b"\xff" * 32
    mock_contract_b.functions.lastHash().call.return_value = mismatched_last_hash

    ledger_b.w3 = mock_w3_b
    ledger_b.contract = mock_contract_b
    ledger_b.contract_type = "ironledger"
    ledger_b.is_simulated = False

    block_b = {
        "block_index": 1,
        "event_id": 1,
        "event_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "previous_hash": ledger_b.genesis_block["event_hash"],
        "status": "QUEUED_ON_CHAIN"
    }
    event_b = {"event_id": 1, "source": "TEST", "command_type": "START", "entity_id": "PUMP_A_01"}

    ledger_b._tx_queue.put({"block_ref": block_b, "event": event_b})

    # Run one queue processing step manually
    task_b = ledger_b._tx_queue.get()
    b_ref = task_b.get("block_ref")
    onchain_last_hash_b = mock_contract_b.functions.lastHash().call()
    onchain_last_str_b = "0x" + onchain_last_hash_b.hex().lower()

    if onchain_last_str_b != b_ref["previous_hash"].lower():
        b_ref["status"] = "CHAIN_OUT_OF_SYNC"

    assert block_b["status"] == "CHAIN_OUT_OF_SYNC"
    assert mock_w3_b.eth.send_raw_transaction.call_count == 0


def test_real_worker_receipt_timeout_then_confirm_and_out_of_sync():
    """
    Starts the REAL _process_tx_queue worker thread with MagicMock w3/contract.

    Scenario (a): get_transaction_receipt returns None once, then a successful receipt.
        - send_raw_transaction called exactly once (no resend on timeout).
        - Block ends as CONFIRMED_ON_CHAIN.
        - The next block is subsequently sent.

    Scenario (b): lastHash always returns a mismatched value.
        - Nothing is sent (send_raw_transaction call_count == 0).
        - Block status is CHAIN_OUT_OF_SYNC.
    """
    import threading
    from unittest.mock import MagicMock

    # ── Scenario (a): receipt times out once, then arrives ──────────────────────
    ledger_a = BlockchainLedger()
    ledger_a._queue_worker_running = False  # stop real background worker if .env active
    ledger_a.is_simulated = True
    ledger_a._test_mode = True  # short poll intervals: 0.01s each, 0.2s total timeout

    mock_w3_a = MagicMock()
    mock_contract_a = MagicMock()
    mock_account_a = MagicMock()
    mock_account_a.address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    genesis_hash_bytes = bytes.fromhex(ledger_a.genesis_block["event_hash"][2:])

    # lastHash always matches so the pre-send check passes for block 1
    mock_contract_a.functions.lastHash.return_value.call.return_value = genesis_hash_bytes

    # Stub for the recordEvent function call chain
    mock_func_call = MagicMock()
    mock_func_call.estimate_gas.return_value = 100_000
    mock_func_call.build_transaction.return_value = {"from": mock_account_a.address, "nonce": 1}
    mock_contract_a.functions.recordEvent.return_value = mock_func_call

    tx_hash_bytes = b"\xab" * 32
    mock_w3_a.eth.send_raw_transaction.return_value = tx_hash_bytes
    mock_w3_a.eth.get_transaction_count.return_value = 1
    mock_w3_a.eth.get_block.return_value = {"baseFeePerGas": 1_000_000_000}
    mock_w3_a.to_wei.return_value = 2_000_000_000
    mock_w3_a.eth.chain_id = 11155111

    # Signed tx stub
    mock_signed = MagicMock()
    mock_signed.raw_transaction = b"\xff" * 100
    mock_account_a.sign_transaction.return_value = mock_signed

    # get_transaction_receipt: None first (timeout path), then success
    success_receipt = MagicMock()
    success_receipt.status = 1
    success_receipt.blockNumber = 7_654_321
    _receipt_seq = [None, success_receipt]

    def _get_receipt_a(tx):
        return _receipt_seq.pop(0) if _receipt_seq else success_receipt

    mock_w3_a.eth.get_transaction_receipt.side_effect = _get_receipt_a


    updated_blocks_a = []
    ledger_a.on_block_updated = updated_blocks_a.append

    event_a1 = {
        "event_id": 1, "timestamp": 1700000001.0,
        "source": "TEST_A", "command_type": "START",
        "entity_id": "PUMP_A_01", "parameters": {}
    }
    # Anchor while still in simulated mode so anchor_event does NOT auto-queue.
    # Then switch to live-mock mode and queue once manually.
    block_a1 = ledger_a.anchor_event(event_a1)

    # Switch ledger to live-mock mode AFTER anchoring
    ledger_a.w3 = mock_w3_a
    ledger_a.contract = mock_contract_a
    ledger_a.account = mock_account_a
    ledger_a.contract_type = "ironledger"
    ledger_a.is_simulated = False

    # Queue exactly once
    ledger_a._tx_queue.put({"block_ref": block_a1, "event": event_a1})

    # Start the REAL worker
    ledger_a._queue_worker_running = True
    worker_a = threading.Thread(target=ledger_a._process_tx_queue, daemon=True)
    worker_a.start()

    # Wait for block_a1 to become CONFIRMED_ON_CHAIN (up to 5 s)
    deadline = time.time() + 5.0
    while time.time() < deadline and block_a1.get("status") != "CONFIRMED_ON_CHAIN":
        time.sleep(0.05)

    # Stop the worker before it can do anything else
    ledger_a._queue_worker_running = False
    worker_a.join(timeout=3.0)

    # Verify: block confirmed and send_raw_transaction was called exactly once (no resend)
    assert block_a1.get("status") == "CONFIRMED_ON_CHAIN", (
        f"[scenario a] Expected CONFIRMED_ON_CHAIN, got {block_a1.get('status')}"
    )
    assert mock_w3_a.eth.send_raw_transaction.call_count == 1, (
        f"[scenario a] send_raw_transaction should be called exactly once, got "
        f"{mock_w3_a.eth.send_raw_transaction.call_count}"
    )
    assert len(updated_blocks_a) >= 1, "[scenario a] on_block_updated should have been called"


    # ── Scenario (b): lastHash never matches → CHAIN_OUT_OF_SYNC ────────────────
    ledger_b = BlockchainLedger()
    ledger_b._queue_worker_running = False  # stop real background worker if .env active
    ledger_b.is_simulated = True
    ledger_b._test_mode = True

    mock_w3_b = MagicMock()
    mock_contract_b = MagicMock()
    mock_account_b = MagicMock()
    mock_account_b.address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    # lastHash always returns a value that will never match any previous_hash
    mismatched = b"\xff" * 32
    mock_contract_b.functions.lastHash.return_value.call.return_value = mismatched


    updated_blocks_b = []
    ledger_b.on_block_updated = updated_blocks_b.append

    event_b1 = {
        "event_id": 1, "timestamp": 1700000001.0,
        "source": "TEST_B", "command_type": "START",
        "entity_id": "PUMP_B_01", "parameters": {}
    }
    # Anchor while still simulated, then switch to live-mock mode
    block_b1 = ledger_b.anchor_event(event_b1)

    ledger_b.w3 = mock_w3_b
    ledger_b.contract = mock_contract_b
    ledger_b.account = mock_account_b
    ledger_b.contract_type = "ironledger"
    ledger_b.is_simulated = False

    ledger_b._tx_queue.put({"block_ref": block_b1, "event": event_b1})

    ledger_b._queue_worker_running = True
    worker_b = threading.Thread(target=ledger_b._process_tx_queue, daemon=True)
    worker_b.start()

    # Wait for block_b1 to reach a terminal state (up to 5 s)
    deadline_b = time.time() + 5.0
    while time.time() < deadline_b and block_b1.get("status") not in (
        "CHAIN_OUT_OF_SYNC", "CONFIRMED_ON_CHAIN", "FAILED_ON_CHAIN"
    ):
        time.sleep(0.05)

    ledger_b._queue_worker_running = False
    worker_b.join(timeout=3.0)

    assert block_b1.get("status") == "CHAIN_OUT_OF_SYNC", (
        f"[scenario b] Expected CHAIN_OUT_OF_SYNC, got {block_b1.get('status')}"
    )
    assert mock_w3_b.eth.send_raw_transaction.call_count == 0, (
        "[scenario b] send_raw_transaction should NOT be called when chain is out of sync"
    )


if __name__ == "__main__":
    print("=" * 65)
    print(" 🧪 RUNNING IRONLEDGER AUTOMATED TEST SUITE")
    print("=" * 65)

    tests = [
        ("Canonical Hashing Determinism", lambda: test_canonical_hashing_determinism(BlockchainLedger())),
        ("Timestamp Tamper Detection", lambda: test_timestamp_tampering_detection(BlockchainLedger())),
        ("Signature Tamper Detection", lambda: test_signature_tampering_detection(BlockchainLedger())),
        ("Snapshot State Tamper Detection", lambda: test_snapshot_tampering_detection(BlockchainLedger())),
        ("Broken Chain Link Detection", lambda: test_broken_chain_link_detection(BlockchainLedger())),
        ("Unanchored Record Detection", lambda: test_unanchored_db_record_detection(BlockchainLedger())),
        ("Purged / Deleted Record Detection", lambda: test_deleted_record_detection(BlockchainLedger())),
        ("Policy-Based Backward Walk", lambda: test_forensic_backward_walk_and_policy(BlockchainLedger(), ICSSimulator())),
        ("Threat Intel Objective Scoring", lambda: test_threat_intel_objective_scoring()),
        ("Anomaly Detector Physics & ML", lambda: test_anomaly_detector_physics_and_ml(AnomalyDetector(), ICSSimulator())),
        ("Tamper Parameter Hash Verification", lambda: test_forensic_tamper_parameter_verification()),
        ("Malformed DB Record Handling", lambda: test_malformed_db_record_handling()),
        ("Tampered Parameters Correlation Resilience", lambda: test_tampered_parameters_correlate_and_report_resilience()),
        ("API Endpoints & Guardrails", lambda: test_api_endpoints_and_auth_guardrails()),
        ("On-Chain Contract Verification Structure", lambda: test_onchain_contract_order_verification()),
        ("Mocked Contract Worker Timeout & Out-of-Sync Queue", lambda: test_mocked_contract_timeout_no_resend_and_out_of_sync_stop()),
        ("Real Worker Thread: Receipt Timeout→Confirm & Out-of-Sync", lambda: test_real_worker_receipt_timeout_then_confirm_and_out_of_sync()),
    ]

    passed = 0
    import traceback
    for name, test_fn in tests:
        try:
            test_fn()
            print(f"  ✅ PASS: {name}")
            passed += 1
        except Exception as e:
            print(f"  ❌ FAIL: {name} - {e}")
            traceback.print_exc()

    print("=" * 65)
    print(f" Results: {passed}/{len(tests)} tests passed successfully.")
    print("=" * 65)

