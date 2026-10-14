"""
IronLedger - Core FastAPI Server & REST API
Coordinates SCADA simulation, blockchain evidence anchoring, dual-layer anomaly detection,
forensic reconstruction, threat intelligence correlation, and serves the frontend dashboard.
"""

import asyncio
import time
import os
import json
import logging
import re
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body, Query, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, model_validator

from backend.simulator import ICSSimulator
from backend.blockchain import BlockchainLedger, GENESIS_HASH
from backend.anomaly_detector import AnomalyDetector
from backend.forensics import ForensicReconstructionEngine
from backend.threat_intel import ThreatIntelligenceEngine
from backend.report_generator import ForensicReportGenerator
from backend.database import SupabaseDatabase

logger = logging.getLogger("ironledger.api")


@asynccontextmanager
async def lifespan(app):
    """Starts background continuous physics simulation at 1 Hz tick rate."""
    async def _physics_background_loop():
        while True:
            try:
                simulator.update_physics(dt=1.0)
            except Exception as exc:
                logger.warning("Physics tick error: %s", exc, exc_info=True)
            await asyncio.sleep(1.0)

    task = asyncio.create_task(_physics_background_loop())
    yield
    task.cancel()


app = FastAPI(
    title="IronLedger ICS Forensic Framework",
    description="Blockchain-anchored forensic evidence and MITRE ATT&CK for ICS attribution",
    version="2.2.0",
    lifespan=lifespan
)

# Configuration:
# By default, DEMO_MODE is enabled for local evaluation and interactive testing.
# For production environments, set DEMO_MODE=false in .env and place this service
# behind an authenticating reverse proxy (e.g., Nginx, OAuth2-Proxy, or VPN/mTLS)
# or implement a session/JWT authentication layer.
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ["1", "true", "yes"]

# Initialize Core Services
simulator = ICSSimulator()
ledger = BlockchainLedger()
detector = AnomalyDetector()
forensics = ForensicReconstructionEngine(ledger)
threat_intel = ThreatIntelligenceEngine()
report_gen = ForensicReportGenerator()
db = SupabaseDatabase()
ledger.on_block_updated = db.upsert_block


# ── Operational Guardrails ───────────────────────────────────────────────────

def check_demo_mode():
    """Restricts simulation/tamper routes when DEMO_MODE is disabled in production."""
    if not DEMO_MODE:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Attack/tamper endpoints are disabled when DEMO_MODE=false."
        )
    return True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _anchor_and_persist(event: Dict[str, Any]) -> Dict[str, Any]:
    """Anchor an event on the ledger AND persist both event + block to Supabase if enabled (sync for startup)."""
    block = ledger.anchor_event(event)
    if db.enabled:
        db.upsert_event(event)
        db.upsert_block(block)
    return block


async def _anchor_and_persist_async(event: Dict[str, Any]) -> Dict[str, Any]:
    """Non-blocking async version that offloads database I/O to a worker thread."""
    block = ledger.anchor_event(event)
    if db.enabled:
        await asyncio.to_thread(db.upsert_event, event)
        await asyncio.to_thread(db.upsert_block, block)
    return block


# ── Startup: restore persisted session ───────────────────────────────────────

def seed_baseline():
    """Record normal startup commands and anchor them onto the cryptographic chain."""
    cmd1 = simulator.execute_command("AUTHORIZED_ENG_01", "START", "PUMP_A_01", {"rpm": 2400.0})
    _anchor_and_persist(cmd1)

    cmd2 = simulator.execute_command("AUTHORIZED_ENG_01", "SET_VALVE", "VALVE_INLET_01", {"open_percent": 75.0})
    _anchor_and_persist(cmd2)

    cmd3 = simulator.execute_command("SCADA_AUTO_PID", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 15.0})
    _anchor_and_persist(cmd3)


def startup_restore():
    """
    On startup, attempt to reload the previous session's ICS event log from Supabase.
    If the database is empty or not configured, seed a fresh baseline instead.
    """
    persisted = db.load_events()
    if persisted is None:
        raise RuntimeError("Failed to load events from Supabase. Aborting startup to prevent data loss.")

    if persisted:
        simulator.event_log = persisted
        blocks = db.load_blocks()
        if blocks is None:
            raise RuntimeError("Failed to load blocks from Supabase. Aborting startup to prevent data loss.")

        if blocks:
            ledger.chain = [ledger.genesis_block]  # keep genesis
            for blk in blocks:
                if blk.get("block_index", 0) == 0:
                    continue  # skip genesis duplicate
                ledger.chain.append(blk)
            ledger._immutable_anchor_mirror = [dict(b) for b in ledger.chain]
        print(f"✅ Restored {len(persisted)} events and {len(ledger.chain)-1} blocks from Supabase.")
    else:
        print("ℹ️  No persisted session found — seeding fresh baseline.")
        seed_baseline()
        if not ledger.is_simulated and ledger.contract:
            try:
                sync_res = ledger.sync_with_onchain()
                if sync_res.get("success") and sync_res.get("total_synced", 0) > 0:
                    print(f"🔗 Auto-synchronized {sync_res['total_synced']} blocks from on-chain contract.")
            except Exception as exc:
                print(f"⚠️ Auto-sync notice on startup: {exc}")


startup_restore()


# ── Pydantic Models ───────────────────────────────────────────────────────────

class CommandRequest(BaseModel):
    source: str = "OPERATOR_01"
    command_type: str
    entity_id: str
    parameters: Dict[str, Any] = {}

    @model_validator(mode="after")
    def validate_parameters(self):
        if not isinstance(self.parameters, dict):
            raise ValueError("Field 'parameters' must be a JSON dictionary.")

        # Fields that must be numeric when present
        numeric_fields = {
            "SET_RPM": ["rpm"],
            "START": ["rpm"],
            "SET_VALVE": ["open_percent"],
            "SET_SETPOINT": ["target_temp", "target_rpm", "target_pressure"],
        }

        # Validate by command type
        for field in numeric_fields.get(self.command_type, []):
            if field in self.parameters:
                val = self.parameters[field]
                if isinstance(val, bool):
                    raise ValueError(f"Parameter '{field}' must be a numeric value, not boolean.")
                try:
                    float(val)
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter '{field}' must be a valid number, got '{val}'.")

        # Validate any general numeric keys regardless of command type or target entity
        general_numeric_keys = {"rpm", "open_percent", "target_rpm", "target_temp", "pressure"}
        for k, v in self.parameters.items():
            if k in general_numeric_keys:
                if isinstance(v, bool):
                    raise ValueError(f"Parameter '{k}' must be a numeric value, not boolean.")
                try:
                    float(v)
                except (ValueError, TypeError):
                    raise ValueError(f"Parameter '{k}' must be a valid number, got '{v}'.")
        return self

class AttackRequest(BaseModel):
    scenario: str  # "stuxnet", "triton", "overpressure", "log_tamper"

class TamperRequest(BaseModel):
    event_id: int
    malicious_field: str
    tampered_value: Any

class AnchorReceipt(BaseModel):
    """Receipt reported by the browser after MetaMask signed + confirmed a recordEvent tx."""
    block_index: int
    event_hash: str
    tx_hash: str
    block_number: Optional[int] = None
    recorded_by: Optional[str] = None
    contract_address: Optional[str] = None

class SaveCaseRequest(BaseModel):
    case_name: Optional[str] = None




# ── REST API Endpoints ────────────────────────────────────────────────────────

@app.get("/api/telemetry")
async def get_telemetry():
    """
    Returns real-time SCADA telemetry, physical states, anomaly evaluation, and ledger state.
    Strictly read-only and idempotent: physics is advanced by the background loop.
    """
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    
    return {
        "telemetry": snapshot,
        "anomaly": anomaly_status,
        "recent_blocks": ledger.get_recent_blocks(limit=10),
        "total_events": len(simulator.event_log),
        "total_blocks": len(ledger.chain),
        "db_connected": db.enabled,
        "blockchain_mode": "LIVE_ETHEREUM_SEPOLIA" if not ledger.is_simulated else "SIMULATED_LOCAL_LEDGER",
        "demo_mode": DEMO_MODE
    }

# ── MetaMask (browser-signed) anchoring support ──────────────────────────────

_TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

@app.get("/api/config")
async def get_config():
    """Public config the dashboard needs to anchor hashes from MetaMask."""
    return {
        "genesis_hash": GENESIS_HASH,
        "contract_address": os.environ.get("SEPOLIA_CONTRACT_ADDRESS", "").strip(),
        "chain_id": 11155111,
        "network": "sepolia",
        "demo_mode": DEMO_MODE,
    }

@app.get("/api/chain")
async def get_full_chain():
    """Returns the full local hash chain (oldest first) so the browser can anchor every block."""
    return {"genesis_hash": GENESIS_HASH, "blocks": list(ledger.chain)}

@app.post("/api/chain/anchor")
async def record_anchor_receipt(req: AnchorReceipt):
    """Marks a local block as anchored on-chain after the browser confirmed the MetaMask transaction."""
    if not _TX_RE.match(req.tx_hash):
        raise HTTPException(status_code=422, detail="tx_hash must be a 0x-prefixed 32-byte hex string.")
    if req.recorded_by and not _ADDR_RE.match(req.recorded_by):
        raise HTTPException(status_code=422, detail="recorded_by must be a 0x-prefixed address.")
    if req.block_index <= 0 or req.block_index >= len(ledger.chain):
        raise HTTPException(status_code=404, detail=f"Block {req.block_index} not found.")
    block = ledger.chain[req.block_index]
    if str(block.get("event_hash", "")).lower() != req.event_hash.lower():
        raise HTTPException(status_code=409, detail="event_hash does not match the local block at that index.")

    block["tx_hash"] = req.tx_hash
    block["block_number"] = req.block_number
    block["status"] = "CONFIRMED_ON_CHAIN"
    block["is_simulated"] = False
    block["etherscan_url"] = f"https://sepolia.etherscan.io/tx/{req.tx_hash}"
    if req.recorded_by:
        block["recorded_by"] = req.recorded_by
    if req.contract_address:
        block["contract_address"] = req.contract_address
    if db.enabled:
        await asyncio.to_thread(db.upsert_block, block)
    return {"status": "ANCHOR_RECORDED", "block": block}


@app.post("/api/chain/sync-onchain")
async def sync_chain_onchain():
    """Synchronizes the local ledger with the on-chain deployed smart contract on Sepolia."""
    res = await asyncio.to_thread(ledger.sync_with_onchain)
    if not res.get("success"):
        return JSONResponse(status_code=400, content={
            "status": "SYNC_FAILED",
            "message": res.get("error", "Failed to sync with smart contract.")
        })

    # Align simulator event log with on-chain records
    if res.get("total_synced", 0) > 0:
        synced_blocks = ledger.chain[1:]
        existing_event_ids = {e.get("event_id") for e in simulator.event_log}
        for blk in synced_blocks:
            e_id = blk.get("event_id")
            if e_id not in existing_event_ids:
                simulator.event_log.append({
                    "event_id": e_id,
                    "timestamp": blk.get("timestamp", time.time()),
                    "source": blk.get("source", "ONCHAIN_SEPOLIA"),
                    "command_type": blk.get("command_type", "STATE_ANCHOR"),
                    "entity_id": blk.get("entity_id", "PLANT"),
                    "parameters": blk.get("parameters", {}),
                    "plant_state_snapshot": simulator.get_telemetry_snapshot(),
                    "signature": blk.get("signature")
                })
                existing_event_ids.add(e_id)

    return {
        "status": "SYNCED",
        "synced_blocks": res.get("total_synced", 0),
        "latest_hash": res.get("onchain_last_hash"),
        "contract_address": res.get("contract_address"),
        "message": f"Successfully synced {res.get('total_synced', 0)} block(s) from Sepolia smart contract."
    }


@app.post("/api/plant/command")
async def send_command(cmd: CommandRequest):
    """Dispatches an ICS command and anchors it onto the blockchain ledger."""
    try:
        event = simulator.execute_command(
            source=cmd.source,
            command_type=cmd.command_type,
            entity_id=cmd.entity_id,
            parameters=cmd.parameters
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid command parameters: {str(exc)}")
    block = await _anchor_and_persist_async(event)
    return {
        "status": "COMMAND_EXECUTED_AND_ANCHORED",
        "event": event,
        "blockchain_anchor": block,
        "persisted_to_supabase": db.enabled,
    }

@app.post("/api/attack/inject")
async def inject_attack(payload: AttackRequest, _=Depends(check_demo_mode)):
    """Injects a standardized ICS threat scenario (Stuxnet, Triton, Overpressure, Log Tamper)."""
    scenario = payload.scenario
    meta = simulator.inject_attack(scenario)

    if scenario == "triton":
        e1 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
        await _anchor_and_persist_async(e1)
        e2 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        await _anchor_and_persist_async(e2)

    elif scenario == "stuxnet":
        e1 = simulator.execute_command("SCADA_EXPLOIT_PAYLOAD", "SET_RPM", "PUMP_A_01", {"rpm": 3550.0})
        await _anchor_and_persist_async(e1)

    elif scenario == "overpressure":
        e1 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_VALVE", "VALVE_VENT_02", {"open_percent": 0.0})
        await _anchor_and_persist_async(e1)
        e2 = simulator.execute_command("ATTACKER_SSH_TUNNEL", "SET_RPM", "PUMP_A_01", {"rpm": 3600.0})
        await _anchor_and_persist_async(e2)

    elif scenario == "log_tamper":
        e1 = simulator.execute_command("ROGUE_OPERATOR_0x7b", "OVERRIDE_SIS", "SIS_INTERLOCK_01", {"bypass": True, "authorized": False})
        await _anchor_and_persist_async(e1)
        # Tamper the in-memory record and Supabase row to simulate off-chain historian modification
        e1["command_type"] = "ROUTINE_DIAGNOSTIC_PING"
        e1["parameters"] = {"test": "ok"}
        e1["source"] = "MAINTENANCE_TECH_03"
        if db.enabled:
            await asyncio.to_thread(db.tamper_event_field, e1["event_id"], "command_type", "ROUTINE_DIAGNOSTIC_PING")
            await asyncio.to_thread(db.tamper_event_field, e1["event_id"], "source", "MAINTENANCE_TECH_03")
            await asyncio.to_thread(db.tamper_event_field, e1["event_id"], "parameters", {"test": "ok"})

    return {
        "status": "ATTACK_INJECTED",
        "scenario": scenario,
        "metadata": meta,
        "snapshot": simulator.get_telemetry_snapshot(),
        "persisted_to_supabase": db.enabled,
    }

@app.post("/api/attack/stop")
async def stop_attack(_=Depends(check_demo_mode)):
    """Stops attack and resets plant parameters to nominal baseline."""
    simulator.stop_attack()
    reset_event = simulator.execute_command("AUTHORIZED_ENG_01", "RESET_TRIP", "SIS_INTERLOCK_01", {})
    await _anchor_and_persist_async(reset_event)
    return {
        "status": "ATTACK_HALTED_SYSTEM_NORMALIZED",
        "snapshot": simulator.get_telemetry_snapshot(),
    }

@app.post("/api/tamper/simulate")
async def simulate_tamper(req: TamperRequest, _=Depends(check_demo_mode)):
    """
    Simulates malicious tampering in the local database (both in-memory + Supabase)
    to prove blockchain tamper-detection capabilities.
    """
    for ev in simulator.event_log:
        if ev.get("event_id") == req.event_id:
            original_value = ev.get(req.malicious_field)
            ev[req.malicious_field] = req.tampered_value
            if db.enabled:
                await asyncio.to_thread(db.tamper_event_field, req.event_id, req.malicious_field, req.tampered_value)
            return {
                "status": "DATABASE_RECORD_TAMPERED",
                "event_id": req.event_id,
                "field": req.malicious_field,
                "original_value": original_value,
                "tampered_value": req.tampered_value,
                "supabase_patched": db.enabled,
                "note": "Off-chain database record altered! Cryptographic hash anchor exposes deviation.",
            }
    
    raise HTTPException(status_code=404, detail=f"Event ID {req.event_id} not found in database.")

@app.get("/api/tamper/audit")
async def audit_integrity():
    """Audits entire off-chain database against on-chain blockchain hashes."""
    result = ledger.audit_entire_chain(simulator.event_log)
    return result

@app.get("/api/forensics/reconstruct")
async def reconstruct_incident():
    """Runs backward-walk forensic reconstruction from anomaly back to root cause entry point."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    recon = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    return recon

@app.get("/api/threat-intel/correlate")
async def get_threat_intel():
    """Runs MITRE ATT&CK for ICS correlation and attribution scoring."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )
    return intel

@app.get("/api/threat-intel/matrix")
async def get_mitre_matrix():
    """Returns the full MITRE ATT&CK for ICS matrix with live technique activation based on current incident state."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )
    active_ids = {t["id"] for t in intel.get("matched_techniques", [])}

    # Build matrix organized by tactic
    all_tactics = [
        "Initial Access", "Execution", "Persistence", "Evasion",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Inhibit Response Function",
        "Impair Process Control", "Impact"
    ]
    matrix = {tactic: [] for tactic in all_tactics}
    for tech_id, tech in threat_intel.techniques.items():
        tactic = tech.get("tactic", "Impact")
        if tactic not in matrix:
            matrix[tactic] = []
        matrix[tactic].append({
            "id": tech_id,
            "name": tech["name"],
            "description": tech["description"],
            "mitigation": tech["mitigation"],
            "active": tech_id in active_ids
        })

    return {
        "tactics": all_tactics,
        "matrix": matrix,
        "active_technique_ids": list(active_ids),
        "attribution": intel.get("primary_hypothesis"),
        "attribution_ranking": intel.get("attribution_ranking", []),
        "correlation_summary": intel.get("correlation_summary", "")
    }

@app.get("/api/report/html", response_class=HTMLResponse)
async def get_forensic_report():
    """Generates court-ready HTML forensic incident report with cryptographic validation."""
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    forensic_data = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )

    html = report_gen.generate_html_report(
        forensic_data=forensic_data,
        threat_intel=intel,
        telemetry_snapshot=snapshot,
        contract_address=ledger.sepolia_contract_address,
        is_simulated=ledger.is_simulated
    )
    return HTMLResponse(content=html)


# ── Forensic Cases API ────────────────────────────────────────────────────────

@app.post("/api/cases/save")
async def save_forensic_case(req: SaveCaseRequest):
    """
    Runs a full forensic reconstruction + threat intel correlation and saves the
    result as a named forensic case in Supabase for permanent record-keeping.
    """
    snapshot = simulator.get_telemetry_snapshot()
    anomaly_status = detector.evaluate_telemetry(snapshot)
    audit = ledger.audit_entire_chain(simulator.event_log)
    tampered = not audit["integrity_healthy"]

    reconstruction = forensics.reconstruct_incident(simulator.event_log, anomaly_status)
    intel = threat_intel.correlate_incident(
        command_history=simulator.event_log,
        anomaly_details=anomaly_status,
        tampered_detected=tampered
    )

    active_attack = simulator.active_attack or "baseline"
    auto_name = f"ICS-{active_attack.upper()}-{time.strftime('%Y%m%d-%H%M%S')}"
    case_name = req.case_name.strip() if req.case_name else auto_name

    saved = await asyncio.to_thread(
        db.save_case,
        case_name=case_name,
        attack_scenario=simulator.active_attack,
        reconstruction=reconstruction,
        threat_intel=intel,
        telemetry_snapshot=snapshot,
    )

    if saved:
        return {
            "status": "CASE_SAVED",
            "case": saved,
            "reconstruction_summary": {
                "events_analyzed": reconstruction.get("events_analyzed"),
                "tamper_detected": reconstruction.get("tamper_detected"),
                "root_cause": reconstruction.get("root_cause_artifact"),
            },
        }
    else:
        return {
            "status": "CASE_NOT_PERSISTED_DB_OFFLINE",
            "note": "Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY in .env to enable persistence.",
            "reconstruction_summary": {
                "events_analyzed": reconstruction.get("events_analyzed"),
                "tamper_detected": reconstruction.get("tamper_detected"),
                "root_cause": reconstruction.get("root_cause_artifact"),
            },
        }

@app.get("/api/cases")
async def list_cases():
    """Lists all saved forensic investigation cases from Supabase (newest first)."""
    cases = await asyncio.to_thread(db.get_all_cases)
    return {
        "total": len(cases),
        "db_connected": db.enabled,
        "cases": cases,
    }

@app.get("/api/cases/{case_id}")
async def get_case(case_id: int):
    """Returns the full detail of a single saved forensic case."""
    case = await asyncio.to_thread(db.get_case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return case

@app.get("/api/db/status")
async def db_status():
    """Returns the Supabase connection status and table row counts."""
    status = {
        "connected": db.enabled,
        "message": "Supabase connected and operational." if db.enabled
                   else "Supabase not configured — running in memory-only mode. Add SUPABASE_URL and SUPABASE_KEY to .env",
    }
    if db.enabled:
        cases = await asyncio.to_thread(db.get_all_cases)
        events = await asyncio.to_thread(db.load_events)
        status["row_counts"] = {
            "ics_events": len(events or []),
            "forensic_cases": len(cases or []),
        }
    return status


# ── Serve Frontend ────────────────────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
