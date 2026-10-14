"""
IronLedger - Supabase Database Layer
Handles persistent storage of ICS events, blockchain blocks, and forensic cases.

Tables required (run supabase_schema.sql in Supabase SQL Editor):
  - ics_events         : off-chain ICS command log (the "mutable" DB that can be tampered)
  - blockchain_blocks  : mirror of the immutable ledger anchor blocks
  - forensic_cases     : saved forensic reconstruction results

Graceful degradation: if SUPABASE_URL / SUPABASE_KEY are not set the class
operates in no-op mode and the app falls back to pure in-memory behaviour.
"""

import os
import json
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ironledger.db")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from supabase import create_client, Client
    _SUPABASE_AVAILABLE = True
except ImportError:
    _SUPABASE_AVAILABLE = False
    logger.warning("supabase-py not installed — running in memory-only mode.")


def _safe_json_loads(val: Any, default: Any = None) -> Any:
    """Safely decodes JSON whether it is returned as str, dict, or list from Supabase."""
    if val is None:
        return default if default is not None else {}
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return default if default is not None else {}
    return default if default is not None else {}


class SupabaseDatabase:
    """
    Thin wrapper around the Supabase Python client for IronLedger persistence.
    All methods are safe to call even when no credentials are configured; they
    will log a warning and return gracefully (empty list / None).
    """

    def __init__(self):
        self._client: Optional[Any] = None
        self._enabled = False
        self._connect()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _connect(self):
        url = os.getenv("SUPABASE_URL", "").strip()
        key = os.getenv("SUPABASE_KEY", "").strip()

        if not url or not key or "your-project" in url:
            logger.info("Running in local session mode. Add SUPABASE_URL & SUPABASE_KEY to .env for cloud persistence.")
            return

        if not _SUPABASE_AVAILABLE:
            logger.warning("supabase package not available — running in memory-only mode.")
            return

        try:
            self._client: Client = create_client(url, key)
            self._enabled = True
            logger.info(f"✅ Supabase connected: {url}")
        except Exception as exc:
            logger.error(f"Supabase connection failed: {exc} — falling back to memory-only mode.")

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ── ICS Events ────────────────────────────────────────────────────────────

    def upsert_event(self, event: Dict[str, Any]) -> bool:
        """
        Persist a single ICS command event to the `ics_events` table.
        """
        if not self._enabled:
            return False
        try:
            raw_ts = float(event.get("timestamp", time.time()))
            row = {
                "event_id":             event.get("event_id"),
                "timestamp":            raw_ts,
                "timestamp_ms":         int(raw_ts * 1000),
                "source":               event.get("source", "UNKNOWN"),
                "command_type":         event.get("command_type", "UNKNOWN"),
                "entity_id":            event.get("entity_id", "UNKNOWN"),
                "parameters":           json.dumps(event.get("parameters", {})),
                "plant_state_snapshot": json.dumps(event.get("plant_state_snapshot", {})),
                "signature":            event.get("signature"),
            }
            self._client.table("ics_events").upsert(row, on_conflict="event_id").execute()
            return True
        except Exception as exc:
            logger.error(f"upsert_event failed: {exc}")
            return False

    def load_events(self) -> Optional[List[Dict[str, Any]]]:
        """
        Restore the full ICS event log from Supabase (used on server startup).
        """
        if not self._enabled:
            return []
        try:
            events = []
            offset = 0
            limit = 1000
            while True:
                resp = self._client.table("ics_events").select("*").order("event_id").range(offset, offset + limit - 1).execute()
                if not resp.data:
                    break
                for row in resp.data:
                    events.append({
                        "event_id":             row["event_id"],
                        "timestamp":            row["timestamp"],
                        "timestamp_ms":         row.get("timestamp_ms") or int(row["timestamp"] * 1000),
                        "source":               row["source"],
                        "command_type":         row["command_type"],
                        "entity_id":            row["entity_id"],
                        "parameters":           _safe_json_loads(row.get("parameters"), {}),
                        "plant_state_snapshot": _safe_json_loads(row.get("plant_state_snapshot"), {}),
                        "signature":            row.get("signature"),
                    })
                offset += limit
            logger.info(f"Loaded {len(events)} ICS events from Supabase.")
            return events
        except Exception as exc:
            logger.error(f"load_events failed: {exc}")
            return None

    def delete_event(self, event_id: int) -> bool:
        """Delete a single ICS event (used in log-tamper simulation)."""
        if not self._enabled:
            return False
        try:
            self._client.table("ics_events").delete().eq("event_id", event_id).execute()
            return True
        except Exception as exc:
            logger.error(f"delete_event failed: {exc}")
            return False

    def tamper_event_field(self, event_id: int, field: str, value: Any) -> bool:
        """
        Directly patches a single field in the `ics_events` row — simulates
        an attacker altering the off-chain database to hide malicious activity.
        """
        if not self._enabled:
            return False
        ALLOWED = {"source", "command_type", "entity_id", "parameters", "timestamp", "plant_state_snapshot"}
        if field not in ALLOWED:
            logger.warning(f"tamper_event_field: field '{field}' not patchable.")
            return False
        try:
            if field in ["parameters", "plant_state_snapshot"]:
                patch_value = json.dumps(value) if isinstance(value, (dict, list)) else value
            else:
                patch_value = value
            self._client.table("ics_events").update({field: patch_value}).eq("event_id", event_id).execute()
            return True
        except Exception as exc:
            logger.error(f"tamper_event_field failed: {exc}")
            return False

    # ── Blockchain Blocks ─────────────────────────────────────────────────────

    def upsert_block(self, block: Dict[str, Any]) -> bool:
        """Persist a blockchain anchor block to `blockchain_blocks`."""
        if not self._enabled:
            return False
        try:
            row = {
                "block_index":    block.get("block_index"),
                "event_id":       block.get("event_id"),
                "event_hash":     block.get("event_hash"),
                "previous_hash":  block.get("previous_hash"),
                "timestamp":      block.get("timestamp"),
                "timestamp_ms":   block.get("timestamp_ms"),
                "source":         block.get("source", "UNKNOWN"),
                "command_type":   block.get("command_type", "UNKNOWN"),
                "entity_id":      block.get("entity_id", "UNKNOWN"),
                "tx_hash":        block.get("tx_hash"),
                "block_number":   block.get("block_number"),
                "recorded_by":    block.get("recorded_by"),
                "status":         block.get("status", "CONFIRMED_ON_CHAIN"),
                "is_simulated":   block.get("is_simulated", True),
                "etherscan_url":  block.get("etherscan_url"),
                "parameters":     json.dumps(block.get("parameters", {})),
            }
            self._client.table("blockchain_blocks").upsert(row, on_conflict="block_index").execute()
            return True
        except Exception as exc:
            logger.error(f"upsert_block failed: {exc}")
            return False

    def load_blocks(self) -> Optional[List[Dict[str, Any]]]:
        """Restore blockchain blocks from Supabase."""
        if not self._enabled:
            return []
        try:
            blocks = []
            offset = 0
            limit = 1000
            while True:
                resp = self._client.table("blockchain_blocks").select("*").order("block_index").range(offset, offset + limit - 1).execute()
                if not resp.data:
                    break
                for row in resp.data:
                    # Parse parameters JSON if present (column added in schema V2.2)
                    if "parameters" in row and isinstance(row["parameters"], str):
                        row["parameters"] = _safe_json_loads(row["parameters"], {})
                    blocks.append(row)
                offset += limit
            return blocks
        except Exception as exc:
            logger.error(f"load_blocks failed: {exc}")
            return None

    def clear_all_tables(self) -> bool:
        """Truncate all events, blocks, and forensic cases to migrate or reset clean state."""
        if not self._enabled:
            return False
        try:
            self._client.table("blockchain_blocks").delete().neq("block_index", -1).execute()
            self._client.table("ics_events").delete().neq("event_id", -1).execute()
            self._client.table("forensic_cases").delete().neq("id", -1).execute()
            logger.info("Cleared all events, blocks, and forensic cases from Supabase.")
            return True
        except Exception as exc:
            logger.error(f"clear_all_tables failed: {exc}")
            return False

    # ── Forensic Cases ────────────────────────────────────────────────────────

    def save_case(
        self,
        case_name: str,
        attack_scenario: Optional[str],
        reconstruction: Dict[str, Any],
        threat_intel: Dict[str, Any],
        telemetry_snapshot: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Save a complete forensic reconstruction as a named case row in `forensic_cases`.
        """
        if not self._enabled:
            return None

        root_cause = reconstruction.get("root_cause_artifact", {})
        actor = threat_intel.get("primary_hypothesis", {})

        row = {
            "case_name":           case_name,
            "attack_scenario":      attack_scenario,
            "events_analyzed":      reconstruction.get("events_analyzed", 0),
            "tamper_detected":      reconstruction.get("tamper_detected", False),
            "tampered_records":     reconstruction.get("tampered_records_count", 0),
            "root_cause_source":    root_cause.get("source_identity"),
            "root_cause_command":   root_cause.get("entry_command"),
            "root_cause_entity":    root_cause.get("target_entity"),
            "forensic_conclusion":  root_cause.get("forensic_conclusion"),
            "attribution_actor":    actor.get("name"),
            "confidence_score":     float(actor.get("confidence_score", 0)),
            "mitre_techniques":     json.dumps(threat_intel.get("matched_techniques", [])),
            "timeline":             json.dumps(reconstruction.get("timeline", [])),
            "threat_intel":         json.dumps(threat_intel),
            "telemetry_snapshot":   json.dumps(telemetry_snapshot),
        }

        try:
            resp = self._client.table("forensic_cases").insert(row).execute()
            if resp.data:
                logger.info(f"✅ Saved forensic case '{case_name}' to Supabase (id={resp.data[0]['id']}).")
                return resp.data[0]
            return None
        except Exception as exc:
            logger.error(f"save_case failed: {exc}")
            return None

    def get_all_cases(self) -> List[Dict[str, Any]]:
        """Fetch all saved forensic cases (newest first)."""
        if not self._enabled:
            return []
        try:
            resp = (
                self._client.table("forensic_cases")
                .select("id, case_name, attack_scenario, created_at, events_analyzed, tamper_detected, attribution_actor, confidence_score, root_cause_command")
                .order("created_at", desc=True)
                .execute()
            )
            return resp.data or []
        except Exception as exc:
            logger.error(f"get_all_cases failed: {exc}")
            return []

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Fetch the full detail of a single case by ID."""
        if not self._enabled:
            return None
        try:
            resp = (
                self._client.table("forensic_cases")
                .select("*")
                .eq("id", case_id)
                .single()
                .execute()
            )
            if not resp.data:
                return None
            c = resp.data
            c["mitre_techniques"]   = _safe_json_loads(c.get("mitre_techniques"), [])
            c["timeline"]           = _safe_json_loads(c.get("timeline"), [])
            c["threat_intel"]       = _safe_json_loads(c.get("threat_intel"), {})
            c["telemetry_snapshot"] = _safe_json_loads(c.get("telemetry_snapshot"), {})
            return c
        except Exception as exc:
            logger.error(f"get_case({case_id}) failed: {exc}")
            return None
