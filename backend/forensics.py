"""
IronLedger - Forensic Reconstruction & Backward-Walk Engine
Performs backward traversal along the immutable cryptographic hash chain,
reconstructs chronological attack timelines, evaluates unauthorized policy violations,
and verifies on-chain evidence integrity against value-based physical safety limits.
"""

import os
import time
import hmac
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from backend.blockchain import BlockchainLedger

AUTHORIZED_SOURCES = {"AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"}
SCADA_HMAC_SECRET = os.environ.get("SCADA_HMAC_SECRET", "").strip().encode('utf-8')


def _safe_float(val: Any, default: Optional[float] = None) -> Optional[float]:
    """Safely converts a value to float; returns default if conversion fails or val is boolean."""
    if val is None or isinstance(val, bool):
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


class ForensicReconstructionEngine:
    def __init__(self, ledger: BlockchainLedger):
        self.ledger = ledger

    def _verify_command_signature(self, event: Dict[str, Any]) -> bool:
        """
        Verifies cryptographic HMAC signature on commands.
        If SCADA_HMAC_SECRET is set in .env, high-privilege commands MUST provide a valid signature.
        If SCADA_HMAC_SECRET is unset, signature checking is disabled.
        """
        if not SCADA_HMAC_SECRET:
            return True
        sig = event.get("signature")
        if not sig:
            # Cannot accept unsigned command when cryptographic HMAC secret is enforced
            return False
        payload = f"{event.get('source')}:{event.get('command_type')}:{event.get('entity_id')}"
        expected = hmac.new(SCADA_HMAC_SECRET, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)

    def _evaluate_command_policy(self, event: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Evaluates whether a command complies with SCADA operational safety policies.
        Enforces value-based physical envelope limits regardless of self-reported identity.
        Returns: (is_violation: bool, kill_chain_phase: str, policy_reason: str)
        """
        source = str(event.get("source", "UNKNOWN"))
        cmd_type = str(event.get("command_type", "UNKNOWN"))
        params = event.get("parameters") or {}
        if not isinstance(params, dict):
            params = {}
        entity_id = str(event.get("entity_id", "UNKNOWN"))

        # Check 1: Value-based physical boundary limits (Applies to ANY source, even if claiming to be authorized)
        if cmd_type == "SET_RPM":
            raw_rpm = params.get("rpm", 2400.0)
            rpm = _safe_float(raw_rpm)
            if rpm is None:
                return True, "Malformed Command Parameter (T0855)", f"Command requested invalid non-numeric RPM '{raw_rpm}' (Source: {source})."
            if rpm > 3000.0:
                return True, "Equipment Overspeed Escalation (T0836)", f"Command requested {rpm} RPM exceeding hard safe limit of 3000 RPM (Source: {source})."
            if 0.0 < rpm < 1000.0:
                return True, "Equipment Sub-Harmonic Stall (T0836)", f"Command requested {rpm} RPM in destructive mechanical resonance band."

        if cmd_type == "SET_VALVE" and "VENT" in entity_id:
            raw_open = params.get("open_percent", 15.0)
            open_pct = _safe_float(raw_open)
            if open_pct is None:
                return True, "Malformed Command Parameter (T0836)", f"Command requested invalid non-numeric open_percent '{raw_open}' (Source: {source})."
            if open_pct < 5.0:
                return True, "Process Parameter Manipulation (T0836)", f"Relief vent clamped shut (0%) during active operations (Source: {source})."

        if cmd_type == "OVERRIDE_SIS":
            if not params.get("authorized", False) or not params.get("dual_signoff", False):
                return True, "Safety Interlock Neutralization (T0888)", f"SIS interlock bypass executed without verified dual-operator safety sign-off (Source: {source})."

        # Check 2: Cryptographic signature verification
        if not self._verify_command_signature(event):
            return True, "Forged Command Signature (T0855)", f"Invalid cryptographic command signature from origin '{source}'."

        # Check 3: Source authorization allowlist
        if source not in AUTHORIZED_SOURCES:
            if "OVERRIDE" in cmd_type or "SIS" in cmd_type or params.get("bypass"):
                return True, "Safety Interlock Neutralization (T0888)", f"Unauthorized operator '{source}' bypassed SIS interlocks."
            if "VALVE" in entity_id:
                return True, "Process Parameter Manipulation (T0836)", f"Unauthorized entity '{source}' altered valve setpoints."
            if "PUMP" in entity_id or cmd_type in ["SET_RPM", "STOP"]:
                return True, "Manipulation of Control (T0831)", f"Unauthorized operator '{source}' modified pump operational speed."
            return True, "Unauthorized Command Injection (T0855)", f"Command dispatched from unauthenticated origin '{source}'."

        # Normal operational command
        phase_map = {
            "START": "Authorized Process Activation",
            "SET_VALVE": "Routine Process Adjustment",
            "SET_RPM": "Routine Speed Regulation",
            "STOP": "Controlled Equipment Shutdown",
            "RESET_TRIP": "Safety System Normalization",
            "TELEMETRY_SNAPSHOT": "Telemetry Observation",
            "INITIALIZE_LEDGER": "System Initialization"
        }
        return False, phase_map.get(cmd_type, "Operational Command"), "Standard operational procedure"

    def reconstruct_incident(
        self,
        db_events: List[Dict[str, Any]],
        anomaly_event: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes evidence-based backward-walk along the blockchain ledger:
        Traverses backwards along previous_hash links to isolate root cause.
        """
        if not db_events:
            return {
                "success": False,
                "message": "No forensic events available in database",
                "timeline": [],
                "root_cause": None
            }

        # Step 1: Run complete cryptographic integrity audit
        audit_result = self.ledger.audit_entire_chain(db_events)
        has_tampering = not audit_result["integrity_healthy"]

        # Step 2: Index database events by event_id
        db_map = {e.get("event_id"): e for e in db_events if "event_id" in e}

        # Step 3: Backward traversal along the blockchain hash chain
        reconstructed_steps = []
        root_cause_candidate = None
        policy_violations_found = []

        reversed_blocks = list(reversed(self.ledger.chain[1:]))

        for idx, block in enumerate(reversed_blocks):
            ev_id = block.get("event_id")
            db_ev = db_map.get(ev_id, {})
            
            # Check if this specific event was tampered with in off-chain storage
            is_event_tampered = False
            tamper_note = None
            for detail in audit_result.get("audit_details", []):
                if detail.get("event_id") == ev_id and detail.get("tampered"):
                    is_event_tampered = True
                    tamper_note = f"RECORD TAMPERED: Off-chain DB record deviates from on-chain SHA-256 anchor! ({detail.get('reason')})"
                    break

            if is_event_tampered:
                # Prefer the immutable on-chain block's authentic metadata
                source = block.get("source", "UNKNOWN")
                cmd_type = block.get("command_type", "UNKNOWN")
                entity_id = block.get("entity_id", "UNKNOWN")
                block_params = block.get("parameters")

                policy_reliable = False
                if block_params is not None and isinstance(block_params, dict):
                    candidate = {
                        "event_id": block.get("event_id"),
                        "timestamp": db_ev.get("timestamp", block.get("timestamp")),
                        "source": source,
                        "command_type": cmd_type,
                        "entity_id": entity_id,
                        "parameters": block_params,
                        "signature": block.get("signature") or db_ev.get("signature"),
                        "plant_state_snapshot": db_ev.get("plant_state_snapshot", {}),
                    }
                    try:
                        recomputed = self.ledger.compute_event_hash(candidate, block.get("previous_hash", "0x" + "0"*64))
                        if recomputed.lower() == block.get("event_hash", "").lower():
                            parameters = block_params
                            policy_reliable = True
                    except Exception:
                        policy_reliable = False

                if not policy_reliable:
                    parameters = db_ev.get("parameters") or {}

                # Capture the forged values from the database record
                claimed_source = db_ev.get("source")
                claimed_command = db_ev.get("command_type")
                claimed_entity = db_ev.get("entity_id")
                claimed_parameters = db_ev.get("parameters")
            else:
                source = db_ev.get("source") or block.get("source", "UNKNOWN")
                cmd_type = db_ev.get("command_type") or block.get("command_type", "UNKNOWN")
                entity_id = db_ev.get("entity_id") or block.get("entity_id", "UNKNOWN")
                parameters = db_ev.get("parameters") or {}
                claimed_source = None
                claimed_command = None
                claimed_entity = None
                claimed_parameters = None
                policy_reliable = True

            timestamp = db_ev.get("timestamp") or block.get("timestamp", time.time())

            # Evaluate operational policy & value limits
            is_violation, kill_chain_phase, policy_reason = self._evaluate_command_policy({
                "source": source,
                "command_type": cmd_type,
                "entity_id": entity_id,
                "parameters": parameters,
                "signature": db_ev.get("signature")
            })

            # If tampered and policy was evaluated against DB-sourced (possibly forged) parameters,
            # override the result to flag it as unreliable.
            if is_event_tampered and not policy_reliable:
                if not is_violation:
                    is_violation = True
                    kill_chain_phase = "Policy Evaluation Unreliable (Tampered Record)"
                    policy_reason = (
                        "Original parameters cannot be verified against the on-chain hash — DB record may be forged."
                    )

            step_entry = {
                "step_order": len(reversed_blocks) - idx,
                "event_id": ev_id,
                "timestamp": timestamp,
                "formatted_time": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(_safe_float(timestamp, time.time()) or time.time())),
                "source": source,
                "command_type": cmd_type,
                "entity_id": entity_id,
                "parameters": parameters,
                "claimed_source": claimed_source,
                "claimed_command": claimed_command,
                "claimed_entity": claimed_entity,
                "claimed_parameters": claimed_parameters,
                "kill_chain_phase": kill_chain_phase,
                "policy_violation": is_violation,
                "policy_reason": policy_reason,
                "tampered": is_event_tampered,
                "tamper_note": tamper_note,
                "onchain_block_number": block.get("block_number"),
                "onchain_hash": block.get("event_hash"),
                "previous_hash": block.get("previous_hash"),
                "tx_hash": block.get("tx_hash"),
                "is_simulated": block.get("is_simulated", True),
                "etherscan_url": block.get("etherscan_url")
            }

            if is_violation:
                policy_violations_found.append(step_entry)
                root_cause_candidate = step_entry

            reconstructed_steps.append(step_entry)

        timeline = list(reversed(reconstructed_steps))

        if not root_cause_candidate and timeline:
            root_cause_candidate = timeline[0]

        is_tampered_culprit = root_cause_candidate and root_cause_candidate.get("tampered")
        if is_tampered_culprit:
            conclusion_text = (
                f"Tampering Unmasked: Off-chain historian falsely claimed [{root_cause_candidate.get('claimed_source')}] "
                f"dispatched [{root_cause_candidate.get('claimed_command')}]. "
                f"Cryptographic blockchain anchor proves authentic root cause is [{root_cause_candidate.get('source')}] "
                f"executing [{root_cause_candidate.get('command_type')}] targeting [{root_cause_candidate.get('entity_id')}]. "
                f"Policy violation: {root_cause_candidate.get('policy_reason')}."
            )
        elif root_cause_candidate:
            conclusion_text = (
                f"Root cause identified via backward hash traversal: source [{root_cause_candidate.get('source')}] "
                f"executed [{root_cause_candidate.get('command_type')}] targeting [{root_cause_candidate.get('entity_id')}]. "
                f"Policy violation: {root_cause_candidate.get('policy_reason')}. "
                f"Cryptographic chain of custody verified against on-chain block."
            )
        else:
            conclusion_text = "Normal operation baseline."

        return {
            "success": True,
            "reconstruction_timestamp": time.time(),
            "events_analyzed": len(timeline),
            "tamper_detected": has_tampering,
            "tampered_records_count": audit_result.get("tampered_blocks_found", 0),
            "policy_violations_count": len(policy_violations_found),
            "timeline": timeline,
            "root_cause_artifact": {
                "event_id": root_cause_candidate.get("event_id") if root_cause_candidate else None,
                "source_identity": root_cause_candidate.get("source") if root_cause_candidate else "Unknown",
                "entry_command": root_cause_candidate.get("command_type") if root_cause_candidate else "Unknown",
                "target_entity": root_cause_candidate.get("entity_id") if root_cause_candidate else "Unknown",
                "parameters": root_cause_candidate.get("parameters") if root_cause_candidate else {},
                "claimed_source": root_cause_candidate.get("claimed_source") if root_cause_candidate else None,
                "claimed_command": root_cause_candidate.get("claimed_command") if root_cause_candidate else None,
                "claimed_entity": root_cause_candidate.get("claimed_entity") if root_cause_candidate else None,
                "onchain_proof_tx": root_cause_candidate.get("tx_hash") if root_cause_candidate else None,
                "policy_violation": root_cause_candidate.get("policy_violation", False) if root_cause_candidate else False,
                "policy_reason": root_cause_candidate.get("policy_reason", "Baseline") if root_cause_candidate else "Baseline",
                "forensic_conclusion": conclusion_text,
                "identity_attribution_caveat": (
                    "Operator identity is based on self-reported source identifier. "
                    "Without hardware-enforced certificates or cryptographic command signatures (HMAC/ECDSA), "
                    "identities may be spoofed on unauthenticated ICS network segments."
                )
            },
            "chain_integrity_audit": audit_result
        }
