"""
IronLedger - Threat Intelligence & MITRE ATT&CK for ICS Correlation
Maps anomalous SCADA commands, setpoint deviations, and physical telemetry patterns
to MITRE ATT&CK for ICS techniques and calculates objective threat actor attribution confidence.
"""

from typing import Dict, Any, List, Optional

MITRE_ICS_TECHNIQUES = {
    "T0855": {
        "id": "T0855",
        "name": "Unauthorized Command Message",
        "tactic": "Impair Process Control",
        "description": "Adversary sends unauthorized control messages or setpoints to SCADA devices to manipulate physical operations.",
        "mitigation": "Enforce cryptographic command signing, strict role-based access control, and network micro-segmentation."
    },
    "T0836": {
        "id": "T0836",
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "description": "Adversary alters operational parameters (speed limits, pressure thresholds, alarm setpoints) causing equipment wear or failure.",
        "mitigation": "Implement out-of-band parameter change approval and immutable blockchain ledger recording."
    },
    "T0831": {
        "id": "T0831",
        "name": "Manipulation of Control",
        "tactic": "Impair Process Control",
        "description": "Adversaries manipulate physical control logic or PLC programs to cause dangerous process transitions.",
        "mitigation": "Enforce physical key switches on PLCs and dual-operator authorization for logic changes."
    },
    "T0888": {
        "id": "T0888",
        "name": "Loss of Safety",
        "tactic": "Inhibit Response Function",
        "description": "Adversaries disable or modify Safety Instrumented Systems (SIS), preventing automated emergency shutdown during dangerous excursions.",
        "mitigation": "Physically isolate safety networks (SIL 3) from supervisory control networks and maintain hardware-enforced interlocks."
    },
    "T0816": {
        "id": "T0816",
        "name": "Device Restart/Shutdown",
        "tactic": "Inhibit Response Function",
        "description": "Adversaries reboot or take offline protective safety controllers or monitoring RTUs.",
        "mitigation": "Audit device power states and monitor firmware health checks."
    },
    "T0879": {
        "id": "T0879",
        "name": "Damage to Property",
        "tactic": "Impact",
        "description": "Adversary drives physical machinery beyond mechanical yield thresholds, causing permanent hardware destruction or catastrophic explosion.",
        "mitigation": "Mechanical pressure relief disks, independent analog thermal fuses, and immutable forensic auditing."
    },
    "T0815": {
        "id": "T0815",
        "name": "Denial of View",
        "tactic": "Evasion",
        "description": "Adversaries spoof HMI telemetry or alter local audit records to hide malicious setpoints from human operators.",
        "mitigation": "Cryptographic ledger verification (IronLedger) cross-checking HMI view against anchored blockchain hashes."
    }
}

THREAT_ACTOR_PROFILES = {
    "XENOTIME": {
        "name": "Xenotime (Triton / HatMan)",
        "origin": "Russian State-Sponsored (CNIIHM)",
        "target_sectors": ["Oil & Gas", "Petrochemical", "Critical Power"],
        "signature_techniques": ["T0888", "T0831", "T0855", "T0816"],
        "known_campaigns": ["2017 Saudi Petrochemical SIS Attack"],
        "description": "Destructive ICS threat group focusing directly on compromising Safety Instrumented Systems (SIS / Triconex) to eliminate failsafe trip mechanisms."
    },
    "SANDWORM": {
        "name": "Sandworm (Industroyer / Industroyer2)",
        "origin": "Russian GRU Unit 74455",
        "target_sectors": ["Electric Grid", "Substations", "Municipal Infrastructure"],
        "signature_techniques": ["T0855", "T0836", "T0879", "T0816"],
        "known_campaigns": ["2015/2016 Ukraine Power Grid Blackouts", "2022 Industroyer2 Substation Raid"],
        "description": "Military cyber warfare unit skilled in bespoke industrial protocol manipulation (IEC 60870-5-104, IEC 61850, Modbus TCP) to cause kinetic impacts."
    },
    "EQUATION_GROUP": {
        "name": "Stuxnet Taskforce",
        "origin": "Classified State Entity (Operation Olympic Games)",
        "target_sectors": ["Nuclear Enrichment", "Centrifuge Cascades"],
        "signature_techniques": ["T0836", "T0855", "T0815", "T0831"],
        "known_campaigns": ["Natanz Centrifuge Sabotage"],
        "description": "Destructive cyber-physical operation that weaponized variable-frequency drives (VFDs) and manipulated SCADA frequency parameters while playing back spoofed sensor feeds."
    },
    "VOLT_TYPHOON": {
        "name": "Volt Typhoon (ICS Pre-Positioning)",
        "origin": "PRC State-Sponsored",
        "target_sectors": ["Water Utilities", "Ports", "Critical Energy"],
        "signature_techniques": ["T0815", "T0855", "T0836"],
        "known_campaigns": ["2023-2024 Critical Infrastructure Infiltration"],
        "description": "Pre-positioning adversary that leverages living-off-the-land techniques and alters or erases local event logs to maintain prolonged undetected access."
    }
}


class ThreatIntelligenceEngine:
    def __init__(self):
        self.techniques = MITRE_ICS_TECHNIQUES
        self.actors = THREAT_ACTOR_PROFILES

    def correlate_incident(
        self,
        command_history: List[Dict[str, Any]],
        anomaly_details: Dict[str, Any],
        tampered_detected: bool = False
    ) -> Dict[str, Any]:
        """
        Maps the reconstructed sequence of commands and physical anomalies
        to MITRE ATT&CK for ICS techniques and calculates objective attribution confidence based on technique overlap.
        """
        matched_techniques = []
        identified_tech_ids = set()

        # Check for unauthorized or abnormal commands
        for cmd in command_history:
            cmd_type = str(cmd.get("command_type", ""))
            source = str(cmd.get("source", ""))
            raw_params = cmd.get("parameters")
            params = raw_params if isinstance(raw_params, dict) else {}

            if "OVERRIDE_SIS" in cmd_type or params.get("bypass"):
                identified_tech_ids.add("T0888")  # Loss of Safety
                identified_tech_ids.add("T0831")  # Manipulation of Control

            if cmd_type in ["SET_RPM", "SET_VALVE"]:
                identified_tech_ids.add("T0836")  # Modify Parameter
                if source not in ["AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"]:
                    identified_tech_ids.add("T0855")  # Unauthorized Command Message

            if cmd_type == "STOP" and "TRIP" not in cmd_type:
                if source not in ["AUTHORIZED_ENG_01", "SCADA_AUTO_PID", "GENESIS_NODE"]:
                    identified_tech_ids.add("T0816")  # Device Restart/Shutdown

        # Check physical damage / limits
        severity = anomaly_details.get("severity", "NORMAL")
        if severity in ["CRITICAL", "CATASTROPHIC"]:
            identified_tech_ids.add("T0879")  # Damage to Property

        # Check log tampering
        if tampered_detected:
            identified_tech_ids.add("T0815")  # Denial of View

        # Compile full technique metadata
        for tid in identified_tech_ids:
            if tid in self.techniques:
                matched_techniques.append(self.techniques[tid])

        # Attribute to Threat Actor Candidates using objective signature coverage
        attribution_scores = []
        for actor_key, actor in self.actors.items():
            sig = set(actor["signature_techniques"])
            intersection = sig.intersection(identified_tech_ids)
            missing = sig.difference(identified_tech_ids)

            if len(sig) > 0:
                # Objective percentage of the threat actor's signature observed in the incident
                confidence = round((len(intersection) / len(sig)) * 100.0, 1)
            else:
                confidence = 0.0

            attribution_scores.append({
                "actor_id": actor_key,
                "name": actor["name"],
                "origin": actor["origin"],
                "target_sectors": actor["target_sectors"],
                "confidence_score": confidence,
                "matched_signature_techniques": list(intersection),
                "missing_signature_techniques": list(missing),
                "profile": actor["description"]
            })

        # Sort by confidence descending
        attribution_scores.sort(key=lambda x: x["confidence_score"], reverse=True)
        top_attribution = attribution_scores[0] if attribution_scores else None

        attribution_caveat = (
            "Forensic Note: Technique overlap provides behavioral correlation based on observed TTPs, "
            "not definitive legal proof of actor identity. False-flag tactics and shared commodity tooling "
            "should be evaluated by human forensic analysts."
        )

        return {
            "matched_techniques": matched_techniques,
            "tactics_involved": list(set(t["tactic"] for t in matched_techniques)),
            "attribution_ranking": attribution_scores,
            "primary_hypothesis": top_attribution,
            "attribution_caveat": attribution_caveat,
            "correlation_summary": (
                f"Identified {len(matched_techniques)} MITRE ATT&CK for ICS techniques. "
                f"Primary attribution hypothesis points to '{top_attribution['name']}' "
                f"with {top_attribution['confidence_score']}% signature match based on observed ICS telemetry and commands."
                if top_attribution and top_attribution['confidence_score'] > 0 else "Insufficient signatures for definitive threat actor correlation."
            )
        }
