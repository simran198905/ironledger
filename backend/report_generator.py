"""
IronLedger - Forensic Incident Report Generator
Compiles structured, cryptographically verified ICS incident reports
with chain-of-custody, backward-walk timeline, and MITRE ATT&CK for ICS attribution.
"""

import time
import html as html_mod
from typing import Dict, Any, List


class ForensicReportGenerator:
    def generate_html_report(
        self,
        forensic_data: Dict[str, Any],
        threat_intel: Dict[str, Any],
        telemetry_snapshot: Dict[str, Any],
        contract_address: str = "",
        is_simulated: bool = True
    ) -> str:
        """Generates self-contained, publication-grade HTML digital forensics report with clear mode disclosure."""
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        report_id = f"IL-ICS-FOR-{int(time.time())}"
        root_cause = forensic_data.get("root_cause_artifact", {})
        timeline = forensic_data.get("timeline", [])
        actor = threat_intel.get("primary_hypothesis", {})
        tampered = forensic_data.get("tamper_detected", False)

        mode_badge = (
            '<span class="mode-simulated">LOCAL SIMULATION MODE (SHA-256 HASH CHAIN)</span>'
            if is_simulated else
            '<span class="mode-live">LIVE ETHEREUM SEPOLIA ANCHOR</span>'
        )

        mode_banner = (
            """<div class="alert-banner warning">
                <strong>⚠️ EVIDENCE NOTICE — SIMULATION MODE ACTIVE:</strong>
                This report was generated using IronLedger's local cryptographic SHA-256 state ledger.
                Transactions were verified against the local anchor state mirror and were not broadcast to the public Ethereum Sepolia testnet.
            </div>"""
            if is_simulated else
            f"""<div class="alert-banner success">
                <strong>🔗 LIVE ON-CHAIN ANCHOR VERIFIED:</strong>
                State hashes are committed directly to Ethereum Sepolia Smart Contract <code>{contract_address}</code>.
            </div>"""
        )

        # Coerce root cause parameters if present
        rc_params = root_cause.get("parameters")
        if not isinstance(rc_params, dict):
            root_cause_params = {}
            root_cause_params_raw = html_mod.escape(str(rc_params)) if rc_params is not None else ""
        else:
            root_cause_params = rc_params
            root_cause_params_raw = ""

        # Build timeline HTML rows
        timeline_rows = ""
        for item in timeline:
            raw_params = item.get("parameters")
            if isinstance(raw_params, dict):
                params_dict = raw_params
                params_text = ", ".join(f"{html_mod.escape(str(k))}={html_mod.escape(str(v))}" for k, v in params_dict.items()) if params_dict else ""
            else:
                params_dict = {}
                params_text = html_mod.escape(str(raw_params)) if raw_params is not None else ""

            badge_class = "tamper-badge" if item.get("tampered") else "valid-badge"
            badge_text = "TAMPERED MISMATCH" if item.get("tampered") else "BLOCKCHAIN VERIFIED"
            
            tx_display = item.get("tx_hash")
            if tx_display and not is_simulated:
                tx_link = f'<a href="{item.get("etherscan_url")}" target="_blank" class="tx-link">{tx_display[:10]}...</a>'
            elif tx_display:
                tx_link = f'<span class="tx-sim">{tx_display[:10]}... (Sim)</span>'
            else:
                tx_link = '<span class="tx-none">Local Anchor</span>'

            policy_text = f"<br><small style='color:#f87171;'>{html_mod.escape(str(item.get('policy_reason', '')))}</small>" if item.get('policy_violation') else ""

            src = html_mod.escape(str(item.get('source', '-')))
            cmd = html_mod.escape(str(item.get('command_type', '-')))
            ent = html_mod.escape(str(item.get('entity_id', '-')))
            phase = html_mod.escape(str(item.get('kill_chain_phase', '-')))

            if item.get("tampered") and item.get("claimed_source"):
                claimed_s = html_mod.escape(str(item.get('claimed_source', '')))
                claimed_c = html_mod.escape(str(item.get('claimed_command', '')))
                src_display = f'<span class="source-tag">{src}</span><br><small style="color:#f87171;">(DB claimed: {claimed_s})</small>'
                cmd_display = f'<code>{cmd}</code><br><small style="color:#f87171;">(DB claimed: {claimed_c})</small>'
            else:
                src_display = f'<span class="source-tag">{src}</span>'
                cmd_display = f'<code>{cmd}</code>'
                if params_text:
                    cmd_display += f'<br><small style="color:var(--text-muted);">({params_text})</small>'

            timeline_rows += f"""
            <tr>
                <td><strong>#{item.get('event_id', '-')}</strong></td>
                <td>{item.get('formatted_time', '-')}</td>
                <td>{src_display}</td>
                <td>{cmd_display}</td>
                <td>{ent}</td>
                <td>{phase}{policy_text}</td>
                <td><span class="{badge_class}">{badge_text}</span></td>
                <td class="hash-col" title="{item.get('onchain_hash', '')}"><code>{str(item.get('onchain_hash', ''))[:16]}...</code></td>
                <td>{tx_link}</td>
            </tr>
            """

        # Build MITRE techniques rows
        mitre_rows = ""
        for t in threat_intel.get("matched_techniques", []):
            t_id = html_mod.escape(str(t.get('id', '')))
            t_tactic = html_mod.escape(str(t.get('tactic', '')))
            t_name = html_mod.escape(str(t.get('name', '')))
            t_desc = html_mod.escape(str(t.get('description', '')))
            t_mit = html_mod.escape(str(t.get('mitigation', '')))
            mitre_rows += f"""
            <div class="technique-card">
                <div class="tech-header">
                    <span class="tech-id">{t_id}</span>
                    <span class="tech-tactic">{t_tactic}</span>
                </div>
                <h4>{t_name}</h4>
                <p>{t_desc}</p>
                <div class="tech-mitigation"><strong>Mitigation:</strong> {t_mit}</div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IronLedger Forensic Report - {report_id}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-border: #1f293d;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        @media print {{
            body {{ background: #fff !important; color: #111 !important; }}
            .no-print {{ display: none !important; }}
            .container {{ box-shadow: none !important; border: none !important; width: 100% !important; }}
            table th {{ background: #f3f4f6 !important; color: #111 !important; }}
            .technique-card {{ border: 1px solid #ddd !important; background: #fafafa !important; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px 15px;
        }}
        .container {{
            max-width: 1080px;
            margin: 0 auto;
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--surface-border);
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .brand h1 {{
            font-size: 24px;
            letter-spacing: 1px;
            color: #fff;
        }}
        .brand h1 span {{ color: var(--accent-cyan); }}
        .meta-box {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }}
        .mode-simulated {{
            display: inline-block;
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
            border: 1px solid var(--warning);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            margin-top: 6px;
        }}
        .mode-live {{
            display: inline-block;
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid var(--success);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            margin-top: 6px;
        }}
        .alert-banner {{
            padding: 14px 18px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 13px;
        }}
        .alert-banner.danger {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--danger);
            color: #fca5a5;
        }}
        .alert-banner.warning {{
            background: rgba(245, 158, 11, 0.12);
            border: 1px solid var(--warning);
            color: #fde68a;
        }}
        .alert-banner.success {{
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--success);
            color: #6ee7b7;
        }}
        h2 {{
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--accent-cyan);
            margin: 30px 0 15px 0;
            border-bottom: 1px solid #2d3748;
            padding-bottom: 6px;
        }}
        .card-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .info-card {{
            background: #1e293b;
            border: 1px solid #334155;
            padding: 16px;
            border-radius: 8px;
        }}
        .info-card .label {{
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }}
        .info-card .value {{
            font-size: 18px;
            font-weight: bold;
            margin: 6px 0 2px 0;
        }}
        .info-card .sub {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 25px;
        }}
        table th, table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #1f293d;
            text-align: left;
        }}
        table th {{
            background: #1e293b;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
        }}
        .tamper-badge {{
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 10px;
        }}
        .valid-badge {{
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 10px;
        }}
        .source-tag {{
            font-family: monospace;
            font-size: 11px;
            background: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .technique-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .technique-card {{
            background: #1e293b;
            border: 1px solid #334155;
            padding: 16px;
            border-radius: 8px;
        }}
        .tech-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }}
        .tech-id {{
            background: var(--accent-blue);
            color: #fff;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }}
        .tech-tactic {{
            color: var(--warning);
            font-size: 12px;
        }}
        .technique-card h4 {{
            font-size: 14px;
            color: #fff;
            margin-bottom: 6px;
        }}
        .technique-card p {{
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .tech-mitigation {{
            font-size: 11px;
            color: #94a3b8;
            border-top: 1px dashed #334155;
            padding-top: 6px;
        }}
        .print-btn {{
            background: var(--accent-cyan);
            color: #0b0f19;
            border: none;
            padding: 10px 22px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: opacity 0.2s;
        }}
        .print-btn:hover {{ opacity: 0.85; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-top">
            <div class="brand">
                <h1>IRON<span>LEDGER</span> FORENSIC REPORT</h1>
                <p style="color: var(--text-muted); font-size: 13px;">Industrial Control Systems Immutable Evidence & Attribution Framework</p>
                {mode_badge}
            </div>
            <div class="meta-box">
                <div>Report ID: <strong>{report_id}</strong></div>
                <div>Generated: <strong>{timestamp_str}</strong></div>
                <div>Contract Anchor: <strong>{(contract_address[:8] + '...' + contract_address[-6:]) if len(contract_address) > 14 else ('Local Simulation' if not contract_address else contract_address)}</strong></div>
                <div style="margin-top: 10px;" class="no-print">
                    <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
                </div>
            </div>
        </div>

        {mode_banner}

        {"<div class='alert-banner danger'><strong>TAMPER DETECTED:</strong> Off-chain database records deviate from the immutable SHA-256 state anchor. The forensic timeline below highlights tampered modifications.</div>" if tampered else "<div class='alert-banner success'><strong>BLOCKCHAIN INTEGRITY VERIFIED:</strong> Complete chain of custody matches cryptographic hashes with zero evidence degradation.</div>"}

        <h2>1. Executive Summary & Root Cause Attribution</h2>
        <div class="card-grid">
            <div class="info-card">
                <div class="label">Primary Threat Actor Hypothesis</div>
                <div class="value" style="color: #60a5fa;">{html_mod.escape(str(actor.get('name', 'Uncorrelated')))}</div>
                <div class="sub">Origin: {html_mod.escape(str(actor.get('origin', 'Unknown')))}</div>
            </div>
            <div class="info-card">
                <div class="label">Attribution Confidence</div>
                <div class="value" style="color: {'#10b981' if actor.get('confidence_score', 0) > 75 else '#f59e0b'};">{actor.get('confidence_score', 0)}%</div>
                <div class="sub">Correlated via MITRE ATT&CK for ICS matrix</div>
            </div>
            <div class="info-card">
                <div class="label">Root Cause Entry Point</div>
                <div class="value" style="color: #f87171;">{html_mod.escape(str(root_cause.get('source_identity', 'Unknown')))}</div>
                <div class="sub">Command: {html_mod.escape(str(root_cause.get('entry_command', 'None')))} ({html_mod.escape(str(root_cause.get('target_entity', '-')))})</div>
            </div>
        </div>
        <p style="font-size: 14px; color: #cbd5e1; margin-bottom: 24px; background: #0f172a; padding: 14px; border-left: 4px solid var(--accent-cyan); border-radius: 4px;">
            <strong>Forensic Determination:</strong> {html_mod.escape(str(root_cause.get('forensic_conclusion', 'Baseline inspection.')))}
        </p>

        <div class="alert-banner warning" style="margin-bottom: 25px;">
            <strong>⚠️ OPERATOR ATTRIBUTION LIMITATION:</strong>
            Operator identity is based on the self-reported command source identifier. Without hardware-enforced IEEE 802.1AR device certificates, cryptographic command signatures (HMAC/ECDSA), or network-layer mTLS, unauthenticated endpoints on the ICS control network can forge source headers (e.g., claiming <code>AUTHORIZED_ENG_01</code>). Identity attribution should be corroborated with switch port 802.1X logs and physical facility access records.
        </div>

        <h2>2. Cryptographically Anchored Reconstructed Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Source Entity</th>
                    <th>Command</th>
                    <th>Target</th>
                    <th>Kill-Chain Phase & Policy</th>
                    <th>Integrity Status</th>
                    <th>Anchor Hash</th>
                    <th>On-Chain Tx</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows}
            </tbody>
        </table>

        <h2>3. MITRE ATT&CK for ICS Technical Mapping</h2>
        <div class="technique-grid">
            {mitre_rows}
        </div>

        <h2>4. Physical Plant Sensor Peaks During Incident</h2>
        <div class="card-grid">
            <div class="info-card">
                <div class="label">Peak Pressure Vessel</div>
                <div class="value">{telemetry_snapshot.get('pressure_vessel', {}).get('pressure_bar', 0)} Bar</div>
                <div class="sub">Safe Max: <= 8.0 Bar</div>
            </div>
            <div class="info-card">
                <div class="label">Peak Temperature</div>
                <div class="value">{telemetry_snapshot.get('pressure_vessel', {}).get('temp_celsius', 0)} °C</div>
                <div class="sub">Safe Max: <= 85.0 °C</div>
            </div>
            <div class="info-card">
                <div class="label">Pump A RPM & Vibration</div>
                <div class="value">{telemetry_snapshot.get('pump_a', {}).get('rpm', 0):.0f} RPM</div>
                <div class="sub">Vibration: {telemetry_snapshot.get('pump_a', {}).get('vibration', 0)} mm/s</div>
            </div>
            <div class="info-card">
                <div class="label">SIS Interlock Status</div>
                <div class="value" style="color: {'#ef4444' if telemetry_snapshot.get('sis', {}).get('bypass_active') else '#10b981'};">
                    {'BYPASS ENGAGED' if telemetry_snapshot.get('sis', {}).get('bypass_active') else 'ARMED'}
                </div>
                <div class="sub">Trip Status: {'TRIPPED' if telemetry_snapshot.get('sis', {}).get('tripped') else 'NOMINAL'}</div>
            </div>
        </div>

        <h2>5. Digital Forensics Certification & Chain of Custody Sign-Off</h2>
        <div class="info-card" style="margin-bottom: 25px;">
            <div class="label">FRE 902(13) & 902(14) Authentication Support Statement</div>
            <p style="font-size: 13px; color: var(--text-main); margin: 10px 0;">
                This document is designed to assist forensic investigators with Federal Rules of Evidence (FRE) 902(13) & 902(14) digital records authentication requirements. Cryptographic hash chains, smart contract verification logs, and telemetry snapshots provide verifiable evidence of data integrity. Final legal certification requires a qualified forensic analyst's review and sign-off.
            </p>
            <div style="display: flex; justify-content: space-between; margin-top: 20px; padding-top: 15px; border-top: 1px dashed #334155; font-size: 12px; color: var(--text-muted);">
                <div><strong>Certified By:</strong> ___________________________</div>
                <div><strong>Title / Organization:</strong> ___________________________</div>
                <div><strong>Date:</strong> _______________</div>
            </div>
        </div>

        <div class="footer">
            <div>Framework: <strong>IronLedger Digital Forensics</strong></div>
            <div>Investigating Officers: <strong>Simran & Garima</strong> | IronLedger Core</div>
        </div>
    </div>
</body>
</html>
        """
        return html_content
