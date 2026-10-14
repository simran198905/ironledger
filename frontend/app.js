/**
 * IronLedger - Industrial Cyber Defense Command Center Logic
 * Handles real-time SCADA telemetry, SVG animations, attack triggers,
 * blockchain evidence streaming, tamper detection, and forensic reconstruction.
 */

let state = {
    pollingInterval: null,
    lastSnapshot: null,
    isTamperedDemo: false,
    walletConnected: false,
    activeScenario: null
};

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    startTelemetryPolling();
    fetchBlockchainBlocks();
    checkDbStatus();
    loadCases();
    loadMitreMatrix();
});

// Telemetry Polling Loop
function startTelemetryPolling() {
    updateDashboard();
    state.pollingInterval = setInterval(updateDashboard, 1200);
}

async function updateDashboard() {
    try {
        const res = await fetch("/api/telemetry");
        if (!res.ok) return;
        const data = await res.json();
        state.lastSnapshot = data;

        renderSCADASchematic(data.telemetry);
        renderInstrumentGauges(data.telemetry);
        renderAnomalyEngine(data.anomaly);
        renderRecentBlocks(data.recent_blocks);
        updateDbStatusBadge(data.db_connected);
        if (window.IronWallet) window.IronWallet.onTelemetry(data);
    } catch (err) {
        console.warn("Telemetry polling error:", err);
    }
}

// 1. Render SCADA Synoptic SVG
function renderSCADASchematic(telemetry) {
    if (!telemetry) return;
    const { pump_a, valve_inlet, valve_vent, pressure_vessel, sis } = telemetry;

    // Pump A Dynamics & Impeller
    const impeller = document.getElementById("pump-impeller");
    const rpmText = document.getElementById("svg-pump-rpm-txt");
    if (rpmText) rpmText.textContent = `${Math.round(pump_a.rpm)} RPM`;

    if (impeller) {
        if (pump_a.state === "RUNNING" && pump_a.rpm > 100) {
            const duration = Math.max(0.2, 1.6 - (pump_a.rpm / 3600));
            impeller.style.animation = `spinImpeller ${duration}s linear infinite`;
        } else {
            impeller.style.animation = "none";
        }
    }

    // Pipes Flow Animations
    const flowInlet = document.getElementById("flow-inlet");
    const flowMid = document.getElementById("flow-mid");
    const flowVent = document.getElementById("flow-vent");
    const flowOutlet = document.getElementById("flow-outlet");

    const isFlowing = pump_a.state === "RUNNING" && pump_a.rpm > 200;
    [flowInlet, flowMid, flowOutlet].forEach(pipe => {
        if (pipe) pipe.style.display = isFlowing ? "block" : "none";
    });

    if (flowVent) {
        flowVent.style.display = (valve_vent.open_percent > 2.0 && pressure_vessel.pressure_bar > 2.0) ? "block" : "none";
    }

    // Vessel Readings & Fluid
    const txtPressure = document.getElementById("svg-vessel-pressure");
    const txtTemp = document.getElementById("svg-vessel-temp");
    const vesselBorder = document.getElementById("vessel-border");
    const vesselFluid = document.getElementById("vessel-fluid");

    if (txtPressure) txtPressure.textContent = `${pressure_vessel.pressure_bar.toFixed(1)} Bar`;
    if (txtTemp) txtTemp.textContent = `${pressure_vessel.temp_celsius.toFixed(1)} °C`;

    // Visual Stress Alert on Vessel
    if (vesselBorder && vesselFluid) {
        if (pressure_vessel.pressure_bar >= 9.5 || pressure_vessel.temp_celsius >= 95.0) {
            vesselBorder.setAttribute("stroke", "#ef4444");
            vesselBorder.setAttribute("stroke-width", "3.5");
            vesselFluid.setAttribute("fill", "rgba(239, 68, 68, 0.4)");
        } else if (pressure_vessel.pressure_bar >= 8.0 || pressure_vessel.temp_celsius >= 85.0) {
            vesselBorder.setAttribute("stroke", "#f59e0b");
            vesselBorder.setAttribute("stroke-width", "2.5");
            vesselFluid.setAttribute("fill", "rgba(245, 158, 11, 0.3)");
        } else {
            vesselBorder.setAttribute("stroke", "#38bdf8");
            vesselBorder.setAttribute("stroke-width", "2.5");
            vesselFluid.setAttribute("fill", "rgba(6, 182, 212, 0.25)");
        }
    }

    // Vent Valve Position
    const ventLabel = document.getElementById("svg-vent-label");
    const ventCirc = document.getElementById("vent-circ");
    const ventPolyL = document.getElementById("vent-poly-l");
    const ventPolyR = document.getElementById("vent-poly-r");
    if (ventLabel) ventLabel.textContent = `VENT-02 (${Math.round(valve_vent.open_percent)}%)`;

    const ventColor = valve_vent.open_percent < 5.0 ? "#ef4444" : "#10b981";
    if (ventCirc) ventCirc.setAttribute("fill", ventColor);
    if (ventPolyL) ventPolyL.setAttribute("fill", ventColor);
    if (ventPolyR) ventPolyR.setAttribute("fill", ventColor);

    // SIS Interlock
    const sisLed = document.getElementById("sis-led");
    const sisTitle = document.getElementById("sis-title");
    const sisBorder = document.getElementById("sis-border");
    if (sis.bypass_active) {
        if (sisLed) sisLed.setAttribute("fill", "#ef4444");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (BYPASS ENGAGED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#ef4444");
    } else if (sis.tripped) {
        if (sisLed) sisLed.setAttribute("fill", "#f59e0b");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (TRIPPED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#f59e0b");
    } else {
        if (sisLed) sisLed.setAttribute("fill", "#10b981");
        if (sisTitle) sisTitle.textContent = "SIS INTERLOCK (ARMED)";
        if (sisBorder) sisBorder.setAttribute("stroke", "#334155");
    }

    // Top Status Badge
    const plantBadge = document.getElementById("plant-status-badge");
    if (plantBadge) {
        if (telemetry.active_attack) {
            plantBadge.className = "status-badge alarm";
            plantBadge.textContent = `UNDER ATTACK: ${telemetry.active_attack.toUpperCase()}`;
        } else if (sis.bypass_active || pressure_vessel.pressure_bar > 8.0) {
            plantBadge.className = "status-badge alarm";
            plantBadge.textContent = "SAFETY THRESHOLD BREACH";
        } else {
            plantBadge.className = "status-badge nominal";
            plantBadge.textContent = "NOMINAL OPERATION";
        }
    }
}

// 2. Render Digital Gauges
function renderInstrumentGauges(telemetry) {
    if (!telemetry) return;
    const { pump_a, pressure_vessel } = telemetry;

    // Pressure
    const pVal = pressure_vessel.pressure_bar;
    document.getElementById("val-pressure").textContent = pVal.toFixed(2);
    const pPct = Math.min(100, (pVal / 12.0) * 100);
    const barP = document.getElementById("bar-pressure");
    const cardP = document.getElementById("card-pressure");
    barP.style.width = `${pPct}%`;
    cardP.className = "metric-card" + (pVal >= 9.5 ? " critical" : pVal >= 8.0 ? " warning" : "");

    // Temperature
    const tVal = pressure_vessel.temp_celsius;
    document.getElementById("val-temp").textContent = tVal.toFixed(1);
    const tPct = Math.min(100, ((tVal - 20.0) / 100.0) * 100);
    const barT = document.getElementById("bar-temp");
    const cardT = document.getElementById("card-temp");
    barT.style.width = `${tPct}%`;
    cardT.className = "metric-card" + (tVal >= 95.0 ? " critical" : tVal >= 85.0 ? " warning" : "");

    // RPM
    const rVal = pump_a.rpm;
    document.getElementById("val-rpm").textContent = Math.round(rVal);
    const rPct = Math.min(100, (rVal / 3600.0) * 100);
    const barR = document.getElementById("bar-rpm");
    const cardR = document.getElementById("card-rpm");
    barR.style.width = `${rPct}%`;
    cardR.className = "metric-card" + (rVal >= 3400.0 ? " critical" : rVal >= 3000.0 ? " warning" : "");

    // Vibration
    const vVal = pump_a.vibration;
    document.getElementById("val-vibration").textContent = vVal.toFixed(2);
    const vPct = Math.min(100, (vVal / 8.0) * 100);
    const barV = document.getElementById("bar-vibration");
    const cardV = document.getElementById("card-vibration");
    barV.style.width = `${vPct}%`;
    cardV.className = "metric-card" + (vVal >= 5.5 ? " critical" : vVal >= 3.0 ? " warning" : "");
}

// 3. Render Anomaly Engine
function renderAnomalyEngine(anomaly) {
    if (!anomaly) return;

    // Badge
    const badge = document.getElementById("anomaly-badge");
    if (anomaly.is_anomaly) {
        badge.className = "badge-pill alarm";
        badge.textContent = `ALERT (${anomaly.severity})`;
    } else {
        badge.className = "badge-pill normal";
        badge.textContent = "PASS";
    }

    // ML Score
    const mlScore = anomaly.ml_anomaly_score;
    const mlScoreText = document.getElementById("ml-score-text");
    const mlBar = document.getElementById("ml-bar-indicator");
    
    let statusLabel = mlScore >= 0.65 ? "(Drift Anomaly!)" : mlScore >= 0.45 ? "(Elevated)" : "(Normal)";
    mlScoreText.textContent = `${mlScore.toFixed(2)} ${statusLabel}`;
    mlScoreText.style.color = mlScore >= 0.65 ? "#ef4444" : mlScore >= 0.45 ? "#f59e0b" : "#38bdf8";
    mlBar.style.width = `${Math.min(100, mlScore * 100)}%`;

    // Rule Violations Box
    const box = document.getElementById("violations-box");
    if (anomaly.rule_violations && anomaly.rule_violations.length > 0) {
        box.innerHTML = anomaly.rule_violations.map(v => `<div class="violation-item">${esc(v)}</div>`).join("");
    } else {
        box.innerHTML = `<div class="empty-state">No physics threshold violations detected. Process envelope is secure.</div>`;
    }
}

// 4. Render Recent Blockchain Blocks
function renderRecentBlocks(blocks) {
    if (!blocks) return;
    const tbody = document.getElementById("blocks-tbody");
    if (!tbody) return;

    tbody.innerHTML = blocks.map(b => {
        // For confirmed on-chain blocks: show the Ethereum tx_hash so it matches Etherscan.
        // For simulated/local blocks: show the IronLedger event_hash (SHA-256 payload digest).
        const hasTx = !!b.tx_hash;
        const displayHash = hasTx ? b.tx_hash : b.event_hash;
        const hashDisplay = displayHash
            ? `${displayHash.slice(0, 10)}...${displayHash.slice(-6)}`
            : "N/A";

        // Full hover tooltip shows both values for transparency
        const tooltipFull = hasTx
            ? `Tx: ${b.tx_hash || ""}\nSHA-256: ${b.event_hash || ""}`
            : (b.event_hash || "");

        const dateStr = new Date(b.timestamp * 1000).toLocaleTimeString();
        const onChain = b.status === "CONFIRMED_ON_CHAIN" || hasTx;
        const isGenesis = b.block_index === 0;
        const chipText = isGenesis ? "GENESIS" : (onChain ? "ON-CHAIN ✓" : "ANCHORED (local)");
        const hashEl = b.etherscan_url
            ? `<a href="${esc(b.etherscan_url)}" target="_blank" rel="noopener" class="hash-link" title="${esc(tooltipFull)}">${esc(hashDisplay)}</a>`
            : `<span class="hash-link" title="${esc(tooltipFull)}">${esc(hashDisplay)}</span>`;

        return `
        <tr id="block-row-${b.block_index}">
            <td class="block-tag">${b.block_number != null ? '#' + b.block_number : 'SIM'}</td>
            <td><strong>#${b.event_id}</strong></td>
            <td>${dateStr}</td>
            <td><code>${esc(b.command_type || "")}</code></td>
            <td><span style="color:#94a3b8">${esc(b.source || "")}</span></td>
            <td>${hashEl}</td>
            <td><span class="status-chip anchored">${chipText}</span></td>
        </tr>
        `;
    }).join("");
}

async function fetchBlockchainBlocks() {
    try {
        const res = await fetch("/api/telemetry");
        const data = await res.json();
        renderRecentBlocks(data.recent_blocks);
    } catch (e) {}
}

// 5. Attack Scenario Triggers
async function triggerAttack(scenario) {
    state.activeScenario = scenario;
    try {
        const res = await fetch("/api/attack/inject", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ scenario })
        });
        const data = await res.json();
        console.log("Attack injected:", data);
        updateDashboard();
    } catch (err) {
        console.error("Failed to inject attack:", err);
    }
}

async function resetToNominal() {
    try {
        await fetch("/api/attack/stop", { 
            method: "POST"
        });
        const banner = document.getElementById("tamper-banner");
        if (banner) banner.classList.add("hidden");
        updateDashboard();
    } catch (err) {
        console.error("Failed to reset:", err);
    }
}

// 6. Tamper Simulation & Blockchain Verification
async function simulateDatabaseTamper() {
    try {
        // Pick an event from database to tamper with
        const res = await fetch("/api/tamper/simulate", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                event_id: 1,
                malicious_field: "command_type",
                tampered_value: "BENIGN_MAINTENANCE_PING"
            })
        });
        const data = await res.json();
        
        const banner = document.getElementById("tamper-banner");
        banner.className = "tamper-banner";
        banner.innerHTML = `
            <div>
                <strong>SIMULATED OFF-CHAIN LOG TAMPER:</strong> Event #${data.event_id} command_type altered to <code>${data.tampered_value}</code> in off-chain DB!
            </div>
            <button class="audit-btn" onclick="runIntegrityAudit()">Audit Against Blockchain</button>
        `;
        banner.classList.remove("hidden");
    } catch (err) {
        console.error("Tamper simulation failed:", err);
    }
}

async function runIntegrityAudit() {
    try {
        const res = await fetch("/api/tamper/audit");
        const audit = await res.json();
        const banner = document.getElementById("tamper-banner");

        if (!audit.integrity_healthy) {
            const tamperedBlock = audit.audit_details.find(d => d.tampered);
            banner.className = "tamper-banner";
            banner.innerHTML = `
                <div>
                    <strong>CRITICAL TAMPER DETECTED:</strong> On-chain hash <code>${tamperedBlock.immutable_onchain_hash.slice(0, 16)}...</code> does NOT match computed DB hash <code>${tamperedBlock.computed_db_hash.slice(0, 16)}...</code>! Tampering exposed by IronLedger!
                </div>
            `;
            banner.classList.remove("hidden");

            // Highlight the row in the table
            const row = document.getElementById(`block-row-${tamperedBlock.block_index}`);
            if (row) {
                row.style.background = "rgba(239, 68, 68, 0.25)";
                row.querySelector(".status-chip").className = "status-chip tampered";
                row.querySelector(".status-chip").textContent = "TAMPER DETECTED";
            }
        } else {
            banner.className = "tamper-banner";
            banner.style.borderColor = "var(--accent-emerald)";
            banner.style.color = "#34d399";
            banner.innerHTML = `<div><strong>ALL BLOCKS VERIFIED:</strong> 100% cryptographic match between off-chain database and Ethereum Sepolia anchors.</div>`;
            banner.classList.remove("hidden");
        }
    } catch (err) {
        console.error("Audit error:", err);
    }
}

// 6.5 Sync Local Chain with Sepolia Smart Contract
async function syncWithContract() {
    const btn = document.getElementById("sync-contract-btn");
    const banner = document.getElementById("tamper-banner");
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Syncing…`;
    }

    try {
        const res = await fetch("/api/chain/sync-onchain", { method: "POST" });
        const data = await res.json();

        if (banner) {
            banner.className = "tamper-banner";
            if (data.status === "SYNCED") {
                banner.style.borderColor = "#38bdf8";
                banner.style.color = "#38bdf8";
                banner.style.background = "rgba(56, 189, 248, 0.15)";
                banner.innerHTML = `<div><strong>ON-CHAIN SYNC COMPLETE:</strong> Local chain synchronized with Sepolia contract. Restored <strong>${data.synced_blocks}</strong> block(s). Latest hash: <code>${(data.latest_hash || "").slice(0, 18)}…</code></div>`;
            } else {
                banner.style.borderColor = "#f59e0b";
                banner.style.color = "#f59e0b";
                banner.style.background = "rgba(245, 158, 11, 0.15)";
                banner.innerHTML = `<div><strong>SYNC NOTICE:</strong> ${esc(data.message || data.error || "Could not sync with contract.")}</div>`;
            }
            banner.classList.remove("hidden");
        }

        // Refresh blocks table and telemetry view
        if (typeof fetchBlockchainBlocks === "function") fetchBlockchainBlocks();
        if (typeof pollTelemetry === "function") pollTelemetry();
    } catch (err) {
        console.error("Sync error:", err);
        if (banner) {
            banner.className = "tamper-banner";
            banner.style.borderColor = "var(--accent-crimson)";
            banner.style.color = "#fca5a5";
            banner.style.background = "rgba(239, 68, 68, 0.2)";
            banner.innerHTML = `<div><strong>SYNC FAILED:</strong> ${esc(String(err))}</div>`;
            banner.classList.remove("hidden");
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = origHtml;
        }
    }
}

// 7. Forensic Reconstruction & MITRE ATT&CK Attribution
async function runForensicReconstruction() {
    try {
        const [reconRes, intelRes] = await Promise.all([
            fetch("/api/forensics/reconstruct"),
            fetch("/api/threat-intel/correlate")
        ]);

        const recon = await reconRes.json();
        const intel = await intelRes.json();

        // Render Threat Actor Attribution Card
        const hypothesis = intel.primary_hypothesis;
        if (hypothesis) {
            document.getElementById("attr-actor-name").textContent = hypothesis.name;
            document.getElementById("attr-actor-origin").textContent = `Origin: ${hypothesis.origin} | Sector Targets: ${hypothesis.target_sectors.join(", ")}`;
            document.getElementById("attr-score-badge").textContent = `${hypothesis.confidence_score}% Match`;
            document.getElementById("attr-summary").textContent = intel.correlation_summary;
        }

        // Render Reconstructed Timeline Steps
        const container = document.getElementById("timeline-steps");
        if (recon.timeline && recon.timeline.length > 0) {
            container.innerHTML = recon.timeline.map((step, idx) => {
                const isRoot = (recon.root_cause_artifact && step.event_id === recon.root_cause_artifact.event_id);
                const isTampered = step.tampered;
                let cardClass = "step-card" + (isRoot ? " root-cause" : "") + (isTampered ? " tampered" : "");
                const claimedHtml = (isTampered && step.claimed_source)
                    ? `<br><small style="color: #f87171; font-weight: normal;">[Historian Forged: claimed ${esc(step.claimed_source)} &rarr; ${esc(step.claimed_command)}]</small>`
                    : '';

                return `
                <div class="${cardClass}">
                    <div class="step-left">
                        <span class="step-phase">${isRoot ? "🚨 [ROOT CAUSE ENTRY] " : ""}${esc(step.kill_chain_phase)}</span>
                        <span class="step-cmd">${esc(step.source)} &rarr; ${esc(step.command_type)} (${esc(step.entity_id)})${claimedHtml}</span>
                    </div>
                    <div class="step-right">
                        <div>${esc(step.formatted_time)}</div>
                        <div style="font-family: monospace; color: var(--accent-cyan);">${step.onchain_hash ? step.onchain_hash.slice(0, 12) + '...' : ''}</div>
                    </div>
                </div>
                `;
            }).join("");
        }
    } catch (err) {
        console.error("Forensic reconstruction failed:", err);
    }
}

// 8. 3-Act Demo Controller
async function runDemoAct(actNumber) {
    if (actNumber === 1) {
        // Normal Baseline
        await resetToNominal();
        alert("Act 1: SCADA Plant operating in nominal baseline envelope. Commands are anchored to Sepolia ledger.");
    } else if (actNumber === 2) {
        // Triton Attack
        await triggerAttack("triton");
        setTimeout(async () => {
            await updateDashboard();
        }, 800);
    } else if (actNumber === 3) {
        // Tamper Simulation
        await simulateDatabaseTamper();
        setTimeout(async () => {
            await runIntegrityAudit();
        }, 500);
    }
}

// 9. Modal Report Handler
function openReportModal() {
    const modal = document.getElementById("report-modal");
    const iframe = document.getElementById("report-iframe");
    iframe.src = "/api/report/html";
    modal.classList.remove("hidden");
}

function closeReportModal() {
    document.getElementById("report-modal").classList.add("hidden");
}

function openReportInNewTab() {
    window.open("/api/report/html", "_blank");
}

function toggleMetaMask() {
    if (window.IronWallet) {
        window.IronWallet.toggle();
    } else {
        alert("Wallet module failed to load — reload the page.");
    }
}

// ── Supabase DB Status ────────────────────────────────────────────────────────

async function checkDbStatus() {
    const badge  = document.getElementById("db-status-badge");
    const text   = document.getElementById("db-status-text");
    if (!badge) return;
    badge.className = "db-status-badge checking";
    text.textContent = "DB: Connecting…";
    try {
        const res  = await fetch("/api/db/status");
        const data = await res.json();
        updateDbStatusBadge(data.connected);
    } catch {
        badge.className = "db-status-badge offline";
        text.textContent = "DB: Unreachable";
    }
}

function updateDbStatusBadge(connected) {
    const badge   = document.getElementById("db-status-badge");
    const text    = document.getElementById("db-status-text");
    const indic   = document.getElementById("cases-db-indicator");
    const hint    = document.getElementById("cases-db-hint");
    if (!badge) return;
    if (connected) {
        badge.className = "db-status-badge online";
        text.textContent = "Supabase: Connected";
        if (indic) { indic.textContent = "🟢 Supabase Online"; indic.className = "cases-db-indicator online"; }
        if (hint) hint.textContent = "";
    } else {
        badge.className = "db-status-badge offline";
        text.textContent = "DB: Offline (memory mode)";
        if (indic) { indic.textContent = "⚪ DB Offline"; indic.className = "cases-db-indicator"; }
        if (hint) hint.innerHTML = `<span style="color:#f59e0b">ℹ️ To enable persistence: copy <code>.env.example</code> → <code>.env</code> and add your Supabase URL + key, then restart the server.</span>`;
    }
}

// ── Forensic Cases List ───────────────────────────────────────────────────────

async function loadCases() {
    const grid  = document.getElementById("cases-grid");
    const empty = document.getElementById("cases-empty");
    if (!grid) return;
    try {
        const res  = await fetch("/api/cases");
        const data = await res.json();
        // Update DB indicator from cases response
        updateDbStatusBadge(data.db_connected);

        // Remove old case cards (keep empty state)
        Array.from(grid.querySelectorAll(".case-card")).forEach(el => el.remove());

        if (!data.cases || data.cases.length === 0) {
            if (empty) empty.style.display = "flex";
            return;
        }
        if (empty) empty.style.display = "none";

        data.cases.forEach(c => {
            const card = buildCaseCard(c);
            grid.appendChild(card);
        });
    } catch (err) {
        console.warn("loadCases error:", err);
    }
}

function buildCaseCard(c) {
    const card = document.createElement("div");
    card.className = "case-card" + (c.tamper_detected ? " tampered" : "");
    card.onclick   = () => openCaseDetail(c.id);

    const ts = c.created_at ? new Date(c.created_at).toLocaleString() : "--";
    const mitreTags = parseMitreTags(c.mitre_techniques);
    const mitreHtml = mitreTags.slice(0,3).map(t => `<span class="case-mitre-tag">${esc(t)}</span>`).join("");

    card.innerHTML = `
        <div class="case-card-top">
            <div class="case-card-name">${esc(c.case_name || "Untitled Case")}</div>
            <div class="case-card-scenario">${esc(c.attack_scenario || "—")}</div>
        </div>
        <div class="case-card-meta">
            <span class="case-card-meta-item">🕐 ${esc(ts)}</span>
            <span class="case-card-meta-item">📊 <strong>${c.events_analyzed || 0}</strong> events</span>
        </div>
        <div class="case-card-attribution">🎯 ${esc(c.attribution_actor || "Unknown")}</div>
        <div class="case-card-conclusion">${esc(c.forensic_conclusion || "No conclusion recorded.")}</div>
        ${c.tamper_detected ? `<div class="case-tamper-flag">⚠️ TAMPER DETECTED</div>` : ""}
        ${mitreHtml ? `<div class="case-mitre-tags" style="margin-top:10px">${mitreHtml}</div>` : ""}
        <div class="case-card-confidence">${Math.round(c.confidence_score || 0)}%</div>
    `;
    return card;
}

function parseMitreTags(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw.map(t => t.technique_id || t.id || t.name || String(t));
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.map(t => t.technique_id || t.id || t.name || String(t)) : [];
    } catch { return []; }
}

// ── Save Case Modal ───────────────────────────────────────────────────────────

function openSaveCaseModal() {
    document.getElementById("case-name-input").value = "";
    const res = document.getElementById("save-case-result");
    res.className = "save-case-result hidden";
    res.textContent = "";
    const btn = document.getElementById("btn-confirm-save");
    btn.disabled = false;
    document.getElementById("save-case-modal").classList.remove("hidden");
    setTimeout(() => document.getElementById("case-name-input").focus(), 80);
}

function closeSaveCaseModal() {
    document.getElementById("save-case-modal").classList.add("hidden");
}

async function confirmSaveCase() {
    const btn      = document.getElementById("btn-confirm-save");
    const inputEl  = document.getElementById("case-name-input");
    const result   = document.getElementById("save-case-result");
    btn.disabled = true;
    btn.textContent = "Saving…";
    result.className = "save-case-result hidden";

    try {
        const res = await fetch("/api/cases/save", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ case_name: inputEl.value.trim() || null })
        });
        const data = await res.json();

        result.className = "save-case-result " + (data.status === "CASE_SAVED" ? "success" : "error");
        if (data.status === "CASE_SAVED") {
            const cn = data.case?.case_name || "Case";
            result.textContent = `✅ Case "${cn}" saved to Supabase! Refreshing case list…`;
            setTimeout(() => { closeSaveCaseModal(); loadCases(); }, 1500);
        } else {
            result.innerHTML = `⚠️ ${esc(data.note || "Case not persisted — Supabase may be offline.")}
<br><br>Reconstruction summary:<br>
• Events analyzed: ${esc(String(data.reconstruction_summary?.events_analyzed ?? "—"))}<br>
• Tamper detected: ${esc(String(data.reconstruction_summary?.tamper_detected ?? "—"))}<br>
• Root cause: ${esc(data.reconstruction_summary?.root_cause?.source_identity ?? "—")}`;
        }
    } catch (err) {
        result.className = "save-case-result error";
        result.textContent = `❌ Save failed: ${err.message}`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Save to Supabase`;
    }
}

// ── Case Detail Modal ─────────────────────────────────────────────────────────

async function openCaseDetail(caseId) {
    document.getElementById("case-detail-title").textContent = "Loading…";
    document.getElementById("case-detail-body").innerHTML = `<div style="padding:40px;text-align:center;color:#64748b">Loading case data…</div>`;
    document.getElementById("case-detail-modal").classList.remove("hidden");

    try {
        const res  = await fetch(`/api/cases/${caseId}`);
        if (!res.ok) throw new Error("Not found");
        const c    = await res.json();
        renderCaseDetail(c);
    } catch (err) {
        document.getElementById("case-detail-body").innerHTML =
            `<div style="padding:40px;text-align:center;color:#ef4444">Failed to load case: ${err.message}</div>`;
    }
}

function closeCaseDetailModal() {
    document.getElementById("case-detail-modal").classList.add("hidden");
}

function renderCaseDetail(c) {
    document.getElementById("case-detail-title").textContent = c.case_name || "Case Detail";
    const body   = document.getElementById("case-detail-body");
    const ts     = c.created_at ? new Date(c.created_at).toLocaleString() : "--";
    const mitreTags = parseMitreTags(c.mitre_techniques);
    const timeline  = Array.isArray(c.timeline) ? c.timeline :
                      (typeof c.timeline === "string" ? JSON.parse(c.timeline || "[]") : []);
    const intel     = (typeof c.threat_intel === "object" ? c.threat_intel :
                      JSON.parse(c.threat_intel || "{}"));

    body.innerHTML = `
        <!-- Overview -->
        <div class="case-detail-section">
            <div class="case-detail-section-title">📋 Case Overview</div>
            <div class="case-detail-kv">
                <span class="case-detail-key">Case ID</span>
                <span class="case-detail-val">#${c.id}</span>
                <span class="case-detail-key">Scenario</span>
                <span class="case-detail-val">${esc(c.attack_scenario || "—")}</span>
                <span class="case-detail-key">Saved At</span>
                <span class="case-detail-val">${esc(ts)}</span>
                <span class="case-detail-key">Events Analyzed</span>
                <span class="case-detail-val">${c.events_analyzed ?? "—"}</span>
                <span class="case-detail-key">Tamper Detected</span>
                <span class="case-detail-val" style="color:${c.tamper_detected ? '#ef4444' : '#10b981'}">
                    ${c.tamper_detected ? `⚠️ YES — ${c.tampered_records} tampered record(s)` : '✅ NO — All blocks verified'}
                </span>
            </div>
        </div>

        <!-- Attribution -->
        <div class="case-detail-section">
            <div class="case-detail-section-title">🎯 Attribution & MITRE ATT&CK</div>
            <div class="case-detail-kv">
                <span class="case-detail-key">Attributed Actor</span>
                <span class="case-detail-val" style="color:#f59e0b;font-weight:700">${esc(c.attribution_actor || "Unknown")}</span>
                <span class="case-detail-key">Confidence</span>
                <span class="case-detail-val">${Math.round(c.confidence_score || 0)}%</span>
                <span class="case-detail-key">MITRE Techniques</span>
                <span class="case-detail-val">
                    <div class="case-mitre-tags">
                        ${mitreTags.map(t => `<span class="case-mitre-tag">${esc(String(t))}</span>`).join("") || "—"}
                    </div>
                </span>
            </div>
        </div>

        <!-- Root Cause -->
        <div class="case-detail-section">
            <div class="case-detail-section-title">🔍 Root Cause Artifact</div>
            <div class="case-detail-kv">
                <span class="case-detail-key">Source Identity</span>
                <span class="case-detail-val" style="color:#ef4444">${esc(c.root_cause_source || "—")}</span>
                <span class="case-detail-key">Entry Command</span>
                <span class="case-detail-val">${esc(c.root_cause_command || "—")}</span>
                <span class="case-detail-key">Target Entity</span>
                <span class="case-detail-val">${esc(c.root_cause_entity || "—")}</span>
                <span class="case-detail-key">Forensic Conclusion</span>
                <span class="case-detail-val" style="line-height:1.6">${esc(c.forensic_conclusion || "—")}</span>
            </div>
        </div>

        <!-- Timeline -->
        <div class="case-detail-section">
            <div class="case-detail-section-title">📅 Reconstructed Event Timeline (${timeline.length} steps)</div>
            ${timeline.length === 0 ? `<div style="color:#64748b;font-size:12px">No timeline data recorded.</div>` : 
                timeline.map((step, i) => {
                    const isMalicious = (step.kill_chain_phase || "").toLowerCase().includes("malicious") ||
                                        (step.kill_chain_phase || "").toLowerCase().includes("neutraliz");
                    return `
                    <div class="case-timeline-step">
                        <div class="step-num ${step.tampered ? 'tampered' : ''}">${step.step_order ?? i+1}</div>
                        <div class="step-info">
                            <div class="step-cmd">${esc(step.command_type || "—")} → ${esc(step.entity_id || "—")}</div>
                            <div class="step-meta">${esc(step.formatted_time || "")} &nbsp;|&nbsp; Source: ${esc(step.source || "—")}</div>
                            <div class="step-phase ${isMalicious ? 'malicious' : ''}">${esc(step.kill_chain_phase || "—")}</div>
                            ${step.tampered ? `<div style="font-size:10px;color:#ef4444;margin-top:4px">⚠️ ${esc(step.tamper_note || 'TAMPER DETECTED')}</div>` : ""}
                        </div>
                    </div>`;
                }).join("")
            }
        </div>
    `;
}

// ── Utility ───────────────────────────────────────────────────────────────────
function esc(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ── MITRE ATT&CK Matrix Logic ──────────────────────────────────────────────────
function switchMitreTab(tabId) {
    document.querySelectorAll('.mitre-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.mitre-tab-content').forEach(c => c.classList.add('hidden'));
    
    document.getElementById(`tab-${tabId}`).classList.add('active');
    document.getElementById(`mitre-tab-${tabId}`).classList.remove('hidden');
}

async function loadMitreMatrix() {
    try {
        const res = await fetch("/api/threat-intel/matrix");
        if (!res.ok) throw new Error("Failed to load MITRE matrix");
        const data = await res.json();
        
        renderMitreMatrix(data);
        renderAttributionRanking(data.attribution_ranking);
        renderTechniqueDetails(data.matrix, data.active_technique_ids);
    } catch (err) {
        console.error("MITRE Matrix error:", err);
    }
}

function renderMitreMatrix(data) {
    const grid = document.getElementById("mitre-matrix-grid");
    if (!data.matrix || data.tactics.length === 0) {
        grid.innerHTML = '<div class="mitre-loading">Matrix data unavailable.</div>';
        return;
    }
    
    let html = '';
    data.tactics.forEach(tactic => {
        const techniques = data.matrix[tactic] || [];
        html += `<div class="mitre-tactic-col">`;
        html += `<div class="mitre-tactic-header" title="${esc(tactic)}">${esc(tactic)}</div>`;
        
        techniques.forEach(tech => {
            const activeClass = tech.active ? 'active' : '';
            html += `
            <div class="mitre-technique-cell ${activeClass}">
                <span class="technique-cell-id">${esc(tech.id)}</span>
                ${esc(tech.name)}
                <div class="cell-tooltip">
                    <div class="cell-tooltip-id">${esc(tech.id)}</div>
                    <div class="cell-tooltip-name">${esc(tech.name)}</div>
                    <div class="cell-tooltip-desc">${esc(tech.description)}</div>
                    <div class="cell-tooltip-mit">Mitigation: ${esc(tech.mitigation)}</div>
                </div>
            </div>`;
        });
        html += `</div>`;
    });
    grid.innerHTML = html;
}

function renderAttributionRanking(ranking) {
    const list = document.getElementById("attribution-ranking-list");
    if (!ranking || ranking.length === 0) {
        list.innerHTML = '<div class="mitre-loading">No attribution data generated yet. Run an attack scenario.</div>';
        return;
    }
    
    list.innerHTML = ranking.map((actor, idx) => {
        const isTop = idx === 0;
        return `
        <div class="actor-rank-card ${isTop ? 'top-actor' : ''}">
            <div class="actor-rank-num">#${idx + 1}</div>
            <div>
                <div class="actor-rank-name">${esc(actor.name)}</div>
                <div class="actor-rank-origin">${esc(actor.origin)} &bull; Targets: ${esc(actor.target_sectors.join(", "))}</div>
                <div class="actor-rank-techniques">Matches: ${esc(actor.matched_signature_techniques.join(", ") || "None")}</div>
            </div>
            <div class="actor-rank-score">
                ${actor.confidence_score}%
                <div class="score-bar-wrap">
                    <div class="score-bar-fill" style="width: ${actor.confidence_score}%; background: ${isTop ? '#ef4444' : '#38bdf8'}"></div>
                </div>
            </div>
        </div>
        `;
    }).join("");
}

function renderTechniqueDetails(matrix, activeIds) {
    const list = document.getElementById("techniques-detail-list");
    let allTechs = [];
    Object.keys(matrix).forEach(tactic => {
        matrix[tactic].forEach(tech => {
            allTechs.push({...tech, tactic});
        });
    });
    
    // Sort active ones first
    allTechs.sort((a, b) => (b.active ? 1 : 0) - (a.active ? 1 : 0));
    
    if (allTechs.length === 0) {
        list.innerHTML = '<div class="mitre-loading">No techniques available.</div>';
        return;
    }
    
    list.innerHTML = allTechs.map(tech => `
        <div class="technique-detail-card ${tech.active ? 'active' : ''}">
            <div class="tech-detail-id">${esc(tech.id)}</div>
            <div class="tech-detail-name">${esc(tech.name)}</div>
            <div class="tech-detail-tactic">Tactic: ${esc(tech.tactic)}</div>
            <div class="tech-detail-desc">${esc(tech.description)}</div>
            <div class="tech-detail-mit">🛡️ ${esc(tech.mitigation)}</div>
        </div>
    `).join("");
}
