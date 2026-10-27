# 🛡️ IronLedger — Blockchain-Anchored ICS Digital Forensics & Attribution Framework

IronLedger addresses a critical vulnerability in Industrial Control Systems (ICS / SCADA): when an adversary breaches an operational technology (OT) network, they can tamper with, forge, or purge local historian database records to conceal root causes and blind forensic investigators (anti-forensics).

IronLedger establishes an immutable, cryptographic chain of custody for all sensor telemetry states, setpoint modifications, and control messages. When anomalous behavior is detected by the dual-layer detection engine (Physics Safety Envelopes + Unsupervised Isolation Forest), IronLedger traverses the cryptographic ledger backwards, reconstructs the authentic timeline, exposes database tampering, and correlates observed behaviors with the MITRE ATT&CK for ICS matrix for objective attribution.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- (Optional) An Ethereum Sepolia testnet RPC endpoint (e.g. Alchemy/Infura) and private key for live on-chain anchoring.

### Installation & Run
```bash
# 1. Clone the repository
git clone https://github.com/simran198905/ironledger.git
cd ironledger

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Configure environment variables
cp .env.example .env

# 4. Launch the application
python3 run.py
```
Open **[http://localhost:8080](http://localhost:8080)** in your browser.

### Running the Test Suite
```bash
python3 backend/test_pipeline.py
# or if pytest is installed:
pytest backend/test_pipeline.py -v
```

### 📜 Deploying the Smart Contract (Optional for Live Sepolia Mode)

To deploy the [`contracts/IronLedger.sol`](contracts/IronLedger.sol) contract to Ethereum Sepolia testnet using Remix, Hardhat, or Foundry:

1. **Constructor Argument:** Deploy `IronLedger.sol` with the `_genesisHash` argument:
   `0x465d14d810bcba66615818b4ac0a1e63ba763dfcc86a1c02c584c4c5af213723`
   *(This matches the deterministic `GENESIS_HASH` defined in [`backend/blockchain.py`](backend/blockchain.py)).*
2. **Environment Configuration:** Set `CONTRACT_TYPE=ironledger` and update `SEPOLIA_CONTRACT_ADDRESS=0xYOUR_NEW_ADDRESS` in `.env`.
3. **Database Reset & Re-deployment:** If you run `python3 reset_db.py` to wipe stored events/blocks and restart the genesis chain, the smart contract **must be redeployed** and `SEPOLIA_CONTRACT_ADDRESS` updated in `.env` so on-chain `lastHash` linkage remains synchronized with the fresh genesis root.

---

## 🏗️ Architecture & Modules

1. **ICS Simulation Layer ([`backend/simulator.py`](backend/simulator.py))**:
   - High-fidelity physical simulation of centrifugal feed pumps, pressurized reactor vessels, feedstock/relief control valves, and a Triconex Safety Instrumented System (SIS).
   - Interactive attack injection scenarios: TRITON / HatMan (SIS bypass), Industroyer2 (overpressure), Stuxnet (frequency cycling), and Local Log Tampering.

2. **Blockchain Evidence Layer ([`contracts/IronLedger.sol`](contracts/IronLedger.sol), [`backend/blockchain.py`](backend/blockchain.py))**:
   - Solidity 0.8.20 smart contract deployed for Ethereum Sepolia testnet with `onlyOwner` access control, strict `previousHash` linkage checks, duplicate replay protection, and storage optimization.
   - Computes deterministic SHA-256 state hashes:
     $$H_i = \text{SHA256}(\text{canonical\_json}(\{ \text{event\_id}, \text{timestamp\_ms}, \text{source}, \text{cmd}, \text{entity}, \text{params}, \text{signature}, \text{snapshot\_hash}, H_{i-1} \}))$$
   - **Dual-Mode Operation:** Automatically broadcasts transactions to Ethereum Sepolia when Web3 credentials are configured in `.env`, and gracefully operates in a local cryptographic SHA-256 simulation mode when running offline.

3. **Dual-Layer Anomaly Detection ([`backend/anomaly_detector.py`](backend/anomaly_detector.py))**:
   - **Deterministic Physics Envelopes:**
     - Vessel Pressure: Warning $\ge 8.0\text{ bar}$, Critical $\ge 10.0\text{ bar}$
     - Core Temperature: Warning $\ge 85.0\text{ }^\circ\text{C}$, Critical $\ge 95.0\text{ }^\circ\text{C}$
     - Pump RPM: Warning $\ge 3000\text{ RPM}$, Critical $\ge 3400\text{ RPM}$
     - Rotor Vibration: Critical $\ge 5.5\text{ mm/s}$
     - Contradiction rules: Clamped relief vent during high-throughput flow, unauthorized SIS bypass.
   - **Unsupervised Machine Learning:** Scikit-learn `IsolationForest` detecting multivariate telemetry drift.

4. **Forensic Reconstruction & MITRE ATT&CK for ICS ([`backend/forensics.py`](backend/forensics.py), [`backend/threat_intel.py`](backend/threat_intel.py))**:
   - Backward-walk algorithm following the immutable `previous_hash` chain to identify unauthorized commands and operational policy violations.
   - Objective MITRE ATT&CK for ICS technique mapping (`T0855`, `T0836`, `T0831`, `T0888`, `T0879`, `T0815`, `T0816`).
   - Signature coverage scoring against threat actor profiles (Xenotime, Sandworm, Equation Group, Volt Typhoon) with forensic attribution caveats.

5. **Court-Ready Report Generator ([`backend/report_generator.py`](backend/report_generator.py))**:
   - Generates structured HTML forensic reports designed to assist with Federal Rules of Evidence 902(13) & 902(14) digital records authentication requirements, complete with investigator certification sign-off blocks.

---

## 🔒 Threat Model & Security Considerations

- **Adversary Assumptions:** An attacker may gain administrative or root access on the SCADA supervisory workstation or historian database (e.g., Supabase, SQLite, SQL Server) and attempt to alter historical event records, modify timestamps, or forge benign maintenance logs.
- **Cryptographic Guarantees:** Because each state hash incorporates the event ID, millisecond-precision timestamp, command parameters, plant state snapshot hash, and the prior block's hash, any retro-active modification creates an immediate cryptographic hash mismatch during audit.
- **Local Demo vs. Production Security:** 
  - **Local Demo:** The server binds strictly to `127.0.0.1:8080` (localhost-only). For demo simplicity, write endpoints are accessible without requiring credentials embedded in frontend JavaScript (which provides no genuine security). Interactive attack and tamper features are enabled via `DEMO_MODE=true`.
  - **Production Deployment:** Bind the application behind an authenticating reverse proxy (e.g., Nginx with mTLS/OIDC, Cloudflare Access, or OAuth2-Proxy) or integrate user session/JWT authentication (e.g., Supabase Auth). Set `DEMO_MODE=false` to permanently disable attack and tamper simulation endpoints, and restrict Supabase database access using strict Row-Level Security (RLS) policies.

---

## 🎬 Incident Response Walkthrough

1. **Act 1: Normal Baseline**
   - Plant operates in steady state within green safety envelopes; each telemetry state is hashed and anchored.
2. **Act 2: Attack Injection (TRITON / HatMan)**
   - Rogue operator engages SIS interlock bypass and clamps relief valves shut. Reactor temperature and pressure surge, triggering physics threshold alarms and elevated Isolation Forest ML drift scores.
3. **Act 3: Log Tampering & Blockchain Proof**
   - Adversary alters historian database records to disguise the malicious setpoint as a benign maintenance ping. IronLedger's cryptographic audit instantly flags a **HASH_MISMATCH** against the on-chain anchor.
4. **Act 4: Reconstruct Timeline & Legal Report**
   - Backward-walk graph traversal identifies the unauthorized entry point, correlates MITRE techniques to **Xenotime**, and generates a court-admissible forensic report.
