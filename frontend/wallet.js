/**
 * IronLedger - MetaMask wallet integration.
 *
 * Connects the browser wallet (MetaMask) to the user's deployed IronLedger contract on
 * Ethereum Sepolia and anchors every block of the local hash chain with one signed
 * recordEvent(...) transaction per block, strictly in order.
 *
 * Contract rules this file respects (see contracts/IronLedger.sol):
 *   - recordEvent is onlyOwner      -> connected account must be the contract owner
 *   - previousHash == lastHash      -> blocks must be sent in order, starting where the chain left off
 *   - duplicate hashes are rejected -> we resume from on-chain lastHash instead of resending
 *
 * Depends on the global `ethers` (v6) loaded before this script.
 */
(function () {
    "use strict";

    const SEPOLIA_CHAIN_ID = 11155111;
    const SEPOLIA_CHAIN_HEX = "0xaa36a7";
    const STORAGE_KEY = "ironledger_contract_address";

    const ABI = [
        "function owner() view returns (address)",
        "function lastHash() view returns (bytes32)",
        "function totalEvents() view returns (uint256)",
        "function recordEvent(bytes32 _eventHash, bytes32 _previousHash, string _source, string _commandType, string _entityId) returns (uint256)"
    ];

    const W = {
        ready: false,        // wallet connected + contract validated
        connecting: false,
        busy: false,         // an anchoring loop is running
        paused: false,       // stopped after a rejection / error until the user resumes
        pauseReason: "",
        account: null,
        contractAddress: null,
        provider: null,
        signer: null,
        contract: null,
        lastIndex: 0,        // highest local block index known to be on-chain
        anchoredThisSession: 0,
        config: null
    };

    // ── small helpers ────────────────────────────────────────────────────────

    const $ = (id) => document.getElementById(id);
    const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "");

    function setButton(text) {
        const el = $("wallet-text");
        if (el) el.textContent = text;
    }

    function setBanner(kind, html) {
        const el = $("wallet-banner");
        if (!el) return;
        if (!html) {
            el.className = "wallet-banner hidden";
            el.innerHTML = "";
            return;
        }
        el.className = "wallet-banner " + kind; // info | ok | warn | error
        el.innerHTML = html;
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function updateContractPill(address) {
        const pill = $("contract-pill");
        const addr = $("contract-pill-addr");
        if (pill) pill.href = `https://sepolia.etherscan.io/address/${address}`;
        if (addr) addr.textContent = short(address);
    }

    async function getConfig() {
        if (W.config) return W.config;
        try {
            const res = await fetch("/api/config");
            W.config = await res.json();
        } catch (e) {
            W.config = {};
        }
        return W.config;
    }

    function resetState(message) {
        W.ready = false;
        W.connecting = false;
        W.busy = false;
        W.paused = false;
        W.pauseReason = "";
        W.account = null;
        W.provider = null;
        W.signer = null;
        W.contract = null;
        W.lastIndex = 0;
        W.anchoredThisSession = 0;
        setButton("Connect MetaMask");
        if (message) setBanner("warn", message);
        else setBanner("", "");
    }

    function isUserRejection(err) {
        return (
            err &&
            (err.code === 4001 ||
                err.code === "ACTION_REJECTED" ||
                (err.info && err.info.error && err.info.error.code === 4001))
        );
    }

    function describeError(err) {
        if (!err) return "Unknown error";
        return err.shortMessage || (err.info && err.info.error && err.info.error.message) || err.reason || err.message || String(err);
    }

    // ── connect flow ─────────────────────────────────────────────────────────

    async function ensureSepolia(provider) {
        const net = await provider.getNetwork();
        if (Number(net.chainId) === SEPOLIA_CHAIN_ID) return;
        try {
            await window.ethereum.request({
                method: "wallet_switchEthereumChain",
                params: [{ chainId: SEPOLIA_CHAIN_HEX }]
            });
        } catch (err) {
            if (err && err.code === 4902) {
                await window.ethereum.request({
                    method: "wallet_addEthereumChain",
                    params: [{
                        chainId: SEPOLIA_CHAIN_HEX,
                        chainName: "Sepolia",
                        nativeCurrency: { name: "Sepolia ETH", symbol: "ETH", decimals: 18 },
                        rpcUrls: ["https://ethereum-sepolia-rpc.publicnode.com"],
                        blockExplorerUrls: ["https://sepolia.etherscan.io"]
                    }]
                });
            } else {
                throw err;
            }
        }
    }

    async function resolveContractAddress() {
        const cfg = await getConfig();
        let addr = (cfg.contract_address || "").trim();
        // Ignore placeholder / invalid values (e.g. "0xYOUR_CONTRACT_ADDRESS" copied from .env.example)
        if (addr && !ethers.isAddress(addr)) addr = "";
        if (!addr) {
            try { addr = (localStorage.getItem(STORAGE_KEY) || "").trim(); } catch (e) { /* ignore */ }
            if (addr && !ethers.isAddress(addr)) addr = "";
        }
        if (!addr) {
            addr = (window.prompt(
                "Paste the address of YOUR deployed IronLedger contract on Sepolia.\n\n" +
                "It must be deployed from the wallet you are connecting, with this genesis hash:\n" +
                (cfg.genesis_hash || "(see /api/config)")
            ) || "").trim();
        }
        if (!addr) throw new Error("No contract address provided.");
        if (!ethers.isAddress(addr)) throw new Error(`"${addr}" is not a valid address.`);
        return ethers.getAddress(addr);
    }

    async function connect() {
        if (W.connecting) return;
        if (typeof window.ethereum === "undefined") {
            setBanner("error",
                "MetaMask was not detected in this browser. Install it from " +
                '<a href="https://metamask.io/download/" target="_blank" rel="noopener">metamask.io</a> ' +
                "and reload the page (use Chrome, Edge, Brave or Firefox with the extension enabled).");
            return;
        }
        if (typeof ethers === "undefined") {
            setBanner("error", "The ethers.js library failed to load (check your internet connection) — reload the page.");
            return;
        }

        W.connecting = true;
        setButton("Connecting…");
        setBanner("info", "Approve the connection request in the MetaMask popup…");

        try {
            const provider = new ethers.BrowserProvider(window.ethereum);
            await provider.send("eth_requestAccounts", []); // <- this opens the MetaMask popup
            await ensureSepolia(provider);

            const freshProvider = new ethers.BrowserProvider(window.ethereum); // re-create after a chain switch
            const signer = await freshProvider.getSigner();
            const account = await signer.getAddress();

            const contractAddress = await resolveContractAddress();
            const code = await freshProvider.getCode(contractAddress);
            if (!code || code === "0x") {
                try { localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
                throw new Error(`No contract found at ${contractAddress} on Sepolia. Deploy contracts/IronLedger.sol first, then try again.`);
            }

            const contract = new ethers.Contract(contractAddress, ABI, signer);
            const owner = await contract.owner();
            if (owner.toLowerCase() !== account.toLowerCase()) {
                throw new Error(
                    `The connected account (${short(account)}) is not the contract owner (${short(owner)}). ` +
                    "Only the owner can record events — switch to the deploying account in MetaMask."
                );
            }

            try { localStorage.setItem(STORAGE_KEY, contractAddress); } catch (e) { /* ignore */ }

            W.provider = freshProvider;
            W.signer = signer;
            W.contract = contract;
            W.account = account;
            W.contractAddress = contractAddress;
            W.ready = true;
            W.paused = false;
            W.pauseReason = "";
            W.lastIndex = 0;
            W.anchoredThisSession = 0;

            updateContractPill(contractAddress);
            setButton(`MetaMask: ${short(account)} (Sepolia)`);
            setBanner("ok", `Connected as <code>${short(account)}</code> · anchoring to contract <code>${short(contractAddress)}</code>. ` +
                "Each new block will ask you to confirm one transaction in MetaMask.");

            anchorPending();
        } catch (err) {
            const msg = isUserRejection(err) ? "Connection was rejected in MetaMask." : describeError(err);
            resetState();
            setBanner("error", escapeHtml(msg));
        } finally {
            W.connecting = false;
        }
    }

    function disconnect() {
        resetState("Wallet disconnected — new blocks will stay local until you reconnect.");
    }

    function toggle() {
        if (W.connecting) return;
        if (W.ready && W.paused) return resume();
        if (W.ready) return disconnect();
        return connect();
    }

    function resume() {
        if (!W.ready) return connect();
        W.paused = false;
        W.pauseReason = "";
        setBanner("info", "Resuming anchoring…");
        anchorPending();
    }

    // ── anchoring loop ───────────────────────────────────────────────────────

    function pause(reason, kind, html) {
        W.paused = true;
        W.pauseReason = reason;
        setButton(`MetaMask: ${short(W.account)} — paused (click to resume)`);
        setBanner(kind || "warn", html);
    }

    async function anchorPending() {
        if (!W.ready || W.busy || W.paused) return;
        W.busy = true;
        try {
            const res = await fetch("/api/chain");
            const chain = await res.json();
            const blocks = chain.blocks || [];
            const genesis = String(chain.genesis_hash || "").toLowerCase();

            // Where did the on-chain chain stop? Resume right after that block.
            const onchainTip = String(await W.contract.lastHash()).toLowerCase();
            let startIdx = -1;
            if (onchainTip === genesis) {
                startIdx = 1;
            } else {
                const idx = blocks.findIndex((b) => String(b.event_hash).toLowerCase() === onchainTip);
                if (idx >= 0) startIdx = idx + 1;
            }

            if (startIdx < 0) {
                pause("desync", "error",
                    "<strong>Chain mismatch.</strong> This contract's latest hash is not part of the current local chain " +
                    "(the server was probably restarted, which creates new hashes). A contract can only continue the chain it started. " +
                    "Deploy a fresh IronLedger contract with the genesis hash from <code>/api/config</code>, then reconnect with its address.");
                try { localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
                return;
            }

            W.lastIndex = startIdx - 1;

            for (let i = startIdx; i < blocks.length; i++) {
                const b = blocks[i];
                setButton(`MetaMask: confirm block #${i}…`);
                setBanner("info", `Waiting for your confirmation in MetaMask for block <strong>#${i}</strong> (<code>${escapeHtml(String(b.event_hash).slice(0, 14))}…</code>)`);

                const tx = await W.contract.recordEvent(
                    b.event_hash,
                    b.previous_hash,
                    String(b.source || "UNKNOWN"),
                    String(b.command_type || "EVENT"),
                    String(b.entity_id || "PLANT")
                );

                setBanner("info", `Block <strong>#${i}</strong> submitted — waiting for Sepolia confirmation… <code>${short(tx.hash)}</code>`);
                const receipt = await tx.wait();
                if (!receipt || receipt.status !== 1) {
                    throw new Error(`Transaction for block #${i} failed on-chain.`);
                }

                W.lastIndex = i;
                W.anchoredThisSession += 1;

                try {
                    await fetch("/api/chain/anchor", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            block_index: i,
                            event_hash: b.event_hash,
                            tx_hash: tx.hash,
                            block_number: receipt.blockNumber,
                            recorded_by: W.account,
                            contract_address: W.contractAddress
                        })
                    });
                } catch (e) {
                    console.warn("Could not report anchor receipt to backend:", e);
                }
                if (typeof updateDashboard === "function") updateDashboard();
            }

            setButton(`MetaMask: ${short(W.account)} (Sepolia)`);
            setBanner("ok",
                `All blocks anchored on Sepolia ✓ — ${W.anchoredThisSession} transaction(s) this session, contract <code>${short(W.contractAddress)}</code>. ` +
                "New blocks will prompt MetaMask again automatically.");
        } catch (err) {
            if (isUserRejection(err)) {
                pause("rejected", "warn",
                    "You rejected the transaction in MetaMask, so anchoring is paused. Click the MetaMask button to resume.");
            } else {
                console.error("Anchoring failed:", err);
                pause("error", "error",
                    `<strong>Anchoring failed:</strong> ${escapeHtml(describeError(err))}. Click the MetaMask button to retry.`);
            }
        } finally {
            W.busy = false;
        }
    }

    // Called by app.js on every telemetry poll.
    function onTelemetry(data) {
        if (!W.ready || W.busy || W.paused || !data) return;
        if (typeof data.total_blocks === "number" && data.total_blocks - 1 > W.lastIndex) {
            anchorPending();
        }
    }

    // ── wallet events ────────────────────────────────────────────────────────

    if (typeof window !== "undefined" && window.ethereum && window.ethereum.on) {
        window.ethereum.on("accountsChanged", () => {
            if (W.ready) resetState("MetaMask account changed — click Connect MetaMask to reconnect.");
        });
        window.ethereum.on("chainChanged", () => {
            if (W.ready) resetState("MetaMask network changed — click Connect MetaMask to reconnect.");
        });
    }

    window.IronWallet = { toggle, connect, disconnect, resume, onTelemetry, _state: W };
})();
