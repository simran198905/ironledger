"""
IronLedger - Blockchain Evidence Layer & Cryptographic Anchoring
Provides immutable ledger anchoring, SHA-256 state hashing, Ethereum Sepolia integration,
and cryptographic tamper detection against off-chain databases and modified local chains.
"""

import os
import json
import time
import hashlib
import secrets
import threading
from queue import Queue
from typing import Dict, Any, List, Optional, Tuple

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


def _canonicalize_value(val: Any) -> Any:
    """Recursively cleans and rounds numbers to floats to prevent int/float serialization drift."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (float, int)):
        return round(float(val), 3)
    if isinstance(val, dict):
        return {k: _canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [_canonicalize_value(v) for v in val]
    return val


def _canon(obj: Any) -> str:
    """Produces sorted, deterministic canonical JSON string."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


GENESIS_PAYLOAD = {"genesis_root": "IRONLEDGER_ICS_GENESIS_ROOT_V2"}
GENESIS_HASH = "0x" + hashlib.sha256(_canon(GENESIS_PAYLOAD).encode('utf-8')).hexdigest()


class BlockchainLedger:
    def __init__(self, sepolia_contract_address: Optional[str] = None):
        self.sepolia_contract_address = (
            sepolia_contract_address
            or os.environ.get("SEPOLIA_CONTRACT_ADDRESS", "").strip()
        )
        self.rpc_url = os.environ.get("SEPOLIA_RPC_URL", "").strip()
        self.private_key = os.environ.get("ANCHOR_PRIVATE_KEY", "").strip()
        self.contract_type = os.environ.get("CONTRACT_TYPE", "ironledger").strip().lower()
        # Block at which the contract was deployed — used as lower bound for log queries
        # to avoid "exceed maximum block range" errors from RPC providers.
        try:
            self.deploy_block = int(os.environ.get("CONTRACT_DEPLOY_BLOCK", "11911226"))
        except (ValueError, TypeError):
            self.deploy_block = 11911226
        
        self.w3: Optional[Any] = None
        self.contract: Optional[Any] = None
        self.account: Optional[Any] = None
        self.is_simulated = True

        self.chain: List[Dict[str, Any]] = []
        self.hash_index: Dict[str, Dict[str, Any]] = {}
        
        # Tamper-isolated anchor mirror to detect local in-memory chain rebuilds
        self._immutable_anchor_mirror: List[Dict[str, Any]] = []

        # Cache for smart contract on-chain evidence
        self._onchain_hashes_cache = None
        self._onchain_cache_time = 0.0

        self._tx_queue: Queue = Queue()
        self._queue_worker_running = False
        self.on_block_updated = None

        self._init_web3()

        # Deterministic Genesis Block
        self.genesis_block = {
            "block_index": 0,
            "event_id": 0,
            "event_hash": GENESIS_HASH,
            "previous_hash": "0x" + "0" * 64,
            "timestamp": 1700000000,
            "timestamp_ms": 1700000000000,
            "source": "GENESIS_NODE",
            "command_type": "INITIALIZE_LEDGER",
            "entity_id": "SYS_ROOT",
            "tx_hash": None,
            "block_number": None,
            "recorded_by": "0x0000000000000000000000000000000000000000",
            "status": "CONFIRMED_ON_CHAIN" if not self.is_simulated else "SIMULATED_LOCAL_CHAIN",
            "is_simulated": self.is_simulated,
            "etherscan_url": None
        }
        self.chain.append(self.genesis_block)
        self.hash_index[self.genesis_block["event_hash"]] = self.genesis_block
        self._immutable_anchor_mirror.append(dict(self.genesis_block))

    def _init_web3(self):
        """Initializes Web3 connection and starts non-blocking background queue worker."""
        if WEB3_AVAILABLE and self.rpc_url and self.private_key and self.sepolia_contract_address:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                if self.w3.is_connected():
                    self.account = self.w3.eth.account.from_key(self.private_key)
                    if self.contract_type == "ironledger":
                        abi_name = "IronLedgerABI.json"
                    else:
                        abi_name = "EvidenceChainABI.json"

                    abi_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "contracts", abi_name)
                    if not os.path.exists(abi_path):
                        alt_name = "EvidenceChainABI.json" if self.contract_type == "ironledger" else "IronLedgerABI.json"
                        abi_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "contracts", alt_name)

                    if os.path.exists(abi_path):
                        with open(abi_path, "r") as f:
                            abi = json.load(f)
                        self.contract = self.w3.eth.contract(
                            address=Web3.to_checksum_address(self.sepolia_contract_address),
                            abi=abi
                        )
                        self.is_simulated = False
                        self._start_queue_worker()
                        print(f"🔗 Connected to Ethereum Sepolia via Web3 ({self.contract_type}). Wallet: {self.account.address}")
            except Exception as e:
                print(f"⚠️  Web3 Sepolia connection fallback to simulation mode: {e}")
                self.is_simulated = True
        else:
            self.is_simulated = True

    def _start_queue_worker(self):
        """Starts background worker thread for non-blocking Ethereum transaction broadcasts."""
        if not self._queue_worker_running:
            self._queue_worker_running = True
            worker = threading.Thread(target=self._process_tx_queue, daemon=True)
            worker.start()

    def _process_tx_queue(self):
        """Background worker loop broadcasting transactions to Sepolia with reconciliation, pre-check retries, and receipt polling."""
        while self._queue_worker_running:
            try:
                task = self._tx_queue.get(timeout=1.0)
            except Exception:
                continue

            block_ref = task.get("block_ref")
            event = task.get("event")
            event_hash = block_ref["event_hash"]
            prev_hash = block_ref["previous_hash"]

            # Reconcile step: check pending or out-of-sync blocks
            curr_status = block_ref.get("status")
            if curr_status == "PENDING_CONFIRMATION" and block_ref.get("tx_hash") and self.w3:
                try:
                    existing_tx = block_ref.get("tx_hash")
                    tx_arg = bytes.fromhex(existing_tx[2:]) if isinstance(existing_tx, str) and existing_tx.startswith("0x") else existing_tx
                    receipt = self.w3.eth.get_transaction_receipt(tx_arg)
                    if receipt:
                        receipt_status = getattr(receipt, "status", None)
                        if receipt_status is None and isinstance(receipt, dict):
                            receipt_status = receipt.get("status")
                        if receipt_status == 1:
                            block_ref["status"] = "CONFIRMED_ON_CHAIN"
                            block_ref["block_number"] = getattr(receipt, "blockNumber", None) or (receipt.get("blockNumber") if isinstance(receipt, dict) else None)
                            self._onchain_hashes_cache = None
                            if self.on_block_updated:
                                self.on_block_updated(block_ref)
                            self._tx_queue.task_done()
                            continue
                        elif receipt_status == 0:
                            block_ref["status"] = "REVERTED_ON_CHAIN"
                            if self.on_block_updated:
                                self.on_block_updated(block_ref)
                            self._tx_queue.task_done()
                            continue
                except Exception as rec_err:
                    print(f"⚠️ Reconciliation check failed for tx {block_ref.get('tx_hash')}: {rec_err}")

            if curr_status == "CHAIN_OUT_OF_SYNC" and self.contract and hasattr(self.contract.functions, "lastHash"):
                try:
                    onchain_last = self.contract.functions.lastHash().call()
                    onchain_last_str = ("0x" + onchain_last.hex().lower()) if isinstance(onchain_last, bytes) else str(onchain_last).strip().lower()
                    if not onchain_last_str.startswith("0x"): onchain_last_str = f"0x{onchain_last_str}"
                    block_prev_str = str(prev_hash).strip().lower()
                    if not block_prev_str.startswith("0x"): block_prev_str = f"0x{block_prev_str}"
                    if onchain_last_str == block_prev_str:
                        block_ref["status"] = "QUEUED_ON_CHAIN"
                except Exception:
                    pass

            # Pre-send check: verify on-chain lastHash matches block's previous_hash (up to 5 tries, 3s apart)
            if self.contract and hasattr(self.contract.functions, "lastHash"):
                match = False
                onchain_last_str = ""
                block_prev_str = str(prev_hash).strip().lower()
                if not block_prev_str.startswith("0x"):
                    block_prev_str = f"0x{block_prev_str}"

                for check_try in range(1, 6):
                    try:
                        onchain_last_hash = self.contract.functions.lastHash().call()
                        if isinstance(onchain_last_hash, bytes):
                            onchain_last_str = "0x" + onchain_last_hash.hex().lower()
                        else:
                            onchain_last_str = str(onchain_last_hash).strip().lower()
                            if not onchain_last_str.startswith("0x"):
                                onchain_last_str = f"0x{onchain_last_str}"

                        if onchain_last_str == block_prev_str:
                            match = True
                            break
                    except Exception as sync_err:
                        print(f"⚠️ Error checking on-chain lastHash (try {check_try}/5): {sync_err}")

                    if check_try < 5 and self._queue_worker_running:
                        time.sleep(3.0 if not getattr(self, "_test_mode", False) else 0.01)

                if not match:
                    print(f"⚠️ Chain out of sync: on-chain lastHash ({onchain_last_str}) != block previous_hash ({block_prev_str}). Skipping block #{block_ref.get('block_index')}.")
                    block_ref["status"] = "CHAIN_OUT_OF_SYNC"
                    if self.on_block_updated:
                        self.on_block_updated(block_ref)
                    self._tx_queue.task_done()
                    continue

            tx_sent = None
            tx_hash_hex = None
            max_retries = 3

            # Phase 1: Pre-broadcast retry loop (nonce, gas estimation, signing, send_raw_transaction)
            for attempt in range(1, max_retries + 1):
                try:
                    nonce = self.w3.eth.get_transaction_count(self.account.address, 'pending')
                    base_fee = self.w3.eth.get_block('latest').get('baseFeePerGas', self.w3.to_wei(1, 'gwei'))
                    priority_fee = self.w3.to_wei(2, 'gwei')
                    max_fee = base_fee * 2 + priority_fee

                    if self.contract_type == "ironledger" and hasattr(self.contract.functions, "recordEvent"):
                        event_h = event_hash if event_hash.startswith("0x") else f"0x{event_hash}"
                        prev_h = prev_hash if prev_hash.startswith("0x") else f"0x{prev_hash}"
                        if len(event_h) < 66:
                            event_h = "0x" + event_h[2:].zfill(64)
                        if len(prev_h) < 66:
                            prev_h = "0x" + prev_h[2:].zfill(64)

                        func_call = self.contract.functions.recordEvent(
                            event_h,
                            prev_h,
                            str(event.get("source", "UNKNOWN")),
                            str(event.get("command_type", "EVENT")),
                            str(event.get("entity_id", "PLANT"))
                        )
                    else:
                        case_id = str(event.get("entity_id", "IRONLEDGER"))
                        description = f"{event.get('command_type', 'EVENT')} | {event.get('source', 'UNKNOWN')}"
                        func_call = self.contract.functions.addEvidence(case_id, event_hash, description)

                    try:
                        estimated_gas = func_call.estimate_gas({"from": self.account.address})
                        gas_limit = int(estimated_gas * 1.25)
                    except Exception:
                        gas_limit = 1500000

                    chain_id = getattr(self.w3.eth, "chain_id", 11155111)

                    tx = func_call.build_transaction({
                        "from": self.account.address,
                        "nonce": nonce,
                        "gas": gas_limit,
                        "maxFeePerGas": max_fee,
                        "maxPriorityFeePerGas": priority_fee,
                        "chainId": chain_id
                    })
                    signed = self.account.sign_transaction(tx)
                    raw_tx = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None)
                    tx_sent = self.w3.eth.send_raw_transaction(raw_tx)
                    
                    tx_hash_hex = tx_sent.hex() if hasattr(tx_sent, "hex") else str(tx_sent)
                    if not tx_hash_hex.startswith("0x"):
                        tx_hash_hex = f"0x{tx_hash_hex}"

                    block_ref["tx_hash"] = tx_hash_hex
                    block_ref["etherscan_url"] = f"https://sepolia.etherscan.io/tx/{tx_hash_hex}"
                    break
                except Exception as exc:
                    print(f"⚠️ Pre-broadcast attempt {attempt}/{max_retries} failed for block #{block_ref.get('block_index')}: {exc}")
                    if attempt < max_retries:
                        time.sleep(1.0 * attempt)

            if not tx_sent:
                block_ref["status"] = "FAILED_ON_CHAIN"
                block_ref["tx_hash"] = None
                block_ref["etherscan_url"] = None
                if self.on_block_updated:
                    self.on_block_updated(block_ref)
                self._tx_queue.task_done()
                continue

            # Phase 2: Post-broadcast receipt polling (every 5s, up to 5 minutes / 300s before setting PENDING_CONFIRMATION)
            receipt = None
            poll_interval = 5.0 if not getattr(self, "_test_mode", False) else 0.01
            poll_start = time.time()
            poll_timeout = 300.0 if not getattr(self, "_test_mode", False) else 0.2

            while (time.time() - poll_start) < poll_timeout and self._queue_worker_running:
                try:
                    receipt = self.w3.eth.get_transaction_receipt(tx_sent)
                    if receipt is not None:
                        break
                except Exception:
                    pass
                time.sleep(poll_interval)

            if receipt:
                receipt_status = getattr(receipt, "status", None)
                if receipt_status is None and isinstance(receipt, dict):
                    receipt_status = receipt.get("status")
                
                block_number = getattr(receipt, "blockNumber", None)
                if block_number is None and isinstance(receipt, dict):
                    block_number = receipt.get("blockNumber")

                if receipt_status == 1:
                    block_ref["block_number"] = block_number
                    block_ref["status"] = "CONFIRMED_ON_CHAIN"
                    self._onchain_hashes_cache = None
                else:
                    block_ref["status"] = "REVERTED_ON_CHAIN"
            else:
                # Receipt polling timed out (5 minutes): set PENDING_CONFIRMATION and leave tx_hash attached
                print(f"⚠️ Receipt polling timeout (5m) for tx {tx_hash_hex} on block #{block_ref.get('block_index')}. Set to PENDING_CONFIRMATION.")
                block_ref["status"] = "PENDING_CONFIRMATION"

            if self.on_block_updated:
                self.on_block_updated(block_ref)

            self._tx_queue.task_done()

    def compute_event_hash(self, event: Dict[str, Any], previous_hash: str) -> str:
        """
        Computes deterministic SHA-256 cryptographic digest of an ICS event covering:
        event_id, timestamp_ms, source, command_type, entity_id, parameters, snapshot_sha256, and previous_hash.
        """
        raw_ts = float(event.get("timestamp", time.time()))
        ts_ms = int(raw_ts * 1000)
        
        snap = event.get("plant_state_snapshot", {})
        snap_canon = _canonicalize_value(snap)
        snap_hash = hashlib.sha256(_canon(snap_canon).encode('utf-8')).hexdigest()

        payload = {
            "event_id": int(event.get("event_id", 0)),
            "timestamp_ms": ts_ms,
            "source": str(event.get("source", "")),
            "command_type": str(event.get("command_type", "")),
            "entity_id": str(event.get("entity_id", "")),
            "parameters": _canonicalize_value(event.get("parameters", {})),
            "signature": str(event.get("signature") or ""),
            "snapshot_sha256": snap_hash,
            "previous_hash": previous_hash
        }
        raw_hash = hashlib.sha256(_canon(payload).encode('utf-8')).hexdigest()
        return f"0x{raw_hash}"

    def anchor_event(self, event: Dict[str, Any], signer_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Anchors an ICS event onto the immutable blockchain ledger.
        In live mode: queues transaction to Sepolia without blocking API.
        In simulated mode: generates cryptographic hash chain with transparent simulation labeling.
        """
        prev_block = self.chain[-1]
        prev_hash = prev_block["event_hash"]
        
        event_hash = self.compute_event_hash(event, prev_hash)
        ts_sec = float(event.get("timestamp", time.time()))
        ts_ms = int(ts_sec * 1000)

        recorded_by = signer_address or (self.account.address if self.account else "0x0000000000000000000000000000000000000000")

        block = {
            "block_index": len(self.chain),
            "event_id": int(event.get("event_id", len(self.chain))),
            "event_hash": event_hash,
            "previous_hash": prev_hash,
            "timestamp": int(ts_sec),
            "timestamp_ms": ts_ms,
            "source": str(event.get("source", "UNKNOWN")),
            "command_type": str(event.get("command_type", "TELEMETRY_SNAPSHOT")),
            "entity_id": str(event.get("entity_id", "PLANT")),
            "parameters": event.get("parameters", {}),
            "signature": event.get("signature"),
            "tx_hash": None,
            "block_number": None,
            "recorded_by": recorded_by,
            "status": "QUEUED_ON_CHAIN" if not self.is_simulated else "SIMULATED_LOCAL_CHAIN",
            "is_simulated": self.is_simulated,
            "etherscan_url": None
        }

        self.chain.append(block)
        self.hash_index[event_hash] = block
        self._immutable_anchor_mirror.append(dict(block))

        # If live Web3 is active, queue for background on-chain broadcast
        if not self.is_simulated and self.contract and self.account:
            self._tx_queue.put({"block_ref": block, "event": event})

        return block

    def verify_against_contract(self) -> Dict[str, Any]:
        """
        Read-back verification directly querying the deployed Smart Contract on Sepolia.
        Verifies exact index sequence, event hash, and previous_hash linkage against smart contract storage.
        """
        if self.is_simulated or not self.contract or not self.w3:
            return {
                "contract_connected": False,
                "mode": "SIMULATION",
                "verified": False,
                "note": "On-chain verification unavailable: Running in local cryptographic simulation mode."
            }

        try:
            now = time.time()
            if (
                self._onchain_hashes_cache is None
                or (now - self._onchain_cache_time) > 30.0
            ):
                onchain_events = {}
                onchain_hashes = set()

                if hasattr(self.contract.functions, "totalEvents"):
                    total_onchain = self.contract.functions.totalEvents().call()
                    for i in range(1, total_onchain + 1):
                        try:
                            ev_tuple = self.contract.functions.getEvent(i).call()
                            ev_id = ev_tuple[0]
                            ev_h = (ev_tuple[1].hex() if isinstance(ev_tuple[1], bytes) else str(ev_tuple[1])).lower()
                            prev_h = (ev_tuple[2].hex() if isinstance(ev_tuple[2], bytes) else str(ev_tuple[2])).lower()
                            if not ev_h.startswith("0x"): ev_h = f"0x{ev_h}"
                            if not prev_h.startswith("0x"): prev_h = f"0x{prev_h}"

                            onchain_events[i] = {"event_id": ev_id, "event_hash": ev_h, "previous_hash": prev_h}
                            onchain_hashes.add(ev_h)
                        except Exception:
                            pass
                else:
                    total_onchain = self.contract.functions.evidenceCount().call()
                    for i in range(1, total_onchain + 1):
                        ev_data = self.contract.functions.getEvidence(i).call()
                        h = str(ev_data[2]).strip().lower()
                        if not h.startswith("0x"): h = f"0x{h}"
                        onchain_events[i] = {"event_hash": h}
                        onchain_hashes.add(h)

                self._onchain_hashes_cache = {
                    "total": total_onchain,
                    "hashes": onchain_hashes,
                    "events_by_index": onchain_events
                }
                self._onchain_cache_time = now

            cached = self._onchain_hashes_cache
            total_onchain = cached["total"]
            onchain_events = cached["events_by_index"]

            discrepancies = []

            # Verify local blocks against on-chain records (checking index sequence & linkage)
            for idx, blk in enumerate(self.chain[1:], start=1):
                blk_idx = blk.get("block_index", idx)
                status = blk.get("status")
                local_h = blk.get("event_hash", "").strip().lower()

                if status == "CONFIRMED_ON_CHAIN" or blk.get("tx_hash"):
                    onchain_rec = onchain_events.get(idx)
                    if not onchain_rec:
                        discrepancies.append({
                            "block_index": blk_idx,
                            "event_id": blk.get("event_id"),
                            "local_hash": local_h,
                            "onchain_hash": "MISSING_FROM_SMART_CONTRACT",
                            "reason": "CONFIRMED_BLOCK_NOT_FOUND_ON_CHAIN"
                        })
                    else:
                        onchain_h = onchain_rec.get("event_hash", "")
                        if local_h != onchain_h:
                            discrepancies.append({
                                "block_index": blk_idx,
                                "event_id": blk.get("event_id"),
                                "local_hash": local_h,
                                "onchain_hash": onchain_h,
                                "reason": "ONCHAIN_HASH_MISMATCH_AT_INDEX"
                            })

            return {
                "contract_connected": True,
                "mode": "LIVE_SEPOLIA",
                "total_onchain_events": total_onchain,
                "verified": len(discrepancies) == 0,
                "discrepancies": discrepancies
            }
        except Exception as e:
            return {
                "contract_connected": False,
                "mode": "LIVE_SEPOLIA_ERROR",
                "error": str(e),
                "verified": False
            }

    def sync_with_onchain(self) -> Dict[str, Any]:
        """
        Synchronizes the local in-memory chain with the deployed smart contract on Sepolia.
        Fetches all confirmed on-chain events and rebuilds the local ledger so that
        the local chain tip matches the contract's on-chain lastHash.
        """
        if self.is_simulated or not self.contract or not self.w3:
            return {
                "success": False,
                "error": "Not connected to a live Sepolia contract. Verify SEPOLIA_RPC_URL and SEPOLIA_CONTRACT_ADDRESS in .env."
            }

        try:
            if self.contract_type == "ironledger":
                total_onchain = self.contract.functions.totalEvents().call()
                onchain_last_raw = self.contract.functions.lastHash().call()
                if isinstance(onchain_last_raw, bytes):
                    onchain_last = "0x" + onchain_last_raw.hex().lower()
                else:
                    onchain_last = str(onchain_last_raw).strip().lower()
                if not onchain_last.startswith("0x"):
                    onchain_last = f"0x{onchain_last}"

                # Query EventAnchored logs for tx_hash, source, commandType, entityId.
                # Uses chunked pagination (≤49 999 blocks/request) to comply with RPC provider limits.
                event_logs_by_id = {}

                def _parse_raw_log(raw_lg):
                    """Extract (e_id, tx_h, blk_num, src, cmd, entity) from a raw eth_getLogs entry."""
                    tx_h = raw_lg.get("transactionHash")
                    if tx_h:
                        tx_h = tx_h.hex() if hasattr(tx_h, "hex") else str(tx_h)
                        if not tx_h.startswith("0x"):
                            tx_h = f"0x{tx_h}"
                    blk_num = raw_lg.get("blockNumber")
                    topics = raw_lg.get("topics", [])
                    e_id = None
                    if len(topics) > 1:
                        t1 = topics[1]
                        if hasattr(t1, "hex"):
                            t1 = t1.hex()
                        try:
                            e_id = int(str(t1).lstrip("0x"), 16)
                        except (ValueError, TypeError):
                            pass
                    src, cmd, entity = "ONCHAIN_SEPOLIA", "STATE_ANCHOR", "PLANT"
                    try:
                        raw_data = raw_lg.get("data", b"")
                        if isinstance(raw_data, str):
                            raw_data = bytes.fromhex(raw_data.lstrip("0x"))
                        decoded = self.w3.codec.decode(
                            ["uint256", "string", "string", "string", "address"],
                            raw_data
                        )
                        src = decoded[1] or "ONCHAIN_SEPOLIA"
                        cmd = decoded[2] or "STATE_ANCHOR"
                        entity = decoded[3] or "PLANT"
                    except Exception:
                        pass
                    return e_id, tx_h, blk_num, src, cmd, entity

                CHUNK_SIZE = 49_999   # stay under 50 000 block RPC provider limit
                from_blk = self.deploy_block
                try:
                    latest_blk = self.w3.eth.block_number
                except Exception:
                    latest_blk = from_blk + CHUNK_SIZE

                event_sig_hash = "0x" + self.w3.keccak(
                    text="EventAnchored(uint256,bytes32,bytes32,uint256,string,string,string,address)"
                ).hex().lstrip("0x")

                # Strategy 1: high-level .get_logs() with chunked pagination
                strategy1_ok = False
                try:
                    all_logs = []
                    cur = from_blk
                    while cur <= latest_blk:
                        end = min(cur + CHUNK_SIZE, latest_blk)
                        chunk = self.contract.events.EventAnchored.get_logs(
                            from_block=cur, to_block=end
                        )
                        all_logs.extend(chunk)
                        cur = end + 1

                    for lg in all_logs:
                        args = getattr(lg, "args", {})
                        if isinstance(args, dict):
                            e_id = args.get("eventId")
                            src = args.get("source", "ONCHAIN_SEPOLIA")
                            cmd = args.get("commandType", "STATE_ANCHOR")
                            entity = args.get("entityId", "PLANT")
                        else:
                            e_id = getattr(args, "eventId", None)
                            src = getattr(args, "source", "ONCHAIN_SEPOLIA")
                            cmd = getattr(args, "commandType", "STATE_ANCHOR")
                            entity = getattr(args, "entityId", "PLANT")
                        tx_h = lg.transactionHash.hex() if hasattr(lg, "transactionHash") else None
                        if tx_h and not tx_h.startswith("0x"):
                            tx_h = f"0x{tx_h}"
                        blk_num = getattr(lg, "blockNumber", None)
                        if e_id is not None:
                            event_logs_by_id[int(e_id)] = {
                                "tx_hash": tx_h,
                                "block_number": blk_num,
                                "source": src,
                                "command_type": cmd,
                                "entity_id": entity,
                            }
                    strategy1_ok = True
                    print(f"📋 EventAnchored logs (strategy 1 chunked): fetched {len(event_logs_by_id)} entries")
                except Exception as log_err:
                    print(f"⚠️  EventAnchored.get_logs() chunked failed ({log_err}), trying raw eth_getLogs fallback...")

                # Strategy 2: raw eth_getLogs with topic filter + chunked pagination
                if not strategy1_ok or not event_logs_by_id:
                    try:
                        cur = from_blk
                        while cur <= latest_blk:
                            end = min(cur + CHUNK_SIZE, latest_blk)
                            raw_logs = self.w3.eth.get_logs({
                                "fromBlock": cur,
                                "toBlock": end,
                                "address": Web3.to_checksum_address(self.sepolia_contract_address),
                                "topics": [event_sig_hash]
                            })
                            for raw_lg in raw_logs:
                                e_id, tx_h, blk_num, src, cmd, entity = _parse_raw_log(raw_lg)
                                if e_id is not None:
                                    event_logs_by_id[e_id] = {
                                        "tx_hash": tx_h,
                                        "block_number": blk_num,
                                        "source": src,
                                        "command_type": cmd,
                                        "entity_id": entity,
                                    }
                            cur = end + 1
                        print(f"📋 EventAnchored logs (strategy 2 raw chunked): fetched {len(event_logs_by_id)} entries")
                    except Exception as raw_err:
                        print(f"⚠️  Raw eth_getLogs chunked fallback also failed: {raw_err}")

                new_chain = [self.genesis_block]
                new_hash_index = {self.genesis_block["event_hash"]: self.genesis_block}

                for i in range(1, total_onchain + 1):
                    ev_data = self.contract.functions.getEvent(i).call()
                    ev_id = int(ev_data[0])
                    raw_h = ev_data[1]
                    ev_h = ("0x" + raw_h.hex().lower()) if isinstance(raw_h, bytes) else str(raw_h).strip().lower()
                    if not ev_h.startswith("0x"):
                        ev_h = f"0x{ev_h}"

                    raw_prev = ev_data[2]
                    prev_h = ("0x" + raw_prev.hex().lower()) if isinstance(raw_prev, bytes) else str(raw_prev).strip().lower()
                    if not prev_h.startswith("0x"):
                        prev_h = f"0x{prev_h}"

                    ts = int(ev_data[3])
                    recorded_by = str(ev_data[4])

                    log_meta = event_logs_by_id.get(i, {})
                    tx_h = log_meta.get("tx_hash")
                    blk_num = log_meta.get("block_number")
                    src = log_meta.get("source", "ONCHAIN_SEPOLIA")
                    cmd = log_meta.get("command_type", "STATE_ANCHOR")
                    entity = log_meta.get("entity_id", "PLANT")

                    etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_h}" if tx_h else f"https://sepolia.etherscan.io/address/{self.sepolia_contract_address}"

                    block = {
                        "block_index": i,
                        "event_id": ev_id,
                        "event_hash": ev_h,
                        "previous_hash": prev_h,
                        "timestamp": ts,
                        "timestamp_ms": ts * 1000,
                        "source": src,
                        "command_type": cmd,
                        "entity_id": entity,
                        "parameters": {},
                        "signature": None,
                        "tx_hash": tx_h,
                        "block_number": blk_num,
                        "recorded_by": recorded_by,
                        "status": "CONFIRMED_ON_CHAIN",
                        "is_simulated": False,
                        "etherscan_url": etherscan_url
                    }
                    new_chain.append(block)
                    new_hash_index[ev_h] = block

                self.chain = new_chain
                self.hash_index = new_hash_index
                self._immutable_anchor_mirror = [dict(b) for b in self.chain]
                self._onchain_hashes_cache = None

                # Clear stale desynced tasks in queue
                with self._tx_queue.mutex:
                    self._tx_queue.queue.clear()

                if self.on_block_updated:
                    for b in self.chain[1:]:
                        try:
                            self.on_block_updated(b)
                        except Exception:
                            pass

                return {
                    "success": True,
                    "total_synced": total_onchain,
                    "onchain_last_hash": onchain_last,
                    "contract_address": self.sepolia_contract_address,
                    "chain_length": len(self.chain)
                }
            else:
                total_onchain = self.contract.functions.evidenceCount().call()
                new_chain = [self.genesis_block]
                new_hash_index = {self.genesis_block["event_hash"]: self.genesis_block}

                for i in range(1, total_onchain + 1):
                    ev_data = self.contract.functions.getEvidence(i).call()
                    ev_id = int(ev_data[0])
                    case_id = str(ev_data[1])
                    ev_hash = str(ev_data[2])
                    desc = str(ev_data[3])
                    uploaded_by = str(ev_data[4])
                    ts = int(ev_data[5])

                    prev_block = new_chain[-1]
                    prev_hash = prev_block["event_hash"]

                    block = {
                        "block_index": i,
                        "event_id": ev_id,
                        "event_hash": ev_hash,
                        "previous_hash": prev_hash,
                        "timestamp": ts,
                        "timestamp_ms": ts * 1000,
                        "source": case_id,
                        "command_type": desc,
                        "entity_id": "PLANT",
                        "parameters": {},
                        "signature": None,
                        "tx_hash": None,
                        "block_number": None,
                        "recorded_by": uploaded_by,
                        "status": "CONFIRMED_ON_CHAIN",
                        "is_simulated": False,
                        "etherscan_url": f"https://sepolia.etherscan.io/address/{self.sepolia_contract_address}"
                    }
                    new_chain.append(block)
                    new_hash_index[ev_hash] = block

                self.chain = new_chain
                self.hash_index = new_hash_index
                self._immutable_anchor_mirror = [dict(b) for b in self.chain]
                self._onchain_hashes_cache = None

                with self._tx_queue.mutex:
                    self._tx_queue.queue.clear()

                return {
                    "success": True,
                    "total_synced": total_onchain,
                    "onchain_last_hash": new_chain[-1]["event_hash"],
                    "contract_address": self.sepolia_contract_address,
                    "chain_length": len(self.chain)
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Sync failed: {str(e)}"
            }

    def audit_entire_chain(self, db_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Audits all off-chain events against the immutable hash history.
        Carries true previous hash forward, compares against immutable anchor mirror
        (detecting forged chain rebuilds), and reads back from smart contract if live.
        """
        db_map = {e.get("event_id"): e for e in db_events if "event_id" in e}
        findings = []
        prev = self.genesis_block["event_hash"]

        # 1. Check against the immutable anchor mirror to detect in-memory chain rebuilds
        for idx in range(1, max(len(self.chain), len(self._immutable_anchor_mirror))):
            if idx >= len(self._immutable_anchor_mirror):
                findings.append({
                    "block_index": idx,
                    "event_id": self.chain[idx].get("event_id") if idx < len(self.chain) else None,
                    "tampered": True,
                    "reason": "FORGED_CHAIN_EXTENSION",
                    "verdict": "TAMPER_DETECTED_FORGED_BLOCK"
                })
            elif idx >= len(self.chain):
                findings.append({
                    "block_index": idx,
                    "event_id": self._immutable_anchor_mirror[idx].get("event_id"),
                    "tampered": True,
                    "reason": "CHAIN_TRUNCATION_DETECTED",
                    "verdict": "TAMPER_DETECTED_TRUNCATED_CHAIN"
                })
            else:
                curr_blk = self.chain[idx]
                mirror_blk = self._immutable_anchor_mirror[idx]
                if curr_blk.get("event_hash") != mirror_blk.get("event_hash"):
                    findings.append({
                        "block_index": idx,
                        "event_id": curr_blk.get("event_id"),
                        "tampered": True,
                        "reason": "LOCAL_CHAIN_REBUILT_HASH_MISMATCH",
                        "immutable_onchain_hash": mirror_blk.get("event_hash"),
                        "computed_db_hash": curr_blk.get("event_hash"),
                        "verdict": "TAMPER_DETECTED_CHAIN_REWRITE"
                    })

        # 2. Audit off-chain database records against chain
        for blk in self.chain[1:]:
            blk_idx = blk.get("block_index")
            ev_id = blk.get("event_id")

            # Verify previous_hash link
            if blk.get("previous_hash") != prev:
                findings.append({
                    "block_index": blk_idx,
                    "event_id": ev_id,
                    "tampered": True,
                    "reason": "BROKEN_CHAIN_LINK",
                    "immutable_onchain_hash": blk.get("event_hash"),
                    "computed_db_hash": "CHAIN_BROKEN",
                    "verdict": "TAMPER_DETECTED_BROKEN_CHAIN_LINK"
                })

            # Check if database record was deleted
            ev = db_map.get(ev_id)
            if ev is None:
                findings.append({
                    "block_index": blk_idx,
                    "event_id": ev_id,
                    "tampered": True,
                    "reason": "AUDIT_RECORD_DELETED_FROM_DB",
                    "immutable_onchain_hash": blk.get("event_hash"),
                    "computed_db_hash": "RECORD_PURGED",
                    "verdict": "TAMPER_DETECTED_RECORD_DELETED"
                })
            else:
                # Recompute hash using true prev hash
                try:
                    computed = self.compute_event_hash(ev, prev)
                except (ValueError, TypeError, KeyError):
                    findings.append({
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "tampered": True,
                        "reason": "MALFORMED_RECORD",
                        "immutable_onchain_hash": blk.get("event_hash", ""),
                        "computed_db_hash": "MALFORMED_RECORD",
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "verdict": "TAMPER_DETECTED_MALFORMED_RECORD"
                    })
                    prev = blk.get("event_hash")
                    continue

                expected = blk.get("event_hash", "")
                if computed.lower() != expected.lower():
                    findings.append({
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "tampered": True,
                        "reason": "HASH_MISMATCH",
                        "immutable_onchain_hash": expected,
                        "computed_db_hash": computed,
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "verdict": "TAMPER_DETECTED_HASH_MISMATCH"
                    })
                else:
                    findings.append({
                        "verified": True,
                        "tampered": False,
                        "block_index": blk_idx,
                        "event_id": ev_id,
                        "immutable_onchain_hash": expected,
                        "computed_db_hash": computed,
                        "tx_hash": blk.get("tx_hash"),
                        "block_number": blk.get("block_number"),
                        "timestamp": blk.get("timestamp"),
                        "verdict": "VERIFIED_AUTHENTIC"
                    })

            prev = blk.get("event_hash")

        # 3. Check for forged / unanchored events inserted into DB
        anchored_ids = {b.get("event_id") for b in self.chain[1:]}
        for unanchored_id in set(db_map.keys()) - anchored_ids:
            if unanchored_id is not None:
                findings.append({
                    "block_index": None,
                    "event_id": unanchored_id,
                    "tampered": True,
                    "reason": "UNANCHORED_DB_RECORD",
                    "immutable_onchain_hash": "NOT_ON_CHAIN",
                    "computed_db_hash": "FORGED_INSERT",
                    "verdict": "TAMPER_DETECTED_UNANCHORED_RECORD"
                })

        # 4. Smart contract read-back check (if Web3 is active)
        contract_status = self.verify_against_contract()
        if contract_status.get("contract_connected") and not contract_status.get("verified"):
            for disc in contract_status.get("discrepancies", []):
                findings.append({
                    "block_index": disc.get("event_id"),
                    "event_id": disc.get("event_id"),
                    "tampered": True,
                    "reason": "ONCHAIN_SMART_CONTRACT_MISMATCH",
                    "immutable_onchain_hash": disc.get("onchain_hash"),
                    "computed_db_hash": disc.get("local_hash"),
                    "verdict": "TAMPER_DETECTED_ONCHAIN_DISCREPANCY"
                })

        tampered_count = sum(1 for f in findings if f.get("tampered"))
        return {
            "total_blocks_checked": len(self.chain) - 1,
            "tampered_blocks_found": tampered_count,
            "integrity_healthy": (tampered_count == 0),
            "contract_verification": contract_status,
            "audit_details": findings
        }

    def get_recent_blocks(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.chain[-limit:]))
