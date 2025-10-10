# miner_client.py
"""
Helper utilities for the miner:
- canonical JSON header hashing (single/double)
- merkle detection & builders
- time/difficulty helpers
- HTTP helpers (wait_ready, get_json, submit_block)
- reward tx builder
"""

from __future__ import annotations
import json, time, hashlib, requests, os
from typing import Any, Dict, List, Tuple, Callable, Optional, Union
import os
import time
MIN_DIFFICULTY = int(os.getenv("MIN_DIFFICULTY", "1"))
MAX_DIFFICULTY = int(os.getenv("MAX_DIFFICULTY", "64"))
DIFFICULTY_STEP_UP = int(os.getenv("DIFFICULTY_STEP_UP", "1"))
DIFFICULTY_STEP_DOWN = int(os.getenv("DIFFICULTY_STEP_DOWN", "1"))
# ---------- canonical JSON bytes + sha helpers ----------
def _canon_bytes(o: Any) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _sha256d_hex(b: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()

# ---------- parent/merkle helpers ----------
def parent_hexcat(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256((left_hex + right_hex).encode("utf-8")).hexdigest()

def parent_bytescat(left_hex: str, right_hex: str) -> str:
    left_b = bytes.fromhex(left_hex)
    right_b = bytes.fromhex(right_hex)
    return hashlib.sha256(left_b + right_b).hexdigest()

def _build_merkle(leaves_hex: List[str], parent_fn: Callable[[str, str], str]) -> str:
    if not leaves_hex:
        return hashlib.sha256(b"").hexdigest()
    level = leaves_hex[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(parent_fn(level[i], level[i+1]))
        level = nxt
    return level[0]

# leaf candidate functions
def _leaf_sha256_json_hex(tx: dict) -> str:
    return _sha256_hex_bytes(_canon_bytes(tx))

def _leaf_sha256_txid_hex(tx: dict) -> str:
    tid = str(tx.get("id", json.dumps(tx, sort_keys=True)))
    return hashlib.sha256(tid.encode("utf-8")).hexdigest()

# merkle candidate list (used by detector)
MERKLE_CANDIDATES = [
    (_leaf_sha256_json_hex, parent_hexcat, "sha256(json) + sha256(hexcat)"),
    (_leaf_sha256_json_hex, parent_bytescat, "sha256(json) + sha256(bytescat)"),
    (_leaf_sha256_txid_hex, parent_hexcat, "sha256(txid) + sha256(hexcat)"),
    (_leaf_sha256_txid_hex, parent_bytescat, "sha256(txid) + sha256(bytescat)"),
]

def detect_merkle_builder_from_tip(tip_block: Dict[str, Any]) -> Tuple[Callable, Callable, str]:
    data = tip_block.get("data") or []
    tip_merkle = str(tip_block.get("merkle") or tip_block.get("merkle_root") or "")
    for leaf_fn, parent_fn, label in MERKLE_CANDIDATES:
        try:
            leaves = [leaf_fn(tx) for tx in data]
            m = _build_merkle(leaves, parent_fn)
            if tip_merkle and m == tip_merkle:
                print(f"[miner_client] merkle mode: {label}")
                return leaf_fn, parent_fn, label
        except Exception:
            pass
    print("[miner_client] merkle mode: default sha256(json)+hexcat")
    return _leaf_sha256_json_hex, parent_hexcat, "sha256(json) + sha256(hexcat)"

def compute_merkle_with(leaf_fn, parent_fn, data: List[dict]) -> str:
    leaves = [leaf_fn(tx) for tx in data]
    return _build_merkle(leaves, parent_fn)

# ---------- canonical header JSON hashing used by node diagnostics ----------
def compute_header_json_hash(version: int,
                             last_hash: str,
                             merkle_root: str,
                             timestamp: int,
                             difficulty: int,
                             nonce: int,
                             double: bool = False) -> str:
    hdr = {
        "version": int(version),
        "last_hash": (last_hash or "").lower(),
        "merkle_root": (merkle_root or "").lower(),
        "timestamp": int(timestamp),
        "difficulty": int(difficulty),
        "nonce": int(nonce),
    }
    jb = _canon_bytes(hdr)
    if double:
        return _sha256d_hex(jb)
    return _sha256_hex_bytes(jb)

# ---------- small helpers ----------
def hex_to_binary(h: str) -> str:
    return bin(int(h, 16))[2:].zfill(4 * len(h))

def _to_int_ns(v) -> int:
    try:
        if v is None:
            return 0
        if isinstance(v, (int, float)):
            return int(v)
        return int(float(str(v).strip()))
    except Exception:
        return 0

def median_past_ns(chain: List[Dict[str,Any]], window: int) -> int:
    if not chain: return 0
    tail = chain[-window:] if len(chain) >= window else chain[:]
    ts = [_to_int_ns(b.get("timestamp")) for b in tail if isinstance(b, dict)]
    if not ts: return 0
    ts.sort()
    n = len(ts)
    return ts[n // 2] if n % 2 else (ts[n // 2 - 1] + ts[n // 2]) // 2

def safe_ts_ns(now_ns: int, parent_ts_ns: int, mtp_ns: int) -> int:
    return max(int(now_ns), int(parent_ts_ns)+1, int(mtp_ns)+1)

def adjust_difficulty(parent_diff: int, parent_ts_ns: int, now_ts_ns: int, mine_rate_ns: Optional[int]) -> int:
    try:
        pd = int(parent_diff)
    except Exception:
        pd = MIN_DIFFICULTY

    pd = max(pd, MIN_DIFFICULTY)

    if not mine_rate_ns or int(mine_rate_ns) <= 0:
        return pd

    if (int(now_ts_ns) - int(parent_ts_ns)) < int(mine_rate_ns):
        return min(pd + DIFFICULTY_STEP_UP, MAX_DIFFICULTY)
    else:
        return max(pd - DIFFICULTY_STEP_DOWN, MIN_DIFFICULTY)

# ---------- reward tx builder ----------

def build_reward_tx(
    miner_address: str,
    mempool: Optional[List[Dict[str, Any]]] = None,
    mining_reward_input: Union[str, Dict[str, Any]] = "*--official-mining-reward--*",
    reward_asset: str = "COIN",
    mining_reward_amount: int = 50,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a canonical reward (coinbase) transaction for miners.

    - miner_address: destination address (string).
    - mempool: list of mempool tx dicts (optional) — used to sum fees.
    - mining_reward_input: the sentinel value the node uses to detect reward tx.
      This should be passed-through *exactly* as returned by node /health (string or dict).
      IMPORTANT: We DO NOT add timestamp or other keys to this sentinel object.
    - reward_asset: currency string (e.g. "COIN").
    - mining_reward_amount: base block reward (int).
    - metadata: optional metadata to add to the tx (e.g. {"miner": miner_address}).

    Returns a JSON-serializable tx dict accepted by the node.
    """
    # Sum fees from mempool (defensive)
    total_fees = 0
    if mempool:
        for tx in mempool:
            try:
                inp = tx.get("input", {}) or {}
                fee = int(inp.get("fee", 0))
                total_fees += fee
            except Exception:
                # ignore malformed fee fields
                continue

    amount = int(mining_reward_amount) + int(total_fees)

    tx = {
        "id": f"cb-{int(time.time())}",          # unique-ish id for debugging
        "input": mining_reward_input,            # <<< MUST be the sentinel exactly; no extra keys
        "output": {miner_address: {reward_asset: amount}},
        "metadata": dict(metadata or {"miner": miner_address})
    }

    return tx

# ---------- HTTP helpers ----------
def wait_ready(sess: requests.Session, base: str) -> Dict[str, Any]:
    while True:
        try:
            r = sess.get(f"{base}/health", timeout=(5,10))
            if r.ok:
                j = r.json()
                if j.get("ready") or j.get("ok") or j.get("status") == "ok" or j.get("height",0) > 0:
                    print("[miner_client] node is ready.")
                    return j
        except Exception:
            pass
        print("[miner_client] waiting for node health...")
        time.sleep(1)

def get_json(sess: requests.Session, base: str, path: str) -> Any:
    r = sess.get(f"{base}{path}", timeout=(5,20))
    r.raise_for_status()
    return r.json()
