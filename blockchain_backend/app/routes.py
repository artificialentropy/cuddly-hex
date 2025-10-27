import os
import uuid
import time, datetime
import requests
from collections import defaultdict, deque
from flask import request, jsonify
import traceback
import json
import hashlib
from typing import List, Dict, Tuple, Any, Union
# fcntl is POSIX-only; guard import for cross-platform compatibility
try:
    import fcntl  # for file locking on POSIX
except Exception:
    fcntl = None

import threading
import time as _time
from blockchain_backend.utils.helpers import normalize_timestamp, _strip_block_extras
from . import app, blockchain, wallet, transaction_pool, pubsub
from .app_state import ASSETS, PEER_URLS, PEERS, resolve_asset_fn
from blockchain_backend.core.block import Block
from blockchain_backend.core.blockchain import Blockchain
from blockchain_backend.wallet.transaction import Transaction, Asset
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.wallet_registry import REGISTRY
from blockchain_backend.wallet.helpers import address_balance_from_chain
from blockchain_backend.wallet.ledger import (
    build_ledger_from_chain,
    enforce_sufficient_funds,
    apply_tx_to_ledger,
)
from blockchain_backend.utils.config import (
    ROLE,                    # ROOT | VALIDATOR
    MINER_TOKEN,             # shared secret for /blocks/submit
    MINING_REWARD,
    MINING_REWARD_CURRENCY,
    MINING_REWARD_INPUT,     # sentinel input for coinbase
)

# Try to import the LevelDB store we created earlier. If unavailable, fall back to file-based store.
try:
    from blockchain_backend.db.level_db import open_default_store
    try:
        STORE = open_default_store()
        print(f"[routes] LevelDB store opened at: {STORE.path}")
    except Exception as e:
        print(f"[routes] failed to open LevelDB store: {e}")
        STORE = None
except Exception as e:
    STORE = None
    # don't spam logs in non-leveldb setups
    # print(f"[routes] leveldb integration not available: {e}")
CHAIN_STORE_PATH = os.getenv("CHAIN_STORE_PATH") or "/data/leveldb/chain_store.json"
CHAIN_STORE_PATH = os.path.abspath(CHAIN_STORE_PATH)
# -------------------------
# Basic rate limiting for tx submission
# -------------------------
RATE_BUCKETS = defaultdict(lambda: deque())  # ip -> timestamps
MAX_REQ = 20
WINDOW_S = 10
_CHAIN_SNAPSHOT_LOADED = False
_CHAIN_SNAPSHOT_LOCK = threading.Lock()

def _rate_ok(ip):
    q = RATE_BUCKETS[ip]
    now = time.time()
    while q and now - q[0] > WINDOW_S:
        q.popleft()
    if len(q) >= MAX_REQ:
        return False
    q.append(now)
    return True


@app.before_request
def guard_rate():
    if request.path in ("/wallet/transact", "/u/tx"):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        if not _rate_ok(ip):
            return jsonify({"error": "rate limit"}), 429


# -------------------------
# Sessions (in-memory)
# -------------------------
SESSIONS = {}  # token -> user_id

# -------------------------
# Chain store (optional, fast multi-worker sync)
# -------------------------
# keep file-path env var for backwards compat / multi-worker JSON visibility
CHAIN_STORE_PATH = os.getenv("CHAIN_STORE_PATH", "/data/chain_store.json")
CHAIN_DB_PATH = os.getenv("CHAIN_DB_PATH", None)  # optional explicit leveldb path


def _atomic_write_json(path, obj):
    """Write JSON to `path` with an exclusive lock. Creates parent dir if needed."""
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        try:
            # only attempt flock if fcntl is available
            if fcntl is not None:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX)
                except Exception:
                    pass
        except Exception:
            pass
        json.dump(obj, f, separators=(",", ":"), ensure_ascii=False)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
        try:
            if fcntl is not None:
                try:
                    fcntl.flock(f, fcntl.LOCK_UN)
                except Exception:
                    pass
        except Exception:
            pass
    try:
        os.replace(tmp_path, path)
    except Exception:
        # fallback to rename (Windows compatibility)
        try:
            os.remove(path)
        except Exception:
            pass
        try:
            os.rename(tmp_path, path)
        except Exception:
            pass


def _atomic_read_json(path):
    """Read JSON from `path` with a shared lock, returns None if not found or error."""
    try:
        with open(path, "r") as f:
            try:
                if fcntl is not None:
                    try:
                        fcntl.flock(f, fcntl.LOCK_SH)
                    except Exception:
                        pass
            except Exception:
                pass
            data = json.load(f)
            try:
                if fcntl is not None:
                    try:
                        fcntl.flock(f, fcntl.LOCK_UN)
                    except Exception:
                        pass
            except Exception:
                pass
            return data
    except FileNotFoundError:
        return None
    except Exception:
        return None

# ensure CHAIN_STORE_PATH default is absolute and writable

def merkle_from_txs(txs: List[Any], include_id: bool = False, parent_hexcat: bool = False) -> str:
    """
    Produce a merkle-root-like hex string from a list of tx dicts.
    """
    def leaf_hash(tx):
        try:
            if include_id and isinstance(tx, dict) and tx.get("id"):
                s = str(tx.get("id"))
            else:
                s = json.dumps(tx or {}, separators=(",", ":"), sort_keys=True)
        except Exception:
            s = str(tx)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    hs = [leaf_hash(t) for t in (txs or [])]

    if not hs:
        return hashlib.sha256(b"").hexdigest()

    while len(hs) > 1:
        next_level = []
        for i in range(0, len(hs), 2):
            left = hs[i]
            right = hs[i + 1] if i + 1 < len(hs) else left
            if parent_hexcat:
                try:
                    bleft = bytes.fromhex(left)
                    bright = bytes.fromhex(right)
                    ph = hashlib.sha256(bleft + bright).hexdigest()
                except Exception:
                    ph = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            else:
                ph = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(ph)
        hs = next_level
    return hs[0]


def header_json_hash(tip_version: int,
                     last_hash: str,
                     merkle: str,
                     timestamp: int,
                     difficulty: int,
                     nonce: int,
                     double: bool = False) -> Tuple[str, str]:
    """
    Compute two canonical header hashes derived from a JSON serialization and a bytes-like
    serialization. Returns a tuple (primary_hex, bytes_variant_hex).
    """
    hdr = {
        "version": int(tip_version or 0),
        "last_hash": last_hash or "",
        "merkle": merkle or "",
        "timestamp": int(timestamp or 0),
        "difficulty": int(difficulty or 0),
        "nonce": int(nonce or 0),
    }
    json_bytes = json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode("utf-8")

    try:
        b_parts = [
            int(tip_version or 0).to_bytes(4, "big", signed=False),
            (last_hash or "").encode("utf-8"),
            (merkle or "").encode("utf-8"),
            int(timestamp or 0).to_bytes(8, "big", signed=False),
            int(difficulty or 0).to_bytes(4, "big", signed=False),
            int(nonce or 0).to_bytes(8, "big", signed=False),
        ]
        bytes_serial = b"||".join([p if isinstance(p, bytes) else str(p).encode("utf-8") for p in b_parts])
    except Exception:
        bytes_serial = json_bytes

    if double:
        primary = hashlib.sha256(hashlib.sha256(json_bytes).digest()).hexdigest()
        bytes_variant = hashlib.sha256(hashlib.sha256(bytes_serial).digest()).hexdigest()
    else:
        primary = hashlib.sha256(json_bytes).hexdigest()
        bytes_variant = hashlib.sha256(bytes_serial).hexdigest()

    return primary, bytes_variant


def header_bytes_hashes(tip_version: int,
                        last_hash: str,
                        merkle: str,
                        timestamp: int,
                        difficulty: int,
                        nonce: int) -> List[Dict[str, Any]]:
    """
    Produce a small list of byte-serialization variants and their single/double sha256 hashes.
    """
    variants = []

    try:
        bA = (
            int(tip_version or 0).to_bytes(4, "big") +
            (last_hash or "").encode("utf-8") +
            (merkle or "").encode("utf-8") +
            int(timestamp or 0).to_bytes(8, "big") +
            int(difficulty or 0).to_bytes(4, "big") +
            int(nonce or 0).to_bytes(8, "big")
        )
        sA = hashlib.sha256(bA).hexdigest()
        dA = hashlib.sha256(hashlib.sha256(bA).digest()).hexdigest()
        variants.append({"single_sha": sA, "double_sha": dA, "params": {"name": "packed_be"}})
    except Exception:
        pass

    try:
        bB = (str(tip_version or 0) + (last_hash or "") + (merkle or "") + str(timestamp or 0) +
              str(difficulty or 0) + str(nonce or 0)).encode("utf-8")
        sB = hashlib.sha256(bB).hexdigest()
        dB = hashlib.sha256(hashlib.sha256(bB).digest()).hexdigest()
        variants.append({"single_sha": sB, "double_sha": dB, "params": {"name": "text_concat"}})
    except Exception:
        pass

    try:
        bC = ("|".join([
            str(tip_version or 0),
            (last_hash or ""),
            (merkle or ""),
            str(int(timestamp or 0)),
            str(int(difficulty or 0)),
            str(int(nonce or 0)),
        ])).encode("utf-8")
        sC = hashlib.sha256(bC).hexdigest()
        dC = hashlib.sha256(hashlib.sha256(bC).digest()).hexdigest()
        variants.append({"single_sha": sC, "double_sha": dC, "params": {"name": "delim_pipe"}})
    except Exception:
        pass

    try:
        bD = (
            int(tip_version or 0).to_bytes(4, "little") +
            (last_hash or "").encode("utf-8") +
            (merkle or "").encode("utf-8") +
            int(timestamp or 0).to_bytes(8, "little") +
            int(difficulty or 0).to_bytes(4, "little") +
            int(nonce or 0).to_bytes(8, "little")
        )
        sD = hashlib.sha256(bD).hexdigest()
        dD = hashlib.sha256(hashlib.sha256(bD).digest()).hexdigest()
        variants.append({"single_sha": sD, "double_sha": dD, "params": {"name": "packed_le"}})
    except Exception:
        pass

    return variants

def save_chain_to_disk(chain_json):
    """Save normalized chain JSON to disk for other workers to load."""
    try:
        d = os.path.dirname(CHAIN_STORE_PATH)
        if d and not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                print("[save_chain_to_disk] mkdir failed:", e)
        _atomic_write_json(CHAIN_STORE_PATH, chain_json)
        print("[save_chain_to_disk] succeeded")
    except PermissionError as pe:
        # fallback to /tmp (best-effort)
        try:
            tmp = "/tmp/chain_store.json"
            print("[save_chain_to_disk] permission denied; falling back to", tmp)
            _atomic_write_json(tmp, chain_json)
        except Exception as e:
            print("[save_chain_to_disk] fallback write failed:", e)
    except Exception as e:
        print("[save_chain_to_disk] failed:", e)

def load_chain_from_disk():
    """
    Load chain from the configured store.
    - If LevelDB STORE is present and has blocks, return list of blocks (ordered by 'height' if present).
    - Else fallback to reading CHAIN_STORE_PATH JSON file. If JSON file exists and STORE is available,
      populate LevelDB from the snapshot (idempotent best-effort).
    Returns: list of block dicts or None
    """
    # 1) If STORE is available, try reading from it first
    global STORE
    if STORE is not None:
        try:
            # If STORE has an iterator method, read blocks
            blocks = []
            # Adjust the iterator call to your LevelDB wrapper API if different.
            if hasattr(STORE, "iter_blocks"):
                for blk in STORE.iter_blocks():
                    if isinstance(blk, dict):
                        blocks.append(blk)
            elif hasattr(STORE, "get_all_blocks"):
                blocks = STORE.get_all_blocks() or []
            else:
                # Generic attempt: try numeric heights
                try:
                    i = 0
                    while True:
                        b = STORE.get_block_by_height(i)
                        if b is None:
                            break
                        blocks.append(b)
                        i += 1
                except Exception:
                    pass

            if blocks:
                # sort by height if present
                try:
                    blocks = sorted(blocks, key=lambda b: int(b.get("height", 0)))
                except Exception:
                    pass
                return blocks
        except Exception as e:
            print("[load_chain_from_disk] LevelDB read failed:", e)

    # 2) Try JSON snapshot
    try:
        snapshot = _atomic_read_json(CHAIN_STORE_PATH)
        if not snapshot:
            return None
        # If snapshot is a dict with 'chain', unwrap:
        if isinstance(snapshot, dict) and "chain" in snapshot:
            chain = snapshot["chain"]
        else:
            chain = snapshot

        if not isinstance(chain, list) or not chain:
            return None

        # If STORE present and empty, populate it from snapshot
        if STORE is not None:
            try:
                # check if STORE already has blocks
                has_blocks = False
                try:
                    # re-run quick check for any blocks
                    if hasattr(STORE, "iter_blocks"):
                        for _ in STORE.iter_blocks():
                            has_blocks = True
                            break
                    elif hasattr(STORE, "get_all_blocks"):
                        has_blocks = bool(STORE.get_all_blocks())
                except Exception:
                    has_blocks = False

                if not has_blocks:
                    print("[load_chain_from_disk] populating LevelDB STORE from chain snapshot...")
                    # Ensure blocks are ordered
                    try:
                        chain_sorted = sorted(chain, key=lambda b: int(b.get("height", 0)))
                    except Exception:
                        chain_sorted = chain

                    for blk in chain_sorted:
                        # If your STORE expects canonical block JSON shape, adapt here.
                        try:
                            # If STORE provides put_block API:
                            if hasattr(STORE, "put_block"):
                                STORE.put_block(blk)
                            elif hasattr(STORE, "put"):
                                # generic put with block hash or height
                                key = blk.get("hash") or str(blk.get("height"))
                                STORE.put(key, blk)
                            else:
                                # best-effort fallback: try store-specific insert
                                if hasattr(STORE, "db") and hasattr(STORE.db, "put"):
                                    key = (str(blk.get("height")) + ":" + (blk.get("hash") or ""))[:200]
                                    STORE.db.put(key.encode("utf-8"), json.dumps(blk).encode("utf-8"))
                                else:
                                    print("[load_chain_from_disk] unknown STORE api; skipping write to LevelDB")
                                    break
                        except Exception as e:
                            print(f"[load_chain_from_disk] warning: failed to put block height={blk.get('height')} hash={blk.get('hash')}: {e}")
                    print("[load_chain_from_disk] LevelDB populate complete.")
            except Exception as e:
                print("[load_chain_from_disk] error populating LevelDB:", e)

        # return the chain loaded from JSON
        return chain

    except FileNotFoundError:
        return None
    except Exception as e:
        print("[load_chain_from_disk] json read failed:", e)
        return None


# -------------------------
# Helpers / headers / JSON normalization
# -------------------------
def normalize_timestamp(ts):
    """Accept seconds / microseconds / nanoseconds heuristically — return seconds (int)."""
    try:
        t = int(ts)
    except Exception:
        return int(time.time())
    # heuristics:
    # seconds ~ 1e9, micro ~1e15, nano ~1e18
    if t > 10**16:  # definitely nanoseconds
        return t // 1_000_000_000
    if t > 10**12:  # microseconds
        return t // 1_000_000
    return t

def _normalize_value(v: Any) -> Any:
    """Helper: returns a JSON-serializable normalized value for v."""
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.hex()
        except Exception:
            return v.decode("utf-8", errors="ignore")
    if isinstance(v, dict):
        return {kk: _normalize_value(vv) for kk, vv in v.items()}
    if isinstance(v, list):
        return [_normalize_value(i) for i in v]
    if isinstance(v, datetime.datetime):
        return normalize_timestamp(v)
    # objects with to_json
    if hasattr(v, "to_json"):
        try:
            return _normalize_value(v.to_json())
        except Exception:
            pass
    # fallback to str
    return str(v)
def _serialize_sig_component(v):
    """
    Convert signature numeric component to hex string.
    If component already looks like hex or string, preserve.
    """
    if v is None:
        return None
    # already hex string?
    if isinstance(v, str):
        # if it's a decimal-like string, try to int->hex; else assume it's hex/base64 and return as-is
        try:
            if v.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in v):
                return v.lower()
            # if decimal string, convert to int then hex
            ival = int(v)
            return format(ival, "x")
        except Exception:
            return v
    # numeric (int/float) -> convert to int then hex
    try:
        ival = int(v)
        return format(ival, "x")
    except Exception:
        return str(v)


# def normalize_tx_json_for_output(tx_json):
#     """
#     Ensure tx_json.signature components are hex strings (avoid floats),
#     ensure input.timestamp normalized, and any other small cleanups.
#     Modifies tx_json in-place and returns it.
#     """
#     try:
#         inp = tx_json.get("input", {})
#         # normalize input timestamp if present
#         if "timestamp" in inp:
#             try:
#                 inp["timestamp"] = normalize_timestamp(inp["timestamp"])
#             except Exception:
#                 inp["timestamp"] = int(time.time())

#         sig = inp.get("signature")
#         if sig:
#             # signature may be a list/tuple of two big numbers; convert each to hex string
#             if isinstance(sig, (list, tuple)):
#                 new_sig = [_serialize_sig_component(v) for v in sig]
#                 inp["signature"] = new_sig
#             else:
#                 # single value
#                 inp["signature"] = _serialize_sig_component(sig)
#         tx_json["input"] = inp
#     except Exception:
#         pass
#     return tx_json


def normalize_block_json_for_output(raw_block_json, height=None):
    """
    Normalize one block JSON dict for safe broadcast / HTTP output:
      - ensure height is set (if provided use it, else keep existing or None)
      - normalize timestamp to seconds
      - normalize inner tx signatures/timestamps
    Returns a new dict (not modifying the original ideally).
    """
    b = dict(raw_block_json) if raw_block_json is not None else {}
    # set height if provided
    if height is not None:
        b["height"] = height
    else:
        # if existing is falsy, try to leave it; we'll ensure it's numeric when enumerating
        if b.get("height") in (None, "null", ""):
            b["height"] = None

    # normalize timestamp
    if "timestamp" in b:
        try:
            b["timestamp"] = normalize_timestamp(b["timestamp"])
        except Exception:
            b["timestamp"] = int(time.time())

    # normalize each tx inside data
    try:
        txs = b.get("data", []) or []
        norm_txs = []
        for tx in txs:
            # tx might be object or dict
            if isinstance(tx, dict):
                norm_txs.append(normalize_tx_json_for_output(tx))
            else:
                norm_txs.append(tx)
        b["data"] = norm_txs
    except Exception:
        pass

    return b

# ... rest of your routes remain unchanged ...
# (Everything after normalize_block_json_for_output is identical to your original file)


# -------------------------
# Helpers / headers / JSON normalization
# -------------------------
def normalize_timestamp(ts):
    """Accept seconds / microseconds / nanoseconds heuristically — return seconds (int)."""
    try:
        t = int(ts)
    except Exception:
        return int(time.time())
    # heuristics:
    # seconds ~ 1e9, micro ~1e15, nano ~1e18
    if t > 10**16:  # definitely nanoseconds
        return t // 1_000_000_000
    if t > 10**12:  # microseconds
        return t // 1_000_000
    return t


def _serialize_sig_component(v):
    """
    Convert signature numeric component to hex string.
    If component already looks like hex or string, preserve.
    """
    if v is None:
        return None
    # already hex string?
    if isinstance(v, str):
        # if it's a decimal-like string, try to int->hex; else assume it's hex/base64 and return as-is
        try:
            if v.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in v):
                return v.lower()
            # if decimal string, convert to int then hex
            ival = int(v)
            return format(ival, "x")
        except Exception:
            return v
    # numeric (int/float) -> convert to int then hex
    try:
        ival = int(v)
        return format(ival, "x")
    except Exception:
        return str(v)


def normalize_tx_json_for_output(tx_json):
    """
    Ensure tx_json.signature components are hex strings (avoid floats),
    ensure input.timestamp normalized, and any other small cleanups.
    Modifies tx_json in-place and returns it.
    """
    try:
        inp = tx_json.get("input", {})
        # normalize input timestamp if present
        if "timestamp" in inp:
            try:
                inp["timestamp"] = normalize_timestamp(inp["timestamp"])
            except Exception:
                inp["timestamp"] = int(time.time())

        sig = inp.get("signature")
        if sig:
            # signature may be a list/tuple of two big numbers; convert each to hex string
            if isinstance(sig, (list, tuple)):
                new_sig = [_serialize_sig_component(v) for v in sig]
                inp["signature"] = new_sig
            else:
                # single value
                inp["signature"] = _serialize_sig_component(sig)
        tx_json["input"] = inp
    except Exception:
        pass
    return tx_json


def normalize_block_json_for_output(raw_block_json, height=None):
    """
    Normalize one block JSON dict for safe broadcast / HTTP output:
      - ensure height is set (if provided use it, else keep existing or None)
      - normalize timestamp to seconds
      - normalize inner tx signatures/timestamps
    Returns a new dict (not modifying the original ideally).
    """
    b = dict(raw_block_json) if raw_block_json is not None else {}
    # set height if provided
    if height is not None:
        b["height"] = height
    else:
        # if existing is falsy, try to leave it; we'll ensure it's numeric when enumerating
        if b.get("height") in (None, "null", ""):
            b["height"] = None

    # normalize timestamp
    if "timestamp" in b:
        try:
            b["timestamp"] = normalize_timestamp(b["timestamp"])
        except Exception:
            b["timestamp"] = int(time.time())

    # normalize each tx inside data
    try:
        txs = b.get("data", []) or []
        norm_txs = []
        for tx in txs:
            # tx might be object or dict
            if isinstance(tx, dict):
                norm_txs.append(normalize_tx_json_for_output(tx))
            else:
                norm_txs.append(tx)
        b["data"] = norm_txs
    except Exception:
        pass

    return b


def normalize_chain_json_for_output(raw_chain_json):
    """
    Accept raw list of block dicts (as produced by blockchain.to_json()).
    Return a normalized list where:
      - each block has explicit height (index in list)
      - timestamps normalized
      - tx signatures normalized to hex strings
    """
    if not isinstance(raw_chain_json, list):
        return raw_chain_json
    out = []
    for idx, rb in enumerate(raw_chain_json):
        try:
            nb = normalize_block_json_for_output(rb, height=idx)
            out.append(nb)
        except Exception:
            out.append(rb)
    return out


# -------------------------
# Auto sync (validator behavior)
# -------------------------
def auto_sync():
    """If this node is a validator, sync from ROOT on demand."""
    if ROLE != "VALIDATOR":
        return

    root_host = os.getenv("ROOT_HOST", "node0")
    root_port = int(os.getenv("ROOT_PORT", 5000))
    base = f"http://{root_host}:{root_port}"

    try:
        resp = requests.get(f"{base}/blockchain", timeout=5)
        resp.raise_for_status()
        chain_data = resp.json()

        # If the remote returns our debug envelope {"pid":..,"length":..,"chain": [...]} 
        if isinstance(chain_data, dict) and "chain" in chain_data:
            remote_chain = chain_data["chain"]
        else:
            remote_chain = chain_data

        sanitized_remote = [ _strip_block_extras(b) for b in (remote_chain or []) ]
        if hasattr(Blockchain, "from_json"):
            try:
                incoming_chain = Blockchain.from_json(sanitized_remote).chain
            except Exception:
                incoming_chain = [Block.from_json(b) for b in sanitized_remote]
        else:
            incoming_chain = [Block.from_json(b) for b in sanitized_remote]
        if len(incoming_chain) > len(blockchain.chain):
            blockchain.replace_chain(incoming_chain)
            print(f"[auto_sync] updated local chain to height {len(blockchain.chain)-1}")
            # persist normalized JSON for other workers
            try:
                save_chain_to_disk(normalize_chain_json_for_output(remote_chain))
            except Exception:
                pass
    except Exception as e:
        print(f"[auto_sync] failed: {e}")


def _validator_background_sync(interval_sec: int = 5, max_failures: int = 8):
    """
    Background thread for validators: periodically attempt to auto_sync() from ROOT.
    Runs quietly (logs) and uses exponential backoff on failures.
    """
    failures = 0
    backoff = interval_sec
    while True:
        try:
            if ROLE == "VALIDATOR":
                auto_sync()
            # reset failure state on success
            failures = 0
            backoff = interval_sec
        except Exception as e:
            failures += 1
            # print limited debug so logs show reason
            print(f"[bg_sync] auto_sync failed ({failures}): {e}")
            # exponential backoff (cap)
            backoff = min(backoff * 2, 60)
        _time.sleep(backoff)

# --- Block normalizer -------------------------------------------------------
def normalize_block_for_output(block: Union[Dict, Any]) -> Dict:
    """
    Normalize a Block instance or block JSON dict into a JSON-serializable dict.
    Ensures:
      - timestamp -> int seconds
      - data (tx list) normalized via normalize_tx_json_for_output
      - any bytes/bytearrays inside are hex-encoded
    """
    # If it's a block object with to_json or attrs, convert to dict first
    if hasattr(block, "to_json"):
        try:
            raw = block.to_json()
        except Exception:
            # try to build from attributes
            raw = _block_obj_to_dict(block)
    elif isinstance(block, dict):
        raw = dict(block)  # shallow copy
    else:
        # try to extract attributes
        raw = _block_obj_to_dict(block)

    out = {}
    # canonical simple fields
    for k in ("version", "last_hash", "hash", "nonce", "difficulty", "height"):
        if k in raw:
            out[k] = _normalize_value(raw[k])

    # timestamp normalization
    if "timestamp" in raw:
        out["timestamp"] = normalize_timestamp(raw["timestamp"])
    else:
        out["timestamp"] = 0

    # normalize data (txs)
    txs = raw.get("data", [])
    normed = []
    if isinstance(txs, (list, tuple)):
        for tx in txs:
            try:
                normed.append(normalize_tx_json_for_output(tx))
            except Exception:
                normed.append(_normalize_value(tx))
    else:
        # if data field is something strange, try to coerce to list
        normed = [_normalize_value(txs)]

    out["data"] = normed

    # copy any other fields shallowly but normalized
    for k, v in raw.items():
        if k in out:
            continue
        if k == "data":
            continue
        out[k] = _normalize_value(v)

    return out


def _block_obj_to_dict(obj: Any) -> Dict:
    """
    Best-effort conversion of a Block object to dict by reading common attributes.
    """
    d = {}
    for attr in ("version", "last_hash", "hash", "nonce", "difficulty", "timestamp", "data", "height"):
        if hasattr(obj, attr):
            d[attr] = getattr(obj, attr)
    # include anything in __dict__
    if hasattr(obj, "__dict__"):
        for k, v in vars(obj).items():
            if k not in d:
                d[k] = v
    return d
# start thread at module import (only in validators)
if ROLE == "VALIDATOR":
    t = threading.Thread(target=_validator_background_sync, kwargs={"interval_sec": 5}, daemon=True)
    t.start()
    print("[bg_sync] validator background sync started (interval 5s)")
# -------------------------
# Blockchain Routes
# -------------------------
@app.route("/")
def route_default():
    if ROLE == "VALIDATOR":
        auto_sync()
    return f"Welcome to blockchain. First block: {blockchain.chain[0].to_json()}"


@app.route("/health")
def health():
    tip = blockchain.chain[-1]
    tip_hash = getattr(tip, "hash", None)
    ready = len(blockchain.chain) > 1
    return jsonify({"ok": True, "ready": ready, "height": len(blockchain.chain), "tip": tip_hash})

@app.route("/blockchain")
def route_blockchain():
    global _CHAIN_SNAPSHOT_LOADED
    # Run auto_sync for validators if desired
    if ROLE == "VALIDATOR":
        auto_sync()

    # Attempt to load/populate snapshot only once per process
    if not _CHAIN_SNAPSHOT_LOADED:
        with _CHAIN_SNAPSHOT_LOCK:
            if not _CHAIN_SNAPSHOT_LOADED:
                try:
                    disk = load_chain_from_disk()
                    if disk:
                        print(f"[startup] loaded {len(disk)} blocks from disk snapshot (one-time)")
                        # only attempt replace/populate via the same startup logic you have
                        # call your existing startup adoption function (factor out if needed)
                        # For now we only log — avoid replacing here to preserve safety.
                except Exception as e:
                    print("[startup] one-time load_chain_from_disk() failed:", e)
                _CHAIN_SNAPSHOT_LOADED = True

    # Source of truth for responses: in-memory chain
    raw = blockchain.to_json()
    normalized = normalize_chain_json_for_output(raw)
    return jsonify({"pid": os.getpid(), "length": len(normalized), "chain": normalized})



# @app.route("/blockchain")
# def route_blockchain():
#     """
#     Return normalized chain JSON (height + timestamp in seconds + signature hex strings).
#     Also include pid + length for debugging multi-worker divergence.
#     Prefer reading the persisted normalized chain store if present.
#     """
#     if ROLE == "VALIDATOR":
#         auto_sync()

#     # Prefer disk-based normalized chain if present (helps multiple workers)
#     disk = load_chain_from_disk()
#     if disk:
#         print(f"[startup] loaded {len(disk)} blocks from disk snapshot")
#         # If your in-memory chain is disk only genesis and loaded has more blocks, replace it:
#         try:
#             if len(disk) > 1:
#                 # adapt following lines to your blockchain object methods:
#                 # set internal chain list or re-initialize from loaded blocks
#                 if hasattr(blockchain, "replace_chain"):
#                     # If replace_chain exists and expects a list of block dicts
#                     blockchain.replace_chain(disk)
#                     print("[startup] in-memory chain replaced from snapshot")
#                 else:
#                     # fallback: directly set attribute if available
#                     if hasattr(blockchain, "chain"):
#                         blockchain.chain = disk
#                         print("[startup] in-memory chain set from snapshot")
#         except Exception as e:
#             print("[startup] failed to set in-memory chain from snapshot:", e)
#     else:
#         print("[startup] no chain snapshot found on disk (or LevelDB had blocks already).")
#     if disk:
#         normalized = disk
#     else:
#         raw = blockchain.to_json()
#         normalized = normalize_chain_json_for_output(raw)
#     return jsonify({"pid": os.getpid(), "length": len(normalized), "chain": normalized})


@app.route("/blockchain/range")
def route_blockchain_range():
    start = int(request.args.get("start", 0))
    end = int(request.args.get("end", start + 25))

    raw = blockchain.to_json()
    sliced = raw[start:end]
    normalized = normalize_chain_json_for_output(sliced)
    return jsonify(normalized)


@app.route("/blockchain/length")
def route_blockchain_length():
    return jsonify(len(blockchain.chain))


@app.route("/blockchain/mine")
def route_blockchain_mine():
    """
    Optional local mining endpoint (useful for dev).
    In your target topology this is DISABLED on ROOT/VALIDATOR unless ENABLE_MINING_ROUTE=true.
    """
    if os.getenv("ENABLE_MINING_ROUTE", "").lower() not in ("1", "true", "yes"):
        return jsonify({"error": "mining disabled on this node"}), 403

    candidates = transaction_pool.get_transactions_for_mining()
    if not candidates:
        return jsonify({"error": "no transactions"}), 400

    block_tx_jsons = []
    try:
        ledger = build_ledger_from_chain(blockchain)
        total_fees = 0

        for tx in candidates:
            Transaction.is_valid_transaction(tx, resolve_asset_fn=resolve_asset_fn)
            tx_json = tx.to_json()
            # ensure tx timestamps are normalized
            if "input" in tx_json and "timestamp" in tx_json["input"]:
                tx_json["input"]["timestamp"] = normalize_timestamp(tx_json["input"]["timestamp"])
            # ensure signature serialized correctly for broadcast persistence
            tx_json = normalize_tx_json_for_output(tx_json)
            fee = int((tx_json.get("input") or {}).get("fee", 0))
            enforce_sufficient_funds(tx_json, ledger)
            apply_tx_to_ledger(tx_json, ledger)
            block_tx_jsons.append(tx_json)
            total_fees += fee

        coinbase_amount = int(MINING_REWARD) + int(total_fees)
        block_tx_jsons.append(
            Transaction.reward_transaction(
                miner_wallet=wallet,
                currency=MINING_REWARD_CURRENCY,
                amount=coinbase_amount
            ).to_json()
        )

        blockchain.add_block(block_tx_jsons)
        block = blockchain.chain[-1]
        transaction_pool.clear_blockchain_transactions(blockchain)

        # persist normalized JSON for cross-worker visibility and for peers on fetch
        try:
            raw_chain = blockchain.to_json()
            normalized_chain = normalize_chain_json_for_output(raw_chain)
            save_chain_to_disk(normalized_chain)
        except Exception as e:
            print("[mine] save_chain_to_disk failed:", e)

        if pubsub:
            # keep broadcasting the Block object as before, but also try to broadcast JSON if supported
            try:
                pubsub.broadcast_block(block)
            except Exception:
                # non-fatal: continue
                pass
            try:
                # If pubsub has broadcast_block_json, prefer that (non-breaking)
                if hasattr(pubsub, "broadcast_block_json"):
                    pubsub.broadcast_block_json(normalized_chain[-1])
            except Exception:
                pass
        
        return jsonify(normalize_block_json_for_output(block.to_json(), height=len(blockchain.chain) - 1))

    except Exception as e:
        return jsonify({"error": f"mining failed: {e}"}), 500


# -------------------------
# Wallet Routes
# -------------------------
@app.route("/wallet/info")
def route_wallet_info():
    return jsonify({"address": wallet.address, "balance": wallet.balance})


@app.route("/wallet/transact", methods=["POST"])
def route_wallet_transact():
    payload = request.get_json(force=True)
    action = payload.get("action", "transfer")

    try:
        if action == "list":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.list_asset_for_sale(
                owner_wallet=wallet,
                asset=asset,
                price=int(payload["price"]),
                currency=payload.get("currency", "COIN"),
                metadata=payload.get("metadata"),
            )

        elif action == "purchase":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404

            # Prefer REGISTRY as canonical wallet lookup for owners; fallback to PEERS
            def _get_owner_wallet(addr):
                try:
                    if hasattr(REGISTRY, "get_wallet_by_address"):
                        return REGISTRY.get_wallet_by_address(addr)
                    if hasattr(REGISTRY, "get_wallet"):
                        return REGISTRY.get_wallet(addr)
                except Exception:
                    pass
                return PEERS.get(addr)

            tx = Transaction.purchase_asset(
                buyer_wallet=wallet,
                asset=asset,
                get_owner_wallet_fn=_get_owner_wallet,
                metadata=payload.get("metadata"),
            )

        elif action == "transfer_asset":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.transfer_asset_direct(
                sender_wallet=wallet,
                recipient_address=payload["recipient"],
                asset=asset,
                metadata=payload.get("metadata"),
            )

        else:  # default: coin transfer
            recipient = payload["recipient"]
            amount = int(payload["amount"])
            currency = payload.get("currency", "COIN")
            if wallet.balances.get(currency, 0) < amount:
                raise Exception(f"Insufficient {currency} balance")

            tx = Transaction(
                sender_wallet=wallet,
                recipient=recipient,
                amount_map={currency: amount},
            )
            if payload.get("metadata"):
                tx.metadata.update(payload["metadata"])

    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        transaction_pool.set_transaction(tx)
    except Exception as e:
        return jsonify({"error": f"rejected by pool: {e}"}), 400

    if pubsub:
        pubsub.broadcast_transaction(tx)

    return jsonify(tx.to_json())


@app.route("/transactions")
def route_transactions():
    return jsonify(transaction_pool.transaction_data())


@app.route("/tx/<txid>")
def get_tx(txid):
    height = None
    tx_obj = None
    for i, block in enumerate(blockchain.chain):
        for tx in getattr(block, "data", []) or []:
            if tx.get("id") == txid:
                height = i
                tx_obj = tx
                break
        if tx_obj:
            break
    if not tx_obj:
        return jsonify({"found": False}), 404
    tip = len(blockchain.chain) - 1
    conf = max(0, tip - height)
    return jsonify({"found": True, "tx": tx_obj, "block_height": height, "confirmations": conf})


@app.route("/known-addresses")
def route_known_addresses():
    known = set()
    for block in blockchain.chain:
        for tx in getattr(block, "data", []) or []:
            out = tx.get("output") or {}
            known.update(out.keys())
    return jsonify(list(known))


# -------------------------
# Peer Management
# -------------------------
@app.route("/peers", methods=["GET"])
def list_peers():
    return jsonify(list(PEER_URLS))


@app.route("/peers", methods=["POST"])
def add_peer():
    data = request.get_json(force=True)
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"error": "peer_url required"}), 400
    if peer_url in PEER_URLS:
        return jsonify({"message": "already a peer"}), 200

    try:
        resp = requests.get(f"{peer_url}/blockchain", timeout=5)
        resp.raise_for_status()
        remote_data = resp.json()

        # If remote returns the debug envelope, extract chain
        if isinstance(remote_data, dict) and "chain" in remote_data:
            remote_chain_raw = remote_data["chain"]
        else:
            remote_chain_raw = remote_data

        sanitized_remote = [ _strip_block_extras(b) for b in (remote_chain_raw or []) ]
        if hasattr(Blockchain, "from_json"):
            try:
                incoming_chain = Blockchain.from_json(sanitized_remote).chain
            except Exception:
                incoming_chain = [Block.from_json(b) for b in sanitized_remote]
        else:
            incoming_chain = [Block.from_json(b) for b in sanitized_remote]

        blockchain.replace_chain(incoming_chain)
        # persist normalized chain for local workers
        try:
            save_chain_to_disk(normalize_chain_json_for_output(remote_chain_raw))
        except Exception:
            pass

        PEER_URLS.add(peer_url)

        # Optional: attempt to fetch known-addresses from peer and register placeholder wallets
        try:
            r2 = requests.get(f"{peer_url}/known-addresses", timeout=3)
            if r2.ok:
                for addr in r2.json():
                    try:
                        if not REGISTRY.get_wallet(addr):
                            w = Wallet(blockchain)
                            REGISTRY.add_wallet(w, label=addr)
                    except Exception:
                        pass
        except Exception:
            pass

        return jsonify({"message": "peer added and chain synchronized", "peer": peer_url}), 200
    except Exception as e:
        return jsonify({"error": f"Could not sync from peer: {e}"}), 500

@app.route("/sync_from_peer", methods=["POST"])
def sync_from_peer():
    """
    Root-only endpoint. Validator nodes may POST their base URL (peer_url) here
    so that root fetches the validator's chain and adopts it if it's longer.
    Returns 200 with {"status":"replaced", "new_length": n} on success,
    200 {"status":"no_change", "length": n} if no replacement needed,
    403 if not allowed on validators, or 400/500 for errors.
    """
    # Protect: only ROOT should accept incoming sync requests
    if ROLE != "ROOT":
        return jsonify({"error": "only root accepts sync requests"}), 403

    data = request.get_json(silent=True) or {}
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"error": "missing peer_url"}), 400

    try:
        app.logger.info(f"[sync_from_peer] fetching chain from {peer_url}")
        r = requests.get(f"{peer_url}/blockchain", timeout=10)
        r.raise_for_status()
        payload = r.json()

        # normalize chain payload shape
        if isinstance(payload, dict) and "chain" in payload:
            remote_chain_raw = payload["chain"]
        else:
            remote_chain_raw = payload

        # sanitize and drop any non-block extras (like 'version')
        sanitized = [{k: v for k, v in (b or {}).items() if k != "version"} for b in (remote_chain_raw or [])]

        # Convert to Block objects / Blockchain instance using existing helpers
        try:
            # prefer Blockchain.from_json if available (keeps internal invariants)
            remote_bc = Blockchain.from_json(sanitized)
            incoming_chain = remote_bc.chain
        except Exception:
            incoming_chain = [Block.from_json(b) for b in sanitized]

        # ensure we actually got something sensible
        if not incoming_chain:
            return jsonify({"error": "fetched empty chain from peer"}), 400

        from blockchain_backend.app import blockchain as app_blockchain

        remote_len = len(incoming_chain)
        local_len = len(app_blockchain.chain)
        app.logger.info(f"[sync_from_peer] remote_len={remote_len}, local_len={local_len}")

        if remote_len > local_len:
            # Replace chain in memory (and rely on blockchain.replace_chain to persist LevelDB if it does)
            app_blockchain.replace_chain(incoming_chain)
            # Persist normalized JSON for other workers / future starts
            try:
                normalized = normalize_chain_json_for_output(remote_chain_raw)
                save_chain_to_disk(normalized)
            except Exception as e:
                app.logger.exception("[sync_from_peer] failed to save_chain_to_disk")

            # Broadcast new tip if pubsub supports JSON broadcast (best-effort)
            try:
                if pubsub and hasattr(pubsub, "broadcast_block_json"):
                    pubsub.broadcast_block_json(normalize_block_json_for_output(incoming_chain[-1], height=len(app_blockchain.chain)-1))
            except Exception:
                app.logger.exception("[sync_from_peer] pubsub broadcast failed (ignored)")

            app.logger.info(f"[sync_from_peer] replaced chain: new_len={len(app_blockchain.chain)}")
            return jsonify({"status": "replaced", "new_length": len(app_blockchain.chain)}), 200

        # remote not longer -> no action
        app.logger.info("[sync_from_peer] no replacement needed (remote not longer)")
        return jsonify({"status": "no_change", "length": local_len}), 200

    except Exception as exc:
        app.logger.exception("[sync_from_peer] failed")
        return jsonify({"error": str(exc)}), 500

# -------------------------
# Asset registry
# -------------------------
@app.route("/asset/register", methods=["POST"])
def asset_register():
    data = request.get_json(force=True)
    asset_id = data["asset_id"]
    owner = data.get("owner", wallet.address)
    price = int(data.get("price", 0))
    currency = data.get("currency", "COIN")
    transferable = bool(data.get("transferable", True))

    if asset_id in ASSETS:
        return jsonify({"error": "asset_id already exists"}), 400

    ASSETS[asset_id] = Asset(
        asset_id=asset_id, owner=owner, price=price, currency=currency, transferable=transferable
    )
    return jsonify(
        {
            "ok": True,
            "asset": {
                "asset_id": asset_id,
                "owner": owner,
                "price": price,
                "currency": currency,
                "transferable": transferable,
            },
        }
    )


@app.route("/asset/<asset_id>", methods=["GET"])
def asset_get(asset_id):
    a = ASSETS.get(asset_id)
    if not a:
        return jsonify({"error": "asset not found"}), 404
    return jsonify(
        {
            "asset_id": a.asset_id,
            "owner": a.owner,
            "price": a.price,
            "currency": a.currency,
            "transferable": a.transferable,
        }
    )


# -------------------------
# Auth + user-scoped routes
# -------------------------
@app.route("/wallet/balance/<addr>")
def route_wallet_balance(addr):
    try:
        bal = address_balance_from_chain(blockchain, addr)
        return jsonify({"address": addr, "balances": bal})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True)
    user_id = (data.get("user_id") or "").strip()
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    w = REGISTRY.get_wallet_by_label(user_id)
    if not w:
        w = Wallet(blockchain)
        REGISTRY.add_wallet(w, label=user_id)

    token = str(uuid.uuid4())
    SESSIONS[token] = user_id

    return jsonify({
        "ok": True,
        "token": token,
        "user_id": user_id,
        "address": w.address,
        "public_key": w.public_key
    })


def _wallet_from_token():
    token = request.headers.get("X-Auth-Token") or (request.json or {}).get("token")
    if not token or token not in SESSIONS:
        raise Exception("invalid or missing token")
    user_id = SESSIONS[token]
    w = REGISTRY.get_wallet_by_label(user_id)
    if not w:
        w = Wallet(blockchain)
        REGISTRY.add_wallet(w, label=user_id)
    return user_id, w


@app.route("/u/me", methods=["GET"])
def u_me():
    try:
        user_id, w = _wallet_from_token()
        bal = address_balance_from_chain(blockchain, w.address, seed=False)
        return jsonify({"user_id": user_id, "address": w.address, "balances": bal or {"COIN": 0}})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/u/tx", methods=["POST"])
def u_tx():
    """
    User-scoped transaction entrypoint.
    Requires X-Auth-Token (or 'token' in JSON).
    """
    try:
        user_id, user_wallet = _wallet_from_token()
    except Exception as e:
        return jsonify({"error": str(e)}), 401

    payload = request.get_json(force=True)
    action = payload.get("action", "transfer")

    try:
        if action == "list":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            if asset.owner != user_wallet.address:
                return jsonify({"error": "Only the asset owner may list it for sale"}), 403
            tx = Transaction.list_asset_for_sale(
                owner_wallet=user_wallet,
                asset=asset,
                price=int(payload["price"]),
                currency=payload.get("currency", "COIN"),
                metadata=payload.get("metadata"),
            )

        elif action == "purchase":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.purchase_asset(
                buyer_wallet=user_wallet,
                asset=asset,
                get_owner_wallet_fn=lambda addr: REGISTRY.get_wallet(addr),
                metadata=payload.get("metadata"),
            )

        elif action == "transfer_asset":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            if asset.owner != user_wallet.address:
                return jsonify({"error": "Only the asset owner may to transfer it"}), 403
            recipient = payload["recipient"]
            tx = Transaction.transfer_asset_direct(
                sender_wallet=user_wallet,
                recipient_address=recipient,
                asset=asset,
                metadata=payload.get("metadata"),
            )

        else:
            recipient = payload["recipient"]
            amount = int(payload["amount"])
            currency = payload.get("currency", "COIN")

            tx = Transaction(
                sender_wallet=user_wallet,
                recipient=recipient,
                amount_map={currency: amount},
            )
            if payload.get("metadata"):
                tx.metadata.update(payload["metadata"])

    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        transaction_pool.set_transaction(tx)
    except Exception as e:
        return jsonify({"error": f"rejected by pool: {e}"}), 400

    if pubsub:
        pubsub.broadcast_transaction(tx)

    return jsonify(tx.to_json())


# -------------------------
# Miner integration (external miners)
# -------------------------
def _sum_fees(block_tx_jsons):
    total = 0
    for tx in block_tx_jsons:
        inp = tx.get("input") or {}
        try:
            total += int(inp.get("fee", 0))
        except Exception:
            pass
    return total


@app.route("/mempool", methods=["GET"])
def route_mempool():
    """Public endpoint for miners to fetch candidate txs (FIFO)."""
    items = transaction_pool.get_transactions_for_mining()
    return jsonify([tx.to_json() for tx in items])


@app.route("/blocks/submit", methods=["POST"])
def route_blocks_submit():
    """
    Miners submit a pre-mined block here. Requires X-Miner-Token.
    Body: { "block": <Block JSON dict> }
    """
    token = request.headers.get("X-Miner-Token", "")
    if not MINER_TOKEN or token != MINER_TOKEN:
        return jsonify({"error": "unauthorized miner"}), 401

    payload = request.get_json(force=True) or {}
    block_json = payload.get("block")
    if not block_json:
        return jsonify({"error": "block required"}), 400

    # Normalize timestamps in incoming JSON to seconds to avoid nanosecond issues
    try:
        if isinstance(block_json, dict) and "timestamp" in block_json:
            block_json["timestamp"] = normalize_timestamp(block_json["timestamp"])
        # normalize inner tx timestamps and signatures if present (best-effort)
        if isinstance(block_json, dict) and "data" in block_json:
            normed_txs = []
            for tx in block_json.get("data", []):
                if isinstance(tx, dict):
                    if "input" in tx and "timestamp" in tx["input"]:
                        tx["input"]["timestamp"] = normalize_timestamp(tx["input"]["timestamp"])
                    # leave signature as-is; normalize_tx_json_for_output below helps when broadcasting out
                normed_txs.append(tx)
            block_json["data"] = normed_txs
    except Exception:
        pass

    # We'll attempt to parse and validate the candidate; on validation error we produce diagnostics.
    cand = None
    last_block = None
    try:
        cand = Block.from_json(block_json)

        # linkage
        last_block = blockchain.chain[-1]
        if cand.last_hash != last_block.hash:
            return jsonify({"error": "bad last_hash"}), 400

        # header / pow checks (this will raise on invalid header/PoW)
        Block.is_valid_block(last_block, cand)

        # tx validation (structural + economic)
        ledger = build_ledger_from_chain(blockchain)
        txs = list(cand.data)
        if not txs:
            return jsonify({"error": "empty block"}), 400

        reward_tx = txs[-1]
        normal_txs = txs[:-1]

        for tx_json in normal_txs:
            tx_obj = Transaction.from_json(tx_json)
            Transaction.is_valid_transaction(tx_obj, resolve_asset_fn=resolve_asset_fn)
            enforce_sufficient_funds(tx_json, ledger)
            apply_tx_to_ledger(tx_json, ledger)

        # reward checks
        rt = Transaction.from_json(reward_tx)
        if rt.input != MINING_REWARD_INPUT:
            return jsonify({"error": "last tx must be reward"}), 400

        total_fees = _sum_fees(normal_txs)
        out = rt.output or {}
        if len(out) != 1:
            return jsonify({"error": "reward must pay exactly one address"}), 400
        (miner_addr, cm) = next(iter(out.items()))
        paid = int(cm.get(MINING_REWARD_CURRENCY, 0))
        expected = int(MINING_REWARD) + int(total_fees)
        if paid != expected:
            return jsonify({"error": f"bad reward: paid={paid}, expected={expected}"}), 400

        # append & broadcast (in-memory)
        blockchain.chain.append(cand)
        transaction_pool.clear_blockchain_transactions(blockchain)

        # persist normalized JSON for cross-worker visibility
        # try:
        #     raw_chain = blockchain.to_json()
        #     normalized_chain = normalize_chain_json_for_output(raw_chain)
        #     save_chain_to_disk(normalized_chain)
        #     print("[blocks/submit] save_chain_to_disk succeeded")
        # except Exception as e:
        #     print("[blocks/submit] save_chain_to_disk failed:", e)

        try:
            # normalized JSON for the last block only
            last_block_json = normalize_block_for_output(cand)   # <-- implement/replace with your normalizer
            # write single block into STORE (if you have put_block)
            if STORE is not None and hasattr(STORE, "put_block"):
                STORE.put_block(last_block_json)
            # optionally also save full chain snapshot so other workers can read JSON file
            try:
                raw_chain = blockchain.to_json()
                normalized_chain = normalize_chain_json_for_output(raw_chain)
                save_chain_to_disk(normalized_chain)
            except Exception:
                pass
            print("[pubsub] appended block persisted")
        except Exception as e:
            print("[pubsub] persist failed:", e)

        if pubsub:
            try:
                pubsub.broadcast_block(cand)
            except Exception:
                pass
            try:
                if hasattr(pubsub, "broadcast_block_json"):
                    pubsub.broadcast_block_json(normalized_chain[-1])
            except Exception:
                pass

        return jsonify({"ok": True, "height": len(blockchain.chain), "tip": cand.hash})

    except Exception as exc:
        err_text = str(exc)
        if cand is None or last_block is None:
            return jsonify({"error": f"submit failed: {err_text}"}), 400

        # Diagnostic generation (unchanged from original)...
        try:
            submitted_hash = getattr(cand, "hash", None)
            block_txs = list(getattr(cand, "data", []))
            tip_version = 1
            last_hash_val = getattr(cand, "last_hash", None)
            ts_val = getattr(cand, "timestamp", None)
            diff_val = getattr(cand, "difficulty", None)
            nonce_val = getattr(cand, "nonce", None)

            variants = []
            for include_id in (False, True):
                for parent_hexcat in (False, True):
                    try:
                        merkle = merkle_from_txs(block_txs, include_id=include_id, parent_hexcat=parent_hexcat)
                    except Exception as ex:
                        merkle = f"err:{ex}"
                    j_single, j_bytes = header_json_hash(tip_version, last_hash_val, merkle, ts_val, diff_val, nonce_val, double=False)
                    j_double, _ = header_json_hash(tip_version, last_hash_val, merkle, ts_val, diff_val, nonce_val, double=True)
                    bytes_variants = header_bytes_hashes(tip_version, last_hash_val, merkle, ts_val, diff_val, nonce_val)

                    variants.append({
                        "include_id": include_id,
                        "parent_hexcat": parent_hexcat,
                        "merkle": merkle,
                        "json_single": j_single,
                        "json_double": j_double,
                        "bytes_variants_sample": bytes_variants[:3]
                    })

            matches = []
            for v in variants:
                if v["json_single"] == submitted_hash:
                    matches.append({"mode": "json_single", **v})
                if v["json_double"] == submitted_hash:
                    matches.append({"mode": "json_double", **v})
                for bv in v["bytes_variants_sample"]:
                    if bv["single_sha"] == submitted_hash:
                        matches.append({"mode": "bytes_single", "bytes_params": bv, **v})
                    if bv["double_sha"] == submitted_hash:
                        matches.append({"mode": "bytes_double", "bytes_params": bv, **v})

            debug = {
                "error": f"submit failed: {err_text}",
                "submitted_hash": submitted_hash,
                "tip_last_hash": getattr(last_block, "hash", None),
                "computed_variants_count": len(variants),
                "variants_checked_example": variants[:4],
                "matches": matches,
                "traceback": traceback.format_exc().splitlines()[-10:]
            }

            return jsonify(debug), 400

        except Exception as diag_exc:
            return jsonify({"error": f"submit failed: {err_text}", "diag_error": str(diag_exc)}), 400
