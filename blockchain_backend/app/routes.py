import os
import uuid
import time
import requests
from collections import defaultdict, deque
from flask import request, jsonify
import traceback
import json

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
    from blockchain_backend.db.leveldb_store import open_default_store
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

# -------------------------
# Basic rate limiting for tx submission
# -------------------------
RATE_BUCKETS = defaultdict(lambda: deque())  # ip -> timestamps
MAX_REQ = 20
WINDOW_S = 10


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
CHAIN_STORE_PATH = os.getenv("CHAIN_STORE_PATH") or "/data/chain_store.json"
CHAIN_STORE_PATH = os.path.abspath(CHAIN_STORE_PATH)

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
    - If LevelDB is available and contains blocks, return list of blocks (ordered by 'height' if present).
    - Else fallback to reading CHAIN_STORE_PATH JSON file (same as previous behavior).
    Returns: list of block dicts or None
    """
    # Try LevelDB first
    if STORE is not None:
        try:
            blocks = []
            for blk in STORE.iter_blocks():
                # each blk is a dict (as stored by put_block)
                if isinstance(blk, dict):
                    blocks.append(blk)
            if blocks:
                # If height keys exist, sort by height to produce an ordered chain
                try:
                    blocks = sorted(blocks, key=lambda b: int(b.get("height", 0)))
                except Exception:
                    # fallback to insertion order if sorting fails
                    pass
                return blocks
        except Exception as e:
            print("[load_chain_from_disk] LevelDB read failed:", e)

    # Fallback to file-based JSON snapshot
    try:
        return _atomic_read_json(CHAIN_STORE_PATH)
    except Exception:
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
    """
    Return normalized chain JSON (height + timestamp in seconds + signature hex strings).
    Also include pid + length for debugging multi-worker divergence.
    Prefer reading the persisted normalized chain store if present.
    """
    if ROLE == "VALIDATOR":
        auto_sync()

    # Prefer disk-based normalized chain if present (helps multiple workers)
    disk = load_chain_from_disk()
    if disk:
        normalized = disk
    else:
        raw = blockchain.to_json()
        normalized = normalize_chain_json_for_output(raw)
    return jsonify({"pid": os.getpid(), "length": len(normalized), "chain": normalized})


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
    if ROLE == "VALIDATOR":
        return jsonify({"ok": False, "error": "only root accepts sync"}), 403

    peer_url = request.get_json(force=True).get("peer_url")
    if not peer_url:
        return jsonify({"ok": False, "error": "peer_url required"}), 400

    try:
        r = requests.get(f"{peer_url}/blockchain", timeout=5)
        r.raise_for_status()
        chain_data = r.json()
        if isinstance(chain_data, dict) and "chain" in chain_data:
            remote_chain_raw = chain_data["chain"]
        else:
            remote_chain_raw = chain_data
        sanitized_remote = [ _strip_block_extras(b) for b in (remote_chain_raw or []) ]
        if hasattr(Block, "from_json"):
            candidate = [Block.from_json(b) for b in sanitized_remote]
        else:
            try:
                candidate = Blockchain.from_json(sanitized_remote).chain
            except Exception:
                candidate = [Block.from_json(b) for b in sanitized_remote]

        if len(candidate) <= len(blockchain.chain):
            return jsonify({"ok": False, "reason": "candidate_not_longer"}), 200

        blockchain.replace_chain(candidate)
        # persist normalized chain for other workers
        try:
            save_chain_to_disk(normalize_chain_json_for_output(remote_chain_raw))
        except Exception:
            pass
        return jsonify({"ok": True, "new_len": len(blockchain.chain)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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
        try:
            raw_chain = blockchain.to_json()
            normalized_chain = normalize_chain_json_for_output(raw_chain)
            save_chain_to_disk(normalized_chain)
        except Exception as e:
            print("[blocks/submit] save_chain_to_disk failed:", e)

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
