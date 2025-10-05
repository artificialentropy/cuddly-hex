# blockchain_backend/app/routes.py
import os
import uuid
import time
import requests
from collections import defaultdict, deque
from flask import request, jsonify
import traceback
import json
import hashlib

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
# Helpers / headers
# -------------------------
@app.route("/headers/range")
def headers_range():
    start = int(request.args.get("start", 0))
    end = int(request.args.get("end", start + 100))
    res = []
    for i, b in enumerate(blockchain.chain[start:end], start=start):
        res.append({
            "height": getattr(b, "height", i),
            "hash": b.hash,
            "last_hash": b.last_hash,
            "timestamp": b.timestamp,
            "difficulty": b.difficulty,
            "merkle": getattr(b, "merkle", None)
        })
    return jsonify(res)


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

        incoming_chain = (
            Blockchain.from_json(chain_data).chain
            if hasattr(Blockchain, "from_json")
            else [Block.from_json(b) for b in chain_data]
        )

        if len(incoming_chain) > len(blockchain.chain):
            blockchain.replace_chain(incoming_chain)
            print(f"[auto_sync] updated local chain to height {len(blockchain.chain)-1}")
    except Exception as e:
        print(f"[auto_sync] failed: {e}")


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
    if ROLE == "VALIDATOR":
        auto_sync()
    return jsonify(blockchain.to_json())


@app.route("/blockchain/range")
def route_blockchain_range():
    start = int(request.args.get("start", 0))
    end = int(request.args.get("end", start + 25))
    return jsonify(blockchain.to_json()[start:end])


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
        if pubsub:
            pubsub.broadcast_block(block)
        return jsonify(block.to_json())

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
            tx = Transaction.purchase_asset(
                buyer_wallet=wallet,
                asset=asset,
                get_owner_wallet_fn=lambda addr: PEERS.get(addr),
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
        incoming_chain = (
            Blockchain.from_json(remote_data).chain
            if hasattr(Blockchain, "from_json")
            else [Block.from_json(b) for b in remote_data]
        )
        blockchain.replace_chain(incoming_chain)
        PEER_URLS.add(peer_url)
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
        candidate = (
            [Block.from_json(b) for b in chain_data]
            if hasattr(Block, "from_json")
            else Blockchain.from_json(chain_data).chain
        )

        if len(candidate) <= len(blockchain.chain):
            return jsonify({"ok": False, "reason": "candidate_not_longer"}), 200

        blockchain.replace_chain(candidate)
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
                return jsonify({"error": "Only the asset owner may transfer it"}), 403
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

    # We'll attempt to parse and validate the candidate; on validation error
    # we may produce diagnostic info for miners (variants) — but only if we
    # have enough context (cand + last_block).
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

        # append & broadcast
        blockchain.chain.append(cand)
        transaction_pool.clear_blockchain_transactions(blockchain)
        if pubsub:
            pubsub.broadcast_block(cand)

        return jsonify({"ok": True, "height": len(blockchain.chain), "tip": cand.hash})

    except Exception as exc:
        # If we don't have a parsed candidate or last_block we cannot produce
        # helpful diagnostics; return a generic error. If we do have them,
        # produce the diagnostic variants (kept concise).
        err_text = str(exc)
        if cand is None or last_block is None:
            # Parsing failed or no chain context
            # Return client error (likely malformed block) or server error depending on exception type
            # Treat everything here as 400 to avoid revealing internals; adjust if desired.
            return jsonify({"error": f"submit failed: {err_text}"}), 400

        # At this point we have cand and last_block and can attempt diagnostics.
        try:
            # helper short-hands
            def sha256(b): return hashlib.sha256(b).digest()
            def sha256_hex(b): return hashlib.sha256(b).hexdigest()
            def sha256d_hex(b): return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
            def canon_json_bytes(o):
                return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

            # helper: txid with/without id
            def txid_bytes(tx, include_id=False):
                txc = {k: v for k, v in tx.items() if include_id or k != "id"}
                return sha256(canon_json_bytes(txc))

            def merkle_from_txs(txs, include_id=False, parent_hexcat=False):
                if not txs:
                    return sha256(b"").hex()
                layer = [txid_bytes(tx, include_id) for tx in txs]
                while len(layer) > 1:
                    if len(layer) % 2 == 1:
                        layer.append(layer[-1])
                    nxt = []
                    for i in range(0, len(layer), 2):
                        left, right = layer[i], layer[i+1]
                        if parent_hexcat:
                            combined = (left.hex() + right.hex()).encode("utf-8")
                        else:
                            combined = left + right
                        nxt.append(sha256(combined))
                    layer = nxt
                return layer[0].hex()

            # header JSON attempt (single or double sha)
            def header_json_hash(version, last_hash, merkle, timestamp, difficulty, nonce, double=False):
                hdr = {
                    "version": int(version),
                    "last_hash": last_hash.lower() if isinstance(last_hash, str) else last_hash,
                    "merkle_root": merkle.lower() if isinstance(merkle, str) else merkle,
                    "timestamp": int(timestamp),
                    "difficulty": int(difficulty),
                    "nonce": int(nonce),
                }
                jb = canon_json_bytes(hdr)
                return (sha256d_hex(jb) if double else sha256_hex(jb)), jb

            # header bytes attempt (try few common widths & endians)
            def header_bytes_hashes(version, last_hash, merkle, timestamp, difficulty, nonce):
                results = []
                for endian in ("little", "big"):
                    for tsw in (4, 8):
                        for diffw in (4, 8):
                            for nonew in (4, 8):
                                try:
                                    parts = []
                                    parts.append(int(version).to_bytes(4, byteorder=endian, signed=False))
                                    parts.append(bytes.fromhex(last_hash))
                                    parts.append(bytes.fromhex(merkle))
                                    parts.append(int(timestamp).to_bytes(tsw, byteorder=endian, signed=False))
                                    parts.append(int(difficulty).to_bytes(diffw, byteorder=endian, signed=False))
                                    parts.append(int(nonce).to_bytes(nonew, byteorder=endian, signed=False))
                                    b = b"".join(parts)
                                    results.append({
                                        "endian": endian,
                                        "ts_width": tsw,
                                        "diff_width": diffw,
                                        "nonce_width": nonew,
                                        "single_sha": sha256_hex(b),
                                        "double_sha": sha256d_hex(b),
                                        # omit raw bytes_hex in response to avoid huge payloads
                                    })
                                except Exception:
                                    continue
                return results

            # gather info
            submitted_hash = getattr(cand, "hash", None)
            block_txs = list(getattr(cand, "data", []))
            tip_version = getattr(last_block, "version", 1)
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

            # Try to find exact match
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

            # Return diagnostics as 400 — validation failed; keep concise
            return jsonify(debug), 400

        except Exception as diag_exc:
            # If diagnostics generation itself fails, return a minimal message
            return jsonify({"error": f"submit failed: {err_text}", "diag_error": str(diag_exc)}), 400

