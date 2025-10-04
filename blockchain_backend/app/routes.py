# blockchain_backend/app/routes.py
import os
import uuid
import requests
from flask import request, jsonify

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
    MINING_REWARD,
    MINING_REWARD_ASSET,  # preferred alias (config also exports back-compat MINING_REWARD_CURRENCY)
)

# Very simple in-memory sessions: token -> user_id
SESSIONS = {}  # {token: user_id}


def auto_sync():
    """Auto-sync peer node from root if needed."""
    if os.getenv("PEER", "").lower() != "true":
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
    if os.getenv("PEER", "").lower() == "true":
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
    if os.getenv("PEER", "").lower() == "true":
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
    Mine a block from current pool candidates, enforcing:
      1) structural validity (signature, per-currency conservation),
      2) ECONOMIC validity against a working ledger built from chain + already-added candidates.
    """
    candidates = transaction_pool.get_transactions_for_mining()
    if not candidates:
        return jsonify({"error": "no transactions"}), 400

    block_tx_jsons = []

    try:
        # 1) Start from on-chain balances (tip)
        ledger = build_ledger_from_chain(blockchain)

        # 2) Validate & reserve each candidate in FIFO order
        for tx in candidates:
            # a) structural validity (signature, per-currency conservation, metadata hooks)
            Transaction.is_valid_transaction(tx, resolve_asset_fn=resolve_asset_fn)

            # b) economic validity against current working ledger (chain + prior accepted candidates)
            tx_json = tx.to_json()
            enforce_sufficient_funds(tx_json, ledger)

            # c) reserve (apply) this tx to the working ledger
            apply_tx_to_ledger(tx_json, ledger)

            # d) include in block
            block_tx_jsons.append(tx_json)

        # 3) Miner reward (mint) — append after all user txs
        block_tx_jsons.append(
            Transaction.reward_transaction(
                miner_wallet=wallet,
                currency=MINING_REWARD_ASSET,
                amount=MINING_REWARD,
            ).to_json()
        )

        # 4) Add block, clear included txs from pool, broadcast
        blockchain.add_block(block_tx_jsons)
        block = blockchain.chain[-1]

        transaction_pool.clear_blockchain_transactions(blockchain)

        if pubsub:
            pubsub.broadcast_block(block)

        return jsonify(block.to_json())

    except Exception as e:
        # any structural/economic validation failure aborts the whole block assembly
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

            # quick pre-check (optional; the constructor checks too)
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


@app.route("/known-addresses")
def route_known_addresses():
    known = set()
    for block in blockchain.chain:
        for tx in getattr(block, "data", []) or []:
            known.update((tx.get("output") or {}).keys())
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
    if os.getenv("PEER", "").lower() == "true":
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

    # Get or create wallet bound to user_id label
    w = REGISTRY.get_wallet_by_label(user_id)
    if not w:
        w = Wallet(blockchain)  # brand-new wallet (STARTING_BALANCE rules)
        REGISTRY.add_wallet(w, label=user_id)

    # Issue a session token
    token = str(uuid.uuid4())
    SESSIONS[token] = user_id

    return jsonify(
        {
            "ok": True,
            "token": token,
            "user_id": user_id,
            "address": w.address,
            "public_key": w.public_key,
        }
    )


def _wallet_from_token():
    token = request.headers.get("X-Auth-Token") or (request.json or {}).get("token")
    if not token or token not in SESSIONS:
        raise Exception("invalid or missing token")
    user_id = SESSIONS[token]
    w = REGISTRY.get_wallet_by_label(user_id)
    if not w:
        # very unlikely; recreate if missing
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
    Requires X-Auth-Token header (or 'token' in JSON).
    Accepts same 'action' payloads as /wallet/transact.
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

        else:  # transfer coins
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
