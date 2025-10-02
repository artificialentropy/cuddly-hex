# blockchain_backend/app/routes.py
import os
import time
import requests
from flask import request, jsonify

from . import app, blockchain, wallet, transaction_pool, pubsub, peers

from blockchain_backend.wallet.transaction import Transaction
from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.core.block import Block
from blockchain_backend.core.blockchain import Blockchain
from blockchain_backend.utils.config import MINING_REWARD, MINING_REWARD_ASSET
from blockchain_backend.app.app_state import ASSETS, resolve_asset_fn



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
    candidates = transaction_pool.get_transactions_for_mining()
    if not candidates:
        return jsonify({"error": "no transactions"}), 400

    block_tx_jsons = []

    try:
        # validate all candidates before packing
        for tx in candidates:
            Transaction.is_valid_transaction(tx, resolve_asset_fn=resolve_asset_fn)
            block_tx_jsons.append(tx.to_json())

        # Use the right parameter name: currency=...
        # If your config uses MINING_REWARD_ASSET as the currency string, keep it.
        block_tx_jsons.append(
            Transaction.reward_transaction(
                miner_wallet=wallet,
                currency=MINING_REWARD_ASSET,   # or MINING_REWARD_CURRENCY if that's your constant
                amount=MINING_REWARD
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
                metadata=payload.get("metadata")
            )

        elif action == "purchase":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.purchase_asset(
                buyer_wallet=wallet,
                asset=asset,
                get_owner_wallet_fn=lambda addr: peers.get(addr),
                metadata=payload.get("metadata")
            )

        elif action == "transfer_asset":
            asset = resolve_asset_fn(payload["asset_id"])
            if not asset:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.transfer_asset_direct(
                sender_wallet=wallet,
                recipient_address=payload["recipient"],
                asset=asset,
                metadata=payload.get("metadata")
            )

        else:  # default: coin transfer
            recipient = payload["recipient"]
            amount = int(payload["amount"])
            currency = payload.get("currency", "COIN")

            # quick pre-check (optional; the constructor checks too)
            if wallet.balances.get(currency, 0) < amount:
                raise Exception(f"Insufficient {currency} balance")

            # ✅ Let Transaction build correct outputs + input
            tx = Transaction(
                sender_wallet=wallet,
                recipient=recipient,
                amount_map={currency: amount},
                asset_ids=None
            )

            # optional: attach metadata
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
        for tx in block.data:
            known.update(tx.get("output", {}).keys())
    return jsonify(list(known))


# -------------------------
# Peer Management
# -------------------------

@app.route("/peers", methods=["GET"])
def list_peers():
    return jsonify(list(peers))


@app.route("/peers", methods=["POST"])
def add_peer():
    data = request.get_json(force=True)
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"error": "peer_url required"}), 400

    if peer_url in peers:
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
        peers.add(peer_url)
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
        candidate = [Block.from_json(b) for b in chain_data] if hasattr(Block, "from_json") else Blockchain.from_json(chain_data).chain

        if len(candidate) <= len(blockchain.chain):
            return jsonify({"ok": False, "reason": "candidate_not_longer"}), 200

        blockchain.replace_chain(candidate)
        return jsonify({"ok": True, "new_len": len(blockchain.chain)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    

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

    ASSETS[asset_id] = Asset(asset_id=asset_id, owner=owner, price=price, currency=currency, transferable=transferable)
    return jsonify({"ok": True, "asset": {
        "asset_id": asset_id, "owner": owner, "price": price, "currency": currency, "transferable": transferable
    }})

@app.route("/asset/<asset_id>", methods=["GET"])
def asset_get(asset_id):
    a = ASSETS.get(asset_id)
    if not a:
        return jsonify({"error": "asset not found"}), 404
    return jsonify({"asset_id": a.asset_id, "owner": a.owner, "price": a.price, "currency": a.currency, "transferable": a.transferable})

