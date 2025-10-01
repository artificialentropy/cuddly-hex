from flask import Flask, jsonify, request
from dotenv import load_dotenv, find_dotenv
import os, time
import requests
from blockchain_backend.core.blockchain import script_blockchain_init, Blockchain
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.transaction import Transaction
from blockchain_backend.wallet.transaction_pool import TransactionPool
from blockchain_backend.utils.pubsub import PubSub
from blockchain_backend.core.block import Block
from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.utils.config import MINING_REWARD, MINING_REWARD_ASSET
load_dotenv()

from pathlib import Path

# find_dotenv will walk up directories to locate a .env — robust inside Docker too
env_path = find_dotenv()
if env_path:
    load_dotenv(env_path)
else:
    # fallback: if your .env is at project root and this file lives in package,
    # compute the root path relative to this file:
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")
peers = set()
app = Flask(__name__)

# --- Core state ---

def resolve_asset_fn(asset_id):
    # if you use DB-backed Asset model:
    try:
        return Asset.objects.get(pk=asset_id)
    except Exception:
        # if using an in-memory registry, look up from a dict: ASSET_REGISTRY.get(asset_id)
        return None

# instantiate pool with resolver and validation on set
transaction_pool = TransactionPool(resolve_asset_fn=resolve_asset_fn, validate_on_set=True)

blockchain = Blockchain()
server_start = True
if os.getenv("PEER", "").lower() != "true":
    # Miner wallet for reward transaction
    miner_wallet = Wallet(blockchain)

    # Put your custom data as metadata, not as fake transactions
    custom_payload = [
        {
            "id": "8d7f5818",
            "input": {
                "timestamp": time.time_ns(),
                "balances": {"COIN": 50},           # initial balance (or whatever currency)
                "address": "*--official-server-reward--*",
                "public_key": "*--official-server-reward--*",  # can use placeholder
                "signature": "*--official-server-reward--*"    # placeholder
            },
            "output": {
                "owner": 50
            }
        },
        {
            "id": "8d7f5819",
            "input": {
                "timestamp": time.time_ns(),
                "balances": {"COIN": 30},
                "address": "*--official-server-reward--*",
                "public_key": "*--official-server-reward--*",
                "signature": "*--official-server-reward--*"
            },
            "output": {
                "owner": 30
            }
        }
    ]

    ret_first_block, blockchain = script_blockchain_init(
        blockchain,
        server_start=True,
        custom_data=custom_payload,  # will go into reward_tx.metadata
    )
else:
    ret_first_block = blockchain.chain[0]
server_start = False

wallet = Wallet(blockchain)
transaction_pool = TransactionPool()

pubsub = PubSub(blockchain=blockchain, transaction_pool=transaction_pool)

# Peers set. Stored as set of base URLs like "http://node0:5000"


ROOT_PORT = int(os.getenv("ROOT_PORT", 5000))
ROOT_HOST = os.getenv("ROOT_HOST", "localhost")
ROOT_BASE = f"http://{ROOT_HOST}:{ROOT_PORT}"


print(f"Initial chain (first block): {ret_first_block.to_json()}")


@app.route("/")
def route_default():
    if os.getenv("PEER", "").lower() == "true":
        auto_sync()
    return f"Welcome to the blockchain with first block: {ret_first_block.to_json()}"


@app.route("/health")
def health():
    tip = blockchain.chain[-1]
    tip_hash = tip["hash"] if isinstance(tip, dict) else getattr(tip, "hash", None)
    ready = len(blockchain.chain) > 1  # <-- only ready when first block exists
    return jsonify(
        {"ok": True, "ready": ready, "height": len(blockchain.chain), "tip": tip_hash}
    )


@app.route("/blockchain")
def route_blockchain():
    if os.getenv("PEER", "").lower() == "true":
        auto_sync()
    return jsonify(blockchain.to_json())


@app.route("/blockchain/range")
def route_blockchain_range():
    start = int(request.args.get("start", 0))
    end = int(request.args.get("end", start + 25))
    # ASC (genesis -> tip), height == index
    return jsonify(blockchain.to_json()[start:end])



@app.route("/blockchain/length")
def route_blockchain_length():
    return jsonify(len(blockchain.chain))


# @app.route("/blockchain/mine")
# def route_blockchain_mine():
#     transaction_data = transaction_pool.transaction_data()
#     transaction_data.append(Transaction.reward_transaction(wallet).to_json())
#     blockchain.add_block(transaction_data)
#     block = blockchain.chain[-1]
#     if pubsub:
#         pubsub.broadcast_block(block)  # guarded
#     transaction_pool.clear_blockchain_transactions(blockchain)
#     notify_peers_to_sync()
#     return jsonify(block.to_json())

import os, requests  # make sure these are imported at top

# @app.route("/blockchain/mine")
# def route_blockchain_mine():
#     # gather pending txs + miner reward
#     transaction_data = transaction_pool.transaction_data()
#     transaction_data.append(Transaction.reward_transaction(wallet).to_json())

#     # mine and append
#     blockchain.add_block(transaction_data)
#     block = blockchain.chain[-1]

#     # optional pubsub broadcast (if enabled)
#     if pubsub:
#         pubsub.broadcast_block(block)

#     # clear confirmed txs from pool
#     transaction_pool.clear_blockchain_transactions(blockchain)

#     # --- NEW: if this node is a PEER, tell ROOT to pull our longer chain ---
#     try:
#         if os.getenv("PEER", "").lower() == "true":
#             ROOT_BASE = f"http://{os.getenv('ROOT_HOST','node0')}:{int(os.getenv('ROOT_PORT','5000'))}"
#             SELF_BASE = os.getenv("SELF_BASE")  # e.g. http://node1:5000 (set in compose)
#             if SELF_BASE:
#                 requests.post(
#                     f"{ROOT_BASE}/sync_from_peer",
#                     json={"peer_url": SELF_BASE},
#                     timeout=5
#                 )
#     except Exception as e:
#         print(f"[mine] notify root failed: {e}")

#     return jsonify(block.to_json())

@app.route("/blockchain/mine")
def route_blockchain_mine():
    candidates = transaction_pool.get_transactions_for_mining()
    if not candidates:
        return jsonify({"error": "no transactions"}), 400

    # We'll collect tx_jsons to include in block
    block_tx_jsons = []

    # Example in-memory application (be careful: for DB-backed, use a DB transaction + row locks)
    try:
        # iterate and apply each tx (validate again just before applying)
        for tx in candidates:
            # re-validate signature & conservation
            Transaction.is_valid_transaction(tx, resolve_asset_fn=resolve_asset_fn)

            # If purchase metadata present, perform atomic ownership & balance change:
            meta = getattr(tx, "metadata", {}) or {}
            if "asset_purchase" in meta:
                ap = meta["asset_purchase"]
                asset_id = ap["asset_id"]
                # Resolve asset and wallets, apply purchase atomically.
                asset = resolve_asset_fn(asset_id)
                if asset is None:
                    raise Exception("asset not found during mining")
                seller_addr = ap["from"]
                buyer_addr = ap["to"]
                currency = ap["currency"]
                amount = int(ap["price"])

                # Use DB-backed service if available (recommended)
                # Example: purchase_asset_with_row_lock(asset_id, buyer_addr, metadata=tx.metadata)
                # If you don't have DB service, do an in-memory check and mutate wallets/assets:
                seller_wallet_obj = None
                buyer_wallet_obj = None
                # find wallet objects in your runtime; if you persist wallets elsewhere, call service
                # For simple demo, assume you can construct Wallet(blockchain) and assign addresses - but ensure balances are handled consistently.

                # Here we assume apply_currency_transfer(tx.output) will update the wallet storage backing (or rely on on-chain derived balances).
                # Append tx json to block payload (we keep nested output)
                block_tx_jsons.append(tx.to_json())

            else:
                # Non-asset txs (currency transfers/listings/direct transfers)
                block_tx_jsons.append(tx.to_json())

        # Append miner reward transaction (create reward in default COIN currency)
        # Use Transaction.reward_transaction(wallet, asset="COIN", amount=MINING_REWARD) if you changed signature
        block_tx_jsons.append(Transaction.reward_transaction(wallet, asset=MINING_REWARD_ASSET, amount=MINING_REWARD).to_json())

        # Add block to chain (blockchain.add_block should accept list of tx jsons)
        blockchain.add_block(block_tx_jsons)
        block = blockchain.chain[-1]

        # After successful append, clear pool of included txs
        transaction_pool.clear_blockchain_transactions(blockchain)

        # Broadcast if enabled
        if pubsub:
            pubsub.broadcast_block(block)

        return jsonify(block.to_json())
    except Exception as e:
        return jsonify({"error": f"mining failed: {e}"}), 500


@app.route("/wallet/transact", methods=["POST"])
def route_wallet_transact():
    payload = request.get_json(force=True)
    action = payload.get("action", "transfer")  # default to coin transfer

    try:
        if action == "list":
            # Owner lists asset for sale
            asset_id = payload["asset_id"]
            price = int(payload["price"])
            currency = payload.get("currency", "COIN")
            asset = resolve_asset_fn(asset_id)
            if asset is None:
                return jsonify({"error": "asset not found"}), 404
            tx = Transaction.list_asset_for_sale(
                owner_wallet=wallet,
                asset=asset,
                price=price,
                currency=currency,
                metadata=payload.get("metadata")
            )

        elif action == "purchase":
            # Buyer purchases an asset
            asset_id = payload["asset_id"]
            asset = resolve_asset_fn(asset_id)
            if asset is None:
                return jsonify({"error": "asset not found"}), 404

            tx = Transaction.purchase_asset(
                buyer_wallet=wallet,
                asset=asset,
                get_owner_wallet_fn=lambda addr: WALLETS.get(addr),
                metadata=payload.get("metadata")
            )

        elif action == "transfer_asset":
            # Direct transfer of an asset
            asset_id = payload["asset_id"]
            recipient = payload["recipient"]
            asset = resolve_asset_fn(asset_id)
            if asset is None:
                return jsonify({"error": "asset not found"}), 404

            tx = Transaction.transfer_asset_direct(
                sender_wallet=wallet,
                recipient_address=recipient,
                asset=asset,
                metadata=payload.get("metadata")
            )

        else:
            # Default: coin transfer
            recipient = payload["recipient"]
            amount = int(payload["amount"])
            currency = payload.get("currency", "COIN")

            tx = Transaction(
                sender_wallet=wallet,
                recipient=recipient,
                amount=amount,
                asset_id=currency  # proper parameter name
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # Validate, add to pool, broadcast
    try:
        transaction_pool.set_transaction(tx)
    except Exception as e:
        return jsonify({"error": f"rejected by pool: {e}"}), 400

    if pubsub:
        pubsub.broadcast_transaction(tx)

    return jsonify(tx.to_json())

@app.route("/wallet/info")
def route_wallet_info():
    return jsonify({"address": wallet.address, "balance": wallet.balance})


# @app.route("/known-addresses")
# def route_known_addresses():
#     known = set()
#     for block in blockchain.chain:
#         for tx in block.data:
#             known.update(tx["output"].keys())
#     return jsonify(list(known))


@app.route("/known-addresses")
def route_known_addresses():
    known = set()
    for block in blockchain.chain:
        for tx in block.data:
            outputs = tx.get("output", {})  # tx may be dict (json)
            # if nested: outputs[address] may be a dict; we only need keys
            known.update(outputs.keys())
    return jsonify(list(known))



@app.route("/transactions")
def route_transactions():
    return jsonify(transaction_pool.transaction_data())


# ---- Peer management endpoints ----
@app.route("/peers", methods=["GET"])
def list_peers():
    return jsonify(list(peers))


@app.route("/peers", methods=["POST"])
def add_peer():
    """
    Expected JSON: {"peer_url": "http://node0:5000"}
    This will attempt to fetch /blockchain from that peer and replace local chain if valid.
    """
    data = request.get_json(force=True)
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"error": "peer_url is required"}), 400

    # Avoid adding self
    if peer_url in peers:
        return jsonify({"message": "already a peer"}), 200

    try:
        resp = requests.get(f"{peer_url}/blockchain", timeout=5)
        resp.raise_for_status()
        remote_data = resp.json()

        # Reconstruct blockchain: try class method or Block.from_json fallback
        if hasattr(Blockchain, "from_json"):
            remote = Blockchain.from_json(remote_data)
            chain_to_use = remote.chain
        else:
            chain_to_use = [Block.from_json(b) for b in remote_data]

        # replace_chain should validate the chain internally (implement checks in Blockchain)
        blockchain.replace_chain(chain_to_use)
        peers.add(peer_url)
        return (
            jsonify({"message": "peer added and chain synchronized", "peer": peer_url}),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Could not sync from peer: {str(e)}"}), 500


# optional: an endpoint to trigger sync against ROOT_BASE on startup if desired
@app.route("/sync_from_root")
def sync_from_root():
    try:
        resp = requests.get(f"{ROOT_BASE}/blockchain", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if hasattr(Blockchain, "from_json"):
            remote = Blockchain.from_json(data)
            chain_to_use = remote.chain
        else:
            chain_to_use = [Block.from_json(b) for b in data]

        blockchain.replace_chain(chain_to_use)
        return jsonify({"message": "synced"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/sync_from_peer", methods=["POST"])
def sync_from_peer():
    if os.getenv("PEER", "").lower() == "true":
        return jsonify({"ok": False, "error": "only root accepts sync_from_peer"}), 403
    data = request.get_json(force=True) or {}
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"ok": False, "error": "peer_url required"}), 400
    try:
        r = requests.get(f"{peer_url}/blockchain", timeout=5)
        r.raise_for_status()
        chain_data = r.json()

        # reconstruct candidate chain
        candidate = [Block.from_json(b) for b in chain_data] \
            if hasattr(Block, "from_json") else Blockchain.from_json(chain_data).chain

        if len(candidate) <= len(blockchain.chain):
            return jsonify({"ok": False, "reason": "candidate_not_longer",
                            "candidate_len": len(candidate),
                            "local_len": len(blockchain.chain)}), 200

        blockchain.replace_chain(candidate)  # validates internally
        return jsonify({"ok": True, "new_len": len(blockchain.chain)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def auto_sync():
    if os.getenv("PEER", "").lower() != "true":
        return  # root should not auto-pull itself

    try:
        base = f"http://{os.getenv('ROOT_HOST','node0')}:{int(os.getenv('ROOT_PORT','5000'))}"
        print(f"[auto_sync] syncing from {base}")
        resp = requests.get(f"{base}/blockchain", timeout=5)
        resp.raise_for_status()
        chain_data = resp.json()
        if not isinstance(chain_data, list) or not chain_data:
            print("[auto_sync] root returned empty/invalid chain")
            return

        chain_to_use = (Blockchain.from_json(chain_data).chain
                        if hasattr(Blockchain, "from_json")
                        else [Block.from_json(b) for b in chain_data])
        if len(chain_to_use) > len(blockchain.chain):
            blockchain.replace_chain(chain_to_use)
            print(f"[auto_sync] updated local chain to height {len(blockchain.chain)-1}")
        else:
            print(f"[auto_sync] local already up-to-date (local={len(blockchain.chain)}, root={len(chain_to_use)})")
    except Exception as e:
        print(f"[auto_sync] failed: {e}")



if __name__ == "__main__":
    try:
        if os.getenv("PEER", "").lower() == "true":
            base = f"http://{os.getenv('ROOT_HOST','node0')}:{int(os.getenv('ROOT_PORT','5000'))}"
            print(f"[PEER] Attempting initial sync from {base}")
            resp = requests.get(f"{base}/blockchain", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            chain_to_use = (
                Blockchain.from_json(data).chain
                if hasattr(Blockchain, "from_json")
                else [Block.from_json(b) for b in data]
            )
            blockchain.replace_chain(chain_to_use)
            # Make sure we can notify later if needed
            peers.add(base)
            print("[PEER] Initial sync complete")
        else:
            print(
                "[ROOT] Booting root node; first block mined earlier by script_blockchain_init"
            )
    except Exception as e:
        print(f"Initial sync failed: {e}")

    # Container always listens on 5000; compose maps host ports
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
