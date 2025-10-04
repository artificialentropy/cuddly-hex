# blockchain_backend/app/__init__.py
import os
import threading
import time
from flask import Flask

from blockchain_backend.core.blockchain import Blockchain, script_blockchain_init
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.transaction_pool import TransactionPool
from blockchain_backend.utils.pubsub import PubSub
from blockchain_backend.utils.config import MINING_REWARD, MINING_REWARD_ASSET

# App-local shared state
from .app_state import ASSETS, PEERS, resolve_asset_fn  # PEERS used by /u endpoints

# --- Flask app ---
app = Flask(__name__)

# --- Global state ---
blockchain = Blockchain()
transaction_pool = TransactionPool(
    resolve_asset_fn=resolve_asset_fn,
    validate_on_set=True,
    blockchain=blockchain,
)
wallet = Wallet(blockchain)
pubsub = PubSub(blockchain=blockchain, transaction_pool=transaction_pool)

# Optional: export root host/port
ROOT_HOST = os.getenv("ROOT_HOST", "node0")
ROOT_PORT = int(os.getenv("ROOT_PORT", 5000))

# --- Blockchain initialization for root node ---
if os.getenv("PEER", "").lower() != "true":
    # This node is the root/miner; create first block with reward (attach any metadata you want)
    custom_payload = [
        {
            "id": "8d7f5818",
            "input": {
                "timestamp": time.time_ns(),
                "balances": {"COIN": 50},
                "address": "*--official-server-reward--*",
                "public_key": "*--official-server-reward--*",
                "signature": "*--official-server-reward--*",
            },
            "output": {"owner": 50},
        },
        {
            "id": "8d7f5819",
            "input": {
                "timestamp": time.time_ns(),
                "balances": {"COIN": 30},
                "address": "*--official-server-reward--*",
                "public_key": "*--official-server-reward--*",
                "signature": "*--official-server-reward--*",
            },
            "output": {"owner": 30},
        },
    ]

    # Mine the first block with a proper reward tx API; script handles metadata
    ret_first_block, blockchain = script_blockchain_init(
        blockchain,
        server_start=True,
        custom_data=custom_payload,
    )
else:
    # Peer nodes start with empty chain; they will sync later
    from .__main__ import startup_sync_if_peer

    threading.Thread(target=startup_sync_if_peer, daemon=True).start()
    ret_first_block = blockchain.chain[0] if blockchain.chain else None

# --- Import routes (Flask sees them) ---
from . import routes  # noqa: E402,F401
