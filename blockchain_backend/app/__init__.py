# blockchain_backend/app/__init__.py
import os
import time
from flask import Flask
from blockchain_backend.wallet.wallet_registry import REGISTRY
from blockchain_backend.core.blockchain import Blockchain, script_blockchain_init
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.transaction_pool import TransactionPool
from blockchain_backend.utils.pubsub import PubSub
from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.utils.config import *
from .app_state import ASSETS, PEERS, resolve_asset_fn

# --- Flask app ---
app = Flask(__name__)
# --- Global state ---
blockchain = Blockchain()

# Optional: define a simple asset resolver function


def resolve_asset_fn(asset_id: str) -> Asset | None:
    return ASSETS.get(asset_id)

transaction_pool = TransactionPool(resolve_asset_fn=resolve_asset_fn, validate_on_set=True)
wallet = Wallet(blockchain)
pubsub = PubSub(blockchain=blockchain, transaction_pool=transaction_pool)
peers = set()

# Optional: export root host/port
ROOT_HOST = os.getenv("ROOT_HOST", "node0")
ROOT_PORT = int(os.getenv("ROOT_PORT", 5000))

# --- Blockchain initialization for root node ---
if os.getenv("PEER", "").lower() != "true":
    # This node is the root/miner; create first block with reward
    custom_payload = [
        {
            "id": "8d7f5818",
            "input": {
                "timestamp": time.time_ns(),
                "balances": {"COIN": 50},
                "address": "*--official-server-reward--*",
                "public_key": "*--official-server-reward--*",
                "signature": "*--official-server-reward--*"
            },
            "output": {"owner": 50}
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
            "output": {"owner": 30}
        }
    ]

    ret_first_block, blockchain = script_blockchain_init(
        blockchain,
        server_start=True,
        custom_data=custom_payload
    )
else:
    # Peer nodes start with empty chain; they will sync later
    ret_first_block = blockchain.chain[0] if blockchain.chain else None

# --- Import routes (Flask sees them) ---
from . import routes
