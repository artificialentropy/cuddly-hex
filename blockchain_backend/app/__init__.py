# blockchain_backend/app/__init__.py (only the relevant changes)

import os
import threading
import time
from flask import Flask
from blockchain_backend.wallet.wallet_registry import REGISTRY
from blockchain_backend.core.blockchain import Blockchain
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.transaction_pool import TransactionPool
from blockchain_backend.utils.pubsub import PubSub
from blockchain_backend.utils.config import ROLE
from .app_state import ASSETS, PEERS, resolve_asset_fn

app = Flask(__name__)
blockchain = Blockchain()

def resolve_asset_fn(asset_id: str):
    return ASSETS.get(asset_id)

transaction_pool = TransactionPool(resolve_asset_fn=resolve_asset_fn, validate_on_set=True, blockchain=blockchain)
wallet = Wallet(blockchain)
REGISTRY.add_wallet(wallet, label="node")   # root/validator node wallet discoverable

pubsub = PubSub(blockchain=blockchain, transaction_pool=transaction_pool)

ROOT_HOST = os.getenv("ROOT_HOST", "node0")
ROOT_PORT = int(os.getenv("ROOT_PORT", 5000))

if ROLE == "ROOT":
    # ROOT boots with just genesis; peers sync from it
    ret_first_block = blockchain.chain[0]
elif ROLE == "VALIDATOR":
    from .__main__ import startup_sync_if_peer
    threading.Thread(target=startup_sync_if_peer, daemon=True).start()
    ret_first_block = blockchain.chain[0]
else:
    # If you ever embed a miner in the app container (not recommended), you could hook it here.
    ret_first_block = blockchain.chain[0]

from . import routes
