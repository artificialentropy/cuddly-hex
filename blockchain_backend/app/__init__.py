# blockchain_backend/app/__init__.py
import os
import threading
import atexit
from flask import Flask

from blockchain_backend.wallet.wallet_registry import REGISTRY
from blockchain_backend.core.blockchain import Blockchain
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.wallet.transaction_pool import TransactionPool
from blockchain_backend.utils.pubsub import PubSub
from blockchain_backend.utils.config import ROLE
from .app_state import resolve_asset_fn, ASSETS, rebuild_assets_from_chain

# Asset class used when loading meta
from blockchain_backend.wallet.transaction import Asset

# Import lazy per-process store accessor (opens LevelDB on first call)
# Note: keep the imported name as a function so opening happens per process.
from blockchain_backend.core.node import get_store, close_store as _close_store_func

app = Flask(__name__)

# Open store in THIS process (get_store will open lazily per-process and return a singleton).
# This avoids master-worker fork/handle-sharing issues with Gunicorn.
STORE = None
try:
    STORE = get_store()
    # get_store may print its own debug message
except Exception as e:
    # don't crash the app on store errors; keep running with in-memory chain
    print(f"[app] get_store() failed: {e}")
    STORE = None

# Create blockchain with the store (if available). This ensures the Blockchain loads from LevelDB.
try:
    blockchain = Blockchain(store=STORE)
    print(f"[app] blockchain len after init = {len(blockchain.chain)} (store present: {STORE is not None})")
except Exception as e:
    # defensive fallback to genesis-only blockchain
    print(f"[app] failed to initialize blockchain from store: {e}")
    blockchain = Blockchain(store=None)

# --- create other singletons that depend on blockchain ---
transaction_pool = TransactionPool(resolve_asset_fn=resolve_asset_fn, validate_on_set=True, blockchain=blockchain)
wallet = Wallet(blockchain)
REGISTRY.add_wallet(wallet, label="node")   # root/validator node wallet discoverable

pubsub = PubSub(blockchain=blockchain, transaction_pool=transaction_pool)

# After blockchain creation: try fast load of ASSETS from LevelDB meta; fallback to full scan.
try:
    store = get_store()
    if store is not None:
        meta = store.get_meta("assets")
        if meta:
            ASSETS.clear()
            for aid, md in meta.items():
                ASSETS[aid] = Asset(
                    asset_id=aid,
                    owner=md.get("owner"),
                    price=md.get("price", 0),
                    currency=md.get("currency", "COIN"),
                    transferable=md.get("transferable", True),
                )
            print(f"[app] loaded {len(ASSETS)} assets from LevelDB meta")
        else:
            rebuild_assets_from_chain(blockchain.chain)
    else:
        rebuild_assets_from_chain(blockchain.chain)
except Exception as e:
    print("[app] load assets from store failed, rebuilding from chain:", e)
    try:
        rebuild_assets_from_chain(blockchain.chain)
    except Exception as e2:
        print("[app] rebuild_assets_from_chain also failed:", e2)

# Expose a reference block for other modules
ROOT_HOST = os.getenv("ROOT_HOST", "node0")
ROOT_PORT = int(os.getenv("ROOT_PORT", 5000))

if ROLE == "ROOT":
    # ROOT boots with just genesis; peers sync from it
    ret_first_block = blockchain.chain[0]
elif ROLE == "VALIDATOR":
    # lazy import to avoid circulars and start background sync thread
    from .__main__ import startup_sync_if_peer
    threading.Thread(target=startup_sync_if_peer, daemon=True).start()
    ret_first_block = blockchain.chain[0]
else:
    ret_first_block = blockchain.chain[0]

# register HTTP routes
from . import routes  # noqa: E402,F401

# register cleanup to close LevelDB on exit (single registration)
def _close_store():
    try:
        # prefer central close helper if available
        try:
            _close_store_func()
        except Exception:
            # fallback: close STORE directly
            if STORE is not None:
                STORE.close()
        print("[app] LevelDB store closed")
    except Exception:
        pass

atexit.register(_close_store)
