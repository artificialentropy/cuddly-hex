# blockchain_backend/app/__init__.py
import os
import threading
import atexit
from flask import Flask
import json
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
    print(f"[app] get_store() returned: {'present' if STORE is not None else 'None'} (NODE_ID={os.getenv('NODE_ID')})")
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

# --- INSERT: robust disk snapshot adoption/population ---
try:
    from . import routes as _routes  # local import to avoid top-level circulars
    if hasattr(_routes, "load_chain_from_disk"):
        try:
            disk_chain = _routes.load_chain_from_disk()
            if not disk_chain:
                print("[app] load_chain_from_disk(): no snapshot found")
            else:
                disk_len = len(disk_chain)
                curr_len = len(blockchain.chain)
                print(f"[app] disk snapshot found: {disk_len} blocks (current in-memory: {curr_len})")

                # Helper: detect if STORE (LevelDB) appears empty for this process
                store_obj = None
                try:
                    store_obj = globals().get("STORE", None)
                except Exception:
                    store_obj = None

                def store_is_empty(store) -> bool:
                    if store is None:
                        return True
                    try:
                        # prefer explicit API
                        if hasattr(store, "get_height"):
                            h = store.get_height()
                            return (h is None) or (int(h) == 0)
                        # fallback to iter_by_height / iter_blocks probes
                        if hasattr(store, "iter_by_height"):
                            it = store.iter_by_height(start=0)
                            for _ in it:
                                return False
                            return True
                        if hasattr(store, "iter_blocks"):
                            it = store.iter_blocks()
                            for _ in it:
                                return False
                            return True
                    except Exception:
                        # if any error reading store, consider it non-empty to be conservative
                        return False
                    return True

                # 1) If incoming chain is longer -> replace (safe)
                if disk_len > curr_len:
                    try:
                        blockchain.replace_chain(disk_chain)
                        print("[app] in-memory blockchain replaced from disk snapshot (incoming longer).")
                    except Exception as e_rep:
                        # try converting dict -> Block objects then replace
                        try:
                            from blockchain_backend.core.block import Block
                            incoming = [Block.from_json(b) for b in disk_chain]
                            blockchain.replace_chain(incoming)
                            print("[app] in-memory blockchain replaced from disk snapshot (converted to Block objects).")
                        except Exception as e_conv:
                            print("[app] failed to replace in-memory blockchain from disk snapshot:", e_rep, e_conv)

                # 2) If lengths equal or shorter: do not replace by default.
                #    But if LevelDB is empty for this process, populate LevelDB from snapshot (safe, idempotent).
                else:
                    # If the store is empty, populate it (so future starts will read from LevelDB)
                    try:
                        if store_is_empty(store_obj):
                            print("[app] LevelDB appears empty for this process; populating from disk snapshot...")
                            # attempt to write blocks into STORE using its put_block / put API
                            # Order blocks by height for consistent insertion
                            try:
                                chain_sorted = sorted(disk_chain, key=lambda b: int(b.get("height", 0)))
                            except Exception:
                                chain_sorted = disk_chain
                            for blk in chain_sorted:
                                try:
                                    if hasattr(store_obj, "put_block"):
                                        store_obj.put_block(blk)
                                    elif hasattr(store_obj, "put"):
                                        key = blk.get("hash") or str(blk.get("height"))
                                        store_obj.put(key, blk)
                                    elif hasattr(store_obj, "db") and hasattr(store_obj.db, "put"):
                                        key = (str(blk.get("height")) + ":" + (blk.get("hash") or ""))[:200]
                                        store_obj.db.put(key.encode("utf-8"), json.dumps(blk).encode("utf-8"))
                                    else:
                                        print("[app] unknown STORE API; skipping population to LevelDB")
                                        break
                                except Exception as e_w:
                                    print(f"[app] warning: failed to put block height={blk.get('height')} hash={blk.get('hash')}: {e_w}")
                            print("[app] LevelDB populate attempt done.")
                        else:
                            # store not empty; we won't overwrite in-memory chain because incoming isn't longer
                            print("[app] LevelDB not empty (or unreadable); skipping population. Incoming snapshot not longer than in-memory chain.")
                    except Exception as e_pop:
                        print("[app] error while checking/populating LevelDB from snapshot:", e_pop)

                    # Optional force-replace controlled by env var (use with extreme caution)
                    try:
                        force = os.getenv("CHAIN_FORCE_REPLACE", "").lower() in ("1", "true", "yes")
                        if force:
                            try:
                                blockchain.replace_chain(disk_chain)
                                print("[app] in-memory blockchain forcibly replaced from disk snapshot (CHAIN_FORCE_REPLACE=1).")
                            except Exception as e_force:
                                print("[app] CHAIN_FORCE_REPLACE requested but replace_chain failed:", e_force)
                    except Exception:
                        pass

        except Exception as e:
            print("[app] load_chain_from_disk() call failed:", e)
except Exception:
    # best-effort: if routes isn't importable yet, skip
    pass
# --- END INSERT ---


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
                try:
                    STORE.close()
                except Exception:
                    pass
        print("[app] LevelDB store closed")
    except Exception:
        pass

atexit.register(_close_store)
