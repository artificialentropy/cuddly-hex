# blockchain_backend/core/node.py
from typing import Optional
import os
import sys
from blockchain_backend.db.level_db import LevelDBStore, open_leveldb_store

_STORE: Optional[LevelDBStore] = None


def get_store() -> Optional[LevelDBStore]:
    """
    Return a per-process LevelDB store singleton.
    Opens on first call using robust open_leveldb_store()
    which detects LOCKs, retries, and respects CHAIN_DB_PATH env var.
    """
    global _STORE
    if _STORE is None:
        try:
            _STORE = open_leveldb_store()
            # add defensive log with NODE_ID + CHAIN_DB_PATH
            node_id = os.getenv("NODE_ID") or os.getenv("PUBNUB_UUID") or "unknown"
            db_path = getattr(_STORE, "path", os.getenv("CHAIN_DB_PATH", "/data/leveldb"))
            print(f"[node:{node_id}] LevelDB store opened at: {db_path}")
        except Exception as e:
            print(f"[node] failed to open LevelDB store: {e}", file=sys.stderr)
            _STORE = None
    return _STORE


def close_store() -> None:
    """
    Safely close and clear the singleton LevelDB store.
    Registered at process exit in app/__init__.py
    """
    global _STORE
    try:
        if _STORE is not None:
            _STORE.close()
            print("[node] LevelDB store closed")
    except Exception as e:
        print(f"[node] error closing store: {e}", file=sys.stderr)
    _STORE = None
