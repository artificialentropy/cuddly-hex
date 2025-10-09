# blockchain_backend/core/node.py
from typing import Optional
from blockchain_backend.db.level_db import open_default_store as _open_default_store

_STORE: Optional[object] = None

def get_store():
    """Return a per-process LevelDB store singleton. Open on first call."""
    global _STORE
    if _STORE is None:
        try:
            _STORE = _open_default_store()
            print(f"[node] LevelDB store opened at: {_STORE.path}")
        except Exception as e:
            print(f"[node] failed to open LevelDB store: {e}")
            _STORE = None
    return _STORE

def close_store():
    global _STORE
    try:
        if _STORE is not None:
            _STORE.close()
            print("[node] LevelDB store closed")
    except Exception:
        pass
    _STORE = None
