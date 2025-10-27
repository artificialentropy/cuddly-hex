import time

def normalize_timestamp(ts):
    """
    Accepts int-like timestamp in seconds or nanoseconds.
    Returns integer seconds.
    """
    try:
        ts = int(ts)
    except Exception:
        return int(time.time())

    # heuristic: if ts is > 1e12 it's likely micro/nano; if >1e15 -> nanoseconds
    if ts > 10**15:            # nanoseconds -> seconds
        return ts // 1_000_000_000
    if ts > 10**12:            # microseconds -> seconds
        return ts // 1_000_000
    return ts


# helper: remove common extraneous debug/meta keys from remote block dicts
def _strip_block_extras(raw_block: dict) -> dict:
    """
    Return a shallow copy of raw_block with keys removed that may be present
    in remote debug envelopes but not accepted by Block.__init__.
    """
    if not isinstance(raw_block, dict):
        return raw_block
    b = dict(raw_block)
    for k in ("version",):  # add other debug keys here if needed in future
        if k in b:
            b.pop(k, None)
    return b

# import os
# import json
# import tempfile
# import shutil
# import time

# # path to JSON snapshot file (override via env var)
# CHAIN_STORE_PATH = os.getenv("CHAIN_STORE_PATH", "/data/chain_store.json")

# # STORE should be set earlier when LevelDB is opened (e.g. STORE = LevelDBWrapper(...))
# # If your code already has a different name for the LevelDB handle, adapt references below.
# STORE = None  # set this to your LevelDB wrapper instance after opening DB

# def _atomic_write_json(path: str, obj: object, mode: int = 0o644) -> None:
#     """Write JSON atomically using a temp file then os.replace."""
#     d = os.path.dirname(path) or "."
#     os.makedirs(d, exist_ok=True)
#     with tempfile.NamedTemporaryFile("w", dir=d, delete=False, encoding="utf-8") as tf:
#         json.dump(obj, tf, indent=2, sort_keys=True)
#         tf.flush()
#         os.fsync(tf.fileno())
#         tmpname = tf.name
#     os.replace(tmpname, path)
#     try:
#         os.chmod(path, mode)
#     except Exception:
#         pass

# def _atomic_read_json(path: str):
#     """Read JSON file and return python object. Raises if unreadable."""
#     with open(path, "r", encoding="utf-8") as f:
#         return json.load(f)
