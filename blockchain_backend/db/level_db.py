# """
# LevelDB integration for blockchain project
# - Provides a simple Python wrapper around LevelDB using plyvel
# - Includes helpers to store/retrieve blocks, chain height, and metadata
# - Adds a height->hash index for strict ordered iteration by block height
# """

# import os
# import json
# import time
# from typing import Optional, Dict, Any, Iterator, List

# # Try to import plyvel and raise a helpful error if missing.
# try:
#     import plyvel
# except Exception as e:
#     raise RuntimeError(
#         "plyvel (LevelDB Python bindings) is required by blockchain_backend.db.level_db. "
#         "Install system level libleveldb (e.g. 'sudo apt install libleveldb-dev') and "
#         "then 'pip install plyvel'. Original import error: " + str(e)
#     )

# META_PREFIX = b"meta:"              # meta:...
# BLOCK_KEY_PREFIX = b"b:"            # b:<hash> -> json(block)
# HEIGHT_INDEX_PREFIX = b"h:"         # h:<8-bytes-be> -> block-hash-bytes
# HEIGHT_META_KEY = META_PREFIX + b"height"  # meta:height -> 8-byte big-endian latest height

# # --- Configuration ---
# OPEN_RETRY_COUNT = int(os.getenv("CHAIN_DB_OPEN_RETRIES", "6"))
# OPEN_RETRY_DELAY = float(os.getenv("CHAIN_DB_OPEN_RETRY_DELAY", "1.0"))  # seconds

# # Utility conversions -------------------------------------------------------
# def _int_to_be(v: int) -> bytes:
#     return int(v).to_bytes(8, byteorder="big", signed=False)


# def _be_to_int(b: bytes) -> int:
#     return int.from_bytes(b, byteorder="big", signed=False)


# def _expand_path(p: Optional[str]) -> Optional[str]:
#     if not p:
#         return None
#     try:
#         return os.path.normpath(os.path.expanduser(os.path.expandvars(str(p))))
#     except Exception:
#         return None


# def _ensure_dir_for_path(path: str) -> None:
#     try:
#         os.makedirs(path, exist_ok=True)
#     except Exception:
#         # Best-effort: ignore
#         pass


# def _candidate_paths_from_env() -> List[str]:
#     """
#     Return ordered candidate absolute paths for LevelDB based on env.
#     NOTE: Only CHAIN_DB_PATH environment variable should control the DB dir.
#     If CHAIN_STORE_PATH is present we will prefer using its DIRECTORY only as a fallback
#     (to guard against misconfiguration), but we will never treat a .json file as the DB path.
#     """
#     cand = []
#     # prefer explicit DB path env var
#     db_env = os.getenv("CHAIN_DB_PATH")
#     if db_env:
#         cand.append(db_env)

#     # if only CHAIN_STORE_PATH provided, use its directory as a fallback (not the file)
#     store_env = os.getenv("CHAIN_STORE_PATH")
#     if store_env:
#         # use dirname only (if store_env ends with '.json', take dirname)
#         cand.append(os.path.dirname(store_env) or store_env)

#     # recommended default path used in compose
#     cand.append("/data/leveldb")

#     # alternative path used by older images / earlier dev runs
#     cand.append("/app/data/leveldb")

#     # project-local data dir (non-container)
#     cand.append(os.path.join(os.getcwd(), "data", "leveldb"))

#     # fallback to /tmp (last resort)
#     cand.append("/tmp/leveldb")

#     # normalize and uniquify
#     out = []
#     for c in cand:
#         try:
#             a = _expand_path(c)
#             if a:
#                 # If path looks like a file (endswith .json), convert to directory parent
#                 if a.lower().endswith(".json"):
#                     a = os.path.dirname(a) or a
#                 if a not in out:
#                     out.append(a)
#         except Exception:
#             continue
#     return out

# class LevelDBStore:
#     """
#     Lightweight LevelDB wrapper using plyvel.
#     Keys:
#       - b:<hash> -> JSON-encoded block bytes
#       - h:<8byteBE> -> block-hash bytes (index by height)
#       - meta:height -> 8byteBE current height
#       - meta:<other> -> JSON metadata bytes
#     """
#     def __init__(self, path: str, create_if_missing: bool = True):
#         self.path = path
#         if create_if_missing:
#             _ensure_dir_for_path(path)
#         # plyvel will create the DB directory when create_if_missing=True
#         self.db = plyvel.DB(path, create_if_missing=create_if_missing)

#     # ---- meta helpers ----
#     def _meta_key(self, key: str) -> bytes:
#         if isinstance(key, str):
#             key = key.encode("utf-8")
#         return META_PREFIX + key

#     def put_meta(self, key: str, value: Any) -> None:
#         """
#         Store metadata under 'meta:{key}'. Serializes value as JSON.
#         """
#         val_bytes = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
#         self.db.put(self._meta_key(key), val_bytes)

#     def get_meta(self, key: str, default: Optional[Any] = None) -> Any:
#         """
#         Get metadata value. Returns default if not found.
#         """
#         raw = self.db.get(self._meta_key(key))
#         if raw is None:
#             return default
#         try:
#             return json.loads(raw.decode("utf-8"))
#         except Exception:
#             # if stored as raw bytes (older format), return raw
#             return raw

#     def delete_meta(self, key: str) -> None:
#         self.db.delete(self._meta_key(key))

#     # ---- block ops ----
#     def _block_key(self, block_hash_hex: str) -> bytes:
#         if isinstance(block_hash_hex, str):
#             return BLOCK_KEY_PREFIX + block_hash_hex.encode("utf-8")
#         return BLOCK_KEY_PREFIX + bytes(block_hash_hex)

#     def put_block(self, block: Dict[str, Any]) -> None:
#         """
#         Persist block JSON, update height index and latest height meta atomically.
#         Expects block to include 'hash' and 'height'.
#         """
#         if "hash" not in block or "height" not in block:
#             raise ValueError("block must include 'hash' and 'height'")
#         h = int(block["height"])
#         key = self._block_key(block["hash"])
#         val = json.dumps(block, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
#         with self.db.write_batch() as wb:
#             wb.put(key, val)
#             wb.put(HEIGHT_INDEX_PREFIX + _int_to_be(h), block["hash"].encode("utf-8"))
#             wb.put(HEIGHT_META_KEY, _int_to_be(h))

#     def get_block(self, block_hash_hex: str) -> Optional[Dict[str, Any]]:
#         val = self.db.get(self._block_key(block_hash_hex))
#         if not val:
#             return None
#         try:
#             return json.loads(val.decode("utf-8"))
#         except Exception:
#             return None

#     def get_height(self) -> Optional[int]:
#         val = self.db.get(HEIGHT_META_KEY)
#         return _be_to_int(val) if val else None

#     def iter_blocks(self, reverse: bool = False) -> Iterator[Dict[str, Any]]:
#         """
#         Yield block dicts in key-lexicographic order of 'b:<hash>' entries.
#         This is maintained for compatibility with callers using block-key iteration.
#         """
#         it = self.db.iterator(prefix=BLOCK_KEY_PREFIX, include_value=True, reverse=reverse)
#         for k, v in it:
#             try:
#                 yield json.loads(v.decode("utf-8"))
#             except Exception:
#                 # skip corrupt entry
#                 continue

#     def iter_by_height(self, start: int = 0, end: Optional[int] = None, reverse: bool = False) -> Iterator[Dict[str, Any]]:
#         """
#         Iterate blocks by numeric height using the height index.
#         - start: inclusive start height
#         - end: exclusive end height (if provided)
#         - reverse: if True, iterate highest->lowest
#         """
#         # Keys are HEIGHT_INDEX_PREFIX + 8-byte big-endian height, so lexicographic order == numeric order.
#         # To support reverse iteration we use iterator with reverse flag.
#         it = self.db.iterator(prefix=HEIGHT_INDEX_PREFIX, include_value=True, reverse=reverse)
#         for k, v in it:
#             # validate key length: prefix + 8 bytes
#             if len(k) != len(HEIGHT_INDEX_PREFIX) + 8:
#                 continue
#             try:
#                 height = _be_to_int(k[len(HEIGHT_INDEX_PREFIX):])
#             except Exception:
#                 continue
#             if reverse:
#                 # when reverse, keys come from high->low; still enforce start/end semantics
#                 if end is not None and height < start:
#                     # passed below start when reverse iter; stop
#                     break
#                 if height >= (end if end is not None else float("inf")):
#                     # skip heights >= end
#                     continue
#             else:
#                 if height < start:
#                     continue
#                 if end is not None and height >= end:
#                     break
#             block_hash = v.decode("utf-8")
#             blk = self.get_block(block_hash)
#             if blk:
#                 yield blk

#     def get_all_blocks(self) -> List[Dict[str, Any]]:
#         """Return all blocks ordered by height (0..N)."""
#         blocks = []
#         for blk in self.iter_by_height(start=0, end=None, reverse=False):
#             blocks.append(blk)
#         return blocks

#     def close(self):
#         try:
#             self.db.close()
#         except Exception:
#             pass

#     def __del__(self):
#         # best-effort close
#         try:
#             self.close()
#         except Exception:
#             pass


# # ---------- Helper to open default store ----------
# def open_default_store(create_if_missing: bool = True) -> LevelDBStore:
#     """
#     Try candidate directories and open LevelDB at the first workable one.
#     This will not attempt to open a file as the DB path.
#     """
#     last_exc = None
#     candidates = _candidate_paths_from_env()
#     print(f"[leveldb] open_default_store: trying candidates: {candidates}")
#     for candidate in candidates:
#         if not candidate:
#             continue
#         path = _expand_path(candidate)
#         if not path:
#             continue

#         # Ensure candidate looks like a directory path (not a file)
#         if os.path.splitext(path)[1].lower() == ".json":
#             path = os.getenv("CHAIN_DB_PATH")
#             if path:
#                 try:
#                     return LevelDBStore(path)
#                 except Exception as e:
#                     raise RuntimeError(f"cannot open configured CHAIN_DB_PATH={path}: {e}")
#             # else fall back to candidates


#         for attempt in range(OPEN_RETRY_COUNT):
#             try:
#                 _ensure_dir_for_path(path)
#                 # confirm path is a directory we can list/create
#                 if not os.path.isdir(path):
#                     # best-effort try to make directory
#                     _ensure_dir_for_path(path)
#                 store = LevelDBStore(path, create_if_missing=create_if_missing)
#                 print(f"[leveldb] opened LevelDB store at: {path}")
#                 return store
#             except Exception as e:
#                 last_exc = e
#                 print(f"[leveldb] open attempt {attempt+1}/{OPEN_RETRY_COUNT} failed for {path}: {e}")
#                 time.sleep(OPEN_RETRY_DELAY)
#                 continue
#     raise RuntimeError(f"Could not open LevelDB store. Tried paths: {candidates}. Last error: {last_exc}")


"""
LevelDB integration for blockchain project
- Provides a simple Python wrapper around LevelDB using plyvel
- Includes helpers to store/retrieve blocks, chain height, and metadata
- Adds a height->hash index for strict ordered iteration by block height
- Robust open helper: uses CHAIN_DB_PATH, retries, detects LOCK and prints actionable errors
"""

import os
import json
import time
import sys
import traceback
from typing import Optional, Dict, Any, Iterator, List

# Try to import plyvel and raise a helpful error if missing.
try:
    import plyvel
except Exception as e:
    raise RuntimeError(
        "plyvel (LevelDB Python bindings) is required by blockchain_backend.db.level_db. "
        "Install system-level libleveldb (e.g. 'sudo apt install libleveldb-dev') and "
        "then 'pip install plyvel'. Original import error: " + str(e)
    )

META_PREFIX = b"meta:"              # meta:...
BLOCK_KEY_PREFIX = b"b:"            # b:<hash> -> json(block)
HEIGHT_INDEX_PREFIX = b"h:"         # h:<8-bytes-be> -> block-hash-bytes
HEIGHT_META_KEY = META_PREFIX + b"height"  # meta:height -> 8-byte big-endian latest height

# --- Configuration ---
OPEN_RETRY_COUNT = int(os.getenv("CHAIN_DB_OPEN_RETRIES", "6"))
OPEN_RETRY_DELAY = float(os.getenv("CHAIN_DB_OPEN_RETRY_DELAY", "1.0"))  # seconds

# Utility conversions -------------------------------------------------------
def _int_to_be(v: int) -> bytes:
    return int(v).to_bytes(8, byteorder="big", signed=False)


def _be_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def _expand_path(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    try:
        return os.path.normpath(os.path.expanduser(os.path.expandvars(str(p))))
    except Exception:
        return None


def _ensure_dir_for_path(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        # Best-effort: ignore
        pass


def _candidate_paths_from_env() -> List[str]:
    """
    Return ordered candidate absolute paths for LevelDB based on env.
    NOTE: Only CHAIN_DB_PATH environment variable should control the DB dir.
    If CHAIN_STORE_PATH is present we will prefer using its DIRECTORY only as a fallback
    (to guard against misconfiguration), but we will never treat a .json file as the DB path.
    """
    cand = []
    # prefer explicit DB path env var
    db_env = os.getenv("CHAIN_DB_PATH")
    if db_env:
        cand.append(db_env)

    # if only CHAIN_STORE_PATH provided, use its directory as a fallback (not the file)
    store_env = os.getenv("CHAIN_STORE_PATH")
    if store_env:
        # use dirname only (if store_env ends with '.json', take dirname)
        cand.append(os.path.dirname(store_env) or store_env)

    # recommended default path used in compose
    cand.append("/data/leveldb")

    # alternative path used by older images / earlier dev runs
    cand.append("/app/data/leveldb")

    # project-local data dir (non-container)
    cand.append(os.path.join(os.getcwd(), "data", "leveldb"))

    # fallback to /tmp (last resort)
    cand.append("/tmp/leveldb")

    # normalize and uniquify
    out = []
    for c in cand:
        try:
            a = _expand_path(c)
            if a:
                # If path looks like a file (endswith .json), convert to directory parent
                if a.lower().endswith(".json"):
                    a = os.path.dirname(a) or a
                if a not in out:
                    out.append(a)
        except Exception:
            continue
    return out


class LevelDBStore:
    """
    Lightweight LevelDB wrapper using plyvel.
    Keys:
      - b:<hash> -> JSON-encoded block bytes
      - h:<8byteBE> -> block-hash bytes (index by height)
      - meta:height -> 8byteBE current height
      - meta:<other> -> JSON metadata bytes
    """
    def __init__(self, path: str, create_if_missing: bool = True):
        self.path = path
        if create_if_missing:
            _ensure_dir_for_path(path)
        # plyvel will create the DB directory when create_if_missing=True
        self.db = plyvel.DB(path, create_if_missing=create_if_missing)

    # ---- meta helpers ----
    def _meta_key(self, key: str) -> bytes:
        if isinstance(key, str):
            key = key.encode("utf-8")
        return META_PREFIX + key

    def put_meta(self, key: str, value: Any) -> None:
        """
        Store metadata under 'meta:{key}'. Serializes value as JSON.
        """
        val_bytes = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.db.put(self._meta_key(key), val_bytes)

    def get_meta(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Get metadata value. Returns default if not found.
        """
        raw = self.db.get(self._meta_key(key))
        if raw is None:
            return default
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            # if stored as raw bytes (older format), return raw
            return raw

    def delete_meta(self, key: str) -> None:
        self.db.delete(self._meta_key(key))

    # ---- block ops ----
    def _block_key(self, block_hash_hex: str) -> bytes:
        if isinstance(block_hash_hex, str):
            return BLOCK_KEY_PREFIX + block_hash_hex.encode("utf-8")
        return BLOCK_KEY_PREFIX + bytes(block_hash_hex)

    def put_block(self, block: Dict[str, Any]) -> None:
        """
        Persist block JSON, update height index and latest height meta atomically.
        Expects block to include 'hash' and 'height'.
        """
        if "hash" not in block or "height" not in block:
            raise ValueError("block must include 'hash' and 'height'")
        h = int(block["height"])
        key = self._block_key(block["hash"])
        val = json.dumps(block, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        with self.db.write_batch() as wb:
            wb.put(key, val)
            wb.put(HEIGHT_INDEX_PREFIX + _int_to_be(h), block["hash"].encode("utf-8"))
            wb.put(HEIGHT_META_KEY, _int_to_be(h))

    def get_block(self, block_hash_hex: str) -> Optional[Dict[str, Any]]:
        val = self.db.get(self._block_key(block_hash_hex))
        if not val:
            return None
        try:
            return json.loads(val.decode("utf-8"))
        except Exception:
            return None

    def get_height(self) -> Optional[int]:
        val = self.db.get(HEIGHT_META_KEY)
        return _be_to_int(val) if val else None

    def iter_blocks(self, reverse: bool = False) -> Iterator[Dict[str, Any]]:
        """
        Yield block dicts in key-lexicographic order of 'b:<hash>' entries.
        This is maintained for compatibility with callers using block-key iteration.
        """
        it = self.db.iterator(prefix=BLOCK_KEY_PREFIX, include_value=True, reverse=reverse)
        for k, v in it:
            try:
                yield json.loads(v.decode("utf-8"))
            except Exception:
                # skip corrupt entry
                continue

    def iter_by_height(self, start: int = 0, end: Optional[int] = None, reverse: bool = False) -> Iterator[Dict[str, Any]]:
        """
        Iterate blocks by numeric height using the height index.
        - start: inclusive start height
        - end: exclusive end height (if provided)
        - reverse: if True, iterate highest->lowest
        """
        # Keys are HEIGHT_INDEX_PREFIX + 8-byte big-endian height, so lexicographic order == numeric order.
        # To support reverse iteration we use iterator with reverse flag.
        it = self.db.iterator(prefix=HEIGHT_INDEX_PREFIX, include_value=True, reverse=reverse)
        for k, v in it:
            # validate key length: prefix + 8 bytes
            if len(k) != len(HEIGHT_INDEX_PREFIX) + 8:
                continue
            try:
                height = _be_to_int(k[len(HEIGHT_INDEX_PREFIX):])
            except Exception:
                continue
            if reverse:
                # when reverse, keys come from high->low; still enforce start/end semantics
                if end is not None and height < start:
                    # passed below start when reverse iter; stop
                    break
                if height >= (end if end is not None else float("inf")):
                    # skip heights >= end
                    continue
            else:
                if height < start:
                    continue
                if end is not None and height >= end:
                    break
            block_hash = v.decode("utf-8")
            blk = self.get_block(block_hash)
            if blk:
                yield blk

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        """Return all blocks ordered by height (0..N)."""
        blocks = []
        for blk in self.iter_by_height(start=0, end=None, reverse=False):
            blocks.append(blk)
        return blocks

    def close(self):
        try:
            self.db.close()
        except Exception:
            pass

    def __del__(self):
        # best-effort close
        try:
            self.close()
        except Exception:
            pass


# ---------- Robust helper to open default store ----------
def open_leveldb_store(create_if_missing: bool = True) -> LevelDBStore:
    """
    Try candidate directories and open LevelDB at the first workable one.
    Preferred behavior:
      - Use CHAIN_DB_PATH env var if present (per-node mount)
      - Fall back to CHAIN_STORE_PATH dirname, /data/leveldb, /app/data/leveldb, ./data/leveldb, /tmp/leveldb
      - Retry OPEN_RETRY_COUNT times per candidate with OPEN_RETRY_DELAY
      - Detect LevelDB 'LOCK' errors and print actionable guidance
    Returns a LevelDBStore instance on success or raises RuntimeError on failure.
    """
    last_exc = None
    candidates = _candidate_paths_from_env()
    print(f"[leveldb] open_default_store: trying candidates: {candidates}")
    for candidate in candidates:
        if not candidate:
            continue
        path = _expand_path(candidate)
        if not path:
            continue

        # Ensure candidate looks like a directory path (not a file)
        if os.path.splitext(path)[1].lower() == ".json":
            # if user accidentally provided CHAIN_STORE_PATH pointing to a file, prefer CHAIN_DB_PATH if present
            configured = os.getenv("CHAIN_DB_PATH")
            if configured:
                try:
                    return LevelDBStore(_expand_path(configured), create_if_missing=create_if_missing)
                except Exception as e:
                    raise RuntimeError(f"cannot open configured CHAIN_DB_PATH={configured}: {e}")
            # else fall back to next candidate

        for attempt in range(OPEN_RETRY_COUNT):
            try:
                _ensure_dir_for_path(path)
                # confirm path is a directory we can list/create
                if not os.path.isdir(path):
                    _ensure_dir_for_path(path)
                # attempt open
                store = LevelDBStore(path, create_if_missing=create_if_missing)
                print(f"[leveldb] opened LevelDB store at: {path}")
                return store
            except Exception as e:
                last_exc = e
                err_text = str(e)
                # print the attempt failure
                print(f"[leveldb] open attempt {attempt+1}/{OPEN_RETRY_COUNT} failed for {path}: {err_text}", file=sys.stderr)
                # detect lock-specific messages and provide guidance early
                if "LOCK" in err_text or "already held" in err_text or "lock" in err_text.lower():
                    print(
                        "[leveldb] ERROR: Lock detected on LevelDB directory. "
                        "This means another process/container is using the same directory.\n"
                        "  - Ensure this container has its own mount (e.g. ./data/nodeX/leveldb:/data/leveldb)\n"
                        "  - Check host directory ownership/permissions\n"
                        "  - Avoid removing the LOCK file unless you are absolutely sure no process owns it.\n"
                        "  - If this is unexpected, check 'lsof <path>/LOCK' or 'docker logs' to find the owner."
                    , file=sys.stderr)
                    # For lock we typically should not keep retrying too long; break to next candidate
                    break
                time.sleep(OPEN_RETRY_DELAY)
                continue
    raise RuntimeError(f"Could not open LevelDB store. Tried paths: {candidates}. Last error: {last_exc}")


# Example entrypoint usage:
# STORE = open_leveldb_store()
