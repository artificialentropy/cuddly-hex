"""
LevelDB integration for blockchain project
- Provides a simple Python wrapper around LevelDB using plyvel
- Includes helpers to store/retrieve blocks, chain height, and metadata
- Adds a height->hash index for strict ordered iteration by block height
"""

import os
import json
import time
import plyvel
from typing import Optional, Dict, Any, Iterator, List


META_PREFIX = b"meta:"
# --- Configuration ---
OPEN_RETRY_COUNT = int(os.getenv("CHAIN_DB_OPEN_RETRIES", "6"))
OPEN_RETRY_DELAY = float(os.getenv("CHAIN_DB_OPEN_RETRY_DELAY", "1.0"))  # seconds

BLOCK_KEY_PREFIX = b"b:"
HEIGHT_KEY = b"height"
META_KEY_PREFIX = b"m:"
HEIGHT_INDEX_PREFIX = b"h:"


# near the bottom of level_db.py — replace existing open_default_store()

def _candidate_paths_from_env() -> List[str]:
    """Return ordered candidate absolute paths for LevelDB based on env and common fallbacks."""
    cand = []
    # explicit env
    p = os.getenv("CHAIN_DB_PATH") or os.getenv("CHAIN_STORE_PATH")
    if p:
        cand.append(p)
    # common absolute mount (compose uses this)
    cand.append("/data/leveldb")
    # some images or test setups use /app/data (your logs showed /app/data/leveldb)
    cand.append("/app/data/leveldb")
    # relative project path inside container
    cand.append(os.path.join(os.getcwd(), "data", "leveldb"))
    # final fallback to /tmp/leveldb
    cand.append("/tmp/leveldb")
    # make absolute and unique
    out = []
    for c in cand:
        try:
            a = os.path.abspath(str(c))
            if a not in out:
                out.append(a)
        except Exception:
            continue
    return out

def open_default_store(create_if_missing: bool = True):
    """
    Open store trying sensible candidate paths in order. This helps on platforms
    (Windows, Docker-for-Desktop) where bind mounts or working-dir vary.
    """
    candidates = _candidate_paths_from_env()
    last_exc = None
    for path in candidates:
        try:
            # try to create parent dir with permissive mode (best-effort)
            os.makedirs(path, exist_ok=True)
            store = LevelDBStore(path, create_if_missing=create_if_missing)
            print(f"[leveldb] opened LevelDB store at: {store.path}")
            return store
        except Exception as e:
            last_exc = e
            print(f"[leveldb] open attempt failed for {path}: {e}")
            continue
    # all failed, raise the last exception
    raise RuntimeError(f"Could not open LevelDB store. Tried: {candidates}. Last error: {last_exc}")


def _int_to_be(v: int) -> bytes:
    return v.to_bytes(8, byteorder="big", signed=False)


def _be_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def _expand_path(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    return os.path.normpath(os.path.expanduser(os.path.expandvars(p)))


def _candidate_paths() -> Iterator[str]:
    yield _expand_path(os.getenv("CHAIN_DB_PATH"))
    yield _expand_path(os.getenv("CHAIN_STORE_PATH"))
    yield "/data/leveldb"
    yield "/data"
    yield os.path.join(os.getcwd(), "data", "leveldb")
    yield os.path.join(os.getcwd(), "data")


def _ensure_dir_for_path(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


class LevelDBStore:
    def __init__(self, path: str, create_if_missing: bool = True):
        self.path = path
        if create_if_missing:
            _ensure_dir_for_path(path)
        self.db = plyvel.DB(path, create_if_missing=create_if_missing)
    def _meta_key(self, key: str) -> bytes:
        if isinstance(key, str):
            key = key.encode("utf-8")
        return META_PREFIX + key

    def put_meta(self, key: str, value: Any) -> None:
        """
        Store metadata under 'meta:{key}'. Serializes value as JSON.
        """
        val_bytes = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        # if using plyvel:
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
        """Optional helper"""
        self.db.delete(self._meta_key(key))
    # ---------- block ops ----------
    def _block_key(self, block_hash_hex: str) -> bytes:
        return BLOCK_KEY_PREFIX + block_hash_hex.encode()

    def put_block(self, block: Dict[str, Any]) -> None:
        if "hash" not in block or "height" not in block:
            raise ValueError("block must include 'hash' and 'height'")
        h = int(block["height"])
        key = self._block_key(block["hash"])
        val = json.dumps(block, separators=(",", ":")).encode()
        with self.db.write_batch() as wb:
            wb.put(key, val)
            wb.put(HEIGHT_INDEX_PREFIX + _int_to_be(h), block["hash"].encode())
            wb.put(HEIGHT_KEY, _int_to_be(h))

    def get_block(self, block_hash_hex: str) -> Optional[Dict[str, Any]]:
        val = self.db.get(self._block_key(block_hash_hex))
        return json.loads(val.decode()) if val else None

    def get_height(self) -> Optional[int]:
        val = self.db.get(HEIGHT_KEY)
        return _be_to_int(val) if val else None
    def iter_blocks(self, reverse: bool = False) -> Iterator[Dict[str, Any]]:
        """
        Yield block dicts in lexicographic order of their block key (b:<hash>).
        This reproduces the older API some callers expect.
        `reverse`: if True, iterate in reverse key order.
        """
        it = self.db.iterator(prefix=BLOCK_KEY_PREFIX, include_value=True, reverse=reverse)
        for k, v in it:
            try:
                yield json.loads(v.decode("utf-8"))
            except Exception:
                continue

    def iter_by_height(self, start: int = 0, end: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        it = self.db.iterator(prefix=HEIGHT_INDEX_PREFIX, include_value=True)
        for k, v in it:
            if len(k) != len(HEIGHT_INDEX_PREFIX) + 8:
                continue
            height = _be_to_int(k[len(HEIGHT_INDEX_PREFIX):])
            if height < start:
                continue
            if end is not None and height >= end:
                break
            block_hash = v.decode()
            blk = self.get_block(block_hash)
            if blk:
                yield blk

    def close(self):
        try:
            self.db.close()
        except Exception:
            pass


# ---------- Helper to open default store ----------
def open_default_store() -> LevelDBStore:
    last_exc = None
    for candidate in _candidate_paths():
        if not candidate:
            continue
        for attempt in range(OPEN_RETRY_COUNT):
            try:
                path = _expand_path(candidate)
                _ensure_dir_for_path(path)
                store = LevelDBStore(path, create_if_missing=True)
                print(f"[leveldb] opened LevelDB store at: {path}")
                return store
            except Exception as e:
                last_exc = e
                time.sleep(OPEN_RETRY_DELAY)
                continue
    raise last_exc or RuntimeError("no LevelDB path available")
