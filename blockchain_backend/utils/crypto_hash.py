import json, hashlib
from typing import Any

def _canon_bytes(x: Any) -> bytes:
    """Canonicalize Python data to deterministic JSON bytes."""
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _deep_canonicalize_for_args(args):
    """Ensure nested dicts/lists inside block data are canonical before hashing."""
    out = []
    for a in args:
        if isinstance(a, list):
            canon_list = []
            for item in a:
                if isinstance(item, dict):
                    canon_list.append(json.loads(_canon_bytes(item).decode("utf-8")))
                else:
                    canon_list.append(item)
            out.append(canon_list)
        elif isinstance(a, dict):
            out.append(json.loads(_canon_bytes(a).decode("utf-8")))
        else:
            out.append(a)
    return out

def crypto_hash(*args) -> str:
    """Deterministic hash: sha256(json([NETWORK_ID, ts, last_hash, data, difficulty, nonce, merkle]))"""
    prepared = _deep_canonicalize_for_args(list(args))
    return _sha256_hex(_canon_bytes(prepared))
