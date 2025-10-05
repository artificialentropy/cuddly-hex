# rig.py
"""
GPU/CPU rig helper for mining.
This rig implementation matches the miner/server canonical header JSON preimage.
Provides `gpu_find_nonce(header, difficulty, txs, *, batch=..., workers=..., version=...)`.

It uses multiprocessing Pool for CPU parallelism and can be swapped for a true GPU implementation.
"""
from __future__ import annotations
import os
import json
import hashlib
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Tuple, Optional, Any

# === CONFIG (match node) ===
# HEADER_MODE is JSON only for compatibility with the server miner code.
HEADER_MODE = "json"

# If you ever switch to byte-packed headers, update these accordingly.
INT_ENDIAN = "little"
TS_WIDTH = 8
DIFF_WIDTH = 4
NONCE_WIDTH = 4
VERSION_WIDTH = 4

# Many nodes use single-sha256 on JSON header, or double-sha256 on bytes (bitcoin-style).
DOUBLE_SHA = False

# === Helpers ===

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def canon_json_bytes(obj: Any) -> bytes:
    # Deterministic JSON representation: sorted keys, no spaces
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# === Merkle computation (txid = sha256(canonical_json(tx without 'id'))) ===

def txid_from_tx(tx: Dict[str, Any]) -> bytes:
    tx_no_id = {k: v for k, v in tx.items() if k != "id"}
    return sha256(canon_json_bytes(tx_no_id))


def merkle_root_from_txs(txs: List[Dict[str, Any]]) -> str:
    """
    Compute merkle root:
      - leaf = sha256(canon_json(tx without 'id'))
      - parent = sha256(left_bytes + right_bytes)
      - if odd, duplicate last
    Returns lower-case hex string (64 chars).
    """
    if not txs:
        return sha256(b"").hex()

    layer = [txid_from_tx(tx) for tx in txs]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(sha256(layer[i] + layer[i + 1]))
        layer = nxt
    return layer[0].hex()

# === Header preimage / hash ===

def header_map(version: int, last_hash_hex: str, merkle_root_hex: str,
               timestamp: int, difficulty: int, nonce: int) -> Dict[str, Any]:
    # canonical field set and types - JSON path
    return {
        "version": int(version),
        "last_hash": last_hash_hex.lower(),
        "merkle_root": merkle_root_hex.lower(),
        "timestamp": int(timestamp),
        "difficulty": int(difficulty),
        "nonce": int(nonce),
    }


def header_hash_hex(version: int, last_hash_hex: str, merkle_root_hex: str,
                    timestamp: int, difficulty: int, nonce: int,
                    double_sha: bool = False) -> str:
    # JSON header hashing
    hdr = header_map(version, last_hash_hex, merkle_root_hex, timestamp, difficulty, nonce)
    b = canon_json_bytes(hdr)
    if double_sha:
        return sha256d(b).hex()
    return sha256_hex(b)

# === Difficulty check ===

def meets_difficulty(hex_digest: str, difficulty: int) -> bool:
    return hex_digest.startswith("0" * int(difficulty))

# === Worker scanning ===

def _scan_range(args) -> Tuple[Optional[int], Optional[str]]:
    version, last_hash, merkle, timestamp, difficulty, start, count, double_sha = args
    end = start + count
    for nonce in range(start, end):
        h = header_hash_hex(version, last_hash, merkle, timestamp, difficulty, nonce, double_sha=double_sha)
        if meets_difficulty(h, difficulty):
            return nonce, h
    return None, None


def gpu_find_nonce(header: Dict[str, Any], difficulty: int, txs: List[Dict[str, Any]], *,
                   batch: int = 1_000_000, workers: Optional[int] = None, version: int = 1,
                   double_sha: Optional[bool] = None) -> Tuple[Optional[int], Optional[str]]:
    """
    header: {"last_hash": str, "timestamp": int, "merkle": optional}
    txs: list of tx dicts (exactly as the node expects)
    returns: (nonce, hexhash) or (None, None) after one sweep

    Note: This function name is `gpu_find_nonce` to be a drop-in replacement for a true GPU rig.
    It uses multiprocessing to parallelize CPU search.
    """
    if workers is None:
        workers = max(1, cpu_count() - 1)

    last_hash = header.get("last_hash")
    timestamp = int(header.get("timestamp"))
    # compute merkle root once (canonical)
    merkle = header.get("merkle") or merkle_root_from_txs(txs)

    # default double_sha if not provided
    if double_sha is None:
        double_sha = DOUBLE_SHA

    start_base = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFF
    chunk = max(10_000, batch // workers)

    tasks = []
    for i in range(workers):
        s = start_base + i * chunk
        tasks.append((version, last_hash, merkle, timestamp, int(difficulty), s, chunk, bool(double_sha)))

    with Pool(processes=workers) as pool:
        for nonce, hexh in pool.imap_unordered(_scan_range, tasks):
            if nonce is not None:
                return nonce, hexh

    return None, None

# === Self-check helper ===

def recompute_and_verify_candidate(block: Dict[str, Any]) -> None:
    txs = block.get("data", [])
    merkle_calc = merkle_root_from_txs(txs) if txs else block.get("merkle", "")
    if merkle_calc and block.get("merkle") and block["merkle"].lower() != merkle_calc:
        raise ValueError(f"Merkle mismatch: block={block.get('merkle')} calc={merkle_calc}")

    calc = header_hash_hex(block.get("version", 1), block["last_hash"], merkle_calc or block.get("merkle"),
                           block["timestamp"], block["difficulty"], block["nonce"],
                           double_sha=block.get("double_sha", False))
    if calc != block.get("hash"):
        raise ValueError(f"Header hash mismatch: block={block.get('hash')} calc={calc}")

# Expose API
__all__ = ["gpu_find_nonce", "recompute_and_verify_candidate", "merkle_root_from_txs"]
