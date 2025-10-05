#!/usr/bin/env python3
"""
simple_miner.py - authoritative miner that matches node preimage & submit guard.

Drop this into your miners/ folder and run from repo root so blockchain_backend imports resolve.

Usage example (PowerShell from repo root):
  $env:PYTHONPATH = (Get-Location).Path
  python .\miners\simple_miner.py --node http://127.0.0.1:5000 --addr miner-demo-addr --token secret123 --debug-dir "..\block data"

Behavior:
 - Mines using crypto_hash(NETWORK_ID, timestamp, last_hash, data, difficulty, nonce, merkle)
 - Uses merkle_root(block_data) as authoritative merkle
 - Validates GPU rig results by recomputing crypto_hash(...)
 - Before any submit, recomputes canonical hash and aborts if mismatch (writes aborted debug file)
"""
from __future__ import annotations
import os
import time
import argparse
import requests
import sys
import json
import hashlib
import inspect
from typing import Any, Dict, List, Tuple, Optional, Callable
from copy import deepcopy

# local helper / client module (expects functions like wait_ready, detect_merkle_builder_from_tip, etc.)
import miner_client as mc

# optional GPU rig (must follow same preimage semantics)
try:
    from rig import gpu_find_nonce  # optional; may not exist
except Exception:
    gpu_find_nonce = None

# node helpers (must be importable when run from repo root)
from blockchain_backend.utils.crypto_hash import crypto_hash
from blockchain_backend.utils.hex_to_binary import hex_to_binary
from blockchain_backend.utils.merkle import merkle_root

# ---------- config / tunables ----------
MAX_VARIANT_TRIES = 6
BASE_BACKOFF = 0.5

# ---------- canonical JSON helpers ----------
def canonical_json(obj: Any, ensure_ascii: bool = False, separators=(',', ':')) -> str:
    return json.dumps(obj, sort_keys=True, separators=separators, ensure_ascii=ensure_ascii)

def _sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_hex_from_text(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

# ---------- header (JSON) preimage helpers - used only for diagnostics ----------
def header_map(version: int, last_hash: str, merkle_root: str,
               timestamp: int, difficulty: int, nonce: int) -> Dict[str, Any]:
    return {
        "version": int(version),
        "last_hash": (last_hash or "").lower(),
        "merkle_root": (merkle_root or "").lower(),
        "timestamp": int(timestamp),
        "difficulty": int(difficulty),
        "nonce": int(nonce),
    }

def header_json_hash(version: int, last_hash: str, merkle_root: str,
                     timestamp: int, difficulty: int, nonce: int,
                     double_sha: bool = False) -> str:
    hdr = header_map(version, last_hash, merkle_root, timestamp, difficulty, nonce)
    jb = canonical_json(hdr, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if double_sha:
        return hashlib.sha256(hashlib.sha256(jb).digest()).hexdigest()
    return hashlib.sha256(jb).hexdigest()

# ---------- merkle helpers (diagnostic builder variants) ----------
def parent_hexcat(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256((left_hex + right_hex).encode('utf-8')).hexdigest()

def parent_bytescat(left_hex: str, right_hex: str) -> str:
    left_b = bytes.fromhex(left_hex)
    right_b = bytes.fromhex(right_hex)
    return hashlib.sha256(left_b + right_b).hexdigest()

def _build_merkle(leaves_hex: List[str], parent_fn: Callable[[str, str], str]) -> str:
    if not leaves_hex:
        return _sha256_hex_bytes(b"")
    level = leaves_hex[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(parent_fn(level[i], level[i+1]))
        level = nxt
    return level[0]

# ---------- diagnostic variants builder (not used for mining) ----------
def build_block_hash_variants(network_id: str,
                              timestamp: int, last_hash: str,
                              merkle: str, nonce: int, difficulty: int, data: List[dict]) -> List[str]:
    variants = []
    arrA = [timestamp, last_hash, merkle, nonce, difficulty, data]
    variants.append(sha256_hex_from_text(canonical_json(arrA)))
    arrB = [network_id, timestamp, last_hash, merkle, nonce, difficulty, data]
    variants.append(sha256_hex_from_text(canonical_json(arrB)))
    arrC = [timestamp, last_hash, data, merkle, nonce, difficulty]
    variants.append(sha256_hex_from_text(canonical_json(arrC)))
    parts = [timestamp, last_hash, merkle, nonce, difficulty, data]
    parts_sha = [sha256_hex_from_text(canonical_json(p)) for p in parts]
    variants.append(sha256_hex_from_text(''.join(parts_sha)))
    variants.append(sha256_hex_from_text(variants[0]))
    seen = set(); out = []
    for v in variants:
        if v and v not in seen:
            seen.add(v); out.append(v)
    return out

# ---------- debug file helper ----------
def safe_make_fname(debug_dir: Optional[str], prefix: str) -> str:
    ts_ms = int(time.time() * 1000)
    if debug_dir:
        dd = os.path.abspath(debug_dir)
        os.makedirs(dd, exist_ok=True)
        fname = os.path.join(dd, f"{prefix}_{ts_ms}.json")
    else:
        fname = f"{prefix}_{ts_ms}.json"
    return fname

# ---------- submit wrapper (authoritative & abort-on-mismatch) ----------
def submit_block(sess: requests.Session,
                 base: str,
                 candidate: Dict[str, Any],
                 detect_version: int,
                 double_sha: bool,
                 network_id: str,
                 token_already_in_headers: bool = True,
                 debug_dir: Optional[str] = None) -> Tuple[bool, int, Dict[str, Any]]:
    """
    Submit the candidate to the node.
    Recompute canonical header hash (node preimage) unconditionally, log it,
    abort POST if miner-provided hash != recomputed canonical hash, and save debug files.
    """
    original_hash = candidate.get("hash")

    # Recompute canonical hash using node preimage
    recomputed_hash = None
    try:
        ts = int(candidate.get("timestamp"))
        last_hash = candidate.get("last_hash")
        diff = int(candidate.get("difficulty"))
        nonce = int(candidate.get("nonce"))
        merkle = candidate.get("merkle", "")
        recomputed_hash = crypto_hash(network_id, ts, last_hash, candidate.get("data", []), diff, nonce, merkle)
    except Exception as e:
        print("[miner|submit] ERROR recomputing canonical hash:", e)
        try:
            recomputed_hash = header_json_hash(int(detect_version or 1), candidate.get("last_hash", ""), candidate.get("merkle", ""),
                                               int(candidate.get("timestamp", 0)), int(candidate.get("difficulty", 0)),
                                               int(candidate.get("nonce", 0)), double_sha=double_sha)
        except Exception:
            recomputed_hash = None

    # Overwrite with authoritative hash
    if recomputed_hash is not None:
        candidate["hash"] = recomputed_hash

    # Log both
    print("[miner|submit] original_hash:  ", original_hash)
    print("[miner|submit] recomputed_hash:", recomputed_hash)

    # If mismatch, abort and save debug
    if original_hash is not None and recomputed_hash is not None and original_hash != recomputed_hash:
        print("[miner|submit] ABORT: miner-provided hash != recomputed canonical hash (submission blocked).")
        if debug_dir:
            try:
                fname = safe_make_fname(debug_dir, "aborted_submit")
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump({
                        "attempted_candidate": candidate,
                        "original_hash": original_hash,
                        "recomputed_hash": recomputed_hash
                    }, f, indent=2, sort_keys=True)
                print(f"[miner|submit] saved aborted debug to {fname}")
            except Exception as e:
                print("[miner|submit] warning: couldn't write aborted debug file:", e)
        return False, 400, {"error": "aborted: miner hash mismatch", "original_hash": original_hash, "recomputed_hash": recomputed_hash}

    # Proceed to HTTP POST
    try:
        r = sess.post(f"{base}/blocks/submit", json={"block": candidate}, timeout=(5, 30))
        code = r.status_code
        try:
            body = r.json()
        except Exception:
            body = {"text": r.text}

        ok = (code == 200)
        print(f"[miner] submit -> status={code} body={body}")

        # Save debug files
        if debug_dir:
            try:
                if ok:
                    fname = safe_make_fname(debug_dir, "accepted_block")
                    with open(fname, "w", encoding="utf-8") as f:
                        json.dump({"block": candidate, "response": body}, f, indent=2, sort_keys=True)
                    print(f"[miner] saved accepted block to {fname}")
                else:
                    fname = safe_make_fname(debug_dir, "rejected_block")
                    with open(fname, "w", encoding="utf-8") as f:
                        json.dump({"block": candidate, "node_response": body}, f, indent=2, sort_keys=True)
                    print(f"[miner] saved rejected debug to {fname}")
            except Exception as e:
                print("[miner] warning: could not save debug file:", e)

        return ok, code, body
    except requests.RequestException as e:
        return False, 0, {"text": str(e)}

# ---------- CLI args ----------
def argp():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default=os.getenv("MINER_NODE_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--addr", default=os.getenv("MINER_ADDRESS", "miner-demo-addr"))
    ap.add_argument("--token", default=os.getenv("MINER_TOKEN", ""))
    ap.add_argument("--allow-empty", action="store_true", default=os.getenv("MINER_ALLOW_EMPTY", "0") == "1")
    ap.add_argument("--interval", type=float, default=float(os.getenv("MINER_INTERVAL", "3")))
    ap.add_argument("--mpt-window", type=int, default=int(os.getenv("MEDIAN_PAST_WINDOW", "11")))
    ap.add_argument("--debug-dir", default=os.getenv("MINER_DEBUG_DIR", ""))
    ap.add_argument("--use-rig", action="store_true", default=os.getenv("MINER_USE_RIG", "0") == "1")
    return ap.parse_args()

# ---------- main miner loop ----------
def main():
    args = argp()
    base = args.node.rstrip("/")
    sess = requests.Session()
    if args.token:
        sess.headers.update({"X-Miner-Token": args.token})

    print(f"[miner] starting. node={base} addr={args.addr} allow_empty={int(args.allow_empty)} debug_dir={args.debug_dir!r}")
    # Print which crypto_hash is imported (debug import path)
    try:
        print("[miner] crypto_hash implementation:", inspect.getfile(crypto_hash))
    except Exception:
        print("[miner] crypto_hash implementation: <unknown>")
    health = mc.wait_ready(sess, base) or {}

    NETWORK_ID = str(health.get("network_id", os.getenv("NETWORK_ID", "devnet-001")))
    print("[miner] NETWORK_ID:", NETWORK_ID)
    MINE_RATE_NS = mc._to_int_ns(health.get("mine_rate_ns") or os.getenv("MINE_RATE", 0))
    MINING_REWARD = int(health.get("mining_reward", os.getenv("MINING_REWARD", 50)))
    MINING_REWARD_ASSET = str(health.get("mining_reward_asset", os.getenv("MINING_REWARD_ASSET", "COIN")))
    MINING_REWARD_INPUT = health.get("mining_reward_input") or {"address": "*--official-mining-reward--*"}

    failures = 0

    # stateful detection flags
    merkle_leaf_fn = None
    merkle_parent_fn = None
    header_double_sha = False
    header_version = 1

    tries = 0
    submitted_ok = False
    last_resp = (False, None, None)

    try:
        while True:
            try:
                chain = mc.get_json(sess, base, "/blockchain")
                mempool = mc.get_json(sess, base, "/mempool")
            except Exception as e:
                print("[miner] network error fetching chain/mempool:", e)
                time.sleep(2)
                continue

            if not chain:
                print("[miner] empty chain; waiting...")
                time.sleep(1)
                continue

            tip = chain[-1]
            tip_hash = tip.get("hash")
            tip_version = getattr(tip, "version", 1)

            # detect merkle builder from tip if not known (just for diagnostics)
            if merkle_leaf_fn is None or merkle_parent_fn is None:
                merkle_leaf_fn, merkle_parent_fn, _ = mc.detect_merkle_builder_from_tip(tip)

            # detect header single/double sha mode from tip (diagnostic)
            try:
                tip_merkle = tip.get("merkle") or tip.get("merkle_root") or ""
                jsingle = header_json_hash(tip_version, tip.get("last_hash") or tip.get("hash"), tip_merkle,
                                           tip.get("timestamp"), tip.get("difficulty"), tip.get("nonce"), double_sha=False)
                jdouble = header_json_hash(tip_version, tip.get("last_hash") or tip.get("hash"), tip_merkle,
                                           tip.get("timestamp"), tip.get("difficulty"), tip.get("nonce"), double_sha=True)
                if jsingle == tip.get("hash"):
                    header_double_sha = False
                elif jdouble == tip.get("hash"):
                    header_double_sha = True
            except Exception:
                pass

            header_version = getattr(tip, "version", 1)

            parent_hash = tip.get("hash")
            parent_ts_ns = mc._to_int_ns(tip.get("timestamp"))
            parent_diff = int(tip.get("difficulty", 1) or 1)

            if not mempool and not args.allow_empty:
                print("[miner] no mempool txs; sleeping")
                time.sleep(args.interval)
                continue

            # prepare block data (mempool txs + reward)
            block_data = list(mempool)
            reward_tx = mc.build_reward_tx(args.addr, mempool, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
            block_data.append(reward_tx)

            # canonical merkle for mining (authoritative)
            canonical_merkle = merkle_root(block_data)

            # optional: detect builder alt and warn if it differs
            try:
                # build fallback leaves using detection (if any)
                def leaf_hex_sha256_json(tx):
                    return hashlib.sha256(canonical_json(tx, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()
                leaves = []
                if merkle_leaf_fn:
                    try:
                        leaves = [merkle_leaf_fn(tx) for tx in block_data]
                    except Exception:
                        leaves = [leaf_hex_sha256_json(tx) for tx in block_data]
                else:
                    leaves = [leaf_hex_sha256_json(tx) for tx in block_data]
                parent_fn = merkle_parent_fn if merkle_parent_fn else parent_hexcat
                alt_merkle = _build_merkle(leaves, parent_fn)
                if alt_merkle != canonical_merkle:
                    print("[miner] warning: detected merkle builder differs from authoritative merkle_root(); using authoritative value.")
            except Exception:
                pass

            # choose safe timestamp/difficulty
            mtp_ns = mc.median_past_ns(chain, args.mpt_window)
            ts_ns = mc.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
            difficulty = mc.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)

            # Mining loop using canonical crypto_hash preimage
            found = False
            nonce = 0
            cur_hash = crypto_hash(NETWORK_ID, ts_ns, parent_hash, block_data, difficulty, nonce, canonical_merkle)
            target = "0" * difficulty

            # GPU rig: validate results if used
            if args.use_rig and gpu_find_nonce is not None:
                try:
                    nonce_r, hexh = gpu_find_nonce(
                        header={"last_hash": parent_hash, "timestamp": ts_ns, "merkle": canonical_merkle},
                        difficulty=difficulty,
                        txs=block_data,
                        batch=1_000_000
                    )
                    if nonce_r is not None and hexh:
                        try:
                            expected_hash = crypto_hash(NETWORK_ID, ts_ns, parent_hash, block_data, difficulty, int(nonce_r), canonical_merkle)
                        except Exception:
                            expected_hash = None
                        if expected_hash and hexh != expected_hash:
                            print("[miner] rig returned hash that doesn't match expected crypto_hash(preimage). Ignoring rig result.")
                        elif hex_to_binary(hexh)[: difficulty] != "0" * difficulty:
                            print("[miner] rig returned candidate that fails binary PoW, ignoring.")
                        else:
                            nonce = int(nonce_r)
                            cur_hash = hexh
                            found = True
                except Exception as e:
                    print("[miner] rig error, falling back to CPU:", e)

            if not found:
                log_every = 50000
                while hex_to_binary(cur_hash)[: difficulty] != target:
                    nonce += 1
                    if nonce % log_every == 0:
                        print(f"[miner] mining... nonce={nonce} ts={ts_ns} diff={difficulty} cur_hash={cur_hash[:16]}...")
                    ts_ns = mc.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
                    difficulty = mc.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)
                    target = "0" * difficulty
                    cur_hash = crypto_hash(NETWORK_ID, ts_ns, parent_hash, block_data, difficulty, nonce, canonical_merkle)

            # Built a canonical candidate
            candidate = {
                "timestamp": ts_ns,
                "last_hash": parent_hash,
                "merkle": canonical_merkle,
                "data": block_data,
                "difficulty": difficulty,
                "nonce": nonce,
                "height": None
            }
            candidate["hash"] = crypto_hash(NETWORK_ID, candidate["timestamp"], candidate["last_hash"], candidate["data"],
                                           candidate["difficulty"], candidate["nonce"], candidate["merkle"])
            print("[dbg] candidate['hash'] =", candidate.get("hash"))

            # Submit-guard: recompute authoritative merkle & hash, overwrite, check PoW locally, abort if mismatch
            candidate['merkle'] = merkle_root(candidate.get('data', []))
            try:
                canonical_hash = crypto_hash(NETWORK_ID, int(candidate['timestamp']), candidate['last_hash'],
                                             candidate.get('data', []), int(candidate['difficulty']), int(candidate['nonce']),
                                             candidate['merkle'])
            except Exception as e:
                print("[miner|submit-guard] error recomputing canonical hash before submit:", e)
                canonical_hash = None

            print("[miner|submit-guard] miner_hash (before overwrite):", candidate.get('hash'))
            print("[miner|submit-guard] recomputed canonical_hash        :", canonical_hash)

            if canonical_hash is None or hex_to_binary(canonical_hash)[: candidate['difficulty']] != "0" * candidate['difficulty']:
                # abort and save debug
                print("[miner|submit-guard] aborting submit: canonical hash missing or fails PoW locally.")
                if args.debug_dir:
                    try:
                        fname = safe_make_fname(args.debug_dir, "aborted_submit")
                        with open(fname, "w", encoding="utf-8") as f:
                            json.dump({"attempted_candidate": candidate, "note": "aborted by submit-guard"}, f, indent=2, sort_keys=True)
                        print("[miner|submit-guard] saved", fname)
                    except Exception as e:
                        print("[miner|submit-guard] could not save aborted debug:", e)
                # skip submit; go back to mining loop
                continue

            # overwrite candidate hash with canonical_hash and submit
            candidate['hash'] = canonical_hash

            # prepare candidate_to_send (strip height)
            candidate_to_send = deepcopy(candidate)
            if 'height' in candidate_to_send:
                del candidate_to_send['height']

            # Build merkle variants (diagnostic) - try some variants but authoritative canonical was used to mine
            merkle_variants = []
            for include_id in (False, True):
                for double_leaf in (False, True):
                    leaves_tmp = []
                    for tx in candidate_to_send.get('data', []):
                        t = deepcopy(tx)
                        if not include_id and isinstance(t, dict) and 'id' in t:
                            del t['id']
                        s = canonical_json(t, ensure_ascii=False, separators=(',', ':'))
                        leaf = hashlib.sha256(s.encode('utf-8')).hexdigest()
                        if double_leaf:
                            leaf = hashlib.sha256(leaf.encode('utf-8')).hexdigest()
                        leaves_tmp.append(leaf)
                    merkle_variants.append(("include_id=%s double=%s parent=hexcat" % (include_id, double_leaf),
                                            _build_merkle(leaves_tmp, parent_hexcat)))
                    try:
                        merkle_variants.append(("include_id=%s double=%s parent=bytescat" % (include_id, double_leaf),
                                                _build_merkle(leaves_tmp, parent_bytescat)))
                    except Exception:
                        pass

            # dedupe preserve order
            seen = set(); merkle_variants_unique = []
            for name, mv in merkle_variants:
                if mv and mv not in seen:
                    seen.add(mv); merkle_variants_unique.append((name, mv))

            # Try submit variants (but we already set canonical merkle/hash; these are diagnostics)
            submitted_ok = False
            tries = 0
            last_resp = (False, None, None)
            candidate_detect_version = header_version

            for name, mval in merkle_variants_unique + [("canonical", candidate_to_send.get("merkle"))]:
                if submitted_ok:
                    break
                if not mval:
                    continue

                candidate_try = deepcopy(candidate_to_send)
                candidate_try['merkle'] = mval

                # recompute authoritative merkle/hash for this candidate_try before submit
                candidate_try['merkle'] = merkle_root(candidate_try.get('data', []))
                try:
                    candidate_try['hash'] = crypto_hash(NETWORK_ID, candidate_try['timestamp'], candidate_try['last_hash'],
                                                        candidate_try.get('data', []), candidate_try['difficulty'], candidate_try['nonce'],
                                                        candidate_try['merkle'])
                except Exception:
                    # if for any reason crypto_hash fails, skip submit for this variant
                    tries += 1
                    continue

                # local PoW guard
                if hex_to_binary(candidate_try['hash'])[: candidate_try['difficulty']] != "0" * candidate_try['difficulty']:
                    print("[miner] local-check: candidate fails PoW -> skipping submit for this variant.")
                    tries += 1
                    continue

                print("[miner] submitting candidate (variant)", name, {"nonce": candidate_try['nonce'], "hash": candidate_try['hash'][:16], "diff": candidate_try['difficulty']})
                ok, code, body = submit_block(sess, base, candidate_try, candidate_detect_version, header_double_sha, NETWORK_ID, debug_dir=args.debug_dir)
                last_resp = (ok, code, body)
                tries += 1

                if ok:
                    print(f"[miner] ✅ accepted variant after {tries} tries ({name})")
                    submitted_ok = True
                    break
                else:
                    backoff = BASE_BACKOFF * (2 ** min(tries - 1, 5))
                    print(f"[miner] ❌ rejected (try {tries}/{MAX_VARIANT_TRIES}), retrying in {backoff:.1f}s...")
                    time.sleep(backoff)

                if tries >= MAX_VARIANT_TRIES:
                    break

            # post submission handling
            if submitted_ok:
                failures = 0
                time.sleep(0.5)
                continue

            ok, code, body = last_resp
            if ok:
                print(f"[miner] submit OK: {body}")
                failures = 0
                time.sleep(0.5)
                continue

            # quick resync on common errors
            errtxt = str(body).lower() if body else ""
            if any(k in errtxt for k in ["bad last_hash", "median past", "hash must be correct", "reward must pay"]):
                try:
                    chain2 = mc.get_json(sess, base, "/blockchain")
                    mempool2 = mc.get_json(sess, base, "/mempool")
                except Exception as e:
                    print("[miner] retry fetch error:", e)
                    time.sleep(2); continue

                tip2 = chain2[-1]
                parent_hash2 = tip2.get("hash")
                parent_ts2_ns = mc._to_int_ns(tip2.get("timestamp"))
                parent_diff2 = int(tip2.get("difficulty", parent_diff) or parent_diff)

                block_data2 = list(mempool2)
                reward_tx2 = mc.build_reward_tx(args.addr, mempool2, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
                block_data2.append(reward_tx2)

                leaves2 = [hashlib.sha256(canonical_json(tx, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest() for tx in block_data2]
                merkle2 = _build_merkle(leaves2, parent_fn)

                mtp2_ns = mc.median_past_ns(chain2, args.mpt_window)
                ts2_ns = mc.safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
                difficulty2 = mc.adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)

                # re-mine quickly (CPU loop) using node preimage + binary test
                nonce2 = 0
                target2 = "0" * difficulty2
                h2 = crypto_hash(NETWORK_ID, ts2_ns, parent_hash2, block_data2, difficulty2, nonce2, merkle2)
                while hex_to_binary(h2)[: difficulty2] != target2:
                    nonce2 += 1
                    ts2_ns = mc.safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
                    difficulty2 = mc.adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)
                    target2 = "0" * difficulty2
                    h2 = crypto_hash(NETWORK_ID, ts2_ns, parent_hash2, block_data2, difficulty2, nonce2, merkle2)

                candidate.update({
                    "timestamp": ts2_ns,
                    "last_hash": parent_hash2,
                    "hash": h2,
                    "data": block_data2,
                    "difficulty": difficulty2,
                    "nonce": nonce2,
                    "merkle": merkle2
                })

                ok2, code2, body2 = submit_block(sess, base, candidate, header_version, header_double_sha, NETWORK_ID, debug_dir=args.debug_dir)
                if ok2:
                    print(f"[miner] submit OK (retry): {body2}")
                    failures = 0
                else:
                    print(f"[miner] submit FAIL (retry) {code2}: {body2}")
                    failures += 1
                time.sleep(2 if failures < 5 else 5)
                continue

            failures += 1
            time.sleep(2 if failures < 5 else 5)

    except KeyboardInterrupt:
        print("\n[miner] interrupted by user, exiting gracefully.")
        return

if __name__ == "__main__":
    main()
