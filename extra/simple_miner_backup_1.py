#!/usr/bin/env python3
"""
simple_miner.py (patched)
- computes canonical merkle (sha256(json(tx)) leaves, ascii-hex parent concat)
- mines using the exact same canonical header preimage (array_full_single)
- verifies mined preimage == submitted hash
- uses submit_and_confirm() to reliably detect acceptance
- saves accepted blocks via miner_client.submit_block debug behavior (unchanged)
"""

from __future__ import annotations
import os
import time
import argparse
import requests
import sys
import json
import hashlib
from copy import deepcopy
from typing import Any, Dict, List, Tuple, Optional

import miner_client as mc
try:
    from rig import gpu_find_nonce  # optional GPU rig
except Exception:
    gpu_find_nonce = None

# ---------- deterministic JSON + hashing helpers ----------
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def sha256_raw(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def merkle_from_leaf_hexes_ascii(leaf_hexes: List[str]) -> str:
    """Pairwise reduce using ascii-hex concatenation then sha256(hex_concat)."""
    nodes = list(leaf_hexes)
    if not nodes:
        return sha256_hex(canonical_json([]))
    while len(nodes) > 1:
        next_level: List[str] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if (i+1) < len(nodes) else nodes[i]
            next_level.append(sha256_hex(left + right))
        nodes = next_level
    return nodes[0]

def compute_leaf_hexes_json_single(txs: List[Dict]) -> List[str]:
    return [sha256_hex(canonical_json(tx)) for tx in txs]

def compute_array_full_single_hash(network_id: str, timestamp: int, last_hash: str,
                                   merkle: str, nonce: int, difficulty: int, data: List[Dict]) -> str:
    """
    array_full_single: sha256(canonical_json([timestamp, last_hash, merkle, nonce, difficulty, data]))
    This is the canonical header preimage used for mining and submission.
    """
    arr = [timestamp, last_hash, merkle, nonce, difficulty, data]
    return sha256_hex(canonical_json(arr))

# ---------- submit + confirm helper ----------
def submit_and_confirm(session: requests.Session, base: str, candidate: Dict[str, Any],
                       network_id: str, timeout: float = 6.0, poll_interval: float = 0.5,
                       debug_dir: Optional[str] = None) -> Tuple[bool, int, Dict[str, Any]]:
    """
    Submit the block using mc.submit_block (which also saves debug files when asked).
    If submit returns non-OK, poll the chain tip for up to `timeout` seconds to see if the
    node accepted the block anyway. Returns (confirmed_bool, status_code, body).
    """
    ok, code, body = mc.submit_block(session, base, candidate, network_id, debug_dir=debug_dir)
    if ok:
        return True, code, body

    # Not OK -> poll tip for confirmation (sometimes acceptance races happen)
    submitted_hash = candidate.get("hash")
    start = time.time()
    while time.time() - start < timeout:
        try:
            tip = session.get(base + "/blockchain", timeout=2).json()[-1]
            if tip.get("hash") == submitted_hash:
                return True, code, body
        except Exception:
            pass
        time.sleep(poll_interval)

    # Not confirmed
    return False, code, body

# ---------- CLI arg parsing ----------
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

    print(f"[miner] starting. node={base} addr={args.addr} allow_empty={int(args.allow_empty)}")
    health = mc.wait_ready(sess, base) or {}

    NETWORK_ID = str(health.get("network_id", os.getenv("NETWORK_ID", "testnet")))
    MINE_RATE_NS = mc._to_int_ns(health.get("mine_rate_ns") or os.getenv("MINE_RATE", 0))
    MINING_REWARD = int(health.get("mining_reward", os.getenv("MINING_REWARD", 50)))
    MINING_REWARD_ASSET = str(health.get("mining_reward_asset", os.getenv("MINING_REWARD_ASSET", "COIN")))
    MINING_REWARD_INPUT = health.get("mining_reward_input") or {"address": "*--official-mining-reward--*"}

    merkle_leaf_fn = None
    merkle_parent_fn = None
    failures = 0

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
        if merkle_leaf_fn is None:
            merkle_leaf_fn, merkle_parent_fn, _ = mc.detect_merkle_builder_from_tip(tip)
            print("[miner] merkle mode detected:", "sha256(json) + sha256(hexcat)" if merkle_leaf_fn is None else "detected via tip")  # best-effort message

        parent_hash = tip.get("hash")
        parent_ts_ns = mc._to_int_ns(tip.get("timestamp"))
        parent_diff = int(tip.get("difficulty", 1) or 1)

        if not mempool and not args.allow_empty:
            print("[miner] no mempool txs; sleeping")
            time.sleep(args.interval)
            continue

        # Build data = mempool + reward
        block_data = list(mempool)
        reward_tx = mc.build_reward_tx(args.addr, mempool, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
        block_data.append(reward_tx)

        # Compute canonical merkle: leaves = sha256(canonical_json(tx)), parents = sha256(left_hex + right_hex)
        leaf_hexes = compute_leaf_hexes_json_single(block_data)
        canonical_merkle = merkle_from_leaf_hexes_ascii(leaf_hexes)
        merkle = canonical_merkle  # use canonical merkle for mining and submission

        # Choose safe timestamp + difficulty
        mtp_ns = mc.median_past_ns(chain, args.mpt_window)
        ts_ns = mc.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
        difficulty = mc.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)

        # Mine: PoW (CPU or multi-process rig)
        found = False
        nonce = 0

        # compute initial candidate hash using canonical preimage so mining checks same function that will be submitted
        h = compute_array_full_single_hash(NETWORK_ID, ts_ns, parent_hash, merkle, nonce, difficulty, block_data)
        target = "0" * difficulty

        if args.use_rig and gpu_find_nonce is not None:
            try:
                nonce, hexh = gpu_find_nonce(
                    header={"network_id": NETWORK_ID, "last_hash": parent_hash, "timestamp": ts_ns, "merkle": merkle},
                    difficulty=difficulty,
                    data=block_data,
                    batch=1_000_000
                )
                if nonce is not None:
                    h = hexh
                    found = True
            except Exception as e:
                print("[miner] rig error, falling back to CPU:", e)

        if not found:
            # CPU loop: search for nonce such that canonical preimage meets difficulty
            while mc.hex_to_binary(h)[:difficulty] != target:
                nonce += 1
                # keep timestamp safe + difficulty adjust around mine rate
                ts_ns = mc.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
                difficulty = mc.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)
                target = "0" * difficulty
                h = compute_array_full_single_hash(NETWORK_ID, ts_ns, parent_hash, merkle, nonce, difficulty, block_data)

                # occasional debug output to observe progress (not too spammy)
                if nonce % 50000 == 0:
                    print(f"[miner dbg] nonce={nonce} ts={ts_ns} diff={difficulty} prefix={mc.hex_to_binary(h)[:difficulty]}")

        # Build candidate (do not include height in hash preimage)
        candidate = {
            "timestamp": ts_ns,
            "last_hash": parent_hash,
            "merkle": merkle,
            "data": block_data,
            "difficulty": difficulty,
            "nonce": nonce,
            "height": None
        }
        # compute candidate['hash'] exactly the same way we mined
        candidate["hash"] = compute_array_full_single_hash(NETWORK_ID, candidate["timestamp"],
                                                          candidate["last_hash"], candidate["merkle"],
                                                          candidate["nonce"], candidate["difficulty"],
                                                          candidate["data"])
        
        print("[dbg] mined h           =", h)
        print("[dbg] candidate['hash'] =", candidate.get("hash"))
        # Sanity check: mined h must equal candidate['hash']
        try:
            if h != candidate["hash"]:
                print("[miner ERROR] mined header hash does not match candidate['hash']!")
                print("   mined h     =", h)
                print("   candidate['hash'] =", candidate["hash"])
                # don't submit if mismatch found
                raise AssertionError("mined preimage != submitted preimage")
        except AssertionError as e:
            print("[miner] aborting submit due to preimage mismatch:", e)
            # increment failures and backoff
            failures += 1
            time.sleep(2 if failures < 5 else 5)
            continue

        # ----- Try submitting with several candidate merkle/hash variants (best-effort) -----
        # This preserves your prior behavior that tried several variants, but we try the canonical merkle first.
        candidate_to_send = deepcopy(candidate)
        if 'height' in candidate_to_send:
            del candidate_to_send['height']

        # build merkle variants to try (in case node expects an alternate)
        merkle_variants = mc.compute_merkle_with(merkle_leaf_fn, merkle_parent_fn, candidate_to_send.get('data', []))
        # compute our common merkle variants (single/double/bytescat) as fallback
        try:
            my_merkle_variants = {
                "canonical": merkle,
                **({} if not candidate_to_send.get('data') else {
                    "single_hexcat": merkle_from_leaf_hexes_ascii(compute_leaf_hexes_json_single(candidate_to_send['data'])),
                    "double_hexcat": merkle_from_leaf_hexes_ascii([sha256_hex(sha256_hex(canonical_json(tx))) for tx in candidate_to_send['data']])
                })
            }
        except Exception:
            my_merkle_variants = {"canonical": merkle}

        # unique ordered list favoring canonical first
        merkle_try_list = []
        for v in (my_merkle_variants.get("canonical"), my_merkle_variants.get("single_hexcat"),
                  my_merkle_variants.get("double_hexcat"), merkle_variants):
            if v and v not in merkle_try_list:
                # if merkle_variants is a dict/result, try to extract reasonable values
                if isinstance(v, dict):
                    # if mc.compute_merkle_with returned a dict-like mapping, extend with its values
                    for val in (v.values() if hasattr(v, "values") else [v]):
                        if val and val not in merkle_try_list:
                            merkle_try_list.append(val)
                else:
                    merkle_try_list.append(v)

        submitted_ok = False
        last_resp = (False, None, None)

        for m in merkle_try_list:
            if not m:
                continue
            candidate_try = deepcopy(candidate_to_send)
            candidate_try['merkle'] = m
            # candidate_try['hash'] must be recomputed to match this merkle
            candidate_try['hash'] = compute_array_full_single_hash(NETWORK_ID, candidate_try['timestamp'],
                                                                  candidate_try['last_hash'], candidate_try['merkle'],
                                                                  candidate_try['nonce'], candidate_try['difficulty'],
                                                                  candidate_try['data'])
            # submit and confirm
            confirmed, code, body = submit_and_confirm(sess, base, candidate_try, NETWORK_ID, timeout=6.0,
                                                      poll_interval=0.5, debug_dir=args.debug_dir or None)
            last_resp = (confirmed, code, body)
            if confirmed:
                print(f"[miner] submit OK (variant) confirmed: {body}")
                submitted_ok = True
                break
            else:
                print(f"[miner] submit attempt returned {code}: {body} (not confirmed)")

        if submitted_ok:
            failures = 0
            time.sleep(0.5)
            continue

        # fallback: use last response to decide retry logic below
        ok_flag, code, body = last_resp
        if ok_flag:
            print(f"[miner] submit OK: {body}")
            failures = 0
            time.sleep(0.5)
            continue

        # Non-OK -> quick resync retry for classic reasons
        errtxt = str(body).lower() if body else ""
        if any(k in errtxt for k in ["bad last_hash", "median past", "hash must be correct"]):
            try:
                chain2 = mc.get_json(sess, base, "/blockchain")
                mempool2 = mc.get_json(sess, base, "/mempool")
            except Exception as e:
                print("[miner] retry fetch error:", e)
                time.sleep(2)
                continue

            tip2 = chain2[-1]
            parent_hash2 = tip2.get("hash")
            parent_ts2_ns = mc._to_int_ns(tip2.get("timestamp"))
            parent_diff2 = int(tip2.get("difficulty", parent_diff) or parent_diff)

            block_data2 = list(mempool2)
            reward_tx2 = mc.build_reward_tx(args.addr, mempool2, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
            block_data2.append(reward_tx2)

            # recompute canonical merkle for retry
            leaf_hexes2 = compute_leaf_hexes_json_single(block_data2)
            merkle2 = merkle_from_leaf_hexes_ascii(leaf_hexes2)

            mtp2_ns = mc.median_past_ns(chain2, args.mpt_window)
            ts2_ns = mc.safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
            difficulty2 = mc.adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)

            # re-mine quickly (CPU loop; you can call rig again if you want)
            nonce2 = 0
            target2 = "0" * difficulty2
            h2 = compute_array_full_single_hash(NETWORK_ID, ts2_ns, parent_hash2, merkle2, nonce2, difficulty2, block_data2)
            while mc.hex_to_binary(h2)[:difficulty2] != target2:
                nonce2 += 1
                ts2_ns = mc.safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
                difficulty2 = mc.adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)
                target2 = "0" * difficulty2
                h2 = compute_array_full_single_hash(NETWORK_ID, ts2_ns, parent_hash2, merkle2, nonce2, difficulty2, block_data2)

            candidate.update({
                "timestamp": ts2_ns,
                "last_hash": parent_hash2,
                "hash": h2,
                "data": block_data2,
                "difficulty": difficulty2,
                "nonce": nonce2,
                "merkle": merkle2
            })

            ok2, code2, body2 = mc.submit_block(sess, base, candidate, NETWORK_ID, debug_dir=args.debug_dir or None)
            if ok2:
                print(f"[miner] submit OK (retry): {body2}")
                failures = 0
            else:
                print(f"[miner] submit FAIL (retry) {code2}: {body2}")
                failures += 1
            time.sleep(2 if failures < 5 else 5)
            continue

        # default backoff
        failures += 1
        time.sleep(2 if failures < 5 else 5)

if __name__ == "__main__":
    main()
