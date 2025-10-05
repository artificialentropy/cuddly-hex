#!/usr/bin/env python3
"""
solo_miner_submit.py
Single-file miner (no rig), same behavior as simple_miner but all-in-one.
"""

from __future__ import annotations
import os, time, json, argparse, requests
from typing import Any, Dict, List, Tuple, Callable, Optional

# ---- embed the same helpers as miner_client to stay standalone ----
import hashlib

def _canon_bytes(x: Any) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _deep_canonicalize_for_args(args):
    out=[]; 
    for a in args:
        if isinstance(a, list):
            cl=[]
            for it in a:
                if isinstance(it, dict):
                    cl.append(json.loads(_canon_bytes(it).decode("utf-8")))
                else:
                    cl.append(it)
            out.append(cl)
        elif isinstance(a, dict):
            out.append(json.loads(_canon_bytes(a).decode("utf-8")))
        else:
            out.append(a)
    return out

def crypto_hash(*args) -> str:
    return _sha256_hex(_canon_bytes(_deep_canonicalize_for_args(list(args))))

def hex_to_binary(h: str) -> str:
    return bin(int(h, 16))[2:].zfill(4*len(h))

def _leaf_hex_sha256_json(tx: dict) -> str: return _sha256_hex(_canon_bytes(tx))
def _leaf_hex_sha256_txid(tx: dict) -> str: return _sha256_hex(str(tx.get("id", json.dumps(tx, sort_keys=True))).encode())
def _leaf_hex_crypto_json(tx: dict) -> str: return crypto_hash(tx)
def _leaf_hex_crypto_txid(tx: dict) -> str: return crypto_hash(str(tx.get("id","")))
def _parent_hex_sha256_hexcat(l: str, r: str) -> str: return _sha256_hex((l+r).encode())
def _parent_hex_bytescat_sha256(l: str, r: str) -> str: return _sha256_hex(bytes.fromhex(l)+bytes.fromhex(r))
def _parent_hex_crypto_pair(l: str, r: str) -> str: return crypto_hash(l, r)

MERKLE_CANDIDATES: List[Tuple[Callable, Callable, str]] = [
    (_leaf_hex_sha256_json,  _parent_hex_sha256_hexcat,       "sha256(json) + sha256(hexcat)"),
    (_leaf_hex_sha256_json,  _parent_hex_bytescat_sha256,     "sha256(json) + sha256(bytescat)"),
    (_leaf_hex_sha256_txid,  _parent_hex_sha256_hexcat,       "sha256(txid) + sha256(hexcat)"),
    (_leaf_hex_sha256_txid,  _parent_hex_bytescat_sha256,     "sha256(txid) + sha256(bytescat)"),
    (_leaf_hex_crypto_json,  _parent_hex_crypto_pair,         "crypto_hash(json) + crypto_hash(pair)"),
    (_leaf_hex_crypto_txid,  _parent_hex_crypto_pair,         "crypto_hash(txid) + crypto_hash(pair)"),
    (_leaf_hex_crypto_json,  _parent_hex_sha256_hexcat,       "crypto_hash(json) + sha256(hexcat)"),
    (_leaf_hex_crypto_txid,  _parent_hex_sha256_hexcat,       "crypto_hash(txid) + sha256(hexcat)"),
]

def _build_merkle(leaves_hex: List[str], parent_fn: Callable[[str, str], str]) -> str:
    if not leaves_hex: return _sha256_hex(b"")
    lvl = leaves_hex[:]
    while len(lvl)>1:
        if len(lvl)%2==1: lvl.append(lvl[-1])
        nxt=[]
        for i in range(0,len(lvl),2):
            nxt.append(parent_fn(lvl[i], lvl[i+1]))
        lvl=nxt
    return lvl[0]

def _merkle_try(data: List[dict], leaf_fn, parent_fn) -> str:
    return _build_merkle([leaf_fn(tx) for tx in data], parent_fn)

def detect_merkle_builder_from_tip(tip: Dict[str,Any]) -> Tuple[Callable, Callable, str]:
    data = tip.get("data") or []
    tip_merkle = str(tip.get("merkle") or tip.get("merkle_root") or "")
    for lf, pf, label in MERKLE_CANDIDATES:
        try:
            if tip_merkle and _merkle_try(data, lf, pf) == tip_merkle:
                print(f"[miner] merkle mode: {label}")
                return lf, pf, label
        except Exception:
            pass
    print("[miner] merkle mode: sha256(json) + sha256(hexcat) (default)")
    return _leaf_hex_sha256_json, _parent_hex_sha256_hexcat, "sha256(json) + sha256(hexcat)"

def median_past_ns(chain: List[Dict[str,Any]], window: int) -> int:
    ts = [int(b.get("timestamp",0)) for b in (chain[-window:] if len(chain)>=window else chain) if isinstance(b, dict)]
    if not ts: return 0
    ts.sort(); n=len(ts)
    return ts[n//2] if n%2 else (ts[n//2-1]+ts[n//2])//2

def safe_ts_ns(now_ns: int, parent_ts_ns: int, mtp_ns: int) -> int:
    return max(int(now_ns), int(parent_ts_ns)+1, int(mtp_ns)+1)

def adjust_difficulty(parent_diff: int, parent_ts_ns: int, now_ts_ns: int, mine_rate_ns: Optional[int]) -> int:
    pd = int(parent_diff or 1)
    if not mine_rate_ns or int(mine_rate_ns) <= 0: return max(1, pd)
    return (pd+1) if (int(now_ts_ns)-int(parent_ts_ns))<int(mine_rate_ns) else max(1, pd-1)

def build_reward_tx(miner_addr: str, mempool: List[Dict[str,Any]], mining_reward_input: Dict[str,Any], asset_id: str, reward_amount: int) -> Dict[str,Any]:
    return {"id": f"cb-{int(time.time()*1000)}", "input": mining_reward_input,
            "output": { miner_addr: { str(asset_id): int(reward_amount) } },
            "metadata": {"miner": miner_addr}}

# ---- CLI & HTTP ----
def argp():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default=os.getenv("MINER_NODE_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--addr", default=os.getenv("MINER_ADDRESS", "miner-demo-addr"))
    ap.add_argument("--token", default=os.getenv("MINER_TOKEN", ""))
    ap.add_argument("--allow-empty", action="store_true", default=os.getenv("MINER_ALLOW_EMPTY","0")=="1")
    ap.add_argument("--interval", type=float, default=float(os.getenv("MINER_INTERVAL","3")))
    ap.add_argument("--mpt-window", type=int, default=int(os.getenv("MEDIAN_PAST_WINDOW","11")))
    ap.add_argument("--debug-dir", default=os.getenv("MINER_DEBUG_DIR",""))
    return ap.parse_args()

def wait_ready(sess, base):
    while True:
        try:
            r = sess.get(f"{base}/health", timeout=(5,10))
            if r.ok:
                j = r.json()
                if j.get("ready") or j.get("ok") or j.get("status")=="ok" or j.get("height",0)>0:
                    print("[miner] node is ready."); return j
        except Exception: pass
        print("[miner] waiting for node health..."); time.sleep(1)

def get_json(sess, base, path):
    r = sess.get(f"{base}{path}", timeout=(5,20)); r.raise_for_status(); return r.json()

def submit_block(sess, base, candidate: Dict[str,Any], network_id: str, debug_dir: Optional[str]=None):
    # recompute canonical hash pre-submit
    candidate["hash"] = crypto_hash(network_id, int(candidate["timestamp"]), candidate["last_hash"],
                                    candidate["data"], int(candidate["difficulty"]), int(candidate["nonce"]),
                                    candidate.get("merkle",""))
    # save debug payload
    try:
        if debug_dir:
            os.makedirs(debug_dir, exist_ok=True)
            fname = os.path.join(debug_dir, f"block_to_test_{int(time.time()*1000)}.json")
        else:
            fname = f"block_to_test_{int(time.time()*1000)}.json"
        with open(fname,"w",encoding="utf-8") as f:
            json.dump({"block": candidate}, f, indent=2, sort_keys=True)
        print(f"[miner] saved block to {fname} (inspect if node rejects)")
    except Exception as e:
        print("[miner] warn: could not save debug:", e)
    # post
    r = sess.post(f"{base}/blocks/submit", json={"block": candidate}, timeout=(5,30))
    code = r.status_code
    try: body = r.json()
    except Exception: body = {"text": r.text}
    print(f"[miner] submit -> status={code} body={body}")
    return (code==200), code, body

def main():
    args = argp()
    base = args.node.rstrip("/")
    sess = requests.Session()
    if args.token: sess.headers.update({"X-Miner-Token": args.token})
    print(f"[miner] starting. node={base} addr={args.addr} allow_empty={int(args.allow_empty)}")

    health = wait_ready(sess, base) or {}
    NETWORK_ID          = str(health.get("network_id", os.getenv("NETWORK_ID","testnet")))
    MINE_RATE_NS        = int(health.get("mine_rate_ns", os.getenv("MINE_RATE", 0)) or 0)
    MINING_REWARD       = int(health.get("mining_reward", os.getenv("MINING_REWARD", 50)))
    MINING_REWARD_ASSET = str(health.get("mining_reward_asset", os.getenv("MINING_REWARD_ASSET","COIN")))
    MINING_REWARD_INPUT = health.get("mining_reward_input") or {"address": "*--official-mining-reward--*"}

    merkle_leaf_fn = None; merkle_parent_fn = None; failures = 0

    while True:
        try:
            chain   = get_json(sess, base, "/blockchain")
            mempool = get_json(sess, base, "/mempool")
        except Exception as e:
            print("[miner] network error:", e); time.sleep(2); continue

        if not chain:
            print("[miner] empty chain; waiting..."); time.sleep(1); continue

        tip = chain[-1]
        if merkle_leaf_fn is None:
            merkle_leaf_fn, merkle_parent_fn, _ = detect_merkle_builder_from_tip(tip)

        parent_hash  = tip.get("hash")
        parent_ts_ns = int(tip.get("timestamp", 0))
        parent_diff  = int(tip.get("difficulty", 1) or 1)

        if not mempool and not args.allow_empty:
            print("[miner] no mempool txs; sleeping"); time.sleep(args.interval); continue

        block_data = list(mempool)
        reward_tx = build_reward_tx(args.addr, mempool, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
        block_data.append(reward_tx)

        merkle = _merkle_try(block_data, merkle_leaf_fn, merkle_parent_fn)
        mtp_ns = median_past_ns(chain, args.mpt_window)
        ts_ns  = safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
        difficulty = adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)

        # mine (CPU)
        nonce = 0
        target = "0"*difficulty
        h = crypto_hash(NETWORK_ID, ts_ns, parent_hash, block_data, difficulty, nonce, merkle)
        while hex_to_binary(h)[:difficulty] != target:
            nonce += 1
            ts_ns = safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
            difficulty = adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)
            target = "0"*difficulty
            h = crypto_hash(NETWORK_ID, ts_ns, parent_hash, block_data, difficulty, nonce, merkle)

        candidate = {
            "timestamp": ts_ns, "last_hash": parent_hash, "hash": h,
            "data": block_data, "difficulty": difficulty, "nonce": nonce,
            "merkle": merkle, "height": None
        }

        ok, code, body = submit_block(sess, base, candidate, NETWORK_ID, debug_dir=args.debug_dir or None)
        if ok:
            print(f"[miner] submit OK: {body}"); failures=0; time.sleep(0.5); continue

        # quick resync retry for classic causes
        errtxt = str(body).lower()
        if any(k in errtxt for k in ["bad last_hash", "median past", "hash must be correct"]):
            try:
                chain2   = get_json(sess, base, "/blockchain")
                mempool2 = get_json(sess, base, "/mempool")
            except Exception as e:
                print("[miner] retry fetch error:", e); time.sleep(2); continue

            tip2 = chain2[-1]
            parent_hash2  = tip2.get("hash")
            parent_ts2_ns = int(tip2.get("timestamp", 0))
            parent_diff2  = int(tip2.get("difficulty", parent_diff) or parent_diff)

            block_data2 = list(mempool2)
            reward_tx2 = build_reward_tx(args.addr, mempool2, MINING_REWARD_INPUT, MINING_REWARD_ASSET, MINING_REWARD)
            block_data2.append(reward_tx2)

            merkle2 = _merkle_try(block_data2, merkle_leaf_fn, merkle_parent_fn)
            mtp2_ns = median_past_ns(chain2, args.mpt_window)
            ts2_ns  = safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
            difficulty2 = adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)

            nonce2=0; target2="0"*difficulty2
            h2 = crypto_hash(NETWORK_ID, ts2_ns, parent_hash2, block_data2, difficulty2, nonce2, merkle2)
            while hex_to_binary(h2)[:difficulty2] != target2:
                nonce2 += 1
                ts2_ns = safe_ts_ns(time.time_ns(), parent_ts2_ns, mtp2_ns)
                difficulty2 = adjust_difficulty(parent_diff2, parent_ts2_ns, ts2_ns, MINE_RATE_NS)
                target2 = "0"*difficulty2
                h2 = crypto_hash(NETWORK_ID, ts2_ns, parent_hash2, block_data2, difficulty2, nonce2, merkle2)

            candidate.update({
                "timestamp": ts2_ns, "last_hash": parent_hash2, "hash": h2,
                "data": block_data2, "difficulty": difficulty2, "nonce": nonce2, "merkle": merkle2
            })

            ok2, code2, body2 = submit_block(sess, base, candidate, NETWORK_ID, debug_dir=args.debug_dir or None)
            if ok2:
                print(f"[miner] submit OK (retry): {body2}"); failures=0
            else:
                print(f"[miner] submit FAIL (retry) {code2}: {body2}"); failures+=1
            time.sleep(2 if failures<5 else 5); continue

        failures += 1
        time.sleep(2 if failures<5 else 5)

if __name__ == "__main__":
    main()
