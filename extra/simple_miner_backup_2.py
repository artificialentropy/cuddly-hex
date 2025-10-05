#!/usr/bin/env python3
"""
Refactored simple miner - drop-in replacement.

Features:
- canonical JSON header preimage used for mining & submit
- merkle variants & header hash variants tried on submit
- strips unknown keys (e.g. 'version') before sending to node
- sanitized --debug-dir handling (Windows quoting issues)
- optional rig GPU helper (rig_fixed.gpu_find_nonce)
"""
from __future__ import annotations
import os, time, argparse, requests, sys, json, hashlib
from typing import Any, Dict, List, Tuple, Optional, Callable
from copy import deepcopy

# try to import rig helper; if not present, miner falls back to CPU loop
try:
    import rig_fixed as rig
    gpu_find_nonce = getattr(rig, "gpu_find_nonce", None)
except Exception:
    rig = None
    gpu_find_nonce = None

# config
MAX_VARIANT_TRIES = 6
BASE_BACKOFF = 0.5

# ---------- small helpers ----------
def canonical_json(obj, ensure_ascii=False, separators=(',',':')):
    return json.dumps(obj, sort_keys=True, separators=separators, ensure_ascii=ensure_ascii)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------- parent fns ----------
def parent_hexcat(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256((left_hex + right_hex).encode('utf-8')).hexdigest()

def parent_bytescat(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()

def _build_merkle(leaves_hex: List[str], parent_fn: Callable[[str, str], str]) -> str:
    if not leaves_hex:
        # keep consistent with node debug: sha256 of empty bytes
        return hashlib.sha256(b"").hexdigest()
    level = leaves_hex[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(parent_fn(level[i], level[i+1]))
        level = nxt
    return level[0]

# ---------- canonical header preimage used for mining/submission ----------
# uses array: [timestamp, last_hash, merkle, nonce, difficulty, data]
def compute_array_full_single_hash(network_id, timestamp, last_hash, merkle, nonce, difficulty, data):
    arr = [timestamp, last_hash, merkle, nonce, difficulty, data]
    return sha256_hex(canonical_json(arr))

# ---------- helper: build hash variants to try at submit ----------
def build_block_hash_variants(network_id, timestamp, last_hash, merkle, nonce, difficulty, data):
    variants = []
    arrA = [timestamp, last_hash, merkle, nonce, difficulty, data]
    variants.append(sha256_hex(canonical_json(arrA)))
    arrB = [network_id, timestamp, last_hash, merkle, nonce, difficulty, data]
    variants.append(sha256_hex(canonical_json(arrB)))
    # another ordering variant
    arrC = [timestamp, last_hash, data, merkle, nonce, difficulty]
    variants.append(sha256_hex(canonical_json(arrC)))
    # field-wise hexcat of sha256(json(field)) parts
    parts = [timestamp, last_hash, merkle, nonce, difficulty, data]
    parts_sha = [sha256_hex(canonical_json(p)) for p in parts]
    variants.append(sha256_hex(''.join(parts_sha)))
    # double-sha of arrA
    variants.append(sha256_hex(variants[0]))
    # dedupe preserve order
    seen = set(); out = []
    for v in variants:
        if v and v not in seen:
            out.append(v); seen.add(v)
    return out

# ---------- submit wrapper ----------
def submit_block(sess: requests.Session,
                 base: str,
                 candidate: Dict[str,Any],
                 network_id: str,
                 token_already_in_headers: bool = True,
                 debug_dir: Optional[str] = None) -> Tuple[bool, int, Dict[str,Any]]:
    """
    Recompute canonical hash; strip unexpected keys; POST to /blocks/submit; save debug files.
    """
    # recompute canonical hash (best-effort)
    try:
        ts = int(candidate["timestamp"])
        last_hash = candidate["last_hash"]
        diff = int(candidate["difficulty"])
        nonce = int(candidate["nonce"])
        merkle = candidate.get("merkle", "")
        data = candidate.get("data", [])
        candidate["hash"] = compute_array_full_single_hash(network_id, ts, last_hash, merkle, nonce, diff, data)
    except Exception as e:
        print("[miner] warning: unable to recompute canonical hash:", e)

    # sanitize debug_dir (strip stray quotes)
    if isinstance(debug_dir, str):
        debug_dir = debug_dir.strip().strip('"').strip("'")
        if debug_dir == "":
            debug_dir = None

    # prepare sanitized payload: only allowed keys
    payload_block = deepcopy(candidate)
    allowed = {"timestamp", "last_hash", "merkle", "data", "difficulty", "nonce", "hash", "height"}
    for k in list(payload_block.keys()):
        if k not in allowed:
            payload_block.pop(k, None)

    try:
        r = sess.post(f"{base}/blocks/submit", json={"block": payload_block}, timeout=(5,30))
        code = r.status_code
        try:
            body = r.json()
        except Exception:
            body = {"text": r.text}

        ok = (code == 200)
        print(f"[miner] submit -> status={code} body={body}")

        mined_h = payload_block.get("hash")
        node_submitted = body.get("submitted_hash") if isinstance(body, dict) else None
        if mined_h or node_submitted:
            print(f"[dbg] candidate['hash'] = {mined_h}  node_submitted_hash = {node_submitted}")

        if debug_dir:
            try:
                os.makedirs(debug_dir, exist_ok=True)
                ts_ms = int(time.time()*1000)
                if ok:
                    fname = os.path.join(debug_dir, f"accepted_block_{ts_ms}.json")
                    with open(fname, "w", encoding="utf-8") as f:
                        json.dump({"block": payload_block, "response": body}, f, indent=2, sort_keys=True)
                    print(f"[miner] saved accepted block to {fname}")
                else:
                    fname = os.path.join(debug_dir, f"rejected_block_{ts_ms}.json")
                    with open(fname, "w", encoding="utf-8") as f:
                        json.dump({"block": payload_block, "node_response": body}, f, indent=2, sort_keys=True)
                    print(f"[miner] saved rejected debug to {fname}")
            except Exception as e:
                print("[miner] warning: could not save debug file:", e)

        return ok, code, body

    except requests.RequestException as e:
        return False, 0, {"text": str(e)}

# ---------- main mining logic ----------
def argp():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default=os.getenv("MINER_NODE_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--addr", default=os.getenv("MINER_ADDRESS", "miner-demo-addr"))
    ap.add_argument("--token", default=os.getenv("MINER_TOKEN", ""))
    ap.add_argument("--allow-empty", action="store_true", default=os.getenv("MINER_ALLOW_EMPTY","0")=="1")
    ap.add_argument("--interval", type=float, default=float(os.getenv("MINER_INTERVAL","3")))
    ap.add_argument("--mpt-window", type=int, default=int(os.getenv("MEDIAN_PAST_WINDOW","11")))
    ap.add_argument("--debug-dir", default=os.getenv("MINER_DEBUG_DIR",""))
    ap.add_argument("--use-rig", action="store_true", default=os.getenv("MINER_USE_RIG","0")=="1")
    return ap.parse_args()

# A tiny local client interface - minimal to keep this file self-contained for demo
class MC:
    def __init__(self, sess, base, token=""):
        self.sess = sess; self.base = base; self.token = token
        if token:
            self.sess.headers.update({"X-Miner-Token": token})

    def wait_ready(self):
        while True:
            try:
                r = self.sess.get(f"{self.base}/health", timeout=(2,5))
                if r.ok:
                    j = r.json()
                    if j.get("ready") or j.get("ok") or j.get("height",0) > 0:
                        print("[miner_client] node is ready.")
                        return j
            except Exception:
                pass
            print("[miner_client] waiting for node health...")
            time.sleep(1)

    def get_json(self, path):
        r = self.sess.get(f"{self.base}{path}", timeout=(5,20))
        r.raise_for_status()
        return r.json()

    def submit_block(self, candidate, network_id, debug_dir=None):
        return submit_block(self.sess, self.base, candidate, network_id, debug_dir=debug_dir)

    @staticmethod
    def hex_to_binary(h: str) -> str:
        return bin(int(h,16))[2:].zfill(4*len(h))

    @staticmethod
    def _to_int_ns(v) -> int:
        try:
            if v is None: return 0
            if isinstance(v, (int, float)): return int(v)
            return int(float(str(v).strip()))
        except Exception:
            return 0

    @staticmethod
    def median_past_ns(chain: List[dict], window: int) -> int:
        if not chain: return 0
        tail = chain[-window:] if len(chain) >= window else chain[:]
        ts = [MC._to_int_ns(b.get("timestamp")) for b in tail if isinstance(b, dict)]
        if not ts: return 0
        ts.sort()
        n = len(ts)
        return ts[n//2] if n%2 else (ts[n//2-1] + ts[n//2])//2

    @staticmethod
    def safe_ts_ns(now_ns: int, parent_ts_ns: int, mtp_ns: int) -> int:
        return max(int(now_ns), int(parent_ts_ns)+1, int(mtp_ns)+1)

    @staticmethod
    def adjust_difficulty(parent_diff: int, parent_ts_ns: int, now_ts_ns: int, mine_rate_ns: Optional[int]) -> int:
        try:
            pd = int(parent_diff)
        except Exception:
            pd = 1
        if not mine_rate_ns or int(mine_rate_ns) <= 0:
            return max(1, pd)
        return (pd + 1) if (int(now_ts_ns) - int(parent_ts_ns)) < int(mine_rate_ns) else max(1, pd - 1)

def main():
    args = argp()
    base = args.node.rstrip("/")
    sess = requests.Session()
    mc = MC(sess, base, token=args.token)

    print(f"[miner] starting. node={base} addr={args.addr} allow_empty={int(args.allow_empty)}")
    health = mc.wait_ready() or {}

    NETWORK_ID = str(health.get("network_id", os.getenv("NETWORK_ID", "testnet")))
    MINE_RATE_NS = int(health.get("mine_rate_ns") or os.getenv("MINE_RATE", 0))
    MINING_REWARD = int(health.get("mining_reward", os.getenv("MINING_REWARD", 50)))
    MINING_REWARD_ASSET = str(health.get("mining_reward_asset", os.getenv("MINING_REWARD_ASSET", "COIN")))

    failures = 0
    while True:
        try:
            chain = mc.get_json("/blockchain")
            mempool = mc.get_json("/mempool")
        except Exception as e:
            print("[miner] network error fetching chain/mempool:", e)
            time.sleep(2); continue

        if not chain:
            print("[miner] empty chain; waiting...")
            time.sleep(1); continue

        tip = chain[-1]
        parent_hash = tip.get("hash")
        parent_ts_ns = MC._to_int_ns(tip.get("timestamp"))
        parent_diff = int(tip.get("difficulty", 1) or 1)

        if not mempool and not args.allow_empty:
            print("[miner] no mempool txs; sleeping")
            time.sleep(args.interval); continue

        # block_data: mempool + reward (append minimal coinbase)
        block_data = list(mempool)
        reward_tx = {
            "id": f"cb-{int(time.time()*1000)}",
            "input": {"address": "*--official-mining-reward--*"},
            "output": { args.addr: { MINING_REWARD_ASSET: MINING_REWARD } },
            "metadata": {"miner": args.addr}
        }
        block_data.append(reward_tx)

        # compute leaf hexes + canonical merkle (sha256(json) + hexcat default)
        leaf_hexes_include_id = [sha256_hex(canonical_json(tx)) for tx in block_data]
        canonical_merkle = _build_merkle(leaf_hexes_include_id, parent_hexcat)
        merkle = canonical_merkle

        # timestamp/difficulty
        mtp_ns = MC.median_past_ns(chain, args.mpt_window)
        ts_ns = MC.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
        difficulty = MC.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)

        # Mine loop (use rig if available/desired)
        found = False
        nonce = 0
        h = compute_array_full_single_hash(NETWORK_ID, ts_ns, parent_hash, merkle, nonce, difficulty, block_data)
        target = "0" * difficulty

        # try rig
        if args.use_rig and gpu_find_nonce is not None:
            try:
                nonce_r, hexh = gpu_find_nonce(
                    header={"last_hash": parent_hash, "timestamp": ts_ns},
                    difficulty=difficulty,
                    txs=block_data,
                    batch=1_000_000
                )
                if nonce_r is not None:
                    nonce = nonce_r
                    h = hexh
                    found = True
            except Exception as e:
                print("[miner] rig error, falling back to CPU:", e)

        if not found:
            while MC.hex_to_binary(h)[:difficulty] != target:
                nonce += 1
                ts_ns = MC.safe_ts_ns(time.time_ns(), parent_ts_ns, mtp_ns)
                difficulty = MC.adjust_difficulty(parent_diff, parent_ts_ns, ts_ns, MINE_RATE_NS)
                target = "0" * difficulty
                h = compute_array_full_single_hash(NETWORK_ID, ts_ns, parent_hash, merkle, nonce, difficulty, block_data)

        print("[dbg] mined h           =", h)
        candidate = {
            "timestamp": ts_ns,
            "last_hash": parent_hash,
            "merkle": merkle,
            "data": block_data,
            "difficulty": difficulty,
            "nonce": nonce,
            "height": None
        }
        candidate["hash"] = compute_array_full_single_hash(NETWORK_ID, candidate["timestamp"],
                                                           candidate["last_hash"], candidate["merkle"],
                                                           candidate["nonce"], candidate["difficulty"],
                                                           candidate["data"])
        print("[dbg] candidate['hash'] =", candidate.get("hash"))

        # produce merkle variants to try at submit time
        merkle_variants = []
        for include_id in (False, True):
            for double in (False, True):
                leaves = []
                for tx in candidate["data"]:
                    t = deepcopy(tx)
                    if not include_id and isinstance(t, dict) and 'id' in t:
                        del t['id']
                    s = canonical_json(t)
                    h_leaf = sha256_hex(s)
                    if double:
                        h_leaf = sha256_hex(h_leaf)
                    leaves.append(h_leaf)
                merkle_variants.append(("include_id=%s double=%s parent=hexcat" % (include_id, double),
                                        _build_merkle(leaves, parent_hexcat)))
                try:
                    merkle_variants.append(("include_id=%s double=%s parent=bytescat" % (include_id, double),
                                            _build_merkle(leaves, parent_bytescat)))
                except Exception:
                    pass

        # dedupe
        seen = set()
        merkle_variants_unique = []
        for name, mv in merkle_variants:
            if mv and mv not in seen:
                seen.add(mv); merkle_variants_unique.append((name, mv))

        tries = 0
        submitted_ok = False
        last_resp = (False, None, None)

        for name, mval in merkle_variants_unique + [("canonical", candidate.get("merkle"))]:
            if submitted_ok: break
            if not mval: continue
            candidate_try = deepcopy(candidate)
            candidate_try['merkle'] = mval
            hash_candidates = build_block_hash_variants(NETWORK_ID,
                                                       candidate_try["timestamp"],
                                                       candidate_try["last_hash"],
                                                       candidate_try["merkle"],
                                                       candidate_try["nonce"],
                                                       candidate_try["difficulty"],
                                                       candidate_try["data"])
            for h_try in hash_candidates:
                if tries >= MAX_VARIANT_TRIES:
                    print("[miner] ⏹ max tries reached — valid block not found, restarting mining...")
                    submitted_ok = False
                    break
                candidate_try['hash'] = h_try
                ok, code, body = mc.submit_block(candidate_try, NETWORK_ID, debug_dir=args.debug_dir)
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

        if submitted_ok:
            failures = 0
            time.sleep(0.5)
            continue

        print("[miner] ⚙️ restarting mining loop...")
        ok, code, body = last_resp
        # fallback quick-resync etc could be added here
        failures += 1
        time.sleep(2 if failures < 5 else 5)

if __name__ == "__main__":
    main()
