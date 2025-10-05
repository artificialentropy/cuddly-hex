#!/usr/bin/env python3
# debug_submit_compare.py
import sys, json, hashlib, argparse, os

def canon_bytes(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def sha256d_hex(b): return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()

def deep_canon_args(args):
    out=[]
    for a in args:
        if isinstance(a, list):
            cl=[]
            for it in a:
                if isinstance(it, dict):
                    cl.append(json.loads(canon_bytes(it).decode("utf-8")))
                else:
                    cl.append(it)
            out.append(cl)
        elif isinstance(a, dict):
            out.append(json.loads(canon_bytes(a).decode("utf-8")))
        else:
            out.append(a)
    return out

def hash_single(arr): return sha256_hex(canon_bytes(deep_canon_args(arr)))
def hash_double(arr): return sha256d_hex(canon_bytes(deep_canon_args(arr)))

def compute_merkle_sha256_json_hexcat(data):
    # leaf = sha256(json(tx)), parent = sha256(hexcat)
    leaves=[sha256_hex(canon_bytes(tx)) for tx in data]
    lvl=leaves[:]
    if not lvl: return sha256_hex(b"")
    while len(lvl)>1:
        if len(lvl)%2==1: lvl.append(lvl[-1])
        nxt=[]
        for i in range(0,len(lvl),2):
            nxt.append(sha256_hex((lvl[i]+lvl[i+1]).encode()))
        lvl=nxt
    return lvl[0]

def try_variants(network_id, block, submitted_hash=None):
    ts = block.get("timestamp")
    last = block.get("last_hash")
    data = block.get("data", [])
    diff = int(block.get("difficulty") or 1)
    nonce = int(block.get("nonce") or 0)
    merkle = block.get("merkle","")
    claimed = block.get("hash","")
    print("Block fields:")
    print(" timestamp:", ts)
    print(" last_hash:", last)
    print(" difficulty:", diff)
    print(" nonce:", nonce)
    print(" merkle:", merkle)
    print(" claimed hash field:", claimed)
    if submitted_hash:
        print(" submitted_hash (node reported):", submitted_hash)
    print()

    variants = []

    # canonical "array full" (the one node matched earlier)
    arr_full = [network_id, int(ts), last, data, diff, nonce, merkle]
    variants.append(("array_full_single", hash_single(arr_full), hash_double(arr_full)))

    # same but canonicalized data (each tx sorted)
    arr_full_canon = [network_id, int(ts), last, [json.loads(canon_bytes(tx).decode()) if isinstance(tx, dict) else tx for tx in data], diff, nonce, merkle]
    variants.append(("array_full_single_canon_data", hash_single(arr_full_canon), hash_double(arr_full_canon)))

    # merkle-only array
    arr_merkle_only = [network_id, int(ts), last, merkle, diff, nonce]
    variants.append(("array_merkle_only", hash_single(arr_merkle_only), hash_double(arr_merkle_only)))

    # alternative ordering (data earlier)
    arr_data_first = [network_id, int(ts), data, last, diff, nonce, merkle]
    variants.append(("array_data_first", hash_single(arr_data_first), hash_double(arr_data_first)))

    # object header variants
    obj_basic = {"network": network_id, "timestamp": int(ts), "last_hash": last, "merkle": merkle, "difficulty": diff, "nonce": nonce}
    variants.append(("json_obj_basic", hash_single(obj_basic), hash_double(obj_basic)))

    obj_alt = {"net": network_id, "ts": int(ts), "prev": last, "m": merkle, "diff": diff, "n": nonce}
    variants.append(("json_obj_alt", hash_single(obj_alt), hash_double(obj_alt)))

    # timestamp scales to try
    for scale_label, scale in [("as_is",1),("ms*1000000",1000000),("ns_to_us",1/1000),("ns_to_ms",1/1000000),("ms_to_ns",1000000)]:
        try:
            ts_scaled = int(int(ts) * scale)
        except Exception:
            ts_scaled = ts
        arr = [network_id, ts_scaled, last, data, diff, nonce, merkle]
        variants.append((f"array_full_ts_{scale_label}", hash_single(arr), hash_double(arr)))
    # compute server-expected merkle (sha256(json)+hexcat) sample
    try:
        merkle_calc = compute_merkle_sha256_json_hexcat(data)
        print("recomputed merkle (sha256(json)+hexcat):", merkle_calc)
    except Exception as e:
        print("could not recompute merkle sample:", e)

    # print and compare
    print("\nComputed variants (name, single-sha, double-sha):\n")
    matched_any = False
    for name, s, d in variants:
        match_sub = (submitted_hash and (s == submitted_hash or d == submitted_hash))
        match_claim = (claimed and (s == claimed or d == claimed))
        print(f"{name:30} single={s} double={d}  match_submitted={match_sub} match_claimed={match_claim}")
        if match_sub or match_claim:
            matched_any = True

    if not matched_any:
        print("\nNo variant matched the node-reported submitted_hash or the block.claimed hash.")
        print("Next checks:")
        print(" - Ensure NETWORK_ID passed here equals node /health network_id exactly.")
        print(" - Ensure the JSON we saved & submitted is the exact object the miner hashed (no mutation after mining).")
        print(" - Compare the exact bytes of the JSON you POSTed (open the block_to_test_*.json) vs the object in memory at mining time.")
        print(" - If you set candidate['hash'] earlier, recompute right before POST (we recommend this).")
    else:
        print("\nAt least one variant matched the submitted or claimed hash above.")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument("file", help="path to block_to_test_....json")
    p.add_argument("--network", default="testnet")
    p.add_argument("--submitted", default=None, help="submitted_hash string (from node response)")
    args = p.parse_args()
    with open(args.file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    block = raw.get("block", raw) if isinstance(raw, dict) else raw
    
    try_variants(args.network, block, submitted_hash=args.submitted)
