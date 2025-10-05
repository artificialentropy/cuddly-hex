#!/usr/bin/env python3
# debug_block_hash_auto.py
import sys, json, hashlib

def sha256(b): return hashlib.sha256(b).digest()
def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def sha256d_hex(b): return hashlib.sha256(hashlib.sha256(b).digest()).hexdigest()
def canon_bytes(x): return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def canon_str(x): return json.dumps(x, sort_keys=True, separators=(",", ":"))

def leaf_sha256_json(tx): return sha256_hex(canon_bytes(tx))
def leaf_sha256_txid(tx): return sha256_hex(str(tx.get("id", canon_str(tx))).encode())
def leaf_crypto_json(tx): return sha256_hex(canon_bytes([tx]))
def leaf_crypto_txid(tx): return sha256_hex(canon_bytes([str(tx.get("id",""))]))

def parent_hex_hexcat(l,r): return sha256_hex((l+r).encode())
def parent_hex_bytescat(l,r): return sha256_hex(bytes.fromhex(l)+bytes.fromhex(r))
def parent_crypto_pair(l,r): return sha256_hex(canon_bytes([l,r]))

def build_merkle(leaves_hex, parent_fn):
    if not leaves_hex: return sha256_hex(b"")
    layer = leaves_hex[:]
    while len(layer)>1:
        if len(layer)%2==1: layer.append(layer[-1])
        nxt=[]
        for i in range(0,len(layer),2):
            nxt.append(parent_fn(layer[i], layer[i+1]))
        layer = nxt
    return layer[0]

def compute_merkle(data, leaf_fn, parent_fn):
    leaves=[leaf_fn(tx) for tx in data]
    return build_merkle(leaves, parent_fn)

def find_block_obj(obj):
    # if obj itself is block-like, return it
    if isinstance(obj, dict) and ("timestamp" in obj or "hash" in obj):
        return obj
    # if wrapped as {"block": {...}}
    if isinstance(obj, dict) and "block" in obj and isinstance(obj["block"], dict):
        return obj["block"]
    # try find any nested dict with timestamp+hash
    if isinstance(obj, dict):
        for k,v in obj.items():
            if isinstance(v, dict) and ("timestamp" in v or "hash" in v):
                return v
    # try first element if it's a list of blocks
    if isinstance(obj, list) and obj:
        if isinstance(obj[0], dict) and ("timestamp" in obj[0] or "hash" in obj[0]):
            return obj[0]
    return None

def try_variants(block, network_guess="testnet"):
    ts = block.get("timestamp")
    last_hash = block.get("last_hash") or block.get("lastHash") or block.get("previous_hash")
    data = block.get("data") or block.get("txs") or block.get("transactions") or []
    diff = int(block.get("difficulty") or 1)
    nonce = int(block.get("nonce") or 0)
    merkle_given = block.get("merkle") or block.get("merkle_root") or ""

    claimed = block.get("hash") or block.get("block_hash") or ""
    if not claimed:
        print("No claimed hash found in block; aborting.")
        return []

    candidates = []
    leafs = [("leaf_sha256_json", leaf_sha256_json), ("leaf_sha256_txid", leaf_sha256_txid),
             ("leaf_crypto_json", leaf_crypto_json), ("leaf_crypto_txid", leaf_crypto_txid)]
    parents = [("hexcat", parent_hex_hexcat), ("bytescat", parent_hex_bytescat), ("crypto_pair", parent_crypto_pair)]

    for lname, lfn in leafs:
        for pname, pfn in parents:
            try:
                m = compute_merkle(data, lfn, pfn)
            except Exception:
                m = None
            for used_m in (m, merkle_given):
                if used_m is None: continue
                # try array preimage: [network, ts, last_hash, data, diff, nonce, merkle]
                arr1 = [network_guess, ts, last_hash, data, diff, nonce, used_m]
                jb = canon_bytes(arr1); s1 = sha256_hex(jb); d1 = sha256d_hex(jb)
                candidates.append((lname, pname, used_m, "array_data", s1, d1))
                # try array preimage without data (merkle only)
                arr2 = [network_guess, ts, last_hash, used_m, diff, nonce]
                jb2 = canon_bytes(arr2); s2 = sha256_hex(jb2); d2 = sha256d_hex(jb2)
                candidates.append((lname, pname, used_m, "array_merkle", s2, d2))
    # also try JSON object header
    obj = {"version": block.get("version",1), "last_hash": last_hash, "merkle_root": merkle_given, "timestamp": ts, "difficulty": diff, "nonce": nonce}
    jb_obj = canon_bytes(obj); s_obj = sha256_hex(jb_obj); d_obj = sha256d_hex(jb_obj)
    candidates.append(("obj","obj", merkle_given, "json_object", s_obj, d_obj))

    matches=[]
    for c in candidates:
        if c[4] == claimed:
            matches.append((c, "single"))
        if c[5] == claimed:
            matches.append((c, "double"))
    return matches, candidates

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: python debug_block_hash_auto.py <file.json> [network_id]")
        sys.exit(1)
    fn=sys.argv[1]; net=sys.argv[2] if len(sys.argv)>2 else "testnet"
    with open(fn,"r",encoding="utf-8") as f:
        data=json.load(f)
    block=find_block_obj(data)
    if not block:
        print("Could not locate block object inside file. Top-level keys:", list(data.keys()) if isinstance(data, dict) else type(data))
        sys.exit(1)
    print("Located block; timestamp:", block.get("timestamp"), "last_hash:", block.get("last_hash")[:10] if block.get("last_hash") else None)
    matches, cand = try_variants(block, net)
    if matches:
        print("MATCHES FOUND:")
        for m,typ in matches:
            lname, pname, used_m, mode, single, double = m
            print(" mode:", mode, "leaf:", lname, "parent:", pname, "used_merkle:", used_m, "matched:", typ)
    else:
        print("No matches found among tried variants. Showing some sample computed merkles:")
        for s in cand[:6]:
            print(" sample:", s[3], s[0], s[1], "used_merkle:", s[2])
    print("done.")
