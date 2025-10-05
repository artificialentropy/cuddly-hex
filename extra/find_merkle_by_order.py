#!/usr/bin/env python3
"""
Try ordering + leaf/parent variants to find the exact merkle equal to block['merkle'].
Usage:
  python find_merkle_by_order.py path/to/block_to_test.json
"""
import json, hashlib, sys, copy
from itertools import product
from pprint import pprint

if len(sys.argv) < 2:
    print("usage: find_merkle_by_order.py path/to/block.json")
    sys.exit(1)

path = sys.argv[1]
doc = json.load(open(path, "r", encoding="utf-8"))
blk = doc.get("block", doc)
target_merkle = blk.get("merkle")
txs_orig = blk.get("data", [])
print("Loaded:", path)
print("block merkle:", target_merkle)
print("tx count:", len(txs_orig))
print()

# helpers
def canonical_json_with_opts(o, ensure_ascii=True, separators=(',',':')):
    return json.dumps(o, sort_keys=True, separators=separators, ensure_ascii=ensure_ascii)

def sha256_hex_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def merkle_hexcat(leaves):
    nodes = list(leaves)
    if not nodes:
        return sha256_hex_str(canonical_json_with_opts([]))
    while len(nodes) > 1:
        next_level=[]
        for i in range(0, len(nodes), 2):
            left = nodes[i]; right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(sha256_hex_str(left + right))
        nodes = next_level
    return nodes[0]

def merkle_bytescat_from_hexleaves(leaves):
    nodes = [bytes.fromhex(h) for h in leaves]
    if not nodes:
        return sha256_hex_str(canonical_json_with_opts([]))
    while len(nodes) > 1:
        next_level=[]
        for i in range(0, len(nodes), 2):
            left = nodes[i]; right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(hashlib.sha256(left + right).hexdigest())
        nodes = next_level
    return nodes[0]

def leaf_for_tx(tx, include_id=False, double=False, ensure_ascii=False, separators=(',',':')):
    t = copy.deepcopy(tx)
    if not include_id and 'id' in t:
        del t['id']
    s = canonical_json_with_opts(t, ensure_ascii=ensure_ascii, separators=separators)
    h = sha256_hex_str(s)
    if double:
        h = sha256_hex_str(h)
    return s, h

# build candidate orderings to try
def gen_orderings(txs):
    # find the reward tx (heuristic: input.address contains "official-mining-reward" or id starts with 'cb-')
    reward_idx = None
    for i, tx in enumerate(txs):
        inp = tx.get("input", {}) or {}
        addr = inp.get("address", "")
        if isinstance(addr, str) and ("--official-mining-reward--" in addr or addr.startswith("*--official") or tx.get("id","").startswith("cb-")):
            reward_idx = i
            break
    orders = []
    # 1) original (as-saved)
    orders.append(("orig", list(txs)))
    # 2) reward first
    if reward_idx is not None:
        t = list(txs)
        r = t.pop(reward_idx)
        orders.append(("reward_first", [r] + t))
        # reward at index 1 (after first tx)
        t2 = list(txs); r2 = t2.pop(reward_idx); t2.insert(1, r2)
        orders.append(("reward_index_1", t2))
    # 3) reward last (explicit)
    if reward_idx is not None:
        t = list(txs)
        r = t.pop(reward_idx); t.append(r)
        orders.append(("reward_last", t))
    # 4) sort by id
    try:
        orders.append(("sort_id", sorted(txs, key=lambda x: x.get("id",""))))
    except Exception:
        pass
    # 5) reverse
    orders.append(("reversed", list(reversed(txs))))
    # 6) stable sort by input.address then id (some nodes may group by address)
    try:
        orders.append(("sort_addr_id", sorted(txs, key=lambda x: (x.get("input",{}).get("address",""), x.get("id","")))))
    except Exception:
        pass
    # remove duplicates while preserving order
    seen = set()
    out = []
    for name, o in orders:
        key = json.dumps(o, sort_keys=True, separators=(',',':'))
        if key not in seen:
            seen.add(key); out.append((name,o))
    return out

orderings = gen_orderings(txs_orig)
print("Will try orderings:", [n for n,_ in orderings])
print()

# options to try for serialization + hashing
serializer_opts = [
    (False, (',',':')),
    (True,  (',',':')),
    (False, (', ',': ')),
    (True,  (', ',': '))
]

tried = 0
matches = []

for ord_name, txs in orderings:
    for include_id, double, (ensure_ascii, separators), parent_mode in product((False,True),(False,True),serializer_opts,("hexcat","bytescat")):
        tried += 1
        # compute leaves
        try:
            serials = []
            leaves = []
            for tx in txs:
                s,h = leaf_for_tx(tx, include_id=include_id, double=double, ensure_ascii=ensure_ascii, separators=separators)
                serials.append(s); leaves.append(h)
        except Exception as e:
            # skip combos that break
            continue
        if parent_mode == "hexcat":
            merkle_val = merkle_hexcat(leaves)
        else:
            try:
                merkle_val = merkle_bytescat_from_hexleaves(leaves)
            except Exception as e:
                merkle_val = f"ERR:{e}"
        if merkle_val == target_merkle:
            matches.append({
                "ordering": ord_name,
                "include_id": include_id,
                "double": double,
                "ensure_ascii": ensure_ascii,
                "separators": separators,
                "parent_mode": parent_mode,
                "leaf_sample": leaves[:4]
            })
            print("=== MATCH FOUND ===")
            pprint(matches[-1])
            # continue to list all matches
        # print some progress for first few combos
        if tried <= 12:
            print(f"[try {tried}] ord={ord_name} incl_id={include_id} dbl={double} ascii={ensure_ascii} sep={separators} parent={parent_mode} -> {merkle_val}")

print()
print("Tried combos:", tried)
if matches:
    print("Matches found:")
    for m in matches:
        pprint(m)
else:
    print("No match found. Consider also these possibilities:")
    print("- node may canonicalize tx objects differently (e.g. drop empty fields)")
    print("- timestamp unit differences (ns vs ms) affecting header preimage but merkle usually independent")
    print("- node may be computing merkle on a different tx list (e.g. it removed some txs before validating)")
    print("Paste the node 'variants_checked_example' JSON if you want me to compare against it directly.")
