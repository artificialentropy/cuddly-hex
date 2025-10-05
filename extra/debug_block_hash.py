#!/usr/bin/env python3
"""
Try many plausible merkle constructions for a saved block_to_test file.
Usage:
  python exhaustive_merkle_check.py path/to/block.json [path/to/node_resp.json]
"""
import json, hashlib, sys, copy
from pprint import pprint
from itertools import product

if len(sys.argv) < 2:
    print("usage: exhaustive_merkle_check.py path/to/block.json [path/to/node_resp.json]")
    sys.exit(1)

block_path = sys.argv[1]
node_resp_path = sys.argv[2] if len(sys.argv) > 2 else None

def sha256_hex_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def merkle_hexcat(leaves):
    nodes = list(leaves)
    if not nodes:
        return sha256_hex_str(json.dumps([], sort_keys=True, separators=(',',':')))
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            # left/right are hex strings
            next_level.append(sha256_hex_str(left + right))
        nodes = next_level
    return nodes[0]

def merkle_bytescat_from_hexleaves(leaves_hex):
    # convert hex->bytes then pairwise sha256 on bytes
    nodes = [bytes.fromhex(h) for h in leaves_hex]
    if not nodes:
        return sha256_hex_str(json.dumps([], sort_keys=True, separators=(',',':')))
    while len(nodes) > 1:
        next_level=[]
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(hashlib.sha256(left + right).hexdigest())
        nodes = next_level
    return nodes[0]

# load block
blk_doc = json.load(open(block_path, "r", encoding="utf-8"))
blk = blk_doc.get("block", blk_doc)
txs = blk.get("data", [])
print("Loaded block:", block_path)
print("block['merkle']:", blk.get("merkle"))
print("block['hash']  :", blk.get("hash"))
print("tx count:", len(txs))
print("")

# optional: load node response JSON to compare variants_checked_example
node_variants = None
if node_resp_path:
    nr = json.load(open(node_resp_path, "r", encoding="utf-8"))
    node_variants = nr.get("variants_checked_example") or nr.get("variants_checked") or nr.get("variants") or None
    if node_variants:
        print("Loaded node response variants (will compare).")
    else:
        print("Node response provided but no 'variants_checked_example' found.")

# define serializer options to try
serializer_options = [
    {"ensure_ascii": False, "separators": (',',':')},
    {"ensure_ascii": True,  "separators": (',',':')},
    {"ensure_ascii": False, "separators": (', ',': ')},
    {"ensure_ascii": True,  "separators": (', ',': ')},
]

def canonical_json_with_opts(obj, ensure_ascii=True, separators=(',',':')):
    return json.dumps(obj, sort_keys=True, separators=separators, ensure_ascii=ensure_ascii)

# helper produce leaf given options
def leaf_for_tx(tx, include_id=False, double=False, ensure_ascii=False, separators=(',',':')):
    t = copy.deepcopy(tx)
    if not include_id and 'id' in t:
        del t['id']
    s = canonical_json_with_opts(t, ensure_ascii=ensure_ascii, separators=separators)
    h = hashlib.sha256(s.encode()).hexdigest()
    if double:
        h = hashlib.sha256(h.encode()).hexdigest()
    return s, h

# Try combinations
tried = []
matches = []
i = 0
for include_id, double, ser_opts, parent_mode in product(
        (False, True), (False, True), serializer_options, ("hexcat", "bytescat")):
    i += 1
    ensure_ascii = ser_opts["ensure_ascii"]
    separators = ser_opts["separators"]
    combo_name = f"include_id={include_id} double={double} ensure_ascii={ensure_ascii} sep={separators} parent={parent_mode}"
    # compute leaves (and keep sample serializations)
    leaves_hex = []
    leaves_serial = []
    for tx in txs:
        s, h = leaf_for_tx(tx, include_id=include_id, double=double,
                           ensure_ascii=ensure_ascii, separators=separators)
        leaves_serial.append(s)
        leaves_hex.append(h)
    if parent_mode == "hexcat":
        merkle_val = merkle_hexcat(leaves_hex)
    else:
        try:
            merkle_val = merkle_bytescat_from_hexleaves(leaves_hex)
        except Exception as e:
            merkle_val = f"error:{e}"
    tried.append((combo_name, merkle_val, leaves_hex[:4], leaves_serial[:2]))

    if merkle_val == blk.get("merkle"):
        matches.append((combo_name, merkle_val))

    # also compare to node variants if available
    nv_match = []
    if node_variants:
        for v in node_variants:
            node_merkle = v.get("merkle")
            if node_merkle and node_merkle == merkle_val:
                nv_match.append(node_merkle)

    # print quick progress for first few and if match
    if i <= 8 or merkle_val == blk.get("merkle") or nv_match:
        print("----")
        print(combo_name)
        print(" merkle:", merkle_val)
        print(" leaves (hex sample):", leaves_hex[:4])
        if nv_match:
            print(" MATCHES node variants:", nv_match)
        if merkle_val == blk.get("merkle"):
            print(" >>> MATCHES block['merkle'] <<<")

# summary
print("\nTried variants count:", len(tried))
if matches:
    print("Found matching construction(s) for block['merkle']:")
    for m in matches:
        print("  ", m)
else:
    print("No exact match found among tried variants.")
    print("First 12 tried variants (name -> merkle):")
    for name, merkle_val, leaves, serial in tried[:12]:
        print(name, "->", merkle_val)
print("\nIf no match, paste the node 'variants_checked_example' JSON here and I will compare and pick exact settings.")
