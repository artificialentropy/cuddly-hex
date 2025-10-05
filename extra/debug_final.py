import json, hashlib, sys
from pprint import pprint
# adjust path to the debug file your miner saved when a block was rejected
p = r"C:\Users\mohit\OneDrive\Desktop\Projects\blockchain_based_ai\block data\block_to_test_1759636520878.json"

def canonical_json(o):
    import json
    return json.dumps(o, sort_keys=True, separators=(',',':'), ensure_ascii=False)
def sha256_hex(s): return hashlib.sha256(s.encode()).hexdigest()
def merkle_hexcat(leaves):
    nodes = list(leaves)
    if not nodes: return sha256_hex(canonical_json([]))
    while len(nodes) > 1:
        next_level=[]
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            next_level.append(sha256_hex(left + right))
        nodes = next_level
    return nodes[0]

doc = json.load(open(p, "r", encoding="utf-8"))
blk = doc.get("block", doc)
txs = blk.get("data", [])
leaf_hexes = [sha256_hex(canonical_json(tx)) for tx in txs]
print("leaf_hexes (sample):")
pprint(leaf_hexes)
print("canonical merkle (hexcat):", merkle_hexcat(leaf_hexes))
print("block merkle field        :", blk.get("merkle"))
print("block submitted hash      :", blk.get("hash"))
