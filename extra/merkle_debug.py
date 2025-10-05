# debug_merkle.py
import hashlib, json, sys
from pprint import pprint

def _h(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def _leaf(tx_json) -> bytes:
    # Must exactly match node: sort_keys=True, separators=(",",":")
    s = json.dumps(tx_json, sort_keys=True, separators=(",",":"))
    return _h(s.encode("utf-8"))

def merkle_root(txs_json) -> str:
    if not txs_json:
        return _h(b"").hex()
    level = [ _leaf(t) for t in txs_json ]
    # debug: show leaf hexes
    print("LEAF HEXES:")
    for i, leaf in enumerate(level):
        print(f"  [{i}] {leaf.hex()}  <-- canonical JSON:")
        print("       ", json.dumps(txs_json[i], sort_keys=True, separators=(",",":")))
    print()
    layers = [ [x.hex() for x in level] ]  # capture hex for debug
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
            print("  (odd number of nodes - duplicating last leaf)")
        new_level = []
        print("PAIRING:")
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1]
            pair_hash = _h(left + right)
            print(f"  pair {i}//{i+1} -> left={left.hex()} right={right.hex()} -> {pair_hash.hex()}")
            new_level.append(pair_hash)
        level = new_level
        layers.append([x.hex() for x in level])
    print("\nMERKLE LAYERS (bottom -> top):")
    for idx, lay in enumerate(layers):
        print(f"  layer {idx}:")
        for item in lay:
            print("    ", item)
    return level[0].hex()

# ---------- USER: paste the exact block JSON object you submitted ----------
# Example placeholder — replace this with your actual block dict (use real objects)
BLOCK_JSON = {
    # Replace with your submitted block. Key part is "data": [ ... ]
    "timestamp": 1759651917256413600,
    "last_hash": "genesis_hash",
    "hash": "e5dc4033a2f262d43ac2020e332aa490c51205533d8547f9f2f1060572283af8",
    "data": [
        {
            "id": "a6b81d60",
            "input": {
                "address": "10ac50ad",
                "balances": {"COIN": 1000},
                "fee": 0,
                "public_key": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnUiMKtHD4N74PcjI7lhf6XSAJ7tMrsJt\nB7sCSlkqrlhL+zEwlZA3LnyAvIkM2CA2pkpliMzGBrEk8e0iLgBj7g==\n-----END PUBLIC KEY-----\n",
                "signature": [
                    48912842475463779104626364775520395265112550557241399889121301892689746341546,
                    93347820810694859006219982043059377837606409472471255592136225669286987804545
                ],
                "timestamp": 1759651915737241624
            },
            "metadata": {},
            "output": {
                "10ac50ad": {"COIN": 988},
                "50060880": {"COIN": 12}
            }
        },
        {
            "id": "cb-1759651917222",
            "input": {
                "address": "*--official-mining-reward--*"
            },
            "metadata": {
                "miner": "miner-demo-addr"
            },
            "output": {
                "miner-demo-addr": {"COIN": 50}
            }
        }
    ],
    "difficulty": 3,
    "nonce": 4880,
    "merkle": "29a17d4ed48e4d2a717c00e4ffd934d2908afb40e9cdbb1be509d2339ed85e71"
}
# -------------------------------------------------------------------------

def run_debug(block):
    print("=== Debugging merkle for submitted block ===\n")
    pprint({k: v for k, v in block.items() if k != "data"})
    print("\n--- Recomputing merkle from block['data'] ---\n")
    computed = merkle_root(block["data"])
    print("\ncomputed merkle:", computed)
    print("submitted merkle:", block.get("merkle"))
    print("match?", computed == block.get("merkle"))
    if not computed == block.get("merkle"):
        print("\n=> MERKLE MISMATCH: miner's merkle differs from recomputed merkle.")
        print("   Compare the canonical JSON outputs above to locate differences.")
    else:
        print("\n=> MERKLE MATCH: merkle ok. If node still rejects, check PoW or timestamp/difficulty checks.")

if __name__ == "__main__":
    run_debug(BLOCK_JSON)
