#!/usr/bin/env python3
"""
compare_hashes.py
Usage:
  # run from repo root (so blockchain_backend imports resolve)
  $env:PYTHONPATH = (Get-Location).Path   # PowerShell
  python compare_hashes.py "<rejected_json_path>" <network_id>

Example:
  python compare_hashes.py "block data/rejected_block_1759656404383.json" devnet-001
"""
import json, sys, os, hashlib
from pprint import pprint

if len(sys.argv) < 3:
    print("Usage: python compare_hashes.py <rejected_json> <network_id>")
    sys.exit(1)

rej_path = sys.argv[1]
NETWORK_ID = sys.argv[2]

# Ensure repo root on PYTHONPATH / run from repo root
try:
    from blockchain_backend.utils.crypto_hash import crypto_hash
    from blockchain_backend.utils.merkle import merkle_root
    from blockchain_backend.utils.hex_to_binary import hex_to_binary
except Exception as e:
    print("ERROR importing blockchain_backend utilities. Are you running from repo root with PYTHONPATH set?")
    print("Exception:", e)
    sys.exit(2)

def canonical_json(obj):
    import json
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

with open(rej_path, "r", encoding="utf-8") as f:
    payload = json.load(f)

# file contains top-level with 'block' or node response in different shape
if "block" in payload:
    block = payload["block"]
elif "attempted_candidate" in payload:
    block = payload["attempted_candidate"]
else:
    # maybe file is rejected_block with node_response and block
    block = payload.get("block") or payload.get("candidate") or payload

print("\nLoaded block from:", rej_path)
pprint({k: block.get(k) for k in ("hash","timestamp","last_hash","merkle","difficulty","nonce")})

# show merkle recompute
data = block.get("data", [])
print("\nTX count:", len(data))
print("Sample txs (canonical json):")
for i, t in enumerate(data[:4]):
    s = canonical_json(t)
    print(f"  tx[{i}]: {s[:180]}")

computed_merkle = None
try:
    computed_merkle = merkle_root(data)
except Exception as e:
    print("error computing merkle_root:", e)

print("\nsubmitted merkle:", block.get("merkle"))
print("recomputed merkle:", computed_merkle)
print("merkle match?:", computed_merkle == block.get("merkle"))

# Recompute crypto_hash using local imported function
try:
    ts = int(block.get("timestamp"))
    last_hash = block.get("last_hash")
    diff = int(block.get("difficulty"))
    nonce = int(block.get("nonce"))
    merkle = block.get("merkle")
    mine_data = data
    my_hash = crypto_hash(NETWORK_ID, ts, last_hash, mine_data, diff, nonce, merkle)
    print("\ncrypto_hash(...) using local crypto_hash and NETWORK_ID=%r:" % NETWORK_ID)
    print("  my_hash:", my_hash)
    print("  submitted_hash:", block.get("hash"))
    print("  equal to submitted?:", my_hash == block.get("hash"))
    print("  hex_to_binary prefix (first 64 bits) =>", hex(int(my_hash[:16], 16))[2:][:64] if my_hash else "")
except Exception as e:
    print("error computing crypto_hash:", e)
    my_hash = None

# Try header-json style variants (diagnostic)
def header_json_map(version, last_hash, merkle_root_val, timestamp, difficulty, nonce):
    return {
        "version": int(version),
        "last_hash": (last_hash or "").lower(),
        "merkle_root": (merkle_root_val or "").lower(),
        "timestamp": int(timestamp),
        "difficulty": int(difficulty),
        "nonce": int(nonce),
    }

def header_json_hash(version, last_hash, merkle_root_val, timestamp, difficulty, nonce, double_sha=False):
    hdr = header_json_map(version, last_hash, merkle_root_val, timestamp, difficulty, nonce)
    jb = canonical_json(hdr).encode('utf-8')
    if double_sha:
        return hashlib.sha256(hashlib.sha256(jb).digest()).hexdigest()
    return hashlib.sha256(jb).hexdigest()

try:
    # try a few guesses for version / inclusion forms
    v = block.get("version", 1)
    jsingle = header_json_hash(v, block.get("last_hash") or block.get("hash"), block.get("merkle"), block.get("timestamp"), block.get("difficulty"), block.get("nonce"), double_sha=False)
    jdouble = header_json_hash(v, block.get("last_hash") or block.get("hash"), block.get("merkle"), block.get("timestamp"), block.get("difficulty"), block.get("nonce"), double_sha=True)
    print("\nheader_json_hash single:", jsingle)
    print("header_json_hash double:", jdouble)
except Exception as e:
    print("header-json diagnostics failed:", e)

print("\nIf my_hash != node's recomputed hash (from debug_it), check:")
print("  1) Are you running this from repo root so crypto_hash is same as node's? (PYTHONPATH)")
print("  2) Does NETWORK_ID match node's network_id (check node /health or miner startup)")
print("  3) Are there any local modifications to blockchain_backend/utils/crypto_hash.py?")

print("\nDone.")
