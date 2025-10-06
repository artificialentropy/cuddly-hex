#!/usr/bin/env python3
# quick_mine_and_submit.py
import time, json, requests, hashlib
from copy import deepcopy

# adjust these
NODE = "http://127.0.0.1:5000"
MINER_TOKEN = "secret123"            # set to your MINER_TOKEN
MINER_ADDR = "miner-demo-addr"
MINING_REWARD_ASSET = "COIN"
MINING_REWARD = 50
MINING_REWARD_INPUT = "*--official-mining-reward--*"  # must match node exactly
DIFFICULTY = 3                        # choose small difficulty for local test

HEADERS = {"X-Miner-Token": MINER_TOKEN, "Content-Type": "application/json"}

# paste your mempool here (from your message)
POOL = [ 
  { "id": "315dc3b1", "input": { "address":"347c8bd7", "balances": {"COIN":1000}, "fee":0, "public_key":"...","signature":["50d8...","2f98..."], "timestamp":1759766791 }, "metadata":{}, "output": {"347c8bd7":{"COIN":989}, "f6ec875a":{"COIN":11}} },
  { "id": "d89fe775", "input": { "address":"347c8bd7", "balances": {"COIN":1000}, "fee":0, "public_key":"...","signature":["b850...","6329..."], "timestamp":1759766792 }, "metadata":{}, "output": {"347c8bd7":{"COIN":989}, "f6ec875a":{"COIN":11}} },
  { "id": "65a5a143", "input": { "address":"347c8bd7", "balances": {"COIN":1000}, "fee":0, "public_key":"...","signature":["2236...","a500..."], "timestamp":1759766792 }, "metadata":{}, "output": {"347c8bd7":{"COIN":989}, "f6ec875a":{"COIN":11}} }
]

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def build_merkle(txs):
    # node's canonical merkle uses sha256(json(tx)) as leaves and hex-concat parent
    leaves = [sha256_hex(canonical_json(tx).encode("utf-8")) for tx in txs]
    if not leaves:
        return sha256_hex(b"")
    layer = leaves[:]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(sha256_hex((layer[i] + layer[i+1]).encode("utf-8")))
        layer = nxt
    return layer[0]

def crypto_hash(network_id, timestamp_s, last_hash, data, difficulty, nonce, merkle):
    # If you have blockchain_backend.utils.crypto_hash, import and use it instead for exact parity.
    # Fallback: header json single-sha of canonical header (version omitted here)
    hdr = {
        "version": 1,
        "last_hash": (last_hash or "").lower(),
        "merkle_root": (merkle or "").lower(),
        "timestamp": int(timestamp_s),
        "difficulty": int(difficulty),
        "nonce": int(nonce),
    }
    jb = canonical_json(hdr).encode("utf-8")
    return sha256_hex(jb)

# get tip's last_hash (we need last_hash from node)
r = requests.get(f"{NODE}/blockchain")
r.raise_for_status()
chain_body = r.json()
chain = chain_body["chain"] if isinstance(chain_body, dict) and "chain" in chain_body else chain_body
last_hash = chain[-1]["hash"] if chain else "genesis_hash"

# compute fees
total_fees = sum(int((tx.get("input") or {}).get("fee", 0)) for tx in POOL)
reward_amount = MINING_REWARD + total_fees

# make block data (ensure reward tx input is sentinel EXACTLY)
block_data = deepcopy(POOL)
reward_tx = {
    "id": f"cb-{int(time.time())}",
    "input": MINING_REWARD_INPUT,             # <= exact sentinel
    "metadata": {"miner": MINER_ADDR},
    "output": {MINER_ADDR: {MINING_REWARD_ASSET: reward_amount}}
}
block_data.append(reward_tx)

# canonical merkle
merkle = build_merkle(block_data)

# mine using seconds in preimage (so node recompute will match)
timestamp_s = int(time.time())
nonce = 0
target_prefix = "0" * DIFFICULTY
while True:
    h = crypto_hash("devnet-001", timestamp_s, last_hash, block_data, DIFFICULTY, nonce, merkle)
    # simple hex-prefix difficulty check (ensure same check as node: hex->binary sometimes used; adapt if node uses binary)
    if h.startswith(target_prefix):
        break
    nonce += 1
    # update timestamp occasionally so we don't spin forever with stale seconds
    if nonce % 100000 == 0:
        timestamp_s = int(time.time())

candidate = {
    "version": 1,
    "last_hash": last_hash,
    "merkle": merkle,
    "timestamp": timestamp_s,
    "difficulty": DIFFICULTY,
    "nonce": nonce,
    "data": block_data,
    "hash": h
}
candidate.pop("version", None)


print("Mined candidate:", candidate["hash"], "nonce:", nonce, "ts:", timestamp_s, "merkle:", merkle)
# submit
resp = requests.post(f"{NODE}/blocks/submit", json={"block": candidate}, headers=HEADERS, timeout=10)
print("submit ->", resp.status_code, resp.text)
