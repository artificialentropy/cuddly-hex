#!/usr/bin/env python3
# diagnose_rejected.py
import json, os, sys, hashlib
from pprint import pprint

# ensure you run from repo root or set PYTHONPATH to repo root
try:
    from blockchain_backend.utils.crypto_hash import crypto_hash
    from blockchain_backend.utils.hex_to_binary import hex_to_binary
    from blockchain_backend.utils.merkle import merkle_root
except Exception as e:
    print("ERROR: cannot import blockchain_backend modules. Run from repo root or set PYTHONPATH.")
    print("Exception:", e)
    sys.exit(2)

def load_rejected(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def canonical_json(obj):
    import json
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)

def leaf_hex_sha256_json(tx):
    return hashlib.sha256(canonical_json(tx).encode("utf-8")).hexdigest()

def parent_hexcat(left_hex, right_hex):
    return hashlib.sha256((left_hex + right_hex).encode("utf-8")).hexdigest()

def parent_bytescat(left_hex, right_hex):
    return hashlib.sha256(bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()

def build_merkle_from_leaves(leaves_hex, parent_fn):
    if not leaves_hex:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaves_hex)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(parent_fn(level[i], level[i+1]))
        level = nxt
    return level[0]

def check_candidate(debug_path, network_id="devnet-001"):
    doc = load_rejected(debug_path)
    # miner saved {"block": candidate, "node_response": body} per the miner code
    candidate = doc.get("block") or doc.get("candidate") or doc
    node_rsp = doc.get("node_response") or doc.get("response") or {}

    print("Loaded:", debug_path)
    print("\nNode response (short):")
    pprint({k: node_rsp.get(k) for k in ("error","submitted_hash","traceback") if k in node_rsp})

    # Basic fields
    submitted_hash = candidate.get("hash")
    difficulty = int(candidate.get("difficulty", 1))
    nonce = int(candidate.get("nonce", 0))
    ts = int(candidate.get("timestamp", 0))
    last_hash = candidate.get("last_hash", "")
    merkle_submitted = candidate.get("merkle", "")
    data = candidate.get("data", [])

    print("\nCandidate summary:")
    print("  submitted hash:", submitted_hash)
    print("  difficulty     :", difficulty)
    print("  nonce          :", nonce)
    print("  timestamp (ns) :", ts)
    print("  last_hash      :", last_hash)
    print("  submitted merkle:", merkle_submitted)
    print("  tx count       :", len(data))

    # 1) Recompute merkle using node merkle_root (preferred)
    recomputed_merkle = merkle_root(data)
    print("\nRecomputed merkle (node merkle_root):", recomputed_merkle)
    if recomputed_merkle != merkle_submitted:
        print("-> MERKLE MISMATCH (this will cause rejection).")
    else:
        print("-> MERKLE matches submitted value.")

    # 2) Recompute node preimage hash (crypto_hash: NETWORK_ID, ts, last_hash, data, difficulty, nonce, merkle)
    recomputed_hash = crypto_hash(network_id, ts, last_hash, data, difficulty, nonce, recomputed_merkle)
    print("\nRecomputed crypto_hash:", recomputed_hash)
    print("Matches submitted hash?:", recomputed_hash == submitted_hash)

    # 3) Check PoW condition using hex_to_binary (node's test)
    pow_ok = hex_to_binary(recomputed_hash)[: difficulty] == "0" * difficulty
    print("\nPoW binary-prefix check for recomputed hash:", pow_ok)
    if not pow_ok:
        # show some diagnostics: show first 64 bits of binary prefix and the needed zeros
        b = hex_to_binary(recomputed_hash)
        print("binary prefix (first 64 bits):", b[:64])
        print("required leading zeros:", difficulty)
        print("actual leading zero count:", len(b) - len(b.lstrip("0")))
        # also show numeric distance from target (informative)
        h_int = int(recomputed_hash, 16)
        max_target = 2**(len(recomputed_hash)*4) - 1
        # approximate ratio
        print("hash int (high bits):", hex(h_int)[:18])
        print("note: if recomputed_hash != submitted_hash the miner likely used a different preimage/merkle.")
    else:
        print("PoW OK for recomputed hash.")

    # 4) Compare submitted_hash itself against node's binary test (in case miner set hash but different preimage)
    submitted_pow_ok = hex_to_binary(submitted_hash)[: difficulty] == "0" * difficulty
    print("\nPoW check against submitted_hash field (not recomputed):", submitted_pow_ok)
    if not submitted_pow_ok:
        print("-> submitted hash does NOT meet node's binary-leading-zero requirement.")

    # 5) Recompute alternative candidate header variants similar to node's 'variants_checked_example'
    print("\nRecomputing common header variants (json_single/json_double + parent hexcat/bytescat leaves):")
    # build canonical leaves (json leaf sha)
    leaves_json = [leaf_hex_sha256_json(tx) for tx in data]
    # parent variations
    vlist = []
    vlist.append(("parent_hexcat", build_merkle_from_leaves(leaves_json, parent_hexcat)))
    try:
        vlist.append(("parent_bytescat", build_merkle_from_leaves(leaves_json, parent_bytescat)))
    except Exception as e:
        vlist.append(("parent_bytescat", f"error: {e}"))
    for name, mval in vlist:
        # try both json_single-like arrangements (but easiest is to show header_json possibilities)
        # candidate header JSON arrays used by miner variants are not precisely defined here; show candidate recomputed crypto_hash for this merkle
        if isinstance(mval, str) and not mval.startswith("error"):
            h = crypto_hash(network_id, ts, last_hash, data, difficulty, nonce, mval)
            print(f"  merkle variant {name}: {mval} -> crypto_hash: {h}  pow_ok={hex_to_binary(h)[:difficulty] == '0'*difficulty}")
        else:
            print("  merkle variant", name, " -> ", mval)

    print("\nDone. Summary recommendations:")
    if recomputed_merkle != merkle_submitted:
        print("  * The node computed a different merkle root from your 'merkle' field. Make miner compute merkle = merkle_root(data) immediately before submit.")
    if recomputed_hash != submitted_hash:
        print("  * The miner's submitted 'hash' was not the node's crypto_hash preimage. Ensure miner uses crypto_hash(NETWORK_ID, timestamp, last_hash, data, difficulty, nonce, merkle).")
    if not pow_ok:
        print("  * The recomputed hash does not meet the binary-leading-zero PoW requirement. Continue searching nonces or confirm difficulty calculation is correct.")
    if recomputed_merkle == merkle_submitted and recomputed_hash == submitted_hash and pow_ok:
        print("  * If all three checks pass locally, it's likely a timing/fork issue (tip changed) or node expects a slightly different variant — but this is unlikely now.")
    print("\nNode response full dump (for reference):")
    pprint(node_rsp)
    print("\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python diagnose_rejected.py <path-to-rejected_block.json> [network_id]")
        print("Example: python diagnose_rejected.py \"./block data/rejected_block_1759653250208.json\" devnet-001")
        sys.exit(1)
    path = sys.argv[1]
    nid = sys.argv[2] if len(sys.argv) >= 3 else "devnet-001"
    check_candidate(path, network_id=nid)
