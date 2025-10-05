import hashlib, json

def _h(x: bytes) -> bytes: return hashlib.sha256(x).digest()
def _leaf(tx_json) -> bytes:
    return _h(json.dumps(tx_json, sort_keys=True, separators=(",",":")).encode())

def merkle_root(txs_json) -> str:
    if not txs_json: return _h(b"").hex()
    level = [ _leaf(t) for t in txs_json ]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [ _h(level[i] + level[i+1]) for i in range(0, len(level), 2) ]
    return level[0].hex()
