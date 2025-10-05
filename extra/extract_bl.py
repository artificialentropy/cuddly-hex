# extract_block.py
import sys, json
if len(sys.argv) < 2:
    print("Usage: python extract_block.py <wrapped-file.json> [out.json]")
    sys.exit(1)
fn = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else "block_inner.json"
with open(fn, "r", encoding="utf-8") as f:
    data = json.load(f)
# locate block object
if isinstance(data, dict) and "block" in data and isinstance(data["block"], dict):
    block = data["block"]
else:
    # fallback: find first nested dict with timestamp/hash
    block = None
    if isinstance(data, dict):
        for k,v in data.items():
            if isinstance(v, dict) and ("timestamp" in v or "hash" in v):
                block = v; break
    if block is None and isinstance(data, list) and data:
        if isinstance(data[0], dict) and ("timestamp" in data[0] or "hash" in data[0]):
            block = data[0]
    if block is None:
        # give up: write original
        block = data
with open(out, "w", encoding="utf-8") as f:
    json.dump(block, f, indent=2, sort_keys=True)
print("Wrote inner block to", out)
