#!/usr/bin/env bash
set -euo pipefail

NODE_URL="${MINER_NODE_URL:-http://node0:5000}"
REWARD="${MINER_REWARD_ADDRESS:-miner-demo-addr}"
TOKEN="${MINER_TOKEN:-secret123}"
SLEEP_SECS="${MINER_INTERVAL:-5}"
ALLOW_EMPTY="${MINER_ALLOW_EMPTY:-0}"
DEBUG_DIR="${MINER_DEBUG_DIR:-/app/block_data}"

mkdir -p "${DEBUG_DIR}"

echo "[miner] starting. node=${NODE_URL} reward=${REWARD} allow_empty=${ALLOW_EMPTY}"

# wait for node healthy (same as you had) ...
until curl -sf "${NODE_URL}/health" | grep -E '"ready": *true|"ok": *true' >/dev/null; do
  echo "[miner] waiting for node health..."
  sleep 1
done
echo "[miner] node is ready."

# call simple_miner with proper CLI args (use -u for unbuffered stdout)
exec python -u /app/simple_miner.py \
  --node "${NODE_URL}" \
  --addr "${REWARD}" \
  --token "${TOKEN}" \
  --debug-dir "${DEBUG_DIR}" \
  $( [ "${ALLOW_EMPTY}" = "1" ] && echo "--allow-empty" || true )
