#!/usr/bin/env bash
set -euo pipefail

# Prevent internal helper scripts from repeatedly pinging /health
# Applications inside the container should check this env var before
# attempting local curl-based health probes.
export DISABLE_INTERNAL_HEALTH_PINGS="${DISABLE_INTERNAL_HEALTH_PINGS:-1}"

if [[ "${ROLE:-ROOT}" == "MINER" ]]; then
  echo "[entrypoint] starting miner client..."
  exec python -u /app/miner_client.py
else
  echo "[entrypoint] starting web app (gunicorn)..."
  exec gunicorn -b 0.0.0.0:5000 blockchain_backend.app:app \
    --workers="${WORKERS:-2}" \
    --threads="${THREADS:-4}" \
    --timeout="${TIMEOUT:-120}" \
    --graceful-timeout=30 \
    --keep-alive=5
fi
