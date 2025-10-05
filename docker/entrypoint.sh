#!/usr/bin/env bash
set -euo pipefail

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
