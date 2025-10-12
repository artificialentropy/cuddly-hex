#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] starting web app (gunicorn)..."
  exec gunicorn -b 0.0.0.0:5000 blockchain_backend.app:app \
    --workers="${WORKERS:-2}" \
    --threads="${THREADS:-4}" \
    --timeout="${TIMEOUT:-120}" \
    --graceful-timeout=30 \
    --keep-alive=5