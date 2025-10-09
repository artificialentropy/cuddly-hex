# blockchain_backend/app/__main__.py
import os
import time
import requests
import logging
from typing import Optional

from blockchain_backend.core.block import Block
from blockchain_backend.core.blockchain import Blockchain
from .app_state import PEER_URLS

def get_root_base() -> str:
    host = os.getenv("ROOT_HOST", "node0")
    port = int(os.getenv("ROOT_PORT", 5000))
    return f"http://{host}:{port}"

def wait_for_root_ready(max_wait_s: int = 60, interval_s: float = 2.0) -> None:
    """
    Poll root /health until ready:true or timeout. Logs progress.
    """
    base = get_root_base()
    deadline = time.time() + max_wait_s
    last_err = None

    while time.time() < deadline:
        try:
            r = requests.get(f"{base}/health", timeout=3)
            if r.ok:
                j = r.json()
                ready = bool(j.get("ready")) or (j.get("height", 0) > 1)
                if ready:
                    print(f"[PEER] Root ready at {base} (height={j.get('height')})")
                    return
                print(f"[PEER] Root not ready yet (height={j.get('height')}); retrying...")
            else:
                print(f"[PEER] /health HTTP {r.status_code}; retrying...")
        except Exception as e:
            last_err = e
            print(f"[PEER] Waiting for root /health failed: {e}; retrying...")
        time.sleep(interval_s)

    print(f"[PEER] Gave up waiting for root readiness after {max_wait_s}s: {last_err}")

def _get_local_base() -> Optional[str]:
    """
    Determine this node's base URL for peers to fetch it.
    Prefer env SELF_BASE, fallback to PUBNUB_UUID-based name if available.
    """
    sb = os.getenv("SELF_BASE")
    if sb:
        return sb
    # fallback: try SERVICE_HOST or PUBNUB_UUID (docker-compose service name)
    pb = os.getenv("PUBNUB_UUID")
    if pb:
        # default port used by nodes inside compose is 5000
        return f"http://{pb}:5000"
    return None

def startup_sync_if_peer() -> None:
    """
    If this process is a validator (PEER=true), attempt to sync with ROOT on startup.
    Enhanced rules:
      - If root's chain is longer than ours, replace local chain from root (existing behavior).
      - If our local chain (loaded from LevelDB) is longer than root's, request root to sync from us
        by POSTing our base URL to root's /sync_from_peer endpoint.
    """
    if os.getenv("PEER", "").lower() != "true":
        print("[ROOT] Booting root node; first block already mined")
        return

    # Lazy import to avoid circular import at module import-time
    from importlib import import_module
    apppkg = import_module("blockchain_backend.app")

    base = get_root_base()
    print(f"[PEER] Attempting initial sync from {base}")

    # Wait until root is minimally ready
    wait_for_root_ready(max_wait_s=120, interval_s=2)

    try:
        resp = requests.get(f"{base}/blockchain", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        # remote may wrap chain as {"pid":..,"length":..,"chain":[...]}
        if isinstance(data, dict) and "chain" in data:
            remote_chain_raw = data["chain"]
        else:
            remote_chain_raw = data

        sanitized = [{k: v for k, v in (b or {}).items() if k != "version"} for b in remote_chain_raw]

        # build incoming Chain objects
        if hasattr(Blockchain, "from_json"):
            try:
                remote_bc = Blockchain.from_json(sanitized)
                incoming_chain = remote_bc.chain
            except Exception:
                incoming_chain = [Block.from_json(b) for b in sanitized]
        else:
            incoming_chain = [Block.from_json(b) for b in sanitized]

        remote_len = len(incoming_chain) if incoming_chain is not None else 0
        local_len = len(getattr(apppkg, "blockchain", Blockchain()).chain)

        print(f"[PEER] remote_len={remote_len}, local_len={local_len}")

        if remote_len > local_len:
            # existing behavior: adopt the longer remote chain
            apppkg.blockchain.replace_chain(incoming_chain)
            PEER_URLS.add(base)
            print(f"[PEER] Initial sync complete. Height: {len(apppkg.blockchain.chain)}")
            return

        if local_len > remote_len:
            # Our local chain is longer: offer it to root (ask root to fetch us).
            # This avoids validators silently holding a longer chain while root remains behind.
            local_base = _get_local_base()
            if not local_base:
                print("[PEER] Local base URL unknown; cannot request root to sync from us.")
                return

            try:
                print(f"[PEER] Local chain (len={local_len}) is longer than root (len={remote_len}). "
                      f"Requesting root {base} to sync from us at {local_base} ...")
                r = requests.post(f"{base}/sync_from_peer", json={"peer_url": local_base}, timeout=5)
                if r.ok:
                    print(f"[PEER] Requested root to sync from us: {r.status_code} {r.text}")
                else:
                    print(f"[PEER] Request root to sync from us failed: {r.status_code} {r.text}")
            except Exception as e:
                print(f"[PEER] Failed to request root to sync from us: {e}")

            # In any case, add root to PEER_URLS so we keep it as peer
            PEER_URLS.add(base)
            return

        # equal length or nothing to do
        print("[PEER] No sync action required (local and remote lengths equal).")
        PEER_URLS.add(base)

    except Exception as e:
        print(f"[Startup] Initial sync failed: {e}")

def main() -> None:
    """Run node startup tasks (sync if peer)."""
    try:
        startup_sync_if_peer()
    except Exception as e:
        print(f"[Startup] Uncaught error during peer sync: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
