# blockchain_backend/app/__main__.py
import os
import time
import requests
import logging
from blockchain_backend.core.block import Block
from blockchain_backend.core.blockchain import Blockchain

# Import the Flask app + shared globals from your package
from . import app, blockchain, peers

try:
    from . import ROOT_HOST, ROOT_PORT  # optional, fallback to env
except Exception:
    ROOT_HOST, ROOT_PORT = None, None


def get_root_base() -> str:
    """Build URL for root node (service name in Docker)."""
    host = os.getenv("ROOT_HOST", ROOT_HOST or "node0")
    port = int(os.getenv("ROOT_PORT", ROOT_PORT or 5000))
    return f"http://{host}:{port}"


def wait_for_root_ready(max_wait_s: int = 60, interval_s: float = 2.0) -> None:
    """Poll root /health until ready:true or timeout."""
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


def startup_sync_if_peer() -> None:
    """If PEER=True, sync chain from root node."""
    if os.getenv("PEER", "").lower() != "true":
        print("[ROOT] Booting root node; first block already mined")
        return

    base = get_root_base()
    print(f"[PEER] Attempting initial sync from {base}")

    wait_for_root_ready(max_wait_s=120, interval_s=2)

    try:
        resp = requests.get(f"{base}/blockchain", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        if hasattr(Blockchain, "from_json"):
            remote_bc = Blockchain.from_json(data)
            incoming_chain = remote_bc.chain
        else:
            incoming_chain = [Block.from_json(b) for b in data]

        blockchain.replace_chain(incoming_chain)
        peers.add(base)

        print(f"[PEER] Initial sync complete. Height: {len(blockchain.chain)}")
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
