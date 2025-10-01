# blockchain_backend/app/__main__.py
import os
import time
import requests

from blockchain_backend.core.block import Block
from blockchain_backend.core.blockchain import Blockchain

# Import the Flask app + shared globals from your package module
# (these are defined in blockchain_backend/app/__init__.py)
from . import app, blockchain, peers

# Optional: if you expose ROOT_HOST/ROOT_PORT in __init__.py, import them;
# otherwise we read from env directly in get_root_base().
try:
    from . import ROOT_HOST, ROOT_PORT  # type: ignore
except Exception:
    ROOT_HOST, ROOT_PORT = None, None


def get_root_base() -> str:
    """Build the URL for the root node (service name in Docker)."""
    host = os.getenv("ROOT_HOST", ROOT_HOST or "node0")
    port = int(os.getenv("ROOT_PORT", ROOT_PORT or 5000))
    return f"http://{host}:{port}"


def wait_for_root_ready(max_wait_s: int = 60, interval_s: float = 2.0) -> None:
    """
    Poll root /health until it reports ready:true (height > 1),
    or timeout. This prevents syncing a half-initialized chain.
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
                    print(f"[PEER] Root is ready at {base} (height={j.get('height')})")
                    return
                else:
                    print(
                        f"[PEER] Root not ready yet (height={j.get('height')}); retrying..."
                    )
            else:
                print(f"[PEER] /health HTTP {r.status_code}; retrying...")
        except Exception as e:
            last_err = e
            print(f"[PEER] Waiting for root /health failed: {e}; retrying...")
        time.sleep(interval_s)

    if last_err:
        print(
            f"[PEER] Gave up waiting for root readiness after {max_wait_s}s: {last_err}"
        )
    else:
        print(f"[PEER] Gave up waiting for root readiness after {max_wait_s}s")


def startup_sync_if_peer() -> None:
    """If this container is a PEER=True node, sync its chain from the root."""
    if os.getenv("PEER", "").lower() != "true":
        print(
            "[ROOT] Booting root node; first block already mined by script_blockchain_init"
        )
        return

    base = get_root_base()
    print(f"[PEER] Attempting initial sync from {base}")

    # Wait until root has mined the first block (height > 1).
    wait_for_root_ready(max_wait_s=120, interval_s=2)

    # Pull chain from root and replace locally (validate as Blocks).
    try:
        resp = requests.get(f"{base}/blockchain", timeout=5)
        resp.raise_for_status()
        data = resp.json()

        # Prefer classmethod if present; otherwise reconstruct Blocks.
        if hasattr(Blockchain, "from_json"):
            remote_bc = Blockchain.from_json(data)
            incoming_chain = remote_bc.chain
        else:
            incoming_chain = [Block.from_json(b) for b in data]

        # Replace local chain (your replace_chain should validate length + hashes).
        blockchain.replace_chain(incoming_chain)

        # Add root to peers so notify_peers_to_sync() has a target.
        peers.add(base)

        print(f"[PEER] Initial sync complete. Height: {len(blockchain.chain)}")
    except Exception as e:
        print(f"[Startup] Initial sync failed: {e}")


def main() -> None:
    try:
        startup_sync_if_peer()
    except Exception as e:
        # Keep the server running even if sync failed; routes like /blockchain can auto-sync on read.
        print(f"[Startup] Uncaught error during peer sync: {e}")

    # Fixed internal port; docker-compose maps host ports.
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
