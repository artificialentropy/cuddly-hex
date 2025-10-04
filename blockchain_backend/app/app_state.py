# blockchain_backend/app/app_state.py
from __future__ import annotations

from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.wallet.wallet import Wallet

ASSETS: dict[str, Asset] = {}
PEERS: dict[str, Wallet] = {}      # address -> Wallet (used for purchases)
PEER_URLS: set[str] = set()        # http://nodeX:5000 (network sync / listing)


def resolve_asset_fn(asset_id: str):
    return ASSETS.get(asset_id)
