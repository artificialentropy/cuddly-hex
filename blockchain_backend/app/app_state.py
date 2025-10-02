
from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.wallet.wallet import Wallet  # this is okay; doesn't import config

ASSETS: dict[str, Asset] = {}    # asset_id -> Asset
PEERS:  dict[str, "Wallet"] = {} # address -> Wallet

def resolve_asset_fn(asset_id: str):
    return ASSETS.get(asset_id)
