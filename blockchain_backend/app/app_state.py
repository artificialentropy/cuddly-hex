# blockchain_backend/app/app_state.py
from __future__ import annotations
from typing import Dict, Any, List
from blockchain_backend.core.block import Block
from blockchain_backend.wallet.transaction import Transaction, Asset
from blockchain_backend.wallet.transaction import Asset
from blockchain_backend.wallet.wallet import Wallet

ASSETS: dict[str, Asset] = {}
PEERS: dict[str, Wallet] = {}      # address -> Wallet (used for purchases)
PEER_URLS: set[str] = set()        # http://nodeX:5000 (network sync / listing)


def resolve_asset_fn(asset_id: str):
    return ASSETS.get(asset_id)
# blockchain_backend/app_state.py  (append these functions)



# ASSETS is expected to be the canonical in-memory map: asset_id -> Asset(...)
# If ASSETS already exists at module top, keep it. Otherwise define:
try:
    ASSETS  # type: ignore
except NameError:
    ASSETS: Dict[str, Asset] = {}

def rebuild_assets_from_chain(chain: List[Block]) -> None:
    """
    Walk the full chain and rebuild ASSETS mapping from scratch.
    Designed to be idempotent so it can be called at startup or after chain.replace_chain().
    Rules:
      - When an asset is registered / listed, create or update ASSETS[asset_id]
      - When an asset is purchased, update ASSETS[asset_id].owner to the buyer
      - When an asset is directly transferred, update owner accordingly
    This approach prefers on-chain events (order matters); it ignores ephemeral in-memory state.
    """
    global ASSETS
    ASSETS = {}

    for block in chain:
        for tx_json in getattr(block, "data", []) or []:
            # Defensive: tx_json might be dict or Transaction object
            if not isinstance(tx_json, dict):
                try:
                    tx_json = tx_json.to_json()
                except Exception:
                    continue

            metadata = tx_json.get("metadata") or {}
            # asset registration/listing
            asset_listing = metadata.get("asset_listing")
            if asset_listing and isinstance(asset_listing, dict):
                aid = str(asset_listing.get("asset_id"))
                price = int(asset_listing.get("price", 0))
                currency = asset_listing.get("currency", "COIN")
                # owner is input.address (if not present, skip)
                inp = tx_json.get("input", {}) or {}
                owner = inp.get("address") or asset_listing.get("owner")
                transferable = asset_listing.get("transferable", True)
                if aid and owner:
                    ASSETS[aid] = Asset(
                        asset_id=aid,
                        owner=owner,
                        price=price,
                        currency=currency,
                        transferable=transferable,
                    )
                continue

            # asset purchase
            asset_purchase = metadata.get("asset_purchase")
            if asset_purchase and isinstance(asset_purchase, dict):
                aid = str(asset_purchase.get("asset_id"))
                to_addr = asset_purchase.get("to") or tx_json.get("output", {}).keys()
                # prefer explicit 'to' then output recipient if single
                if isinstance(to_addr, (list, set)) or getattr(to_addr, "__iter__", False):
                    # pick explicit if provided; otherwise try infer from output map
                    if isinstance(to_addr, (list, set)):
                        to_addr = next(iter(to_addr), None)
                if aid and to_addr:
                    if aid in ASSETS:
                        ASSETS[aid].owner = to_addr
                    else:
                        # create placeholder asset (unknown price/currency)
                        ASSETS[aid] = Asset(asset_id=aid, owner=to_addr, price=0, currency="COIN", transferable=True)
                continue

            # direct transfer via metadata key 'transfer_asset' (if your tx uses that)
            asset_transfer = metadata.get("transfer_asset")
            if asset_transfer and isinstance(asset_transfer, dict):
                aid = str(asset_transfer.get("asset_id"))
                to_addr = asset_transfer.get("to")
                if aid and to_addr:
                    if aid in ASSETS:
                        ASSETS[aid].owner = to_addr
                    else:
                        ASSETS[aid] = Asset(asset_id=aid, owner=to_addr, price=0, currency="COIN", transferable=True)
                continue

    try:
        from blockchain_backend.core.node import get_store
        store = get_store()
        if store is not None:
            # convert Asset dataclass/object to simple dict
            meta = {}
            for aid, a in ASSETS.items():
                meta[aid] = {"owner": a.owner, "price": getattr(a,"price",0), "currency": getattr(a,"currency","COIN"), "transferable": getattr(a,"transferable",True)}
            store.put_meta("assets", meta)
    except Exception:
        pass

    # at end of rebuild_assets_from_chain(chain)
    try:
        from blockchain_backend.core.node import get_store
        store = get_store()
        if store is not None:
            meta = {}
            for aid, a in ASSETS.items():
                meta[aid] = {
                    "owner": getattr(a, "owner", None),
                    "price": getattr(a, "price", 0),
                    "currency": getattr(a, "currency", "COIN"),
                    "transferable": getattr(a, "transferable", True),
                }
            try:
                store.put_meta("assets", meta)
            except Exception as e:
                print("[rebuild_assets_from_chain] failed to persist assets meta:", e)
    except Exception:
        # non-fatal
        pass


    # end for blocks
