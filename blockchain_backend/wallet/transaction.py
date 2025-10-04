# wallet/transaction.py
import time
import uuid
from typing import Optional, Dict, Any, List

from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import MINING_REWARD_INPUT


class Asset:
    """Represents an asset that can be transferred or sold."""
    def __init__(self, asset_id: str, owner: str, price: int = 0, currency: str = "COIN", transferable: bool = True):
        self.asset_id = asset_id
        self.owner = owner
        self.price = int(price)
        self.currency = currency
        self.transferable = bool(transferable)

    def set_price(self, price: int, currency: Optional[str] = None):
        self.price = int(price)
        if currency:
            self.currency = currency

    def set_transferable(self, flag: bool):
        self.transferable = bool(flag)

    def __repr__(self):
        return f"<Asset {self.asset_id} owner={self.owner} price={self.price} {self.currency} transferable={self.transferable}>"


class Transaction:
    """Transaction supporting multi-currency and asset transfers.

    Invariants for non-reward tx:
      - input["balances"] lists ONLY the currencies the sender is spending (pre-spend amounts).
      - output maps amounts ONLY for those currencies. Other currencies must not appear in outputs.
      - For each currency c in input["balances"], sum(output[*][c]) == input["balances"][c].
    """

    def __init__(
        self,
        sender_wallet: Optional[Wallet] = None,
        recipient: Optional[str] = None,
        amount_map: Optional[Dict[str, int]] = None,
        asset_ids: Optional[List[str]] = None,
        id: Optional[str] = None,
        output: Optional[Dict[str, Dict[str, int]]] = None,
        input: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.id = id or str(uuid.uuid4())[:8]
        self.metadata: Dict[str, Any] = dict(metadata or {})
        self.output: Dict[str, Dict[str, int]] = dict(output or {})
        self.input: Dict[str, Any] = dict(input or {})

        # If constructed with a sender wallet, synthesize outputs + input signature
        if sender_wallet:
            self._create_transaction(sender_wallet, recipient, amount_map or {}, asset_ids or [])

    # ---------------------------
    # Core transaction creation
    # ---------------------------
    def _create_transaction(
        self,
        sender_wallet: Wallet,
        recipient: Optional[str],
        amount_map: Dict[str, int],
        asset_ids: List[str]
    ):
        """
        Creates currency outputs and input signature.

        amount_map: dict[currency] = amount to send to recipient
        Outputs:
          - recipient gets {spent currencies}
          - sender gets change per spent currency: sender_balance[c] - amount_map[c] (can be zero)
        """
        if not recipient and amount_map:
            raise Exception("Recipient is required when sending currency")

        # --- Validate funds & normalize (only spent currencies) ---
        spent_map: Dict[str, int] = {}
        for currency, amt in amount_map.items():
            amt = int(amt)
            if amt < 0:
                raise Exception(f"Negative spend not allowed for {currency}")
            if sender_wallet.balances.get(currency, 0) < amt:
                raise Exception(
                    f"Insufficient funds for {currency}: "
                    f"{amt} > {sender_wallet.balances.get(currency, 0)}"
                )
            if amt > 0:
                spent_map[currency] = amt

        # Build outputs only for spent currencies
        outputs: Dict[str, Dict[str, int]] = {}

        if spent_map:
            outputs[recipient] = dict(spent_map)

        # change back to sender for the spent currencies (include zeros to keep balances deterministic)
        change: Dict[str, int] = {}
        for currency, amt in spent_map.items():
            sender_amt = int(sender_wallet.balances.get(currency, 0))
            remaining = sender_amt - int(amt)
            if remaining < 0:
                raise Exception(f"Internal error: negative change for {currency}")
            change[currency] = remaining
        if change:
            outputs[sender_wallet.address] = change

        self.output = outputs

        # NOTE: We intentionally do NOT write asset metadata here.
        # Asset metadata is provided by higher-level helpers (purchase/list/transfer) to avoid conflicts.

        # --- Create input with snapshot for spent currencies only ---
        spent_snapshot = {c: int(sender_wallet.balances[c]) for c in spent_map}
        self.input = {
            "timestamp": time.time_ns(),
            "balances": spent_snapshot,     # ONLY currencies being spent
            "address": sender_wallet.address,
            "public_key": sender_wallet.public_key,
            "signature": sender_wallet.sign(self.output),
        }

    # ---------------------------
    # Asset operations
    # ---------------------------
    @staticmethod
    def list_asset_for_sale(owner_wallet: Wallet, asset: Asset, price: int, currency="COIN", metadata=None):
        """Zero-sum metadata-only tx: no currency moves, just a signed intent."""
        if asset.owner != owner_wallet.address:
            raise Exception("Only the asset owner may list it for sale")
        asset.set_price(price, currency)

        meta = dict(metadata or {})
        meta["asset_listing"] = {"asset_id": asset.asset_id, "price": int(price), "currency": currency}

        output: Dict[str, Dict[str, int]] = {}
        return Transaction(
            output=output,
            input={
                "timestamp": time.time_ns(),
                "balances": {},  # zero-sum
                "address": owner_wallet.address,
                "public_key": owner_wallet.public_key,
                "signature": owner_wallet.sign(output),
            },
            metadata=meta
        )

    @staticmethod
    def cancel_listing(owner_wallet: Wallet, asset: Asset, metadata=None):
        """Zero-sum metadata-only tx: cancel a listing, no currency moves."""
        if asset.owner != owner_wallet.address:
            raise Exception("Only the asset owner can cancel listing")
        asset.set_price(0)

        meta = dict(metadata or {})
        meta["asset_listing_cancel"] = {"asset_id": asset.asset_id}

        output: Dict[str, Dict[str, int]] = {}
        return Transaction(
            output=output,
            input={
                "timestamp": time.time_ns(),
                "balances": {},  # zero-sum
                "address": owner_wallet.address,
                "public_key": owner_wallet.public_key,
                "signature": owner_wallet.sign(output),
            },
            metadata=meta
        )

    @staticmethod
    def purchase_asset(buyer_wallet: Wallet, asset: Asset, get_owner_wallet_fn, metadata=None):
        """Buyer spends {currency: price}; seller receives; buyer gets change; ownership transfers."""
        seller_address = asset.owner
        if seller_address == buyer_wallet.address:
            raise Exception("Buyer already owns asset")

        price, currency = int(asset.price), asset.currency
        if price <= 0:
            raise Exception("Asset is not listed for sale")

        if buyer_wallet.balances.get(currency, 0) < price:
            raise Exception("Insufficient funds")

        seller_wallet = get_owner_wallet_fn(seller_address)
        if not seller_wallet:
            raise Exception("Seller wallet not found")

        # Use the core path to ensure consistent input/output structure and validation
        tx = Transaction(
            sender_wallet=buyer_wallet,
            recipient=seller_address,
            amount_map={currency: price},
        )

        # Attach canonical purchase metadata (single dict)
        meta = dict(metadata or {})
        meta["asset_purchase"] = {
            "asset_id": asset.asset_id,
            "price": price,
            "currency": currency,
            "from": seller_address,
            "to": buyer_wallet.address
        }
        tx.metadata = meta

        # Side-effect: update asset ownership (domain action outside the ledger)
        asset.owner = buyer_wallet.address
        return tx

    @staticmethod
    def transfer_asset_direct(sender_wallet: Wallet, recipient_address: str, asset: Asset, metadata=None):
        """
        Zero-sum asset transfer (no currency). Authenticates ownership transfer via signature.
        """
        if asset.owner != sender_wallet.address:
            raise Exception("Only the current owner can transfer this asset")

        output: Dict[str, Dict[str, int]] = {}  # zero-sum; we only record metadata + signature
        tx = Transaction(
            output=output,
            input={
                "timestamp": time.time_ns(),
                "balances": {},  # zero-sum
                "address": sender_wallet.address,
                "public_key": sender_wallet.public_key,
                "signature": sender_wallet.sign(output)
            },
            metadata=dict(metadata or {})
        )
        tx.metadata["asset_transfer"] = {
            "asset_id": asset.asset_id,
            "from": sender_wallet.address,
            "to": recipient_address
        }

        asset.owner = recipient_address
        return tx

    # ---------------------------
    # Reward transaction
    # ---------------------------
    @staticmethod
    def reward_transaction(miner_wallet: Wallet, currency: str, amount: int, metadata=None):
        """Mint new currency to miner. Special-cased by validator."""
        amount = int(amount)
        if amount <= 0:
            raise Exception("Reward amount must be positive")

        # Only the minted currency should appear in outputs for rewards
        output = {miner_wallet.address: {currency: amount}}
        return Transaction(input=MINING_REWARD_INPUT, output=output, metadata=metadata)

    # ---------------------------
    # Serialization + Validation
    # ---------------------------
    def to_json(self):
        return {"id": self.id, "input": self.input, "output": self.output, "metadata": self.metadata}

    @staticmethod
    def from_json(data):
        return Transaction(**data)

    @staticmethod
    def _sum_output_for_currency(tx_output: Dict[str, Dict[str, int]], currency: str) -> int:
        total = 0
        for addr_map in tx_output.values():
            total += int(addr_map.get(currency, 0))
        return total

    @staticmethod
    def _has_negative_amounts(tx_output: Dict[str, Dict[str, int]]) -> bool:
        for addr_map in tx_output.values():
            for amt in addr_map.values():
                if int(amt) < 0:
                    return True
        return False

    @staticmethod
    def is_valid_transaction(transaction, resolve_asset_fn=None):
        tx_input, tx_output = transaction.input, transaction.output

        # Rewards: allow minting of new currency; must match the special input type
        if tx_input == MINING_REWARD_INPUT:
            if Transaction._has_negative_amounts(tx_output):
                raise Exception("Negative amount in reward output")
            # keep reward flexible (multiple currencies/addresses if you want later)
            return

        # Standard tx validation
        required = ["timestamp", "address", "public_key", "signature", "balances"]
        for f in required:
            if f not in tx_input:
                raise Exception(f"Transaction input missing {f}")

        # Signature authenticity
        if not Wallet.verify(tx_input["public_key"], tx_output, tx_input["signature"]):
            raise Exception("Invalid signature")

        # No negative outputs
        if Transaction._has_negative_amounts(tx_output):
            raise Exception("Negative amount in outputs")

        input_balances: Dict[str, int] = {c: int(v) for c, v in (tx_input.get("balances") or {}).items()}

        # Zero-sum metadata transactions are allowed (e.g., listings, transfers without currency)
        if not input_balances:
            has_any_amount = any(int(v) for addr_map in tx_output.values() for v in addr_map.values())
            if has_any_amount:
                raise Exception("Zero-sum transaction has non-zero outputs")
        else:
            # Per-currency conservation for currencies being spent
            for currency, input_total in input_balances.items():
                output_total = Transaction._sum_output_for_currency(tx_output, currency)
                if input_total != output_total:
                    raise Exception(f"Currency mismatch for {currency}: in={input_total}, out={output_total}")

            # Ensure outputs do not introduce currencies not listed in input (no side-channel minting)
            output_currencies = set()
            for addr_map in tx_output.values():
                output_currencies.update(addr_map.keys())
            extra = output_currencies.difference(input_balances.keys())
            if extra:
                raise Exception(f"Unexpected currencies in outputs: {sorted(extra)}")

        # --- Asset validation (optional hook) ---
        if transaction.metadata:
            if "asset_purchase" in transaction.metadata:
                info = transaction.metadata["asset_purchase"]
                if isinstance(info, list):
                    infos = info
                else:
                    infos = [info]
                for it in infos:
                    for key in ("asset_id", "from", "to"):
                        if key not in it:
                            raise Exception("Invalid asset_purchase metadata")
                    if resolve_asset_fn:
                        asset = resolve_asset_fn(it["asset_id"])
                        if not asset:
                            raise Exception("Asset not found")
                        if asset.owner != it.get("from"):
                            raise Exception("Asset owner mismatch during validation")

            if "asset_transfer" in transaction.metadata:
                info = transaction.metadata["asset_transfer"]
                for key in ("asset_id", "from", "to"):
                    if key not in info:
                        raise Exception("Invalid asset_transfer metadata")
                if resolve_asset_fn:
                    asset = resolve_asset_fn(info["asset_id"])
                    if not asset:
                        raise Exception("Asset not found")
                    if asset.owner != info.get("from"):
                        raise Exception("Asset owner mismatch during transfer")
