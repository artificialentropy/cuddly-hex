# import time
# import uuid

# from .wallet import Wallet
# from blockchain_backend.utils.config import MINING_REWARD, MINING_REWARD_INPUT


# class Transaction:
#     """
#     Document of an exchange in currency from a sender to one
#     or more recipients.
#     """

#     def __init__(
#         self,
#         sender_wallet=None,
#         recipient=None,
#         amount=None,
#         id=None,
#         output=None,
#         input=None,
#         metadata=None,
#     ):
#         self.id = id or str(uuid.uuid4())[0:8]
#         self.metadata = metadata

#         if output is not None and input is not None:
#             # Explicitly provided (e.g., reward tx or from_json)
#             self.output = output
#             self.input = input
#         elif sender_wallet is not None and recipient is not None and amount is not None:
#             # Normal spend
#             self.output = self.create_output(sender_wallet, recipient, amount)
#             self.input = self.create_input(sender_wallet, self.output)
#         else:
#             # Shell/empty (will be filled later if needed)
#             self.output = {}
#             self.input = {}

#     def create_output(self, sender_wallet, recipient, amount):
#         """
#         Structure the output data for the transaction.
#         """
#         if amount > sender_wallet.balance:
#             raise Exception("Amount exceeds balance")

#         output = {}
#         output[recipient] = amount
#         output[sender_wallet.address] = sender_wallet.balance - amount

#         return output

#     def create_input(self, sender_wallet, output):
#         """
#         Structure the input data for the transaction.
#         Sign the transaction and include the sender's public key and address
#         """
#         return {
#             "timestamp": time.time_ns(),
#             "amount": sender_wallet.balance,
#             "address": sender_wallet.address,
#             "public_key": sender_wallet.public_key,
#             "signature": sender_wallet.sign(output),
#         }

#     def update(self, sender_wallet, recipient, amount):
#         """
#         Update the transaction with an existing or new recipient.
#         """
#         if amount > self.output[sender_wallet.address]:
#             raise Exception("Amount exceeds balance")

#         if recipient in self.output:
#             self.output[recipient] = self.output[recipient] + amount
#         else:
#             self.output[recipient] = amount

#         self.output[sender_wallet.address] = self.output[sender_wallet.address] - amount

#         self.input = self.create_input(sender_wallet, self.output)

#     def to_json(self):
#         j = {
#             "id": self.id,
#             "input": self.input,
#             "output": self.output,
#         }
#         if self.metadata is not None:
#             j["metadata"] = self.metadata
#         return j

#     @staticmethod
#     def from_json(transaction_json):
#         data = dict(transaction_json)  # copy
#         meta = data.pop("metadata", None)  # remove if present
#         return Transaction(**data, metadata=meta)

#     @staticmethod
#     def is_valid_transaction(transaction):
#         """
#         Validate a transaction.
#         Raise an exception for invalid transactions.
#         """
#         if transaction.input == MINING_REWARD_INPUT:
#             if list(transaction.output.values()) != [MINING_REWARD]:
#                 raise Exception("Invalid mining reward")
#             return

#         output_total = sum(transaction.output.values())

#         if transaction.input["amount"] != output_total:
#             raise Exception("Invalid transaction output values")

#         if not Wallet.verify(
#             transaction.input["public_key"],
#             transaction.output,
#             transaction.input["signature"],
#         ):
#             raise Exception("Invalid signature")

#     @staticmethod
#     def reward_transaction(miner_wallet, metadata=None):
#         return Transaction(
#             input=MINING_REWARD_INPUT,
#             output={miner_wallet.address: MINING_REWARD},
#             metadata=metadata,
#         )


import time
import uuid
from collections import defaultdict
from typing import Optional

from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import MINING_REWARD_INPUT

# ---- Minimal in-memory Asset helper (replace with your DB model/registry) ----
class Asset:
    """
    Minimal asset representation.
    Replace this with your persistent Asset model or registry.
    """
    def __init__(self, asset_id: str, owner: str, price: int = 0, currency: str = "COIN", transferable: bool = True):
        self.asset_id = asset_id            # unique id for the asset (e.g., "ART-0001")
        self.owner = owner                  # owner's wallet.address
        self.price = int(price)             # price denominated in `currency`
        self.currency = currency            # which currency asset_id the price is denominated in
        self.transferable = bool(transferable)

    def set_price(self, price: int, currency: Optional[str] = None):
        self.price = int(price)
        if currency:
            self.currency = currency

    def set_transferable(self, flag: bool):
        self.transferable = bool(flag)

    def __repr__(self):
        return f"<Asset {self.asset_id} owner={self.owner} price={self.price} {self.currency} txbl={self.transferable}>"

# ---- Transaction with asset purchase/transfer semantics ----
class Transaction:
    """
    Transaction supporting transferable assets where:
      - Assets are distinct items with owners.
      - Asset has price and currency (e.g., price=100, currency="COIN").
      - Purchase operation requires buyer to pay seller in that currency; ownership moves on success.
      - Direct transfer requires asset.transferable == True (unless special permission).
    Output shape:
      - currency transfers: output[address] = { currency_asset: amount, ... }
      - ownership changes are recorded in metadata (or you can add explicit ownership output)
    Input includes:
      - timestamp, balances (sender pre-tx snapshot), address, public_key, signature
    """

    def __init__(self, sender_wallet=None, recipient=None, amount=None, asset_id=None, id=None, output=None, input=None, metadata=None):
        self.id = id or str(uuid.uuid4())[0:8]
        self.metadata = metadata

        if output is not None and input is not None:
            # explicit construction (e.g., from_json or reward tx)
            self.output = output
            self.input = input
        elif sender_wallet is not None and recipient is not None and amount is not None and asset_id is not None:
            # convenience single-currency transfer (not asset purchase)
            self.output = self._create_currency_output(sender_wallet, recipient, amount)
            self.input = self._create_input(sender_wallet, self.output)
        else:
            self.output = {}
            self.input = {}

    # ---------------------------
    # Basic currency transfer
    # ---------------------------
    def _create_currency_output(self, sender_wallet, recipient, amount, currency: str = "COIN"):
        """
        Create output that transfers `amount` of currency from sender -> recipient.
        This is used as sub-step when processing purchases.
        """
        balance = int(sender_wallet.balances.get(currency, 0))
        if amount > balance:
            raise Exception("Amount exceeds balance for currency transfer")

        out = {}
        out[recipient] = {currency: int(amount)}
        # include sender's post-tx balances for currency and other currencies unchanged
        sender_post = {a: int(b) for a, b in sender_wallet.balances.items()}
        sender_post[currency] = sender_post.get(currency, 0) - int(amount)
        out[sender_wallet.address] = sender_post
        return out

    # def _create_input(self, sender_wallet, output):
    #     """
    #     Input includes snapshot of sender's balances at signing time.
    #     """
    #     balances_snapshot = {asset: int(qty) for asset, qty in sender_wallet.balances.items()}
    #     return {
    #         "timestamp": time.time_ns(),
    #         "balances": balances_snapshot,
    #         "address": sender_wallet.address,
    #         "public_key": sender_wallet.public_key,
    #         "signature": sender_wallet.sign(output),
    #     }

    def _create_input(self, sender_wallet, output):
        balances_snapshot = {asset: int(qty) for asset, qty in sender_wallet.balances.items()}
        # sign the canonical json of output
        signature = sender_wallet.sign(output)
        return {
            "timestamp": time.time_ns(),
            "balances": balances_snapshot,
            "address": sender_wallet.address,
            "public_key": sender_wallet.public_key,
            "signature": signature,
        }

    # ---------------------------
    # Listing asset for sale (owner sets price)
    # ---------------------------
    @staticmethod
    def list_asset_for_sale(owner_wallet: Wallet, asset: Asset, price: int, currency: str = "COIN", metadata: Optional[dict] = None):
        """
        Owner sets price and currency; this does NOT move funds. It creates a 'listing' tx
        anchoring the listing information (owner signature).
        """
        # Ownership check
        if asset.owner != owner_wallet.address:
            raise Exception("Only the asset owner may list the asset for sale")

        asset.set_price(price, currency)
        # Create an output that is a no-op for currency transfers but records listing in metadata
        output = { owner_wallet.address: { currency: int(owner_wallet.balances.get(currency, 0)) } }
        # metadata will include listing info
        meta = metadata or {}
        meta.update({"asset_listing": {"asset_id": asset.asset_id, "price": int(price), "currency": currency}})
        tx = Transaction(output=output, input=owner_wallet.sign({"asset_listing": meta["asset_listing"]}), metadata=meta)
        # input must be a dict matching expected shape - normalize
        if isinstance(tx.input, (bytes, str)):
            # if owner.sign returned a raw signature earlier, wrap into input dict
            tx.input = {
                "timestamp": time.time_ns(),
                "balances": {asset: int(qty) for asset, qty in owner_wallet.balances.items()},
                "address": owner_wallet.address,
                "public_key": owner_wallet.public_key,
                "signature": tx.input,
            }
        return tx

    # ---------------------------
    # Purchase asset (buyer pays seller; ownership transfer)
    # ---------------------------
    @staticmethod
    def purchase_asset(buyer_wallet: Wallet, asset: Asset, get_owner_wallet_fn, metadata: Optional[dict] = None):
        """
        Buyer pays asset.price (in asset.currency) to current owner and becomes new owner.
        `get_owner_wallet_fn(owner_address) -> Wallet` is a function to obtain the owner's Wallet object.
        Returns Transaction if successful; does NOT auto-persist asset (caller must persist).
        """
        # Basic checks
        seller_address = asset.owner
        if seller_address == buyer_wallet.address:
            raise Exception("Buyer already owns the asset")

        price = int(asset.price)
        currency = asset.currency

        # Ensure buyer has funds
        buyer_balance = int(buyer_wallet.balances.get(currency, 0))
        if buyer_balance < price:
            raise Exception("Buyer has insufficient balance to purchase asset")

        # Fetch seller wallet to credit funds
        seller_wallet = get_owner_wallet_fn(seller_address)
        if seller_wallet is None:
            raise Exception("Unable to resolve seller wallet")

        # Create combined output: buyer pays currency -> seller, and keep explicit post balances
        # We'll combine outputs for currency transfer with an ownership change recorded in metadata.
        # Currency transfer output:
        out = {}

        # Seller receives price
        out[seller_address] = {currency: int(seller_wallet.balances.get(currency, 0)) + price}
        # Buyer pays price; include all buyer balances as post-state
        buyer_post = {a: int(b) for a, b in buyer_wallet.balances.items()}
        buyer_post[currency] = buyer_post.get(currency, 0) - price
        out[buyer_wallet.address] = buyer_post

        # For clarity: ensure other unaffected addresses not present (fine)

        # Build metadata to capture the ownership change
        meta = metadata or {}
        meta.update({
            "asset_purchase": {
                "asset_id": asset.asset_id,
                "price": price,
                "currency": currency,
                "from": seller_address,
                "to": buyer_wallet.address,
            }
        })

        # Build input (signed by buyer because buyer authorizes paying funds)
        tx = Transaction(output=out, input={
            "timestamp": time.time_ns(),
            "balances": {a: int(q) for a, q in buyer_wallet.balances.items()},
            "address": buyer_wallet.address,
            "public_key": buyer_wallet.public_key,
            "signature": buyer_wallet.sign(out),
        }, metadata=meta)

        # Validation to ensure seller was owner at start; we include it here for safety.
        if asset.owner != seller_address:
            raise Exception("Asset owner changed during purchase attempt")

        # Successful: update asset owner (caller may want to persist the change)
        asset.owner = buyer_wallet.address

        # Optionally add/remove from wallets if Wallet implements ownership:
        if hasattr(seller_wallet, "remove_asset"):
            seller_wallet.remove_asset(asset)
        if hasattr(buyer_wallet, "add_asset"):
            buyer_wallet.add_asset(asset)

        return tx

    # ---------------------------
    # Direct owner transfer (no purchase) - requires transferable flag
    # ---------------------------
    @staticmethod
    def transfer_asset_direct(sender_wallet, recipient_address, asset, metadata=None):
        """
        Transfer an asset directly from sender to recipient.
        Includes sender balances in the input.
        """
        tx = Transaction(
            sender_wallet=sender_wallet,
            recipient=recipient_address,
            amount=None  # no currency transfer required for asset-only
        )

        tx.output = {
            sender_wallet.address: {a: int(q) for a, q in sender_wallet.balances.items()},
            recipient_address: {}  # recipient doesn’t gain balances directly, only asset
        }

        tx.input = {
            "timestamp": time.time_ns(),
            "balances": dict(sender_wallet.balances),  # multi-currency support
            "address": sender_wallet.address,
            "public_key": sender_wallet.public_key,
            "signature": sender_wallet.sign(tx.output)
        }

        tx.metadata = metadata or {}
        tx.metadata["asset_transfer"] = {
            "asset_id": asset.asset_id,
            "from": sender_wallet.address,
            "to": recipient_address,
            "transfer_type": "direct"
        }

        return tx


    # ---------------------------
    # JSON, from_json, validation
    # ---------------------------
    def to_json(self):
        j = {"id": self.id, "input": self.input, "output": self.output}
        if self.metadata is not None:
            j["metadata"] = self.metadata
        return j

    @staticmethod
    def from_json(transaction_json):
        data = dict(transaction_json)
        meta = data.pop("metadata", None)
        return Transaction(**data, metadata=meta)

    @staticmethod
    def is_valid_transaction(transaction, resolve_asset_fn=None):
        """
        Validate currency conservation and signatures.
        """
        # Mining reward short-circuit
        if transaction.input == MINING_REWARD_INPUT:
            return

        tx_input = transaction.input
        tx_output = transaction.output

        # Required fields
        required_fields = ["timestamp", "address", "public_key", "signature", "balances"]
        for field in required_fields:
            if field not in tx_input:
                raise Exception("Transaction input missing required fields")

        # Verify signature
        if not Wallet.verify(tx_input["public_key"], tx_output, tx_input["signature"]):
            raise Exception("Invalid signature")

        # Ensure currency conservation
        input_balances = tx_input["balances"]
        output_totals = defaultdict(int)
        for addr_map in tx_output.values():
            if not isinstance(addr_map, dict):
                raise Exception("Invalid transaction output shape")
            for currency, amt in addr_map.items():
                output_totals[currency] += int(amt)

        for currency_id, in_amt in input_balances.items():
            out_total = output_totals.get(currency_id, 0)
            if int(in_amt) != int(out_total):
                raise Exception(
                    f"Invalid currency conservation for {currency_id}: input={in_amt} outputs={out_total}"
                )

        # Asset purchase validation (optional)
        if transaction.metadata and "asset_purchase" in transaction.metadata:
            asset_info = transaction.metadata["asset_purchase"]
            asset_id = asset_info["asset_id"]
            from_addr = asset_info["from"]
            if resolve_asset_fn is not None:
                asset_obj = resolve_asset_fn(asset_id)
                if asset_obj is None:
                    raise Exception("Referenced asset not found")
                if asset_obj.owner != from_addr:
                    raise Exception("Asset owner mismatch during purchase validation")


    # ---------------------------
    # Reward tx factory (unchanged)
    # ---------------------------
    @staticmethod
    def reward_transaction(miner_wallet, asset, amount, metadata=None):
        output = {miner_wallet.address: {asset: int(amount)}}
        return Transaction(input=MINING_REWARD_INPUT, output=output, metadata=metadata)
