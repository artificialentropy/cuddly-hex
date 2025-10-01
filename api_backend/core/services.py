import uuid
import time
from core.models import Transaction, Wallet, Asset
from collections import defaultdict

class BlockchainService:
    @staticmethod
    def create_currency_tx(sender: Wallet, recipient: Wallet, amount: int, currency="COIN"):
        if sender.balance < amount:
            raise Exception("Insufficient balance")
        sender.balance -= amount
        recipient.balance += amount
        sender.save()
        recipient.save()
        tx = Transaction.objects.create(
            tx_id=str(uuid.uuid4())[:8],
            sender=sender,
            recipient=recipient,
            amount=amount,
            metadata={"currency": currency}
        )
        return tx

    @staticmethod
    def list_asset(owner: Wallet, asset: Asset, price: int, currency="COIN"):
        if asset.owner != owner:
            raise Exception("Only owner can list asset")
        asset.price = price
        asset.currency = currency
        asset.save()
        tx = Transaction.objects.create(
            tx_id=str(uuid.uuid4())[:8],
            sender=owner,
            asset=asset,
            metadata={"action": "list", "price": price, "currency": currency}
        )
        return tx

    @staticmethod
    def purchase_asset(buyer: Wallet, asset: Asset):
        if buyer.balance < asset.price:
            raise Exception("Insufficient funds")
        seller = asset.owner
        buyer.balance -= asset.price
        seller.balance += asset.price
        asset.owner = buyer
        buyer.save()
        seller.save()
        asset.save()
        tx = Transaction.objects.create(
            tx_id=str(uuid.uuid4())[:8],
            sender=seller,
            recipient=buyer,
            asset=asset,
            amount=asset.price,
            metadata={"action": "purchase", "currency": asset.currency}
        )
        return tx

    @staticmethod
    def transfer_asset(sender: Wallet, recipient: Wallet, asset: Asset):
        if asset.owner != sender:
            raise Exception("Only owner can transfer asset")
        if not asset.transferable:
            raise Exception("Asset is non-transferable")
        asset.owner = recipient
        asset.save()
        tx = Transaction.objects.create(
            tx_id=str(uuid.uuid4())[:8],
            sender=sender,
            recipient=recipient,
            asset=asset,
            metadata={"action": "transfer"}
        )
        return tx
