from wallet.wallet import Wallet
from wallet.transaction import Asset, Transaction
from wallet.transaction_pool import TransactionPool
from utils.config import STARTING_BALANCE
from core.blockchain import Blockchain

# 1. Setup blockchain and pool
blockchain = Blockchain()
pool = TransactionPool()

# 2. Create wallets
sender = Wallet(blockchain)
recipient = Wallet(blockchain)

# Serialize public keys AFTER key generation
sender.serialize_public_key()
recipient.serialize_public_key()

# 3. Create an asset owned by sender
asset_obj = Asset(asset_id="123", owner=sender.address, transferable=True)

print("Sender address:", sender.address)
print("Recipient address:", recipient.address)

# 4. Create a dummy transaction (transfer asset)
tx = Transaction.transfer_asset_direct(
    sender_wallet=sender,
    recipient_address=recipient.address,
    asset=asset_obj,
    metadata={"note": "dummy transfer"}
)

# 5. Print transaction JSON (signed)
print("Dummy transaction JSON:")
print(tx.to_json())

# 6. Add transaction to pool
pool.set_transaction(tx)  # Should now pass signature validation

# 7. Check balances (COIN balances, not asset)
print("Sender balance after tx:", sender.balance)
print("Recipient balance after tx:", recipient.balance)
