from django.db import models
from django.utils import timezone


class Block(models.Model):
    height = models.PositiveBigIntegerField(primary_key=True)
    hash = models.CharField(max_length=128, unique=True, db_index=True)
    last_hash = models.CharField(max_length=128, db_index=True)
    timestamp = models.BigIntegerField(db_index=True)
    difficulty = models.IntegerField()
    nonce = models.BigIntegerField()

    class Meta:
        db_table = "block"
        ordering = ["height"]

    def __str__(self):
        return f"Block {self.height} {self.hash[:12]}"


class Transaction(models.Model):
    tx_id = models.CharField(max_length=128, primary_key=True)
    block = models.ForeignKey(Block, on_delete=models.CASCADE, related_name="transactions")

    input_data = models.JSONField()   # full input dict
    output_data = models.JSONField()  # full output dict
    is_reward = models.BooleanField(default=False)

    timestamp = models.BigIntegerField(db_index=True)
    from_address = models.CharField(max_length=128, blank=True, null=True, db_index=True)

    class Meta:
        db_table = "transaction"
        ordering = ["timestamp"]

    def __str__(self):
        return f"Tx {self.tx_id} in block {self.block.height}"


class TransactionOutput(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name="outputs")
    address = models.CharField(max_length=128, db_index=True)
    amount = models.BigIntegerField()

    class Meta:
        db_table = "transaction_output"
        unique_together = ("transaction", "address")

    def __str__(self):
        return f"Output {self.amount} to {self.address}"


class TransactionInputActivity(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name="inputs")
    address = models.CharField(max_length=128, db_index=True)
    amount = models.BigIntegerField()  # signed negative for spend

    class Meta:
        db_table = "transaction_input_activity"
        unique_together = ("transaction", "address")

    def __str__(self):
        return f"Input {self.amount} from {self.address}"


# New wallet/address models
class Wallet(models.Model):
    """
    A logical wallet that can own multiple addresses.
    """
    name = models.CharField(max_length=128, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "wallet"

    def __str__(self):
        return f"Wallet {self.pk} {self.name or ''}"


class WalletAddress(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name="addresses")
    address = models.CharField(max_length=128, unique=True, db_index=True)
    label = models.CharField(max_length=128, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "wallet_address"

    def __str__(self):
        return f"{self.address} ({self.wallet_id})"
