# wallet/models.py
import uuid
from django.db import models

class Wallet(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    address = models.CharField(max_length=128, unique=True)
    public_key = models.TextField()
    balance = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.address

class Asset(models.Model):
    asset_id = models.CharField(max_length=128, unique=True)
    owner = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name="assets")
    price = models.BigIntegerField(default=0)
    transferable = models.BooleanField(default=True)
    currency = models.CharField(max_length=16, default="COIN")

    def __str__(self):
        return f"{self.asset_id} ({self.owner.address})"

class Transaction(models.Model):
    tx_id = models.CharField(max_length=16, unique=True)
    sender = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='sent_transactions', null=True, blank=True)
    recipient = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='received_transactions', null=True, blank=True)
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True)
    amount = models.BigIntegerField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
