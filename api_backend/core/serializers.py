from rest_framework import serializers
from .models import (
    Block,
    Transaction,
    TransactionOutput,
    TransactionInputActivity,
    Wallet,
    WalletAddress,
)


class TransactionInputSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionInputActivity
        fields = ["address", "amount"]


class TransactionOutputSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionOutput
        fields = ["address", "amount"]


class TransactionSerializer(serializers.ModelSerializer):
    inputs = TransactionInputSerializer(many=True, read_only=True)
    outputs = TransactionOutputSerializer(many=True, read_only=True)

    class Meta:
        model = Transaction
        fields = [
            "tx_id",
            "block",
            "input_data",
            "output_data",
            "is_reward",
            "timestamp",
            "from_address",
            "inputs",
            "outputs",
        ]


class BlockSerializer(serializers.ModelSerializer):
    # default related_name transactions -> nested
    transactions = TransactionSerializer(many=True, read_only=True)

    class Meta:
        model = Block
        fields = ["height", "hash", "last_hash", "timestamp", "difficulty", "nonce", "transactions"]


class WalletAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletAddress
        fields = ["id", "address", "label", "created_at"]


class WalletSerializer(serializers.ModelSerializer):
    addresses = WalletAddressSerializer(many=True, read_only=True)
    balance = serializers.SerializerMethodField()

    class Meta:
        model = Wallet
        fields = ["id", "name", "created_at", "addresses", "balance"]

    def get_balance(self, obj):
        # Sum balances of all addresses belonging to this wallet
        addrs = obj.addresses.values_list("address", flat=True)
        from django.db.models import Sum
        # Sum outputs
        out_sum = TransactionOutput.objects.filter(address__in=addrs).aggregate(s=Sum("amount"))["s"] or 0
        # Sum inputs (inputs.amount is negative for spends) -> include directly
        in_sum = TransactionInputActivity.objects.filter(address__in=addrs).aggregate(s=Sum("amount"))["s"] or 0
        return out_sum + in_sum  # inputs are negative, so this results in net balance
