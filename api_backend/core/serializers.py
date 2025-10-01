from rest_framework import serializers
from .models import Wallet, Asset, Transaction

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = "__all__"

class AssetSerializer(serializers.ModelSerializer):
    owner = WalletSerializer(read_only=True)  # nested view for owner
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=Wallet.objects.all(), source="owner", write_only=True
    )

    class Meta:
        model = Asset
        fields = "__all__"

class TransactionSerializer(serializers.ModelSerializer):
    sender = WalletSerializer(read_only=True)
    recipient = WalletSerializer(read_only=True)
    sender_id = serializers.PrimaryKeyRelatedField(
        queryset=Wallet.objects.all(), source="sender", write_only=True, required=False
    )
    recipient_id = serializers.PrimaryKeyRelatedField(
        queryset=Wallet.objects.all(), source="recipient", write_only=True, required=False
    )
    asset_id = serializers.PrimaryKeyRelatedField(
        queryset=Asset.objects.all(), source="asset", write_only=True, required=False
    )

    class Meta:
        model = Transaction
        fields = "__all__"
