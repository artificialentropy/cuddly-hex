from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import transaction as db_transaction
from django.shortcuts import get_object_or_404
from django.db.models import Sum

from .models import (
    Block,
    Transaction,
    TransactionOutput,
    TransactionInputActivity,
    Wallet,
    WalletAddress,
)
from .serializers import (
    BlockSerializer,
    TransactionSerializer,
    WalletSerializer,
    WalletAddressSerializer,
)


class BlockViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Block.objects.all().order_by("height")
    serializer_class = BlockSerializer
    lookup_field = "height"

    @action(detail=True, methods=["get"])
    def transactions(self, request, height=None):
        block = self.get_object()
        qs = block.transactions.all().order_by("timestamp")
        page = self.paginate_queryset(qs)
        if page is not None:
            ser = TransactionSerializer(page, many=True)
            return self.get_paginated_response(ser.data)
        ser = TransactionSerializer(qs, many=True)
        return Response(ser.data)


class TransactionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Transaction.objects.select_related("block").all().order_by("-timestamp")
    serializer_class = TransactionSerializer
    lookup_field = "tx_id"

    def get_queryset(self):
        block_id = self.kwargs.get("block_pk")  # from nested router
        if block_id:
            return self.queryset.filter(block__height=block_id).order_by("timestamp")
        return self.queryset



class WalletViewSet(viewsets.ModelViewSet):
    queryset = Wallet.objects.all().order_by("id")
    serializer_class = WalletSerializer



class WalletAddressViewSet(viewsets.ModelViewSet):
    serializer_class = WalletAddressSerializer
    lookup_field = "address"

    def get_queryset(self):
        wallet_id = self.kwargs.get("wallet_pk")
        if wallet_id:
            return WalletAddress.objects.filter(wallet_id=wallet_id)
        return WalletAddress.objects.all()

    def perform_create(self, serializer):
        wallet = get_object_or_404(Wallet, pk=self.kwargs["wallet_pk"])
        return serializer.save(wallet=wallet)

from rest_framework import mixins

class WalletTransactViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    Nested under /wallet/{id}/transact/
    Only handles transaction creation.
    """
    serializer_class = TransactionSerializer

    def create(self, request, wallet_pk=None):
        wallet = get_object_or_404(Wallet, pk=wallet_pk)

        to_address = request.data.get("to_address")
        amount = request.data.get("amount")
        from_address = request.data.get("from_address")

        if not to_address or amount is None:
            return Response({"detail": "to_address and amount required"}, status=400)

        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return Response({"detail": "amount must be integer"}, status=400)

        if not from_address:
            addr_obj = wallet.addresses.first()
            if not addr_obj:
                return Response({"detail": "wallet has no addresses"}, status=400)
            from_address = addr_obj.address

        out_sum = TransactionOutput.objects.filter(address=from_address).aggregate(s=Sum("amount"))["s"] or 0
        in_sum = TransactionInputActivity.objects.filter(address=from_address).aggregate(s=Sum("amount"))["s"] or 0
        balance = out_sum + in_sum

        if balance < amount:
            return Response({"detail": "insufficient funds", "balance": balance}, status=400)

        import uuid, time
        tx_id = uuid.uuid4().hex[:16]
        latest_block = Block.objects.order_by("-height").first()
        if not latest_block:
            return Response({"detail": "no block found"}, status=500)

        timestamp = int(time.time() * 1_000_000_000)
        input_data = {
            "address": from_address,
            "balances": {"COIN": balance},
            "timestamp": timestamp
        }
        output_data = {
            to_address: {"COIN": amount},
            from_address: {"COIN": balance - amount}
        }

        with db_transaction.atomic():
            tx = Transaction.objects.create(
                tx_id=tx_id,
                block=latest_block,
                input_data=input_data,
                output_data=output_data,
                is_reward=False,
                timestamp=timestamp,
                from_address=from_address,
            )
            TransactionInputActivity.objects.create(transaction=tx, address=from_address, amount=-amount)
            TransactionOutput.objects.create(transaction=tx, address=to_address, amount=amount)
            TransactionOutput.objects.create(transaction=tx, address=from_address, amount=(balance - amount))

        ser = TransactionSerializer(tx)
        return Response(ser.data, status=201)
