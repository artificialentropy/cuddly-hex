import json
import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from core.models import (
    Block,
    Transaction,
    TransactionOutput,
    TransactionInputActivity,
    Wallet,
    WalletAddress,
)


class Command(BaseCommand):
    help = "Ingest blockchain data from a node or local JSON into canonical models."

    def add_arguments(self, parser):
        parser.add_argument(
            "source",
            type=str,
            help="Either a URL to fetch chain JSON (http://host:port/chain) or a local JSON file path",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        source = options["source"]

        # Fetch JSON from URL or load from file
        if source.startswith("http://") or source.startswith("https://"):
            try:
                resp = requests.get(source, timeout=10)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                raise CommandError(f"Failed to fetch JSON from {source}: {e}")
        else:
            try:
                with open(source, "r") as f:
                    data = json.load(f)
            except Exception as e:
                raise CommandError(f"Failed to read JSON file {source}: {e}")

        blocks_data = data.get("blocks", [])
        transactions_data = data.get("transactions", [])

        imported_blocks = imported_txs = imported_rows = imported_wallets = 0

        # Ingest blocks
        for block_data in blocks_data:
            block, _ = Block.objects.update_or_create(
                height=block_data["height"],
                defaults={
                    "hash": block_data["hash"],
                    "last_hash": block_data["last_hash"],
                    "timestamp": block_data["timestamp"],
                    "difficulty": block_data["difficulty"],
                    "nonce": block_data["nonce"],
                },
            )
            imported_blocks += 1

        # Ingest transactions
        for tx_data in transactions_data:
            block = Block.objects.get(height=tx_data["block"])
            tx, _ = Transaction.objects.update_or_create(
                tx_id=tx_data["tx_id"],
                defaults={
                    "block": block,
                    "input_data": tx_data.get("input_data", {}),
                    "output_data": tx_data.get("output_data", {}),
                    "is_reward": tx_data.get("is_reward", False),
                    "timestamp": tx_data.get("timestamp"),
                    "from_address": tx_data.get("from_address"),
                },
            )
            imported_txs += 1

            # Clear old related rows
            TransactionInputActivity.objects.filter(transaction=tx).delete()
            TransactionOutput.objects.filter(transaction=tx).delete()

            # Insert inputs
            for addr, amt in tx_data.get("input_data", {}).get("balances", {}).items():
                TransactionInputActivity.objects.create(
                    transaction=tx, address=addr, amount=amt
                )
                # Ensure wallet + address exist
                wallet, _ = Wallet.objects.get_or_create(owner_hint=addr[:6])  
                WalletAddress.objects.get_or_create(wallet=wallet, address=addr)
                imported_wallets += 1
                imported_rows += 1

            # Insert outputs
            for addr, balances in tx_data.get("output_data", {}).items():
                for coin, amt in balances.items():
                    TransactionOutput.objects.create(
                        transaction=tx, address=addr, amount=amt
                    )
                    wallet, _ = Wallet.objects.get_or_create(owner_hint=addr[:6])
                    WalletAddress.objects.get_or_create(wallet=wallet, address=addr)
                    imported_wallets += 1
                    imported_rows += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Ingested {imported_blocks} blocks, {imported_txs} transactions, "
                f"{imported_rows} input/output rows, {imported_wallets} wallets/addresses"
            )
        )
