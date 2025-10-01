import hashlib
import json
import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

# Updated model imports to match the new models you showed
from core.models import (
    Block,
    Transaction,
    TransactionOutput,
    TransactionInputActivity,
    MetadataStore,
)


def sha256_json(obj) -> str:
    """Stable SHA-256 hash of a JSON-serializable object."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class Command(BaseCommand):
    help = "Ingest blockchain data from a node's /blockchain endpoint into canonical models."

    def add_arguments(self, parser):
        parser.add_argument(
            "--base",
            default="http://localhost:5000",
            help="Base URL of the node (default: http://localhost:5000)",
        )
        parser.add_argument(
            "--from-height",
            type=int,
            default=None,
            help="Only ingest blocks starting from this height (inclusive).",
        )
        parser.add_argument(
            "--to-height",
            type=int,
            default=None,
            help="Only ingest blocks up to this height (inclusive).",
        )
        parser.add_argument(
            "--save-metadata",
            action="store_true",
            help="If tx contains `metadata` on-chain, persist in MetadataStore and anchor with hash.",
        )

    def handle(self, *args, **opts):
        base = opts["base"].rstrip("/")
        save_metadata = opts["save_metadata"]

        # --- fetch full chain ---
        try:
            self.stdout.write(self.style.MIGRATE_HEADING(f"Fetching chain from {base}/blockchain"))
            resp = requests.get(f"{base}/blockchain", timeout=10)
            resp.raise_for_status()
            chain = resp.json()
            if not isinstance(chain, list) or not chain:
                raise CommandError("Unexpected /blockchain payload")
        except Exception as e:
            raise CommandError(f"Failed to fetch /blockchain: {e}")

        # --- range bounds ---
        start_h = opts["from_height"] if opts["from_height"] is not None else 0
        end_h = opts["to_height"] if opts["to_height"] is not None else len(chain) - 1
        end_h = min(end_h, len(chain) - 1)

        if start_h < 0 or end_h < 0 or start_h > end_h:
            raise CommandError("Invalid range for from-height/to-height")

        imported_blocks = imported_txs = imported_address_rows = imported_metadata = 0

        # --- iterate blocks ---
        for height in range(start_h, end_h + 1):
            blk = chain[height]
            with transaction.atomic():
                # Block model: primary key = height
                block_obj, _ = Block.objects.update_or_create(
                    height=height,
                    defaults={
                        "hash": blk.get("hash", ""),
                        "last_hash": blk.get("last_hash", ""),
                        # ensure ints; block timestamps on chain are ns in your model comment
                        "timestamp": int(blk.get("timestamp", 0)),
                        "difficulty": int(blk.get("difficulty", 0)),
                        # nonce may be a string in some chains; fall back to 0
                        "nonce": int(blk.get("nonce", 0)) if not isinstance(blk.get("nonce"), str) else 0,
                    },
                )
                imported_blocks += 1

                # --- iterate txs ---
                for tx in (blk.get("data") or []):
                    tx_id = tx["id"]
                    inp = tx.get("input", {}) or {}
                    out = tx.get("output", {}) or {}

                    is_reward = bool(inp.get("address") == "*--official-mining-reward--*")
                    tx_ts = int(inp.get("timestamp", blk.get("timestamp", 0)))

                    metadata_on_chain = tx.get("metadata")
                    metadata_hash = (
                        sha256_json(metadata_on_chain)
                        if (save_metadata and metadata_on_chain is not None)
                        else None
                    )

                    # Create or update Transaction model
                    tx_obj, _ = Transaction.objects.update_or_create(
                        tx_id=tx_id,
                        defaults={
                            "block": block_obj,
                            "input": inp,
                            "output": out,
                            # store metadata into Transaction.metadata field as well (if present)
                            "metadata": metadata_on_chain if metadata_on_chain is not None else None,
                            "is_reward": is_reward,
                            "timestamp": tx_ts,
                            "from_address": (inp.get("address") if inp.get("address") and not is_reward else None),
                        },
                    )
                    imported_txs += 1

                    # --- clear per-tx input/output and metadata rows and re-insert ---
                    TransactionOutput.objects.filter(transaction=tx_obj).delete()
                    TransactionInputActivity.objects.filter(transaction=tx_obj).delete()
                    MetadataStore.objects.filter(transaction=tx_obj).delete()

                    # Insert input activity (sender) if not reward
                    if not is_reward:
                        sender = inp.get("address")
                        inp_amount = int(inp.get("amount", 0))
                        if sender:
                            # TransactionInputActivity.amount is signed negative value for spend
                            TransactionInputActivity.objects.create(
                                transaction=tx_obj,
                                address=str(sender),
                                amount=-inp_amount,
                            )
                            imported_address_rows += 1

                    # Insert outputs (recipients)
                    # `out` is expected to be mapping address -> amount
                    for addr, amt in (out.items() if isinstance(out, dict) else []):
                        TransactionOutput.objects.create(
                            transaction=tx_obj,
                            address=str(addr),
                            amount=int(amt),
                        )
                        imported_address_rows += 1

                    # Optional large metadata store anchored by content hash
                    if save_metadata and metadata_on_chain is not None:
                        content_hash = metadata_hash or sha256_json(metadata_on_chain)
                        MetadataStore.objects.update_or_create(
                            transaction=tx_obj,
                            defaults={
                                "metadata": metadata_on_chain,
                                "content_hash": content_hash,
                                # stored_at has default=now in model; we set explicitly for clarity
                                "stored_at": timezone.now(),
                            },
                        )
                        imported_metadata += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Ingested blocks={imported_blocks}, txs={imported_txs}, "
                f"address_rows={imported_address_rows}, metadata_rows={imported_metadata}"
            )
        )
