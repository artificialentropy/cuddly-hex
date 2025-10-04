# blockchain_backend/utils/pubsub.py
import os
from pubnub.pubnub import PubNub
from pubnub.pnconfiguration import PNConfiguration
from pubnub.callbacks import SubscribeCallback

from blockchain_backend.core.block import Block
from blockchain_backend.wallet.transaction import Transaction

CHANNELS = {
    "TEST": "TEST",
    "BLOCK": "BLOCK",
    "TRANSACTION": "TRANSACTION",
    "CHAIN": "CHAIN",
}


class PubSub:
    """
    PubSub that can be disabled via ENABLE_PUBSUB.
    When disabled or keys missing, all broadcast_* become no-ops.
    """

    def __init__(self, blockchain, transaction_pool):
        self.blockchain = blockchain
        self.transaction_pool = transaction_pool
        self.pubnub = None
        self.enabled = False

        enabled_flag = os.getenv("ENABLE_PUBSUB", "").lower() in ("1", "true", "yes")
        pub = (os.getenv("PUBNUB_PUBLISH_KEY") or "").strip()
        sub = (os.getenv("PUBNUB_SUBSCRIBE_KEY") or "").strip()
        uuid = (os.getenv("PUBNUB_UUID") or "backend-node").strip()

        if not enabled_flag or not pub or not sub:
            print("[PubSub] disabled (set ENABLE_PUBSUB=true and provide PUBNUB_* keys).")
            return

        try:
            cfg = PNConfiguration()
            cfg.publish_key = pub
            cfg.subscribe_key = sub
            cfg.uuid = uuid

            self.pubnub = PubNub(cfg)
            self.pubnub.add_listener(self._make_listener())
            self.pubnub.subscribe().channels(list(CHANNELS.values())).execute()
            self.enabled = True
            print("[PubSub] enabled.")
        except Exception as e:
            print(f"[PubSub] disabled due to init error: {e}")

    # ---- Listener ----
    def _make_listener(self):
        ps = self

        class Listener(SubscribeCallback):
            def message(self, pubnub, event):
                if not ps.enabled:
                    return
                channel = getattr(event, "channel", None)
                msg = getattr(event, "message", None)
                if channel is None:
                    return
                try:
                    if channel == CHANNELS["CHAIN"]:
                        # msg is a list of block dicts
                        incoming = [Block.from_json(b) for b in (msg or [])]
                        ps.blockchain.replace_chain(incoming)
                        ps.transaction_pool.clear_blockchain_transactions(ps.blockchain)
                        print("[PubSub] Replaced local chain from peer.")
                    elif channel == CHANNELS["BLOCK"]:
                        # single block; append if new and valid
                        block = Block.from_json(msg)
                        if any(getattr(b, "hash", None) == getattr(block, "hash", None) for b in ps.blockchain.chain):
                            return
                        # validate linkage and append
                        Block.is_valid_block(ps.blockchain.chain[-1], block)
                        ps.blockchain.chain.append(block)
                        ps.transaction_pool.clear_blockchain_transactions(ps.blockchain)
                        print("[PubSub] Appended new block from peer.")
                    elif channel == CHANNELS["TRANSACTION"]:
                        tx = Transaction.from_json(msg)
                        ps.transaction_pool.set_transaction(tx)
                        print("[PubSub] Added transaction to pool from peer.")
                except Exception as e:
                    print(f"[PubSub] Listener error on {channel}: {e}")

        return Listener()

    # ---- Publishing ----
    def publish(self, channel, message):
        if not self.enabled or not self.pubnub:
            return
        try:
            self.pubnub.publish().channel(channel).message(message).sync()
        except Exception as e:
            print(f"[PubSub] publish error: {e}")

    def broadcast_block(self, block):
        self.publish(CHANNELS["BLOCK"], block.to_json())

    def broadcast_transaction(self, transaction):
        self.publish(CHANNELS["TRANSACTION"], transaction.to_json())

    def broadcast_chain(self, blockchain):
        self.publish(CHANNELS["CHAIN"], [b.to_json() for b in blockchain.chain])

    def close(self):
        """Gracefully unsubscribe/cleanup."""
        if not self.enabled or not self.pubnub:
            return
        try:
            self.pubnub.unsubscribe_all()
        except Exception:
            pass
