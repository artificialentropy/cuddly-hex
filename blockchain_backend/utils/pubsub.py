# import time

# from pubnub.pubnub import PubNub
# from pubnub.pnconfiguration import PNConfiguration
# from pubnub.callbacks import SubscribeCallback
# import os
# from blockchain_backend.core.block import Block
# from blockchain_backend.wallet.transaction import Transaction
# from dotenv import load_dotenv
# load_dotenv()  # take environment variables from .env.

# CHANNELS = {
#     'TEST': 'TEST',
#     'BLOCK': 'BLOCK',
#     'TRANSACTION': 'TRANSACTION',
#     'CHAIN': 'CHAIN'
# }


# class Listener(SubscribeCallback):
#     def __init__(self, blockchain, transaction_pool):
#         self.blockchain = blockchain
#         self.transaction_pool = transaction_pool

#     def message(self, pubnub, message_object):

#         if message_object.channel == CHANNELS['BLOCK']:

#             print(f'\n-- Channel: {message_object.channel} | Message: {message_object.message}')
#             block = Block.from_json(message_object.message)
#             potential_chain = self.blockchain.chain[:]

#             potential_chain.append(block)
#             print(f"********-----> {potential_chain}")
#             try:
#                 self.blockchain.replace_chain(potential_chain)
#                 self.transaction_pool.clear_blockchain_transactions(
#                     self.blockchain
#                 )
#                 print('\n -- Successfully replaced the local chain')
#             except Exception as e:
#                 print(f'\n -- Did not replace chain  from 2: {e}')

#         elif message_object.channel == CHANNELS['TRANSACTION']:
#             transaction = Transaction.from_json(message_object.message)
#             self.transaction_pool.set_transaction(transaction)
#             print('\n -- Set the new transaction in the transaction pool')


# class PubSub():
#     """
#     Handles the publish/subscribe layer of the application.
#     Provides communication between the nodes of the blockchain network.
#     """
#     def __init__(self, blockchain, transaction_pool):

#         pnconfig = PNConfiguration()
#         self.PUBNUB_SUBSCRIBE_KEY = os.getenv("PUBNUB_SUBSCRIBE_KEY", "")
#         self.PUBNUB_PUBLISH_KEY   = os.getenv("PUBNUB_PUBLISH_KEY", "")
#         self.PUBNUB_UUID          = os.getenv("PUBNUB_UUID", "mohit-dev-1")
#         pnconfig.subscribe_key = self.PUBNUB_SUBSCRIBE_KEY.strip()
#         pnconfig.publish_key = self.PUBNUB_PUBLISH_KEY.strip()
#         pnconfig.uuid = self.PUBNUB_UUID.strip()
#         self.pubnub = PubNub(pnconfig)
#         self.pubnub.subscribe().channels(CHANNELS.values()).execute()
#         self.listener = Listener(blockchain, transaction_pool)


#     def publish(self, channel, message):
#         """
#         Publish the message object to the channel.
#         """
#         self.pubnub.unsubscribe().channels([channel]).execute()
#         self.pubnub.publish().channel(channel).message(message).sync()
#         self.pubnub.subscribe().channels([channel]).execute()

#     def broadcast_block(self, block):
#         """
#         Broadcast a block object to all nodes.
#         """
#         self.publish(CHANNELS['BLOCK'], block.to_json())

#     def broadcast_transaction(self, transaction):
#         """
#         Broadcast a transaction to all nodes.
#         """
#         self.publish(CHANNELS['TRANSACTION'], transaction.to_json())


#     def broadcast_chain(self, blockchain):
#         chain_json = [b.to_json() for b in blockchain.chain]
#         self.publish(CHANNELS['CHAIN'], chain_json)

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

        # feature flag
        self.enabled = os.getenv("ENABLE_PUBSUB", "").lower() in ("1", "true", "yes")

        pub = (os.getenv("PUBNUB_PUBLISH_KEY") or "").strip()
        sub = (os.getenv("PUBNUB_SUBSCRIBE_KEY") or "").strip()
        uuid = (os.getenv("PUBNUB_UUID") or "backend-node").strip()

        if not self.enabled or not pub or not sub:
            self.enabled = False
            self.pubnub = None
            print(
                "[PubSub] disabled (set ENABLE_PUBSUB=true and provide PUBNUB_* keys to enable)."
            )
            return

        try:
            cfg = PNConfiguration()
            cfg.publish_key = pub
            cfg.subscribe_key = sub
            cfg.uuid = uuid

            self.pubnub = PubNub(cfg)
            self.pubnub.add_listener(self._make_listener())
            self.pubnub.subscribe().channels(list(CHANNELS.values())).execute()
            print("[PubSub] enabled.")
        except Exception as e:
            # Don’t spam logs or crash if DNS/keys/network fail
            self.enabled = False
            self.pubnub = None
            print(f"[PubSub] disabled due to init error: {e}")

    # ---- Listener ----
    def _make_listener(self):
        ps = self

        class Listener(SubscribeCallback):
            def message(self, pubnub, event):
                if not ps.enabled:
                    return
                channel = event.channel
                msg = event.message
                try:
                    if channel == CHANNELS["CHAIN"]:
                        # msg is a list of block dicts
                        incoming = [Block.from_json(b) for b in msg]
                        ps.blockchain.replace_chain(incoming)
                        ps.transaction_pool.clear_blockchain_transactions(ps.blockchain)
                        print("[PubSub] Replaced local chain from peer.")
                    elif channel == CHANNELS["BLOCK"]:
                        # single block; append if new and valid
                        block = Block.from_json(msg)
                        if any(b.hash == block.hash for b in ps.blockchain.chain):
                            # avoid duplicates
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
        if not self.enabled:
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
