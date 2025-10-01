# from .block import Block as bp
# from .block import script_backend_single_run
# from blockchain_backend.wallet.transaction import Transaction
# from blockchain_backend.wallet.wallet import Wallet
# from blockchain_backend.utils.config import MINING_REWARD_INPUT


# class Blockchain:
#     """
#     Blockchain: a public ledger of transactions.
#     Implemented as a list of blocks - data sets of transactions
#     """

#     def __init__(self):
#         self.chain = [bp.genesis()]

#     def add_block(self, data):
#         self.chain.append(bp.mine_block(self.chain[-1], data))

#     def __repr__(self):
#         return f"Blockchain: {self.chain}"

#     def replace_chain(self, chain):
#         """
#         Replace the local chain with the incoming one if the following applies:
#           - The incoming chain is longer than the local one.
#           - The incoming chain is formatted properly.
#         """
#         if len(chain) <= len(self.chain):
#             raise Exception("Cannot replace. The incoming chain must be longer.")

#         try:
#             Blockchain.is_valid_chain(chain)
#         except Exception as e:
#             raise Exception(f"Cannot replace. The incoming chain is invalid: {e}")

#         self.chain = chain

#     def to_json(self):
#         """
#         Serialize the blockchain into a list of blocks.
#         """
#         return list(map(lambda block: block.to_json(), self.chain))

#     @staticmethod
#     def from_json(chain_json):
#         """
#         Deserialize a list of serialized blocks into a Blokchain instance.
#         The result will contain a chain list of Block instances.
#         """
#         blockchain = Blockchain()
#         blockchain.chain = list(
#             map(lambda block_json: bp.from_json(block_json), chain_json)
#         )

#         return blockchain

#     @staticmethod
#     def is_valid_chain(chain):
#         """
#         Validate the incoming chain.
#         Enforce the following rules of the blockchain:
#           - the chain must start with the genesis block
#           - blocks must be formatted correctly
#         """
#         if chain[0] != bp.genesis():
#             raise Exception("The genesis block must be valid")

#         for i in range(1, len(chain)):
#             block = chain[i]
#             last_block = chain[i - 1]
#             bp.is_valid_block(last_block, block)

#         Blockchain.is_valid_transaction_chain(chain)

#     @staticmethod
#     def is_valid_transaction_chain(chain):
#         """
#         Enforce the rules of a chain composed of blocks of transactions.
#             - Each transaction must only appear once in the chain.
#             - There can only be one mining reward per block.
#             - Each transaction must be valid.
#         """
#         transaction_ids = set()

#         for i in range(len(chain)):
#             block = chain[i]
#             has_mining_reward = False

#             for transaction_json in block.data:
#                 transaction = Transaction.from_json(transaction_json)

#                 if transaction.id in transaction_ids:
#                     raise Exception(f"Transaction {transaction.id} is not unique")

#                 transaction_ids.add(transaction.id)

#                 if transaction.input == MINING_REWARD_INPUT:
#                     if has_mining_reward:
#                         raise Exception(
#                             "There can only be one mining reward per block. "
#                             f"Check block with hash: {block.hash}"
#                         )

#                     has_mining_reward = True
#                 else:
#                     historic_blockchain = Blockchain()
#                     historic_blockchain.chain = chain[0:i]
#                     historic_balance = Wallet.calculate_balance(
#                         historic_blockchain, transaction.input["address"]
#                     )

#                     if historic_balance != transaction.input["amount"]:
#                         raise Exception(
#                             f"Transaction {transaction.id} has an invalid "
#                             "input amount"
#                         )

#                 Transaction.is_valid_transaction(transaction)


# def script_blockchain_init(blockchain, server_start, custom_data=None):
#     if server_start:
#         miner_wallet = Wallet(blockchain)
#         reward_tx = Transaction.reward_transaction(
#             miner_wallet,
#             metadata={"custom_data": custom_data} if custom_data is not None else None,
#         )
#         blockchain.add_block([reward_tx.to_json()])
#         return blockchain.chain[-1], blockchain
#     else:
#         return None
from blockchain_backend.core.block import Block as bp
from blockchain_backend.core.block import script_backend_single_run
from blockchain_backend.wallet.transaction import Transaction
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import (
    MINING_REWARD_INPUT,
    MINING_REWARD,
    MINING_REWARD_ASSET,
)

class Blockchain:
    """
    Blockchain: a public ledger of transactions.
    Implemented as a list of blocks - data sets of transactions
    """

    def __init__(self):
        self.chain = [bp.genesis()]

    def add_block(self, data):
        # data is expected to be a list of tx json-serializable dicts
        self.chain.append(bp.mine_block(self.chain[-1], data))

    def __repr__(self):
        return f"Blockchain: {self.chain}"

    def replace_chain(self, chain):
        """
        Replace the local chain with the incoming one if the following applies:
          - The incoming chain is longer than the local one.
          - The incoming chain is formatted properly.
        """
        if len(chain) <= len(self.chain):
            raise Exception("Cannot replace. The incoming chain must be longer.")

        try:
            Blockchain.is_valid_chain(chain)
        except Exception as e:
            raise Exception(f"Cannot replace. The incoming chain is invalid: {e}")

        self.chain = chain

    def to_json(self):
        """
        Serialize the blockchain into a list of blocks.
        """
        return list(map(lambda block: block.to_json(), self.chain))

    @staticmethod
    def from_json(chain_json):
        """
        Deserialize a list of serialized blocks into a Blockchain instance.
        The result will contain a chain list of Block instances.
        """
        blockchain = Blockchain()
        blockchain.chain = list(map(lambda block_json: bp.from_json(block_json), chain_json))
        return blockchain

    @staticmethod
    def is_valid_chain(chain):
        """
        Validate the incoming chain.
        Enforce the following rules of the blockchain:
          - the chain must start with the genesis block
          - blocks must be formatted correctly
        """
        if chain[0] != bp.genesis():
            raise Exception("The genesis block must be valid")

        for i in range(1, len(chain)):
            block = chain[i]
            last_block = chain[i - 1]
            bp.is_valid_block(last_block, block)

        Blockchain.is_valid_transaction_chain(chain)

    @staticmethod
    def _normalize_output_entry(entry):
        """
        Normalize tx output entry into a currency->int map.
        Accepts legacy numeric outputs (treat as MINING_REWARD_ASSET or default currency)
        or nested dicts {currency: amount}.
        """
        if isinstance(entry, dict):
            # assume {currency: amount, ...}
            return {str(k): int(v) for k, v in entry.items()}
        else:
            # numeric legacy output — interpret as MINING_REWARD_ASSET
            try:
                return {MINING_REWARD_ASSET: int(entry)}
            except Exception:
                return {}

    @staticmethod
    def is_valid_transaction_chain(chain):
        """
        Enforce rules:
          - Each transaction must only appear once in the chain.
          - There can only be one mining reward per block.
          - Each transaction must be valid (signature + conservation).
          - For normal txs, the historic balance check is done using the input snapshot:
              - prefer input["balances"][currency] if present
              - otherwise fall back to legacy input["amount"] and legacy flat outputs
        """
        transaction_ids = set()

        for i in range(len(chain)):
            block = chain[i]
            has_mining_reward = False

            for transaction_json in block.data:
                transaction = Transaction.from_json(transaction_json)

                if transaction.id in transaction_ids:
                    raise Exception(f"Transaction {transaction.id} is not unique")

                transaction_ids.add(transaction.id)

                # Reward tx check
                if transaction.input == MINING_REWARD_INPUT:
                    if has_mining_reward:
                        raise Exception(
                            "There can only be one mining reward per block. "
                            f"Check block with hash: {getattr(block, 'hash', None)}"
                        )
                    # Verify reward amount + asset (be permissive about output shape)
                    outputs = transaction.output or {}
                    # Expect exactly one recipient with MINING_REWARD_ASSET == MINING_REWARD
                    reward_found = False
                    for addr, out_entry in outputs.items():
                        entry_map = Blockchain._normalize_output_entry(out_entry)
                        if entry_map.get(MINING_REWARD_ASSET, 0) == int(MINING_REWARD):
                            reward_found = True
                            break
                    if not reward_found:
                        raise Exception(
                            f"Invalid mining reward in block {getattr(block, 'hash', None)}; expected {MINING_REWARD} {MINING_REWARD_ASSET}"
                        )
                    has_mining_reward = True
                    continue

                # For non-reward txs: compute historic balance and compare to input snapshot
                historic_blockchain = Blockchain()
                historic_blockchain.chain = chain[0:i]

                # Determine which currency to check:
                # If tx.input contains a balances dict, validate for each currency present there.
                # Otherwise maintain legacy behavior: use input["amount"] and flat outputs.
                input_snapshot = transaction.input or {}
                if isinstance(input_snapshot, dict) and "balances" in input_snapshot:
                    # For each currency in input snapshot, compute historic balance and compare
                    for currency_id, snapshot_amount in input_snapshot["balances"].items():
                        hb = Wallet.calculate_balance(historic_blockchain, transaction.input["address"], currency=currency_id)
                        if int(hb) != int(snapshot_amount):
                            raise Exception(
                                f"Transaction {transaction.id} has invalid input snapshot for currency {currency_id}: historic {hb} != input snapshot {snapshot_amount}"
                            )
                else:
                    # Legacy path: expect input["amount"] and flat outputs
                    legacy_input_amount = input_snapshot.get("amount")
                    if legacy_input_amount is None:
                        raise Exception(f"Transaction {transaction.id} missing input snapshot or amount")
                    # compute historic balance for default/mining currency
                    hb = Wallet.calculate_balance(historic_blockchain, transaction.input["address"])
                    if int(hb) != int(legacy_input_amount):
                        raise Exception(
                            f"Transaction {transaction.id} has an invalid input amount (legacy): historic {hb} != input.amount {legacy_input_amount}"
                        )

                # Validate transaction signature + output conservation using Transaction's own validator
                Transaction.is_valid_transaction(transaction)

def script_blockchain_init(blockchain, server_start, custom_data=None):
    """
    If server_start is True, create an initial block with a miner reward.
    The reward transaction is created using config MINING_REWARD and MINING_REWARD_ASSET.
    This function is backward-compatible with older Transaction.reward_transaction(miner_wallet)
    signatures by falling back if necessary.
    """
    if not server_start:
        return None

    miner_wallet = Wallet(blockchain)

    # Attach custom_data into metadata if provided
    metadata = {"custom_data": custom_data} if custom_data is not None else None

    # Build reward tx with new signature if available, otherwise fallback to old call
    try:
        # preferred signature: (miner_wallet, asset=..., amount=..., metadata=...)
        reward_tx = Transaction.reward_transaction(
            miner_wallet,
            asset=MINING_REWARD_ASSET,
            amount=MINING_REWARD,
            metadata=metadata,
        )
    except TypeError:
        # fallback: older signature that possibly only takes (miner_wallet, metadata=None)
        try:
            reward_tx = Transaction.reward_transaction(miner_wallet, metadata=metadata)
        except TypeError:
            # last-resort: call simple one-arg variant and ignore metadata
            reward_tx = Transaction.reward_transaction(miner_wallet)

    # Add the reward tx as the first (genesis-like) block's data
    blockchain.add_block([reward_tx.to_json()])
    return blockchain.chain[-1], blockchain

