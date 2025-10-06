# core/blockchain.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Union
from blockchain_backend.utils.config import GENESIS_CHECKPOINT_HASH
from blockchain_backend.core.block import Block as bp
from blockchain_backend.wallet.transaction import Transaction
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import (
    MINING_REWARD_INPUT,
    MINING_REWARD,
    MINING_REWARD_ASSET,
)


BlockOrJson = Union[bp, Dict[str, Any]]
from blockchain_backend.utils.config import RETARGET_WINDOW, TARGET_BLOCK_NS, MAX_ADJ_FACTOR



class Blockchain:
    """
    Blockchain: a public ledger of transactions.
    Implemented as a list of blocks (each block holds a list of tx JSONs).
    """

    def __init__(self) -> None:
        self.chain: List[bp] = [bp.genesis()]
    def _retarget(self):
        n = len(self.chain)
        if n < RETARGET_WINDOW+1: 
            return self.chain[-1].difficulty
        window = self.chain[-RETARGET_WINDOW:]
        span = window[-1].timestamp - window[0].timestamp
        avg = span / RETARGET_WINDOW
        last_diff = self.chain[-1].difficulty
        ratio = max(1/MAX_ADJ_FACTOR, min(MAX_ADJ_FACTOR, avg / TARGET_BLOCK_NS))
        new_diff = max(1, int(round(last_diff / ratio)))
        return new_diff
    # -------------------------
    # Basic operations
    # -------------------------
    def add_block(self, data: List[Dict[str, Any]]) -> bp:
        """
        Append a mined block containing 'data' (tx json dicts).
        Returns the new block.
        """
        
        last = self.chain[-1]
        class _Fake: pass
        fake = _Fake(); fake.timestamp=last.timestamp; fake.hash=last.hash; fake.difficulty=self._retarget()
        b = bp.mine_block(fake, data)   # bp.adjust_difficulty uses last_block.difficulty baseline
        b.height = len(self.chain)
        self.chain.append(b)

    def __repr__(self) -> str:
        return f"Blockchain: {self.chain}"

    # -------------------------
    # Serialization
    # -------------------------
    def to_json(self):
        """
        Return a list of block dicts ordered by ascending height.
        Each block dict will include an explicit `height` field.
        Also normalizes timestamps if they look like nanoseconds/microseconds.
        """
        out = []
        for idx, block in enumerate(self.chain):
            # Block.to_json() returns block fields (without height)
            bj = block.to_json() if hasattr(block, "to_json") else dict(block)
            # set explicit height (index in chain)
            bj["height"] = idx
            # normalize timestamp heuristic: if timestamp looks like ns/micro, convert to seconds
            try:
                ts = int(bj.get("timestamp", 0) or 0)
                if ts > 10**15:          # nanoseconds -> seconds
                    bj["timestamp"] = ts // 1_000_000_000
                elif ts > 10**12:       # microseconds -> seconds
                    bj["timestamp"] = ts // 1_000_000
                else:
                    bj["timestamp"] = ts
            except Exception:
                # leave as-is if we can't parse
                pass
            out.append(bj)
        return out

    @staticmethod
    def from_json(chain_json: Sequence[Dict[str, Any]]) -> "Blockchain":
        """
        Deserialize a list of serialized blocks into a Blockchain instance.
        The result will contain a chain list of Block instances.
        """
        bc = Blockchain()
        bc.chain = [bp.from_json(bj) for bj in chain_json]
        return bc

    # -------------------------
    # Chain replacement
    # -------------------------
    def replace_chain(self, incoming: Sequence[BlockOrJson]) -> None:
        """
        Replace the local chain with the incoming one if the following applies:
          - The incoming chain is longer than the local one.
          - The incoming chain is formatted properly.
        Accepts a sequence of Block objects or block-json dicts.
        """
        # Normalize incoming to Block instances
        new_chain: List[bp] = []
        for item in incoming:
            if isinstance(item, bp):
                new_chain.append(item)
            elif isinstance(item, dict):
                new_chain.append(bp.from_json(item))
            else:
                raise Exception(f"Cannot replace. Unsupported block type: {type(item)}")

        if len(new_chain) <= len(self.chain):
            raise Exception("Cannot replace. The incoming chain must be longer.")

        try:
            Blockchain.is_valid_chain(new_chain)
        except Exception as e:
            raise Exception(f"Cannot replace. The incoming chain is invalid: {e}")

        self.chain = new_chain

    # -------------------------
    # Validation
    # -------------------------
    @staticmethod
    def is_valid_chain(chain: Sequence[bp]) -> None:
        """
        Validate the incoming chain.
        Enforce the following rules:
          - the chain must start with the genesis block
          - blocks must be formatted correctly
          - transaction-level rules hold across the whole chain
        """
        if not chain:
            raise Exception("Empty chain is invalid")

        if chain[0] != bp.genesis() or getattr(chain[0], "hash", None) != GENESIS_CHECKPOINT_HASH:
            raise Exception("The genesis block must match network checkpoint")

        for i in range(1, len(chain)):
            block = chain[i]
            last_block = chain[i - 1]
            bp.is_valid_block(last_block, block)

        Blockchain.is_valid_transaction_chain(chain)

    @staticmethod
    def _normalize_output_entry(entry: Any) -> Dict[str, int]:
        """
        Normalize tx output entry into a currency->int map.
        Accepts:
          - dict {currency: amount, ...}
          - numeric legacy output (treated as MINING_REWARD_ASSET)
        """
        if isinstance(entry, dict):
            out: Dict[str, int] = {}
            for k, v in entry.items():
                try:
                    out[str(k)] = int(v)
                except Exception:
                    continue
            return out
        # legacy scalar → assume default asset
        try:
            return {MINING_REWARD_ASSET: int(entry)}
        except Exception:
            return {}

    @staticmethod
    def is_valid_transaction_chain(chain: Sequence[bp]) -> None:
        """
        Enforce rules:
          - Each transaction must only appear once in the chain.
          - There can only be one mining reward per block.
          - Each transaction must be valid (signature + conservation).
          - Historic balance snapshot must match inputs:
              * Prefer input["balances"][currency] when provided (multi-asset).
              * Otherwise legacy input["amount"] for default asset.
        """
        seen_tx_ids = set()

        for i, block in enumerate(chain):
            has_mining_reward = False

            for tx_json in block.data:
                transaction = Transaction.from_json(tx_json)

                if transaction.id in seen_tx_ids:
                    raise Exception(f"Transaction {transaction.id} is not unique")
                seen_tx_ids.add(transaction.id)

                # Reward transaction validation
                if transaction.input == MINING_REWARD_INPUT:
                    if has_mining_reward:
                        raise Exception(
                            "There can only be one mining reward per block. "
                            f"Block hash: {getattr(block, 'hash', None)}"
                        )

                    outputs = transaction.output or {}
                    # Expect at least one recipient where MINING_REWARD_ASSET == MINING_REWARD
                    reward_ok = False
                    for _addr, out_entry in outputs.items():
                        entry_map = Blockchain._normalize_output_entry(out_entry)
                        if entry_map.get(MINING_REWARD_ASSET, 0) == int(MINING_REWARD):
                            reward_ok = True
                            break
                    if not reward_ok:
                        raise Exception(
                            f"Invalid mining reward in block {getattr(block, 'hash', None)}; "
                            f"expected {MINING_REWARD} {MINING_REWARD_ASSET}"
                        )

                    has_mining_reward = True
                    continue  # reward tx doesn't need balance snapshot check

                # Non-reward transactions: validate against historic snapshot
                historic = Blockchain()
                historic.chain = list(chain[0:i])  # blocks strictly before current block

                input_snapshot = transaction.input or {}
                addr = input_snapshot.get("address")

                if isinstance(input_snapshot, dict) and "balances" in input_snapshot:
                    balances = input_snapshot.get("balances") or {}
                    if not isinstance(balances, dict):
                        raise Exception(f"Transaction {transaction.id} has invalid balances snapshot")
                    for currency_id, snapshot_amount in balances.items():
                        hb = Wallet.calculate_balance(historic, addr, currency=str(currency_id))
                        if int(hb) != int(snapshot_amount):
                            raise Exception(
                                f"Transaction {transaction.id} invalid snapshot for {currency_id}: "
                                f"historic {hb} != input {snapshot_amount}"
                            )
                else:
                    # Legacy path: input["amount"] for default asset
                    if "amount" not in input_snapshot:
                        raise Exception(f"Transaction {transaction.id} missing input snapshot or amount")
                    hb = Wallet.calculate_balance(historic, addr)
                    if int(hb) != int(input_snapshot["amount"]):
                        raise Exception(
                            f"Transaction {transaction.id} has an invalid input amount (legacy): "
                            f"historic {hb} != input.amount {input_snapshot['amount']}"
                        )

                # Signature & conservation checks delegated to Transaction
                Transaction.is_valid_transaction(transaction)


# -------------------------
# Utility: create initial reward block (optional)
# -------------------------
def script_blockchain_init(
    blockchain: Blockchain,
    server_start: bool,
    custom_data: Optional[List[Dict[str, Any]]] = None,
):
    """
    If server_start is True, create an initial block with a miner reward.
    The reward transaction uses config MINING_REWARD / MINING_REWARD_ASSET.
    Backward-compatible with older Transaction.reward_transaction() signatures.
    Returns (new_block, blockchain) when a block is added, else None.
    """
    if not server_start:
        return None

    miner_wallet = Wallet(blockchain)
    metadata = {"custom_data": custom_data} if custom_data is not None else None

    # Try new signature; gracefully fall back to older ones
    try:
        reward_tx = Transaction.reward_transaction(
            miner_wallet,
            currency=MINING_REWARD_ASSET,
            amount=MINING_REWARD,
            metadata=metadata,
        )
    except TypeError:
        try:
            reward_tx = Transaction.reward_transaction(miner_wallet, metadata=metadata)  # older
        except TypeError:
            reward_tx = Transaction.reward_transaction(miner_wallet)  # oldest

    new_block = blockchain.add_block([reward_tx.to_json()])
    return new_block, blockchain
