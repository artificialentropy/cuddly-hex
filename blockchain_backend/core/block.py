# core/block.py
import time
from typing import Any, Dict, List, Optional
from blockchain_backend.utils.config import MINE_RATE_NS
from blockchain_backend.utils.crypto_hash import crypto_hash
from blockchain_backend.utils.hex_to_binary import hex_to_binary

# Convert MINE_RATE (seconds) to nanoseconds for consistent comparison with time.time_ns()
MINE_RATE_NS = int(MINE_RATE_NS * 1_000_000_000)

GENESIS_DATA: Dict[str, Any] = {
    "timestamp": 1,                    # ns (arbitrary for genesis)
    "last_hash": "genesis_last_hash",
    "hash": "genesis_hash",
    "data": [],                        # type: List[Any]
    "difficulty": 3,
    "nonce": 0,                        # must be int; mining increments this
}


class Block:
    """
    Block: a unit of storage.
    Stores transactions in a blockchain that supports a cryptocurrency.
    """

    def __init__(
        self,
        timestamp: int,
        last_hash: str,
        hash: str,
        data: List[Any],
        difficulty: int,
        nonce: int,
    ):
        self.timestamp = int(timestamp)
        self.last_hash = str(last_hash)
        self.hash = str(hash)
        self.data = data
        self.difficulty = int(difficulty)
        self.nonce = int(nonce)

    def __repr__(self) -> str:
        return (
            "Block("
            f"timestamp: {self.timestamp}, "
            f"last_hash: {self.last_hash}, "
            f"hash: {self.hash}, "
            f"data: {self.data}, "
            f"difficulty: {self.difficulty}, "
            f"nonce: {self.nonce})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Block):
            return False
        return (
            self.timestamp == other.timestamp
            and self.last_hash == other.last_hash
            and self.hash == other.hash
            and self.data == other.data
            and self.difficulty == other.difficulty
            and self.nonce == other.nonce
        )

    def to_json(self) -> Dict[str, Any]:
        """Serialize the block into a dictionary of its attributes."""
        return {
            "timestamp": self.timestamp,
            "last_hash": self.last_hash,
            "hash": self.hash,
            "data": self.data,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
        }

    @staticmethod
    def from_json(block_json: Dict[str, Any]) -> "Block":
        """Deserialize a block's json representation back into a block instance."""
        return Block(**block_json)

    @staticmethod
    def genesis() -> "Block":
        """Generate the genesis block."""
        return Block(**GENESIS_DATA)

    @staticmethod
    def mine_block(last_block: "Block", data: List[Any]) -> "Block":
        """
        Mine a block based on the given last_block and data, until a block hash
        is found that meets the leading 0's proof-of-work requirement.
        """
        timestamp = time.time_ns()
        last_hash = last_block.hash
        difficulty = Block.adjust_difficulty(last_block, timestamp)
        nonce = 0
        block_hash = crypto_hash(timestamp, last_hash, data, difficulty, nonce)

        # Proof-of-work loop
        target_prefix = "0" * difficulty
        while hex_to_binary(block_hash)[:difficulty] != target_prefix:
            nonce += 1
            timestamp = time.time_ns()
            difficulty = Block.adjust_difficulty(last_block, timestamp)
            # re-evaluate target when difficulty changes
            target_prefix = "0" * difficulty
            block_hash = crypto_hash(timestamp, last_hash, data, difficulty, nonce)

        return Block(timestamp, last_hash, block_hash, data, difficulty, nonce)

    @staticmethod
    def adjust_difficulty(last_block: "Block", new_timestamp: int) -> int:
        if (new_timestamp - int(last_block.timestamp)) < MINE_RATE_NS:
            return last_block.difficulty + 1
        return max(1, last_block.difficulty - 1)

    @staticmethod
    def is_valid_block(last_block: "Block", block: "Block") -> None:
        """
        Validate block by enforcing the following rules:
          - the block must have the proper last_hash reference
          - the block must meet the proof of work requirement
          - the difficulty must only adjust by 1
          - the block hash must be a valid combination of the block fields
        """
        if block.last_hash != last_block.hash:
            raise Exception("The block last_hash must be correct")

        # Enforce PoW
        if hex_to_binary(block.hash)[: block.difficulty] != "0" * block.difficulty:
            raise Exception("The proof of work requirement was not met")

        # Enforce difficulty step of ±1 (and minimum 1 is ensured by mining/adjustment)
        if abs(last_block.difficulty - block.difficulty) > 1:
            raise Exception("The block difficulty must only adjust by 1")

        # Reconstruct the hash with the exact same parameter order as mine_block
        reconstructed_hash = crypto_hash(
            block.timestamp, block.last_hash, block.data, block.difficulty, block.nonce
        )
        if block.hash != reconstructed_hash:
            raise Exception("The block hash must be correct")


def script_backend_single_run(data1: List[Any]) -> Optional[Block]:
    """
    Simple harness: mine one block on top of genesis and validate it.
    Returns the mined Block or None if invalid.
    """
    genesis_block = Block.genesis()
    returned_block = Block.mine_block(genesis_block, data1)

    try:
        Block.is_valid_block(genesis_block, Block.from_json(returned_block.to_json()))
        print("is_valid_block: True")
        print(f"returned_block: {returned_block}")
        return returned_block
    except Exception as e:
        print(f"is_valid_block: {e}")
        return None
