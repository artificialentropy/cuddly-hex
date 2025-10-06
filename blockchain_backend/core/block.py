# core/block.py
import time
from statistics import median
from typing import Any, Dict, List, Optional
import os
from blockchain_backend.utils.config import SECONDS, NETWORK_ID
from blockchain_backend.utils.crypto_hash import crypto_hash
from blockchain_backend.utils.hex_to_binary import hex_to_binary
from blockchain_backend.utils.merkle import merkle_root
from blockchain_backend.utils.helpers import normalize_timestamp

# Genesis block (static, shared by all nodes)
GENESIS_DATA: Dict[str, Any] = {
    "timestamp": 1,                    # ns (arbitrary for genesis)
    "last_hash": "genesis_last_hash",
    "hash": "genesis_hash",
    "data": [],                        # type: List[Any]
    "difficulty": 3,
    "nonce": 0,                        # must be int; mining increments this
    "merkle": merkle_root([]),
    "height": 0,
}

MAX_FUTURE_SKEW_NS = 30 * SECONDS     # allow ~30s clock skew

# core/block.py (inside Block class or module-level)


# default params (override via env)
MIN_DIFFICULTY = int(os.getenv("MIN_DIFFICULTY", "1"))
MAX_DIFFICULTY = int(os.getenv("MAX_DIFFICULTY", "64"))
DIFFICULTY_STEP_UP = int(os.getenv("DIFFICULTY_STEP_UP", "1"))
DIFFICULTY_STEP_DOWN = int(os.getenv("DIFFICULTY_STEP_DOWN", "1"))
# MINE_RATE should be in nanoseconds (use env MINE_RATE_NS) or fall back to seconds->ns
MINE_RATE_NS = int(os.getenv("MINE_RATE_NS", str(int(float(os.getenv("MINE_RATE", "4")) * 1e9))))

def _median_time_past(recent_blocks: List["Block"]) -> int:
    ts = [b.timestamp for b in recent_blocks[-11:]]  # last 11 blocks
    return int(median(ts)) if ts else 0


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
        merkle: Optional[str] = None,
        height: Optional[int] = None
    ):
        self.timestamp = int(timestamp)
        self.last_hash = str(last_hash)
        self.hash = str(hash)
        self.data = data
        self.difficulty = int(difficulty)
        self.nonce = int(nonce)
        self.merkle = merkle if merkle is not None else merkle_root(data)
        self.height = height  # optional; set by blockchain on append

    def __repr__(self) -> str:
        return (
            "Block("
            f"timestamp: {self.timestamp}, "
            f"last_hash: {self.last_hash}, "
            f"hash: {self.hash}, "
            f"data: {self.data}, "
            f"difficulty: {self.difficulty}, "
            f"nonce: {self.nonce}, "
            f"merkle: {self.merkle}, "
            f"height: {self.height})"
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
            and self.merkle == other.merkle
            and self.height == other.height
        )

# blockchain_core.py (where you produce chain JSON)
    def to_json(self):
        """
        Serialize this Block instance as a JSON-serializable dict.
        IMPORTANT: do NOT iterate or reference self.chain here — that belongs to Blockchain.
        """
        # safe get attributes with sensible defaults
        return {
            "version": getattr(self, "version", 1),
            "last_hash": getattr(self, "last_hash", None),
            "hash": getattr(self, "hash", None),
            "merkle": getattr(self, "merkle", None),
            "timestamp": int(getattr(self, "timestamp", 0)) if getattr(self, "timestamp", None) is not None else 0,
            "difficulty": getattr(self, "difficulty", None),
            "nonce": getattr(self, "nonce", None),
            "data": getattr(self, "data", []) or [],
        }

    
    def to_header(self, data):
        return {
            "last_hash": self.hash,
            "difficulty": self.difficulty,
            "timestamp": int(time.time_ns()),
            "merkle": merkle_root(data)
        }

    @staticmethod
    def from_json(block_json: Dict[str, Any]) -> "Block":
        """Deserialize a block's json representation back into a block instance."""
        return Block(**block_json)

    @staticmethod
    def genesis() -> "Block":
        """Generate the genesis block."""
        return Block(**GENESIS_DATA)

    
    def adjust_difficulty(parent_block: Optional["Block"], now_timestamp_ns: int) -> int:
        """
        parent_block: the previous Block (may be None for genesis)
        now_timestamp_ns: current timestamp in ns
        Returns adjusted difficulty (ensures bounds and step +/- 1).
        """
        try:
            pd = int(parent_block.difficulty) if (parent_block is not None and getattr(parent_block, "difficulty", None) is not None) else MIN_DIFFICULTY
        except Exception:
            pd = MIN_DIFFICULTY

        pd = max(pd, MIN_DIFFICULTY)

        # If mine rate not configured, don't change difficulty
        if MINE_RATE_NS <= 0:
            return pd

        parent_ts = int(parent_block.timestamp) if (parent_block is not None and getattr(parent_block, "timestamp", None) is not None) else 0

        if (now_timestamp_ns - parent_ts) < MINE_RATE_NS:
            return min(pd + DIFFICULTY_STEP_UP, MAX_DIFFICULTY)
        else:
            return max(pd - DIFFICULTY_STEP_DOWN, MIN_DIFFICULTY)


    @staticmethod
    def mine_block(last_block: "Block", data: List[Any]) -> "Block":
        """
        Mine a block based on the given last_block and data, until a block hash
        is found that meets the leading 0's proof-of-work requirement.
        Hash preimage includes NETWORK_ID and merkle root.
        """
        timestamp = time.time_ns()
        last_hash = last_block.hash
        difficulty = Block.adjust_difficulty(last_block, timestamp)
        nonce = 0
        merkle = merkle_root(data)

        h = crypto_hash(NETWORK_ID, timestamp, last_hash, data, difficulty, nonce, merkle)
        target_prefix = "0" * difficulty

        while hex_to_binary(h)[:difficulty] != target_prefix:
            nonce += 1
            timestamp = time.time_ns()
            difficulty = Block.adjust_difficulty(last_block, timestamp)
            target_prefix = "0" * difficulty
            h = crypto_hash(NETWORK_ID, timestamp, last_hash, data, difficulty, nonce, merkle)


        return Block(timestamp, last_hash, h, data, difficulty, nonce, merkle)

    @staticmethod
    def is_valid_block(last_block: "Block", block: "Block") -> None:
        """
        Validate block by enforcing the following rules:
          - proper last_hash linkage
          - PoW target satisfied
          - difficulty only adjusts by ±1
          - timestamp sanity (future skew + median-time-past)
          - merkle root matches data
          - hash matches exact preimage (including NETWORK_ID & merkle)
        """
        # Linkage
        if block.last_hash != last_block.hash:
            raise Exception("The block last_hash must be correct")

        # PoW requirement
        if hex_to_binary(block.hash)[: block.difficulty] != "0" * block.difficulty:
            raise Exception("The proof of work requirement was not met")

        # Difficulty step ±1
        if abs(last_block.difficulty - block.difficulty) > 1:
            raise Exception("The block difficulty must only adjust by 1")

        # Timestamp sanity
        now = time.time_ns()
        if (block.timestamp - now) > MAX_FUTURE_SKEW_NS:
            raise Exception("Block timestamp too far in the future")

        # Median-time-past (with just last_block as minimal input; better if caller passes last N)
        mtp = _median_time_past([last_block])
        if block.timestamp <= mtp:
            raise Exception("Block timestamp <= median past")

        # Merkle root integrity
        if block.merkle != merkle_root(block.data):
            raise Exception("Invalid merkle root")

        # Hash must match preimage (include NETWORK_ID & merkle)
        reconstructed_hash = crypto_hash(
            NETWORK_ID, block.timestamp, block.last_hash, block.data, block.difficulty, block.nonce, block.merkle
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
