# blockchain_backend/utils/config.py
# Constants only — no project imports here.

NANOSECONDS  = 1
MICROSECONDS = 1000 * NANOSECONDS
MILLISECONDS = 1000 * MICROSECONDS
SECONDS      = 1000 * MILLISECONDS  # == 1_000_000_000 ns

# Mining difficulty adjustment target (nanoseconds)
MINE_RATE = 0.1 * SECONDS

# Wallet defaults
STARTING_BALANCE = 1000  # default starting balance for a new wallet (in COIN)

# Mining reward
MINING_REWARD = 50
MINING_REWARD_ASSET = "COIN"

# Back-compat alias (remove once you’ve updated imports)
MINING_REWARD_CURRENCY = MINING_REWARD_ASSET

# Sentinel input for miner reward transactions
MINING_REWARD_INPUT = {"address": "*--official-mining-reward--*"}

# add at end
NETWORK_ID = "devnet-001"        # change per environment
GENESIS_CHECKPOINT_HASH = "genesis_hash"  # must match GENESIS_DATA["hash"]

RETARGET_WINDOW = 10   # blocks
TARGET_BLOCK_NS = 5 * SECONDS
MAX_ADJ_FACTOR = 4.0   # cap swing per retarget

import os

ROLE = os.getenv("ROLE", "ROOT").upper()           # ROOT | VALIDATOR | MINER (miner doesn’t run Flask)
ENABLE_MINING_ROUTE = os.getenv("ENABLE_MINING_ROUTE", "").lower() in ("1","true","yes")
MINER_TOKEN = os.getenv("MINER_TOKEN", None)       # shared secret for /blocks/submit



