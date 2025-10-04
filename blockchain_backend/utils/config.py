# blockchain_backend/utils/config.py
# Constants only — no project imports here.

NANOSECONDS  = 1
MICROSECONDS = 1000 * NANOSECONDS
MILLISECONDS = 1000 * MICROSECONDS
SECONDS      = 1000 * MILLISECONDS  # == 1_000_000_000 ns

# Mining difficulty adjustment target (nanoseconds)
MINE_RATE_NS = 5 * SECONDS

# Wallet defaults
STARTING_BALANCE = 1000  # default starting balance for a new wallet (in COIN)

# Mining reward
MINING_REWARD = 50
MINING_REWARD_ASSET = "COIN"

# Back-compat alias (remove once you’ve updated imports)
MINING_REWARD_CURRENCY = MINING_REWARD_ASSET

# Sentinel input for miner reward transactions
MINING_REWARD_INPUT = {"address": "*--official-mining-reward--*"}
