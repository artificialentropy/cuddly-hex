# blockchain_backend/utils/config.py
# Constants only — no project imports here.

NANOSECONDS  = 1
MICROSECONDS = 1000 * NANOSECONDS
MILLISECONDS = 1000 * MICROSECONDS
SECONDS      = 1000 * MILLISECONDS

# Mining difficulty adjustment rate (in nanoseconds)
MINE_RATE = 5 * SECONDS

# Wallet defaults
STARTING_BALANCE = 1000  # default starting balance for a new wallet (in COIN)

# Mining reward
MINING_REWARD = 50                 # reward amount
MINING_REWARD_CURRENCY = "COIN"    # currency id used for rewards

# Sentinel input for miner reward transactions
MINING_REWARD_INPUT = {"address": "*--official-mining-reward--*"}
MINING_REWARD_ASSET = "COIN"