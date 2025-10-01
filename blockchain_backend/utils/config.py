# Time unit constants (nanoseconds up to seconds)
NANOSECONDS = 1
MICROSECONDS = 1000 * NANOSECONDS
MILLISECONDS = 1000 * MICROSECONDS
SECONDS = 1000 * MILLISECONDS

# Mining difficulty adjustment rate (in nanoseconds)
MINE_RATE = 1 * SECONDS

# Wallet defaults
STARTING_BALANCE = 1000  # default starting balance for a new wallet (in COIN)

# Mining reward
MINING_REWARD = 50  # reward amount in the default currency
MINING_REWARD_ASSET = "COIN"  # asset/currency id used for rewards

# Sentinel input for miner reward transactions (used by Transaction.is_valid_transaction)
MINING_REWARD_INPUT = {"address": "*--official-mining-reward--*"}
