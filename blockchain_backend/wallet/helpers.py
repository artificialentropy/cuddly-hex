# wallet/helpers.py
import json
from collections import defaultdict
from typing import Dict

from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import STARTING_BALANCE, MINING_REWARD_INPUT

WALLET_FILE = "wallets.json"
# wallet/tx_serialization.py
# blockchain_backend/wallet/tx_serialization.py
from typing import Tuple, List, Union

def serialize_signature(sig_tuple: Union[Tuple[int, int], List[int]]) -> List[str]:
    """
    Convert (r, s) ints to hex-string pair for safe JSON transport.
    """
    r, s = sig_tuple
    return [format(int(r), "x"), format(int(s), "x")]

def parse_signature(sig_list: List[Union[str, int]]) -> Tuple[int, int]:
    """
    Convert ['hex_r', 'hex_s'] or ['decimal_r','decimal_s'] to (int_r, int_s).
    Accepts ints already too.
    """
    if not sig_list or len(sig_list) < 2:
        raise ValueError("signature must contain two components")
    def to_int(x):
        if isinstance(x, int):
            return x
        xs = str(x)
        if xs.startswith("0x"):
            return int(xs, 16)
        # if looks like hex (only hex chars) treat as hex
        if all(c in "0123456789abcdefABCDEF" for c in xs):
            return int(xs, 16)
        return int(xs, 10)
    return (to_int(sig_list[0]), to_int(sig_list[1]))



def load_wallets():
    try:
        with open(WALLET_FILE, "r") as f:
            data = json.load(f)
        wallets = {}
        for addr, info in data.items():
            wallet = Wallet()
            wallet.address = addr
            wallet.public_key = info["public_key"]
            wallet.private_key = Wallet.deserialize_private_key(info["private_key"])
            wallet.balances = info.get("balances", {"COIN": int(STARTING_BALANCE)})
            wallets[addr] = wallet
        return wallets
    except FileNotFoundError:
        return {}


def save_wallets(wallets):
    data = {}
    for addr, wallet in wallets.items():
        data[addr] = {
            "private_key": Wallet.serialize_private_key(wallet.private_key),
            "public_key": wallet.public_key,
            "balances": wallet.balances,
        }
    with open(WALLET_FILE, "w") as f:
        json.dump(data, f, indent=4)


def get_wallet(address):
    wallets = load_wallets()
    wallet = wallets.get(address)
    if not wallet:
        raise Exception(f"Wallet {address} not found")
    return wallet


def update_wallet(wallet):
    wallets = load_wallets()
    wallets[wallet.address] = wallet
    save_wallets(wallets)


# -------- helpers/balance.py --------
def address_balance_from_chain(blockchain, address: str, seed: bool = False) -> Dict[str, int]:
    """
    Compute on-chain balance for `address`.

    - If seed=False (default): start at 0; only add credits/rewards; subtract debits when it sends.
    - If seed=True: start with STARTING_BALANCE for COIN.
    - Independently, if the address appears as a SENDER at least once, we treat it as an
      initialized wallet and start from STARTING_BALANCE for COIN.
    """
    bal = defaultdict(int)
    chain = getattr(blockchain, "chain", []) or []

    # First pass: did this address appear?
    seen_any = False
    seen_as_sender = False

    for block in chain[1:]:  # skip genesis
        for tx in getattr(block, "data", []) or []:
            tx_in = tx.get("input", {}) or {}
            tx_out = tx.get("output", {}) or {}

            if tx_in == MINING_REWARD_INPUT:
                if address in (tx_out or {}):
                    seen_any = True
                continue

            sender = tx_in.get("address")
            if sender == address:
                seen_any = True
                seen_as_sender = True
            if address in (tx_out or {}):
                seen_any = True

    # Decide initial seeding
    if seed or seen_as_sender:
        bal["COIN"] += int(STARTING_BALANCE)

    # Second pass: apply effects
    for block in chain[1:]:
        for tx in getattr(block, "data", []) or []:
            tx_in = tx.get("input", {}) or {}
            tx_out = tx.get("output", {}) or {}

            # Rewards
            if tx_in == MINING_REWARD_INPUT:
                if address in (tx_out or {}):
                    for cur, amt in (tx_out[address] or {}).items():
                        bal[cur] += int(amt)
                continue

            sender = tx_in.get("address")

            # Credits
            if address != sender:
                for cur, amt in (tx_out.get(address) or {}).items():
                    bal[cur] += int(amt)

            # Debits (sum to others)
            if sender == address:
                sent = defaultdict(int)
                for out_addr, curmap in (tx_out or {}).items():
                    if out_addr == sender:
                        continue
                    for cur, amt in (curmap or {}).items():
                        sent[cur] += int(amt)
                for cur, amt in sent.items():
                    bal[cur] -= int(amt)

    if not seen_any and not seed:
        return {}  # unseen address → empty (you can render {"COIN":0} in your API if preferred)

    return {k: int(v) for k, v in bal.items()}
