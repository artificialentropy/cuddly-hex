import json
from blockchain_backend.wallet.wallet import Wallet

WALLET_FILE = "wallets.json"

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
            wallet.balances = info.get("balances", {"COIN": 1000})
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
            "balances": wallet.balances
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
