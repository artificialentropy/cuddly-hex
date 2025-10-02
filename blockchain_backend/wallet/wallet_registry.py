# wallet_registry.py
from threading import Lock

class WalletRegistry:
    """
    Global registry for Wallet instances.
    Thread-safe for multi-threaded Flask use.
    """
    def __init__(self):
        self._wallets = {}  # {address: Wallet instance}
        self._lock = Lock()

    def add_wallet(self, wallet):
        with self._lock:
            self._wallets[wallet.address] = wallet

    def get_wallet(self, address):
        with self._lock:
            return self._wallets.get(address)

    def all_wallets(self):
        with self._lock:
            return list(self._wallets.values())

    def addresses(self):
        with self._lock:
            return list(self._wallets.keys())
    
    def get_wallet_by_label(self, label):
        return self._wallets.get(label)

# Create a singleton instance
REGISTRY = WalletRegistry()
