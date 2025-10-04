# wallet_registry.py
from __future__ import annotations

from threading import RLock
from typing import Dict, List, Optional, Iterable, Set, Callable, Any


class WalletRegistry:
    """
    Thread-safe in-memory wallet registry.

    - Primary index: address -> Wallet
    - Label index:   label -> address  (avoids stale Wallet refs)
    - A wallet can have multiple labels; labels are unique.
    """

    def __init__(self):
        self._wallets: Dict[str, Any] = {}        # {address: Wallet}
        self._labels: Dict[str, str] = {}         # {label: address}
        self._addr_to_labels: Dict[str, Set[str]] = {}  # {address: {label, ...}}
        self._lock = RLock()

    # -----------------------
    # Core operations
    # -----------------------
    def add_wallet(self, wallet, label: Optional[str] = None) -> None:
        """
        Add (or replace) a wallet by address. Optionally assign a label.
        If replacing an existing wallet with same address, labels are preserved.
        """
        with self._lock:
            addr = wallet.address
            self._wallets[addr] = wallet
            self._addr_to_labels.setdefault(addr, set())
            if label:
                # If label was already pointing to some other address, move it.
                self._assign_label_nolock(label, addr)

    def get_wallet(self, address: str):
        with self._lock:
            return self._wallets.get(address)

    def get_wallet_by_label(self, label: str):
        """Return Wallet for a given label, or None."""
        with self._lock:
            addr = self._labels.get(label)
            return self._wallets.get(addr) if addr else None

    def all_wallets(self) -> List[Any]:
        """Snapshot list of all wallets."""
        with self._lock:
            return list(self._wallets.values())

    def addresses(self) -> List[str]:
        with self._lock:
            return list(self._wallets.keys())

    # -----------------------
    # Labels
    # -----------------------
    def assign_label(self, label: str, address: str) -> None:
        """
        Assign (or reassign) a label to an address.
        Raises if address not present.
        """
        with self._lock:
            if address not in self._wallets:
                raise ValueError(f"Unknown address: {address}")
            self._assign_label_nolock(label, address)

    def remove_label(self, label: str) -> None:
        """Remove a label mapping (no effect on the wallet)."""
        with self._lock:
            addr = self._labels.pop(label, None)
            if addr:
                labels = self._addr_to_labels.get(addr)
                if labels and label in labels:
                    labels.remove(label)
                    if not labels:
                        self._addr_to_labels.pop(addr, None)

    def labels_for(self, address: str) -> List[str]:
        with self._lock:
            return list(self._addr_to_labels.get(address, set()))

    def get_label(self, address: str) -> Optional[str]:
        """
        Return one label for the address if present (arbitrary if multiple).
        Prefer labels_for() when you need all.
        """
        with self._lock:
            labels = self._addr_to_labels.get(address)
            if not labels:
                return None
            # Return any stable choice (sorted for determinism)
            return sorted(labels)[0]

    # -----------------------
    # Removal / housekeeping
    # -----------------------
    def remove_wallet(self, address: str) -> None:
        """
        Remove a wallet by address and clean any labels pointing to it.
        """
        with self._lock:
            self._wallets.pop(address, None)
            labels = self._addr_to_labels.pop(address, set())
            for lbl in labels:
                self._labels.pop(lbl, None)

    def clear(self) -> None:
        """Wipe registry (useful in tests)."""
        with self._lock:
            self._wallets.clear()
            self._labels.clear()
            self._addr_to_labels.clear()

    # -----------------------
    # Convenience
    # -----------------------
    def ensure_wallet(
        self,
        address: str,
        factory: Callable[[], Any],
        label: Optional[str] = None,
    ):
        """
        Get existing wallet by address; if missing, create with factory() and (optionally) label it.
        """
        with self._lock:
            w = self._wallets.get(address)
            if w is None:
                w = factory()
                if getattr(w, "address", None) != address:
                    # If caller wants a specific address, ensure the factory cooperates
                    # or set it explicitly (only if your Wallet allows it).
                    try:
                        w.address = address  # may be disallowed in your model; adjust as needed
                    except Exception:
                        pass
                self._wallets[address] = w
                self._addr_to_labels.setdefault(address, set())
            if label:
                self._assign_label_nolock(label, address)
            return w

    def __contains__(self, address: str) -> bool:
        with self._lock:
            return address in self._wallets

    def __len__(self) -> int:
        with self._lock:
            return len(self._wallets)

    # -----------------------
    # Internal helpers
    # -----------------------
    def _assign_label_nolock(self, label: str, address: str) -> None:
        """
        (Internal) Assign label -> address and keep reverse map in sync.
        Caller must hold the lock.
        """
        # Remove old reverse mapping if label already existed
        old_addr = self._labels.get(label)
        if old_addr and old_addr != address:
            rev = self._addr_to_labels.get(old_addr)
            if rev and label in rev:
                rev.remove(label)
                if not rev:
                    self._addr_to_labels.pop(old_addr, None)

        self._labels[label] = address
        self._addr_to_labels.setdefault(address, set()).add(label)


# singleton
REGISTRY = WalletRegistry()
