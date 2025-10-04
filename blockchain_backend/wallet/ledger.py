# wallet/ledger.py
from collections import defaultdict
from typing import Dict, Any, DefaultDict
from blockchain_backend.utils.config import STARTING_BALANCE, MINING_REWARD_INPUT

CurrencyMap = Dict[str, int]
Ledger = DefaultDict[str, DefaultDict[str, int]]  # address -> currency -> balance


def _ensure_seed(ledger: Ledger, address: str) -> None:
    """Seed a newly-seen address with the configured starting balance (COIN)."""
    if "COIN" not in ledger[address]:
        ledger[address]["COIN"] = int(STARTING_BALANCE)


def build_ledger_from_chain(blockchain) -> Ledger:
    """
    Build a balance sheet from the current chain.
    Per address, per currency. Seeds addresses with STARTING_BALANCE on first sight.
    """
    ledger: Ledger = defaultdict(lambda: defaultdict(int))

    # Genesis has no economic effect
    for block in getattr(blockchain, "chain", [])[1:]:
        for tx in getattr(block, "data", []) or []:
            tx_in: Dict[str, Any] = tx.get("input", {}) or {}
            tx_out: Dict[str, Dict[str, int]] = tx.get("output", {}) or {}

            # Reward (mint): credit outputs directly
            if tx_in == MINING_REWARD_INPUT:
                for out_addr, cm in (tx_out or {}).items():
                    _ensure_seed(ledger, out_addr)
                    for cur, amt in (cm or {}).items():
                        ledger[out_addr][cur] += int(amt)
                continue

            sender = tx_in.get("address")
            if sender:
                _ensure_seed(ledger, sender)

            # Credits to recipients (excluding sender's change)
            for out_addr, cm in (tx_out or {}).items():
                if out_addr == sender:
                    continue
                _ensure_seed(ledger, out_addr)
                for cur, amt in (cm or {}).items():
                    ledger[out_addr][cur] += int(amt)

            # Debits for sender: sum amounts to others
            if sender:
                sent = defaultdict(int)
                for out_addr, cm in (tx_out or {}).items():
                    if out_addr == sender:
                        continue
                    for cur, amt in (cm or {}).items():
                        sent[cur] += int(amt)
                for cur, amt in sent.items():
                    ledger[sender][cur] -= int(amt)

    return ledger


def enforce_sufficient_funds(tx: Dict[str, Any], ledger: Ledger) -> None:
    """
    Raise if the sender doesn't have enough on-chain balance for the amounts
    sent to OTHER addresses (per currency). Zero-sum and reward txs are allowed.
    """
    tx_in: Dict[str, Any] = tx.get("input", {}) or {}
    tx_out: Dict[str, Dict[str, int]] = tx.get("output", {}) or {}

    # Reward mints are fine
    if tx_in == MINING_REWARD_INPUT:
        return

    sender = tx_in.get("address")
    if not sender:
        return  # nothing to enforce if there's no economic sender

    # Zero-sum metadata tx (e.g., listings) — carry no currency movement
    has_any_amount = any(int(v) for addr_map in (tx_out or {}).values() for v in (addr_map or {}).values())
    if not has_any_amount:
        return

    _ensure_seed(ledger, sender)

    # Compute per-currency amounts sent to others
    sent = defaultdict(int)
    for out_addr, cm in (tx_out or {}).items():
        if out_addr == sender:
            continue
        for cur, amt in (cm or {}).items():
            sent[cur] += int(amt)

    # Enforce per-currency sufficient balance
    for cur, amt in sent.items():
        if ledger[sender][cur] < amt:
            raise Exception(f"Insufficient on-chain funds for {cur}: have={ledger[sender][cur]} need={amt}")


def apply_tx_to_ledger(tx: Dict[str, Any], ledger: Ledger) -> None:
    """Mutate ledger by applying the tx effects (for reservation or block assembly)."""
    tx_in: Dict[str, Any] = tx.get("input", {}) or {}
    tx_out: Dict[str, Dict[str, int]] = tx.get("output", {}) or {}

    if tx_in == MINING_REWARD_INPUT:
        for out_addr, cm in (tx_out or {}).items():
            _ensure_seed(ledger, out_addr)
            for cur, amt in (cm or {}).items():
                ledger[out_addr][cur] += int(amt)
        return

    sender = tx_in.get("address")

    # Credits to recipients (excluding sender's change)
    for out_addr, cm in (tx_out or {}).items():
        if out_addr == sender:
            continue
        _ensure_seed(ledger, out_addr)
        for cur, amt in (cm or {}).items():
            ledger[out_addr][cur] += int(amt)

    # Debits for sender: sum amounts to others
    if sender:
        _ensure_seed(ledger, sender)
        sent = defaultdict(int)
        for out_addr, cm in (tx_out or {}).items():
            if out_addr == sender:
                continue
            for cur, amt in (cm or {}).items():
                sent[cur] += int(amt)
        for cur, amt in sent.items():
            ledger[sender][cur] -= int(amt)
