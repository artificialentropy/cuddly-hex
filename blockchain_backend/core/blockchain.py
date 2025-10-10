# blockchain_backend/core/blockchain.py
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Union

from blockchain_backend.utils.config import GENESIS_CHECKPOINT_HASH
from blockchain_backend.core.block import Block as bp
from blockchain_backend.wallet.transaction import Transaction
from blockchain_backend.wallet.wallet import Wallet
from blockchain_backend.utils.config import (
    MINING_REWARD_INPUT,
    MINING_REWARD,
    MINING_REWARD_ASSET,
)

BlockOrJson = Union[bp, Dict[str, Any]]
from blockchain_backend.utils.config import RETARGET_WINDOW, TARGET_BLOCK_NS, MAX_ADJ_FACTOR


class Blockchain:
    """
    Blockchain: a public ledger of transactions.
    """

    def __init__(self, store: Optional[Any] = None) -> None:
        """
        If `store` (LevelDBStore) is provided, attempt to load blocks from it.
        Otherwise initialize with genesis.
        """
        self.store = store
        self.chain: List[bp] = []

        if self.store is not None:
            try:
                blocks = []
                # Prefer the height-indexed iterator for strict ordering
                try:
                    for blk in self.store.iter_by_height():
                        if isinstance(blk, dict):
                            blocks.append(blk)
                except Exception:
                    # Fallback to legacy iterator if height index missing
                    try:
                        for blk in self.store.iter_blocks():
                            if isinstance(blk, dict):
                                blocks.append(blk)
                    except Exception:
                        blocks = []

                if blocks:
                    # If height fields exist, sort by them; otherwise keep iterator order
                    try:
                        blocks = sorted(blocks, key=lambda b: int(b.get("height", 0)))
                    except Exception:
                        pass
                    self.chain = [bp.from_json(b) for b in blocks]
                    print(f"[Blockchain] loaded {len(self.chain)} blocks from LevelDB ({getattr(self.store,'path',None)})")
                else:
                    self.chain = [bp.genesis()]
                    print("[Blockchain] LevelDB present but no blocks found; using genesis")
            except Exception as e:
                # fallback to genesis on any error
                print(f"[Blockchain] failed to load from LevelDB store: {e}")
                self.chain = [bp.genesis()]
        else:
            self.chain = [bp.genesis()]

    def _retarget(self):
        n = len(self.chain)
        if n < RETARGET_WINDOW + 1:
            return self.chain[-1].difficulty
        window = self.chain[-RETARGET_WINDOW:]
        span = window[-1].timestamp - window[0].timestamp
        avg = span / RETARGET_WINDOW
        last_diff = self.chain[-1].difficulty
        ratio = max(1 / MAX_ADJ_FACTOR, min(MAX_ADJ_FACTOR, avg / TARGET_BLOCK_NS))
        new_diff = max(1, int(round(last_diff / ratio)))
        return new_diff

    # -------------------------
    # Basic operations
    # -------------------------
    def add_block(self, data: List[Dict[str, Any]]) -> bp:
        """
        Append a mined block containing 'data' (tx json dicts).
        Returns the new block.
        """
        last = self.chain[-1]
        class _Fake: pass
        fake = _Fake()
        fake.timestamp = last.timestamp
        fake.hash = last.hash
        fake.difficulty = self._retarget()

        b = bp.mine_block(fake, data)
        b.height = len(self.chain)
        self.chain.append(b)

        # persist to LevelDB if store present
        # core/blockchain.py -> inside add_block (after self.store.set_height... block persisted)
        # Persist assets meta as well (best-effort)
        # if self.store is not None:
        #     try:
        #         from blockchain_backend.app.app_state import rebuild_assets_from_chain, ASSETS
        #         # update in-memory assets (if needed) then persist
        #         rebuild_assets_from_chain(self.chain)
        #         meta = {}
        #         for aid, asset_obj in ASSETS.items():
        #             meta[aid] = {
        #                 "owner": getattr(asset_obj, "owner", None),
        #                 "price": getattr(asset_obj, "price", 0),
        #                 "currency": getattr(asset_obj, "currency", "COIN"),
        #                 "transferable": getattr(asset_obj, "transferable", True),
        #             }
        #         try:
        #             self.store.put_meta("assets", meta)
        #         except Exception:
        #             # fallback direct DB put
        #             try:
        #                 dbh = getattr(self.store, "db", None)
        #                 if dbh is not None:
        #                     dbh.put(getattr(self.store, "META_KEY_PREFIX", b"m:") + b"assets", json.dumps(meta, separators=(",", ":")).encode("utf-8"))
        #             except Exception:
        #                 pass
        #     except Exception:
        #         pass

                # ---- persist the new block to LevelDB if store present ----
        if self.store is not None:
            try:
                # Prepare block JSON
                bj = b.to_json() if hasattr(b, "to_json") else dict(b)
                # Ensure height present
                bj["height"] = int(getattr(b, "height", len(self.chain) - 1))

                # Preferred: use store API if available
                try:
                    if hasattr(self.store, "put_block"):
                        # high-level store API
                        self.store.put_block(bj)
                    else:
                        # fallback to raw db handle if available
                        dbh = getattr(self.store, "db", None)
                        if dbh is not None:
                            with dbh.write_batch() as wb:
                                blk_key = getattr(self.store, "BLOCK_KEY_PREFIX", b"b:") + bj["hash"].encode("utf-8")
                                wb.put(blk_key, json.dumps(bj, separators=(",", ":")).encode("utf-8"))
                                # height index => hash
                                height_idx_pref = getattr(self.store, "HEIGHT_INDEX_PREFIX", b"h:")
                                wb.put(height_idx_pref + int(bj["height"]).to_bytes(8, "big", signed=False), bj["hash"].encode("utf-8"))
                                # update top height pointer
                                hk = getattr(self.store, "HEIGHT_KEY", b"height")
                                wb.put(hk, int(bj["height"]).to_bytes(8, "big", signed=False))
                        else:
                            # last fallback: try generic put method if present
                            if hasattr(self.store, "put"):
                                key = getattr(self.store, "BLOCK_KEY_PREFIX", b"b:") + bj["hash"].encode("utf-8")
                                val = json.dumps(bj, separators=(",", ":")).encode("utf-8")
                                try:
                                    self.store.put(key, val)
                                except Exception:
                                    pass

                    # Update height via API if present
                    if hasattr(self.store, "set_height"):
                        try:
                            self.store.set_height(int(bj["height"]))
                        except Exception:
                            pass

                except Exception as inner_e:
                    # fallback to raw db handle if store API failed
                    dbh = getattr(self.store, "db", None)
                    if dbh is not None:
                        try:
                            with dbh.write_batch() as wb:
                                blk_key = getattr(self.store, "BLOCK_KEY_PREFIX", b"b:") + bj["hash"].encode("utf-8")
                                wb.put(blk_key, json.dumps(bj, separators=(",", ":")).encode("utf-8"))
                                height_idx_pref = getattr(self.store, "HEIGHT_INDEX_PREFIX", b"h:")
                                wb.put(height_idx_pref + int(bj["height"]).to_bytes(8, "big", signed=False), bj["hash"].encode("utf-8"))
                                hk = getattr(self.store, "HEIGHT_KEY", b"height")
                                wb.put(hk, int(bj["height"]).to_bytes(8, "big", signed=False))
                        except Exception as e2:
                            print("[Blockchain] failed to persist new block via db handle:", e2)
                    else:
                        print("[Blockchain] store.put_block failed and no db handle available:", inner_e)
            except Exception as e:
                print("[Blockchain] error while persisting new block (non-fatal):", e)



        return b

    def __repr__(self) -> str:
        return f"Blockchain: {self.chain}"

    # -------------------------
    # Serialization
    # -------------------------
    def to_json(self):
        out = []
        for idx, block in enumerate(self.chain):
            bj = block.to_json() if hasattr(block, "to_json") else dict(block)
            bj["height"] = idx
            try:
                ts = int(bj.get("timestamp", 0) or 0)
                if ts > 10**15:
                    bj["timestamp"] = ts // 1_000_000_000
                elif ts > 10**12:
                    bj["timestamp"] = ts // 1_000_000
                else:
                    bj["timestamp"] = ts
            except Exception:
                pass
            out.append(bj)
        return out

    @staticmethod
    def from_json(chain_json: Sequence[Dict[str, Any]]) -> "Blockchain":
        bc = Blockchain()
        bc.chain = [bp.from_json(bj) for bj in chain_json]
        return bc

    # -------------------------
    # Chain replacement
    # -------------------------
    
    def replace_chain(self, incoming: Sequence[BlockOrJson]) -> None:
        """
        Replace the local chain with the incoming one if the following applies:
        - The incoming chain is longer than the local one.
        - The incoming chain is formatted properly.
        Accepts a sequence of Block objects or block-json dicts.
        Persists the incoming chain into LevelDB (if available) after validation.
        """
        new_chain: List[bp] = []
        for item in incoming:
            if isinstance(item, bp):
                new_chain.append(item)
            elif isinstance(item, dict):
                new_chain.append(bp.from_json(item))
            else:
                raise Exception(f"Cannot replace. Unsupported block type: {type(item)}")

        if len(new_chain) <= len(self.chain):
            raise Exception("Cannot replace. The incoming chain must be longer.")

        try:
            Blockchain.is_valid_chain(new_chain)
        except Exception as e:
            raise Exception(f"Cannot replace. The incoming chain is invalid: {e}")

        # Adopt the new chain in-memory
        self.chain = new_chain

        # Persist replaced chain's blocks into store (best-effort).
        if self.store is not None:
            try:
                persisted = 0
                # prefer LevelDB batch if available
                db_handle = getattr(self.store, "db", None)
                if db_handle is not None:
                    with db_handle.write_batch() as wb:
                        # write each block and height index
                        for idx, b in enumerate(self.chain):
                            bj = b.to_json()
                            # ensure height present and correct
                            bj["height"] = int(getattr(b, "height", idx))
                            key = getattr(self.store, "BLOCK_KEY_PREFIX", b"b:") + bj["hash"].encode("utf-8")
                            wb.put(key, json.dumps(bj, separators=(",", ":")).encode("utf-8"))
                            # height index entry
                            prefix = getattr(self.store, "HEIGHT_INDEX_PREFIX", b"h:")
                            wb.put(prefix + int(bj["height"]).to_bytes(8, "big", signed=False), bj["hash"].encode("utf-8"))
                            persisted += 1
                        # set top height
                        last_h = int(self.chain[-1].height)
                        hk = getattr(self.store, "HEIGHT_KEY", b"height")
                        wb.put(hk, last_h.to_bytes(8, "big", signed=False))
                else:
                    # fallback: use store API methods
                    for idx, b in enumerate(self.chain):
                        bj = b.to_json()
                        if "height" not in bj or bj.get("height") is None:
                            bj["height"] = int(getattr(b, "height", idx))
                        self.store.put_block(bj)
                        try:
                            self.store.set_height(bj["height"])
                        except Exception:
                            pass
                        persisted += 1

                print(f"[Blockchain] persisted {persisted} blocks to LevelDB")

                # Rebuild and persist ASSETS metadata (best-effort)
                try:
                    from blockchain_backend.app.app_state import rebuild_assets_from_chain, ASSETS
                    rebuild_assets_from_chain(self.chain)
                    # persist ASSETS summary so other workers can fast-load
                    try:
                        meta = {}
                        for aid, asset_obj in ASSETS.items():
                            meta[aid] = {
                                "owner": getattr(asset_obj, "owner", None),
                                "price": getattr(asset_obj, "price", 0),
                                "currency": getattr(asset_obj, "currency", "COIN"),
                                "transferable": getattr(asset_obj, "transferable", True),
                            }
                        # store meta under key "assets"
                        try:
                            self.store.put_meta("assets", meta)
                        except Exception:
                            # best-effort: try to write directly if db handle present
                            try:
                                dbh = getattr(self.store, "db", None)
                                if dbh is not None:
                                    dbh.put(getattr(self.store, "META_KEY_PREFIX", b"m:") + b"assets", json.dumps(meta, separators=(",", ":")).encode("utf-8"))
                            except Exception:
                                pass
                    except Exception as e:
                        print("[Blockchain] failed to persist assets meta (non-fatal):", e)
                except Exception:
                    # ignore if app_state not importable (e.g. unit tests)
                    pass

            except Exception as e:
                print(f"[Blockchain] failed to persist replaced chain to LevelDB (non-fatal): {e}")
    # -------------------------
    # Validation
    # -------------------------
    @staticmethod
    def is_valid_chain(chain: Sequence[bp]) -> None:
        if not chain:
            raise Exception("Empty chain is invalid")

        if chain[0] != bp.genesis() or getattr(chain[0], "hash", None) != GENESIS_CHECKPOINT_HASH:
            raise Exception("The genesis block must match network checkpoint")

        for i in range(1, len(chain)):
            block = chain[i]
            last_block = chain[i - 1]
            bp.is_valid_block(last_block, block)

        Blockchain.is_valid_transaction_chain(chain)

    @staticmethod
    def _normalize_output_entry(entry: Any) -> Dict[str, int]:
        if isinstance(entry, dict):
            out: Dict[str, int] = {}
            for k, v in entry.items():
                try:
                    out[str(k)] = int(v)
                except Exception:
                    continue
            return out
        try:
            return {MINING_REWARD_ASSET: int(entry)}
        except Exception:
            return {}

    @staticmethod
    def is_valid_transaction_chain(chain: Sequence[bp]) -> None:
        seen_tx_ids = set()

        for i, block in enumerate(chain):
            has_mining_reward = False

            for tx_json in block.data:
                transaction = Transaction.from_json(tx_json)

                if transaction.id in seen_tx_ids:
                    raise Exception(f"Transaction {transaction.id} is not unique")
                seen_tx_ids.add(transaction.id)

                if transaction.input == MINING_REWARD_INPUT:
                    if has_mining_reward:
                        raise Exception(
                            "There can only be one mining reward per block. "
                            f"Block hash: {getattr(block, 'hash', None)}"
                        )
                    outputs = transaction.output or {}
                    reward_ok = False
                    for _addr, out_entry in outputs.items():
                        entry_map = Blockchain._normalize_output_entry(out_entry)
                        if entry_map.get(MINING_REWARD_ASSET, 0) == int(MINING_REWARD):
                            reward_ok = True
                            break
                    if not reward_ok:
                        raise Exception(
                            f"Invalid mining reward in block {getattr(block, 'hash', None)}; expected {MINING_REWARD} {MINING_REWARD_ASSET}"
                        )
                    has_mining_reward = True
                    continue

                historic = Blockchain()
                historic.chain = list(chain[0:i])  # blocks before current block

                input_snapshot = transaction.input or {}
                addr = input_snapshot.get("address")

                if isinstance(input_snapshot, dict) and "balances" in input_snapshot:
                    balances = input_snapshot.get("balances") or {}
                    if not isinstance(balances, dict):
                        raise Exception(f"Transaction {transaction.id} has invalid balances snapshot")
                    for currency_id, snapshot_amount in balances.items():
                        hb = Wallet.calculate_balance(historic, addr, currency=str(currency_id))
                        if int(hb) != int(snapshot_amount):
                            raise Exception(
                                f"Transaction {transaction.id} invalid snapshot for {currency_id}: historic {hb} != input {snapshot_amount}"
                            )
                else:
                    if "amount" not in input_snapshot:
                        raise Exception(f"Transaction {transaction.id} missing input snapshot or amount")
                    hb = Wallet.calculate_balance(historic, addr)
                    if int(hb) != int(input_snapshot["amount"]):
                        raise Exception(
                            f"Transaction {transaction.id} has an invalid input amount (legacy): historic {hb} != input.amount {input_snapshot['amount']}"
                        )

                Transaction.is_valid_transaction(transaction)


def script_blockchain_init(
    blockchain: Blockchain,
    server_start: bool,
    custom_data: Optional[List[Dict[str, Any]]] = None,
):
    if not server_start:
        return None

    miner_wallet = Wallet(blockchain)
    metadata = {"custom_data": custom_data} if custom_data is not None else None

    try:
        reward_tx = Transaction.reward_transaction(
            miner_wallet,
            currency=MINING_REWARD_ASSET,
            amount=MINING_REWARD,
            metadata=metadata,
        )
    except TypeError:
        try:
            reward_tx = Transaction.reward_transaction(miner_wallet, metadata=metadata)
        except TypeError:
            reward_tx = Transaction.reward_transaction(miner_wallet)

    new_block = blockchain.add_block([reward_tx.to_json()])
    return new_block, blockchain
