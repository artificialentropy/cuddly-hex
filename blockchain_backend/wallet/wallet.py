import json
import uuid

from blockchain_backend.utils.config import STARTING_BALANCE
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class Wallet:
    """
    An individual wallet for a miner.
    Keeps track of the miner's balance.
    Allows a miner to authorize transactions.
    """
    def __init__(self, blockchain=None):
        self.blockchain = blockchain

        # Multi-currency balances
        self.balances = {"COIN": STARTING_BALANCE}
        self._balance = STARTING_BALANCE  # legacy compatibility

        # Generate key pair directly
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()

        # Short address
        self.address = str(uuid.uuid4())[0:8]

        # Serialize pubkey into PEM for transport
        self.serialize_public_key()


    @property
    def balance(self):
        """Legacy single-coin balance getter (COIN)."""
        return self.balances.get("COIN", 0)


    def update_balance(self, currency: str, amount: int):
        """Update specific currency balance safely."""
        self.balances[currency] = self.balances.get(currency, 0) + int(amount)

    def sign(self, data):
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return decode_dss_signature(
            self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        )

    def serialize_public_key(self):
        """Reset the public key to its serialized PEM string (only if not already)."""
        if not isinstance(self.public_key, str):
            self.public_key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")


    @staticmethod
    def verify(public_key, data, signature):
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        deserialized_public_key = serialization.load_pem_public_key(
            public_key.encode("utf-8"), default_backend()
        )
        r, s = signature
        try:
            deserialized_public_key.verify(
                encode_dss_signature(r, s),
                payload,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


    # @property
    # def balance(self):
    #     return Wallet.calculate_balance(self.blockchain, self.address)

    # @staticmethod
    # def calculate_balance(blockchain, address):
    #     """
    #     Calculate the balance of the given address considering the transaction
    #     data within the blockchain.

    #     The balance is found by adding the output values that belong to the
    #     address since the most recent transaction by that address.
    #     """
    #     balance = STARTING_BALANCE

    #     if not blockchain:
    #         return balance

    #     for block in blockchain.chain:
    #         for transaction in block.data:
    #             if transaction["input"]["address"] == address:
    #                 # Any time the address conducts a new transaction it resets
    #                 # its balance
    #                 balance = transaction["output"][address]
    #             elif address in transaction["output"]:
    #                 balance += transaction["output"][address]

    #     return balance



    @staticmethod
    def calculate_balance(blockchain, address, currency=None):
        """
        Calculate the balance(s) of the given address considering transaction data on the blockchain.

        - If `currency` is provided (e.g. "COIN"), returns an integer balance for that currency.
        - If `currency` is None, returns a dict: { currency_id: balance_int, ... }.

        Behaviour (preserves your previous semantics for resets):
        - For each transaction in chain (in chronological order):
            - If transaction["input"]["address"] == address:
                -> The address created a new transaction, so its balance for each currency
                   is reset to the values in transaction["output"][address] (or 0 for currencies not present).
            - Else if address in transaction["output"]:
                -> Add the amounts in transaction["output"][address] to the running totals.
        - STARTING_BALANCE is applied only for the default currency when no prior data exists.
        """
        # If no blockchain pointer, return starting defaults
        # When currency is requested, return int; when not, return dict of currencies.
        default_currency = "COIN"

        # Helper to convert tx output entry into a currency -> int mapping
        def output_entry_to_map(entry):
            """
            entry can be:
            - a number (legacy single-currency): interpreted as { default_currency: int(entry) }
            - a dict: { currency: amount, ... } -> normalized to ints
            """
            if isinstance(entry, dict):
                return {str(k): int(v) for k, v in entry.items()}
            else:
                # numeric / other -> treat as default currency numeric value
                try:
                    return {default_currency: int(entry)}
                except Exception:
                    # malformed; treat as zero
                    return {}

        # If no blockchain provided, give STARTING_BALANCE (for default currency) or zeros
        if not blockchain or not getattr(blockchain, "chain", None):
            if currency is None:
                # return dict with default currency initialized
                return {default_currency: int(STARTING_BALANCE)}
            else:
                return int(STARTING_BALANCE) if currency == default_currency else 0

        # Running balances (dict currency -> int)
        balances = {}

        # Initialize default currency with STARTING_BALANCE so deposits add to it.
        balances[default_currency] = int(STARTING_BALANCE)

        # Iterate blocks in chronological order
        for block in blockchain.chain:
            for transaction in block.data:
                # Basic guards — transaction should be a mapping with "input" and "output"
                try:
                    tx_input = transaction["input"]
                    tx_output = transaction["output"]
                except Exception:
                    # Skip malformed txs
                    continue

                # If the tx was created by the address, it resets its balance(s)
                # Note: tx_input["address"] expected to exist based on your previous code
                tx_from_addr = tx_input.get("address") if isinstance(tx_input, dict) else None

                if tx_from_addr == address:
                    # Reset the address balances to the tx's output for that address (if any)
                    if address in tx_output:
                        entry_map = output_entry_to_map(tx_output[address])
                        # Reset all currencies to 0 first (preserve explicitness)
                        balances = {}
                        # Start default currency at 0 unless present in entry_map
                        balances[default_currency] = 0
                        # Apply entry_map values
                        for c, v in entry_map.items():
                            balances[c] = int(v)
                    else:
                        # If the address created a new tx but has no explicit output entry
                        # treat it as zero for all currencies (reset)
                        balances = {default_currency: 0}
                elif address in tx_output:
                    # Incoming funds — add to running totals
                    entry_map = output_entry_to_map(tx_output[address])
                    for c, v in entry_map.items():
                        balances[c] = balances.get(c, 0) + int(v)
                # otherwise, unrelated tx -> skip

        # If the caller asked for a single currency, return the scalar value (0 if absent)
        if currency is not None:
            return int(balances.get(currency, 0))

        # Otherwise return full mapping (ensure default_currency present)
        balances.setdefault(default_currency, int(STARTING_BALANCE))
        # Convert all to ints (defensive)
        balances = {str(k): int(v) for k, v in balances.items()}
        return balances
    
    def generate_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    @staticmethod
    def deserialize_private_key(serialized):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        return load_pem_private_key(serialized.encode("utf-8"), password=None)


