import json
import uuid
import time
from copy import deepcopy

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from blockchain_backend.utils.config import STARTING_BALANCE, MINING_REWARD_INPUT


class Wallet:
    """
    Represents a wallet for multi-currency and asset-based blockchain.
    Manages balances, signs transactions, and tracks keys.
    """

    def __init__(self, blockchain=None):
        self.blockchain = blockchain

        # Multi-currency balances
        self.balances = {"COIN": STARTING_BALANCE}
        self._balance = STARTING_BALANCE  # legacy

        # Generate key pair
        self.private_key, self.public_key_obj = self.generate_key_pair()
        self.public_key = self.serialize_public_key(self.public_key_obj)

        # Short address for simplicity
        self.address = str(uuid.uuid4())[:8]

    @property
    def balance(self):
        """Legacy single-coin getter."""
        return self.balances.get("COIN", 0)

    def update_balance(self, currency: str, amount: int):
        """Safely update specific currency balance."""
        self.balances[currency] = self.balances.get(currency, 0) + int(amount)

    def sign(self, data):
        """Sign JSON-serializable data."""
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        r, s = decode_dss_signature(
            self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        )
        return (r, s)

    @staticmethod
    def verify(public_key, data, signature):
        """Verify signature of JSON-serializable data."""
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        deserialized_pub = serialization.load_pem_public_key(
            public_key.encode("utf-8"), backend=default_backend()
        )
        r, s = signature
        try:
            deserialized_pub.verify(
                encode_dss_signature(r, s),
                payload,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate_key_pair():
        """Generate EC key pair (SECP256K1)."""
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key_obj):
        """Return PEM string of public key."""
        return public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @staticmethod
    def serialize_private_key(private_key):
        """Return PEM string of private key."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    @staticmethod
    def deserialize_private_key(serialized):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        return load_pem_private_key(serialized.encode("utf-8"), password=None)

    @staticmethod
    def calculate_balance(blockchain, address, currency=None):
        """
        Compute multi-currency balances for an address.
        - currency=None -> returns dict {currency: balance}
        - currency="COIN" -> returns integer
        """
        default_currency = "COIN"
        balances = {default_currency: STARTING_BALANCE}

        if not blockchain or not getattr(blockchain, "chain", None):
            return balances if currency is None else balances.get(currency, 0)

        for block in blockchain.chain:
            for tx in block.data:
                try:
                    tx_input = tx["input"]
                    tx_output = tx["output"]
                except Exception:
                    continue

                tx_from = tx_input.get("address") if isinstance(tx_input, dict) else None

                if tx_from == address:
                    # Wallet spent: update currencies in output
                    if address in tx_output:
                        for c, v in tx_output[address].items():
                            balances[c] = v
                elif address in tx_output:
                    # Wallet received funds
                    for c, v in tx_output[address].items():
                        balances[c] = balances.get(c, 0) + v

        if currency is not None:
            return balances.get(currency, 0)
        return balances

    def create_transaction(self, recipient, amount_map=None, asset_ids=None):
        """
        Create a transaction supporting multiple currencies and optional asset transfers.

        :param recipient: Recipient address
        :param amount_map: Dict of {currency: amount} to send
        :param asset_ids: List of asset IDs to transfer
        """
        amount_map = amount_map or {}
        asset_ids = asset_ids or []

        # Validate funds
        for c, amt in amount_map.items():
            if self.balances.get(c, 0) < amt:
                raise Exception(f"Insufficient funds for {c}: {amt} > {self.balances.get(c,0)}")

        # Prepare outputs
        outputs = {}
        if amount_map:
            outputs[recipient] = deepcopy(amount_map)

        # Add change back to self
        change = {}
        for c, amt in self.balances.items():
            sent = amount_map.get(c, 0)
            remaining = amt - sent
            if remaining > 0:
                change[c] = remaining
        if change:
            outputs[self.address] = change

        # Metadata for assets
        metadata = None
        if asset_ids:
            asset_info = [{"asset_id": aid, "from": self.address, "to": recipient} for aid in asset_ids]
            metadata = {"asset_purchase": asset_info}

        # Create signed transaction
        from .transaction import Transaction  # Import locally to avoid circular import
        tx = Transaction(sender_wallet=self, recipient=recipient, amount_map=amount_map, asset_ids=asset_ids)

        return tx
