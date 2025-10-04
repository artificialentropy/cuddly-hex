# wallet/wallet.py
import json
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from blockchain_backend.utils.config import STARTING_BALANCE


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

        Rules:
          - When the address is the TX SENDER, set balances for currencies present
            in the sender's change map (this represents post-spend state for those currencies).
          - When the address is a RECIPIENT, add the received amounts to the running balance.
        """
        default_currency = "COIN"
        balances = {default_currency: STARTING_BALANCE}

        if not blockchain or not getattr(blockchain, "chain", None):
            return balances if currency is None else balances.get(currency, 0)

        for block in blockchain.chain:
            for tx in getattr(block, "data", []) or []:
                if not isinstance(tx, dict):
                    continue

                tx_input = tx.get("input", {})
                tx_output = tx.get("output", {})

                tx_from = tx_input.get("address") if isinstance(tx_input, dict) else None

                # If wallet is the sender, set balances for currencies present in its change entry
                if tx_from == address and address in tx_output:
                    for c, v in tx_output[address].items():
                        balances[c] = int(v)

                # If wallet is a recipient, add amounts
                if address in tx_output and tx_from != address:
                    for c, v in tx_output[address].items():
                        balances[c] = balances.get(c, 0) + int(v)

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
        amount_map = dict(amount_map or {})
        asset_ids = list(asset_ids or [])

        # Validate funds quickly here (Transaction will also re-validate)
        for c, amt in amount_map.items():
            if self.balances.get(c, 0) < int(amt):
                raise Exception(f"Insufficient funds for {c}: {amt} > {self.balances.get(c,0)}")

        # Create signed transaction (includes correct input snapshot + outputs)
        from .transaction import Transaction  # avoid circular import at module load
        return Transaction(sender_wallet=self, recipient=recipient, amount_map=amount_map, asset_ids=asset_ids)
