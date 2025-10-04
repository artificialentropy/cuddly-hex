# blockchain_backend/utils/hex_to_binary.py
from .crypto_hash import crypto_hash

HEX_TO_BINARY_CONVERSION_TABLE = {
    "0": "0000", "1": "0001", "2": "0010", "3": "0011",
    "4": "0100", "5": "0101", "6": "0110", "7": "0111",
    "8": "1000", "9": "1001", "a": "1010", "b": "1011",
    "c": "1100", "d": "1101", "e": "1110", "f": "1111",
}


def hex_to_binary(hex_string: str) -> str:
    if not isinstance(hex_string, str):
        raise TypeError("hex_to_binary expects a hex string")
    hex_string = hex_string.lower()

    # Fast path using the table (keeps compatibility with your original)
    try:
        return "".join(HEX_TO_BINARY_CONVERSION_TABLE[ch] for ch in hex_string)
    except KeyError as e:
        raise ValueError(f"Invalid hex character: {e.args[0]!r}") from None

    # Alternative (bypass table):
    # n = int(hex_string, 16)
    # return bin(n)[2:].zfill(4 * len(hex_string))


def main():
    number = 451
    hex_number = hex(number)[2:]
    print(f"hex_number: {hex_number}")

    binary_number = hex_to_binary(hex_number)
    print(f"binary_number: {binary_number}")

    original_number = int(binary_number, 2)
    print(f"original_number: {original_number}")

    hex_to_binary_crypto_hash = hex_to_binary(crypto_hash("test-data"))
    print(f"hex_to_binary_crypto_hash: {hex_to_binary_crypto_hash}")


if __name__ == "__main__":
    main()
