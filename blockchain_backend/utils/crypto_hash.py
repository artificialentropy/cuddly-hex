# blockchain_backend/utils/crypto_hash.py
import hashlib
import json
from typing import Any


def _jsonifyable(value: Any):
    """
    Convert common non-JSON types to JSON-friendly forms deterministically:
    - bytes -> hex string
    - set  -> sorted list
    - tuple -> list
    - dict -> recursively convert
    - list -> recursively convert
    """
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, set):
        return sorted(_jsonifyable(v) for v in value)
    if isinstance(value, tuple):
        return [_jsonifyable(v) for v in value]
    if isinstance(value, list):
        return [_jsonifyable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonifyable(v) for k, v in value.items()}
    return value


def crypto_hash(*args) -> str:
    """
    Return a SHA-256 hash of the given arguments.
    Arguments are JSON-serialized deterministically after coercion via _jsonifyable.
    """
    coerced = [_jsonifyable(a) for a in args]
    stringified = json.dumps(coerced, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(stringified.encode("utf-8")).hexdigest()


def main():
    print(f"crypto_hash('one', 2, [3]): {crypto_hash('one', 2, [3])}")
    print(f"crypto_hash(2, 'one', [3]): {crypto_hash(2, 'one', [3])}")


if __name__ == "__main__":
    main()
