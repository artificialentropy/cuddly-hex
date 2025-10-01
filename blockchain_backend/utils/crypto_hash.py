import hashlib
import json


def crypto_hash(*args):
    # Ensure identical string across machines
    stringified = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(stringified.encode("utf-8")).hexdigest()


def main():
    print(f"crypto_hash('one', 2, [3]): {crypto_hash('one', 2, [3])}")
    print(f"crypto_hash(2, 'one', [3]): {crypto_hash(2, 'one', [3])}")


if __name__ == "__main__":
    main()
