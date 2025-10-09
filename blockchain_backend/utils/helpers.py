import time

def normalize_timestamp(ts):
    """
    Accepts int-like timestamp in seconds or nanoseconds.
    Returns integer seconds.
    """
    try:
        ts = int(ts)
    except Exception:
        return int(time.time())

    # heuristic: if ts is > 1e12 it's likely micro/nano; if >1e15 -> nanoseconds
    if ts > 10**15:            # nanoseconds -> seconds
        return ts // 1_000_000_000
    if ts > 10**12:            # microseconds -> seconds
        return ts // 1_000_000
    return ts


# helper: remove common extraneous debug/meta keys from remote block dicts
def _strip_block_extras(raw_block: dict) -> dict:
    """
    Return a shallow copy of raw_block with keys removed that may be present
    in remote debug envelopes but not accepted by Block.__init__.
    """
    if not isinstance(raw_block, dict):
        return raw_block
    b = dict(raw_block)
    for k in ("version",):  # add other debug keys here if needed in future
        if k in b:
            b.pop(k, None)
    return b
