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