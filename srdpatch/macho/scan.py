"""The masked scan itself: match one pattern at one offset, or over a range.

The images are tens of megabytes and a patch run resolves a few dozen patterns,
so the scan is vectorised with numpy when it is available and falls back to a
plain loop when it is not. The fallback is correct, just slow.
"""
import struct

try:
    import numpy as _np
except ImportError:                  # the pure-Python fallback is correct, just slow
    _np = None


def have_numpy():
    return _np is not None


def match_at(data, off, pattern):
    if off < 0 or off + 4 * len(pattern) > len(data):
        return False
    for i, (m, mask) in enumerate(pattern):
        if mask == 0:
            continue
        w, = struct.unpack_from("<I", data, off + 4 * i)
        if (w & mask) != m:
            return False
    return True


def scan(im, start_off, end_off, pattern):
    """Scan [start_off, end_off) for `pattern`, aligned to 4 bytes.

    The images are tens of megabytes and a patch run resolves a few dozen
    patterns, so the first element is matched over the whole range at once with
    numpy and only the survivors -- usually a handful -- are checked element by
    element. Without numpy the same thing happens one word at a time.
    """
    if not pattern:
        raise ValueError("empty pattern")
    first_m, first_mask = pattern[0]
    if first_mask == 0:
        raise ValueError("the first element of a pattern must not be a wildcard")
    data, map_base = im.data, im.map_base
    start_off += (-start_off) & 3
    limit = end_off - 4 * len(pattern)
    if limit < start_off:
        return []
    words = im.words()
    if words is None:
        hits = []
        for off in range(start_off, limit + 1, 4):
            w, = struct.unpack_from("<I", data, off)
            if (w & first_mask) == first_m and match_at(data, off, pattern):
                hits.append(map_base + off)
        return hits
    lo, hi = start_off // 4, limit // 4 + 1
    window = words[lo:hi]
    idx = _np.flatnonzero((window & _np.uint32(first_mask)) == _np.uint32(first_m))
    hits = []
    for i in idx.tolist():
        off = (lo + i) * 4
        if match_at(data, off, pattern):
            hits.append(map_base + off)
    return hits

