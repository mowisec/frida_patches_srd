"""The primitives every instruction pattern is built out of.

A pattern is a (match, mask) pair: mask bits that are 0 are "don't care". Every
constructor in patterns.py takes optional fields, folds the ones that were given
in with _f(), and leaves the rest masked out.
"""

ANY = (0x00000000, 0x00000000)


def _f(match, mask, value, shift, width):
    """Fold one optional field into a (match, mask) pair."""
    if value is None:
        return match, mask
    m = (1 << width) - 1
    assert 0 <= value <= m, "field value %r does not fit in %d bits" % (value, width)
    return match | (value << shift), mask | (m << shift)


def raw(match, mask=0xFFFFFFFF):
    """An encoding given literally. The escape hatch."""
    return (match & mask, mask)


def _sf(base_match, base_mask, sf):
    """Fold the 32/64-bit bit (bit 31)."""
    return (base_match | (sf << 31), base_mask | (1 << 31))



def logical_imm(value, sf=0):
    """Encode `value` as an ARM64 logical immediate (the N:immr:imms field).

    Returns the 13-bit field, or raises if the value is not encodable. This is
    what lets a pattern say `orr_imm_w(imm=0xc00)` -- flag constants such as
    P_LTRACED|P_LSIGEXC carry meaning and are worth matching exactly, unlike the
    struct offsets around them.
    """
    width = 64 if sf else 32
    value &= (1 << width) - 1
    if value == 0 or value == (1 << width) - 1:
        raise ValueError("%#x is not encodable as a logical immediate" % value)
    # Find the smallest element size the value repeats at.
    size = width
    while size > 2:
        half = size // 2
        mask = (1 << half) - 1
        if (value & mask) != ((value >> half) & mask):
            break
        size = half
    elem = value & ((1 << size) - 1)
    # The element must be a run of `ones` ones, rotated right by immr.
    ones = bin(elem).count("1")
    run = (1 << ones) - 1
    emask = (1 << size) - 1
    for immr in range(size):
        if ((run >> immr) | (run << (size - immr))) & emask == elem:
            break
    else:
        raise ValueError("%#x is not a rotated run of ones" % value)
    n = 1 if size == 64 else 0
    imms = ((~((size << 1) - 1)) & 0x3F) | (ones - 1)
    return (n << 12) | (immr << 6) | imms


