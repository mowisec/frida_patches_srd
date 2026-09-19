"""Building the words that get WRITTEN, as opposed to matched.

Patterns describe what has to be there; these three build what replaces it.
"""
def encode_movz(rd, imm, sf=0, hw=0):
    """Build a MOVZ. Patterns MATCH instructions; this one is WRITTEN."""
    assert 0 <= imm <= 0xFFFF and 0 <= rd <= 31
    return (sf << 31) | 0x52800000 | (hw << 21) | (imm << 5) | rd


def encode_b(frm, to):
    """B <to>, encoded at <frm>."""
    off = to - frm
    assert off % 4 == 0
    assert -(1 << 27) <= off < (1 << 27), "branch out of range"
    return 0x14000000 | ((off // 4) & 0x03FFFFFF)


NOP = 0xD503201F
RET = 0xD65F03C0
