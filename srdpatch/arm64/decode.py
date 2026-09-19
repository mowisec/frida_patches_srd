"""Reading fields back out of an instruction the finders have already matched.

A pattern says an instruction is a B.cond; these say where it goes. Together
they are what lets a patch read a branch target out of the image rather than
assume one.
"""

def sextract(value, width):
    if value & (1 << (width - 1)):
        value -= 1 << width
    return value


def decode_branch_target(insn, va):
    """B/BL -> absolute target."""
    assert (insn & 0x7C000000) == 0x14000000
    return va + 4 * sextract(insn & 0x03FFFFFF, 26)


def decode_cond_branch_target(insn, va):
    """B.cond/CBZ/CBNZ -> absolute target (imm19)."""
    return va + 4 * sextract((insn >> 5) & 0x7FFFF, 19)


def decode_tb_target(insn, va):
    """TBZ/TBNZ -> absolute target (imm14)."""
    return va + 4 * sextract((insn >> 5) & 0x3FFF, 14)


def decode_adrp(insn, va):
    """ADRP -> the page address it forms."""
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    return (va & ~0xFFF) + (sextract((immhi << 2) | immlo, 21) << 12)


def decode_ldst_off(insn, scale):
    return ((insn >> 10) & 0xFFF) * scale


def rd(insn):
    return insn & 0x1F


def rn(insn):
    return (insn >> 5) & 0x1F

