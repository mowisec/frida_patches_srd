"""The instruction patterns the finders are written in.

Every constructor returns a (match, mask) pair. A field left as None is masked
OUT (it may be anything); a field given a value is masked IN (it must be exactly
that). So `movz_w()` matches any MOVZ of a 32-bit register, `movz_w(imm=0x2e)`
matches only the ones that load 46, and `movz_w(imm=0x2e, rd=0)` pins the
register too.
"""
from .fields import ANY, _f, _sf, logical_imm, raw

# --- moves ----------------------------------------------------------------

def movz(imm=None, rd=None, sf=1, hw=0):
    """MOVZ X<rd>/W<rd>, #imm16, LSL #(hw*16)"""
    match, mask = _sf(0x52800000, 0x7F800000, sf)
    match, mask = _f(match, mask, hw, 21, 2)
    match, mask = _f(match, mask, imm, 5, 16)
    return _f(match, mask, rd, 0, 5)


def movz_w(imm=None, rd=None, hw=0):
    return movz(imm, rd, sf=0, hw=hw)


def movn_w(imm=None, rd=None):
    """MOVN W<rd>, #imm16 -- how the compiler writes small negative constants."""
    match, mask = 0x12800000, 0xFF800000
    match, mask = _f(match, mask, imm, 5, 16)
    return _f(match, mask, rd, 0, 5)


def mov_reg(rd=None, rm=None, sf=1):
    """MOV X<rd>, X<rm>  (ORR <rd>, ZR, <rm>)"""
    match, mask = _sf(0x2A0003E0, 0x7FE0FFE0, sf)
    match, mask = _f(match, mask, rm, 16, 5)
    return _f(match, mask, rd, 0, 5)


def mov_reg_w(rd=None, rm=None):
    return mov_reg(rd, rm, sf=0)


# --- branches -------------------------------------------------------------

def b(target_known=False):
    """B <label>. The displacement is always masked out."""
    return (0x14000000, 0xFC000000)


def bl():
    """BL <label>. The displacement is always masked out."""
    return (0x94000000, 0xFC000000)


def b_cond(cond=None):
    """B.<cond> <label>. cond=None matches any conditional branch."""
    match, mask = 0x54000000, 0xFF000010
    return _f(match, mask, cond, 0, 4)


COND = {"eq": 0, "ne": 1, "cs": 2, "hs": 2, "cc": 3, "lo": 3, "mi": 4, "pl": 5,
        "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12,
        "le": 13, "al": 14}


def bcc(name):
    return b_cond(COND[name])


def cbz(rt=None, sf=0):
    """CBZ W<rt>/X<rt>, <label>"""
    match, mask = _sf(0x34000000, 0x7F000000, sf)
    return _f(match, mask, rt, 0, 5)


def cbnz(rt=None, sf=0):
    """CBNZ W<rt>/X<rt>, <label>"""
    match, mask = _sf(0x35000000, 0x7F000000, sf)
    return _f(match, mask, rt, 0, 5)


def tbz(bit=None, rt=None):
    """TBZ <rt>, #bit, <label>"""
    return _tb(0x36000000, bit, rt)


def tbnz(bit=None, rt=None):
    """TBNZ <rt>, #bit, <label>"""
    return _tb(0x37000000, bit, rt)


def _tb(base, bit, rt):
    match, mask = base, 0x7F000000
    if bit is not None:
        assert 0 <= bit <= 63
        match, mask = _f(match, mask, bit >> 5, 31, 1)
        match, mask = _f(match, mask, bit & 31, 19, 5)
    else:
        mask &= ~(1 << 31) & 0xFFFFFFFF
    return _f(match, mask, rt, 0, 5)


def ret():
    return raw(0xD65F03C0)


def blr(rn=None):
    match, mask = 0xD63F0000, 0xFFFFFC1F
    return _f(match, mask, rn, 5, 5)


def blraa(rn=None, rm=None):
    """BLRAA <rn>, <rm> -- an authenticated indirect call."""
    match, mask = 0xD73F0800, 0xFFFFFC00
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rm, 0, 5)


# --- address formation ----------------------------------------------------

def adrp(rd=None):
    """ADRP X<rd>, <page>. The page displacement is always masked out."""
    match, mask = 0x90000000, 0x9F000000
    return _f(match, mask, rd, 0, 5)


def add_imm(rd=None, rn=None, imm=None, sf=1):
    """ADD <rd>, <rn>, #imm (no shift)"""
    match, mask = _sf(0x11000000, 0x7FC00000, sf)
    match, mask = _f(match, mask, imm, 10, 12)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


def sub_imm(rd=None, rn=None, imm=None, sf=1):
    match, mask = _sf(0x51000000, 0x7FC00000, sf)
    match, mask = _f(match, mask, imm, 10, 12)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


# --- compares -------------------------------------------------------------

def cmp_imm(rn=None, imm=None, sf=0):
    """CMP <rn>, #imm  (SUBS ZR, <rn>, #imm)"""
    match, mask = _sf(0x7100001F, 0x7FC0001F, sf)
    match, mask = _f(match, mask, imm, 10, 12)
    return _f(match, mask, rn, 5, 5)


def cmn_imm(rn=None, imm=None, sf=0):
    """CMN <rn>, #imm  (ADDS ZR, <rn>, #imm)"""
    match, mask = _sf(0x3100001F, 0x7FC0001F, sf)
    match, mask = _f(match, mask, imm, 10, 12)
    return _f(match, mask, rn, 5, 5)


def cmp_reg(rn=None, rm=None, sf=0):
    """CMP <rn>, <rm>  (SUBS ZR, <rn>, <rm>, LSL #0)"""
    match, mask = _sf(0x6B00001F, 0x7FE0FC1F, sf)
    match, mask = _f(match, mask, rm, 16, 5)
    return _f(match, mask, rn, 5, 5)


def cset(rd=None, cond=None):
    """CSET <rd>, <cond>  (CSINC <rd>, ZR, ZR, invert(cond))"""
    match, mask = 0x1A9F07E0, 0xFFFFFFE0
    if cond is not None:
        match, mask = _f(match & ~(0xF << 12), mask, cond ^ 1, 12, 4)
    return _f(match, mask, rd, 0, 5)


# --- loads and stores -----------------------------------------------------

def _ldst(base, rt, rn, imm, scale):
    match, mask = base, 0xFFC00000
    if imm is not None:
        assert imm % scale == 0, "offset %#x is not a multiple of %d" % (imm, scale)
        match, mask = _f(match, mask, imm // scale, 10, 12)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rt, 0, 5)


def ldr_x(rt=None, rn=None, imm=None):
    return _ldst(0xF9400000, rt, rn, imm, 8)


def ldr_w(rt=None, rn=None, imm=None):
    return _ldst(0xB9400000, rt, rn, imm, 4)


def ldrb(rt=None, rn=None, imm=None):
    return _ldst(0x39400000, rt, rn, imm, 1)


def ldrh_w(rt=None, rn=None, imm=None):
    return _ldst(0x79400000, rt, rn, imm, 2)


def strh_w(rt=None, rn=None, imm=None):
    return _ldst(0x79000000, rt, rn, imm, 2)


def str_x(rt=None, rn=None, imm=None):
    return _ldst(0xF9000000, rt, rn, imm, 8)


def str_w(rt=None, rn=None, imm=None):
    return _ldst(0xB9000000, rt, rn, imm, 4)


def ldset_w(rs=None, rt=None, rn=None):
    """LDSET W<rs>, W<rt>, [X<rn>] -- atomic OR, how XNU sets flag bits."""
    match, mask = 0xB8203000, 0xFFE0FC00
    match, mask = _f(match, mask, rs, 16, 5)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rt, 0, 5)


def asr_imm_w(shift=None, rd=None, rn=None):
    """ASR W<rd>, W<rn>, #shift  (SBFM with imms=31)"""
    match, mask = 0x13007C00, 0xFFC0FC00
    match, mask = _f(match, mask, shift, 16, 6)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


def lsr_reg_w(rd=None, rn=None, rm=None):
    """LSR W<rd>, W<rn>, W<rm>  (LSRV)"""
    match, mask = 0x1AC02400, 0xFFE0FC00
    match, mask = _f(match, mask, rm, 16, 5)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


def ldrb_reg_sxtw(rt=None, rn=None, rm=None):
    """LDRB W<rt>, [X<rn>, W<rm>, SXTW] -- how bitstr_test indexes a bitmap."""
    match, mask = 0x3860C800, 0xFFE0FC00
    match, mask = _f(match, mask, rm, 16, 5)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rt, 0, 5)


def orr_imm(rd=None, rn=None, imm=None, sf=0):
    """ORR <rd>, <rn>, #imm. imm=None masks the immediate out."""
    match, mask = _sf(0x32000000, 0x7F800000, sf)
    if imm is not None:
        match, mask = _f(match, mask, logical_imm(imm, sf), 10, 13)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


def orr_imm_w(rd=None, rn=None, imm=None):
    return orr_imm(rd, rn, imm, sf=0)


def and_imm_w(rd=None, rn=None, imm=None):
    """AND W<rd>, W<rn>, #imm"""
    match, mask = 0x12000000, 0xFF800000
    if imm is not None:
        match, mask = _f(match, mask, logical_imm(imm, 0), 10, 13)
    match, mask = _f(match, mask, rn, 5, 5)
    return _f(match, mask, rd, 0, 5)


# --- frame / PAC ----------------------------------------------------------

def pacibsp():
    return raw(0xD503237F)


def stp_pre():
    """STP <rt>, <rt2>, [SP, #-imm]! -- any register pair, any offset."""
    return (0xA9800000 | (31 << 5), 0xFFC003E0)

