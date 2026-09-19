"""ptrace-launchd: let PT_ATTACH run against launchd.

Six instructions, all in _ptrace's PT_ATTACH path, all turned into nops. What
survives is the pair of cs_allow_invalid() calls, which is the whole point.
"""
from ... import arm64 as A
from ... import macho
from ...patch import Patch, nop

_PTRACE_FLAGS = [
    A.add_imm(),                     # add   x9, x8, #0xe28
    A.movz_w(imm=0x80),              # mov   w10, #0x80
    A.ldset_w(),                     # ldset w10, w10, [x9]
    A.ldr_w(),                       # ldr   w10, [x8, #0x448]
    A.orr_imm_w(imm=0xc00),          # orr   w10, w10, #0xc00
    A.str_w(),                       # str   w10, [x8, #0x448]
    A.movz_w(imm=0x100),             # mov   w8, #0x100
    A.ldset_w(),                     # ldset w8, w8, [x9]
]
_PTRACE_REPARENT = [
    A.mov_reg(rd=0), A.mov_reg(rd=1),
    A.movz_w(imm=1, rd=2), A.movz_w(imm=0, rd=3),
    A.bl(), A.mov_reg(rd=0),
]


def locate_ptrace_launchd(im):
    # 1. the `if (uap->pid < 2) return EPERM` gate
    gate = im.find_one([
        A.ldr_w(rt=0), A.cmp_imm(rn=0, imm=2), A.bcc('lt'), A.bl(),
        A.cbz(rt=0, sf=1),
    ], what="ptrace's pid < 2 gate")
    # 2-4. the flag block. The struct offsets (p_lflag at +0x448, the word at
    #      +0xe28) are masked out; the flag VALUES are what carry the meaning.
    flags = im.find_one(_PTRACE_FLAGS, what="ptrace's P_LTRACED/P_LSIGEXC block")
    # 5. the attach-time proc_reparentlocked. There are six calls of this shape
    #    in the image and two of them are in _ptrace, so this one is taken as
    #    the first after the flag block rather than by shape alone. Measured
    #    distance is 27-29 instructions; the detach-time one is 128 further on.
    rep = im.find_next(flags + 4 * len(_PTRACE_FLAGS), _PTRACE_REPARENT, limit=0x40)
    if rep is None:
        raise macho.NotFound("no proc_reparentlocked call after ptrace's "
                                   "flag block")
    # 6. psignal(t, ..., SIGSTOP), identified by `mov w4, #0x11`
    sig = im.find_one([
        A.movz(imm=0, rd=1), A.movz(imm=0, rd=2), A.movz_w(imm=0, rd=3),
        A.movz_w(imm=0x11, rd=4), A.movz(imm=0, rd=5), A.bl(),
    ], what="ptrace's psignal(SIGSTOP) call")
    return [
        nop(im, gate + 8, A.bcc('lt'), "b.lt <EPERM>"),
        nop(im, flags + 8, A.ldset_w(), "ldset (bit 0x80 at t+0xe28)"),
        nop(im, flags + 16, A.orr_imm_w(imm=0xc00), "orr P_LTRACED|P_LSIGEXC"),
        nop(im, flags + 28, A.ldset_w(), "ldset (bit 0x100 at t+0xe28)"),
        nop(im, rep + 16, A.bl(), "bl proc_reparentlocked"),
        nop(im, sig + 20, A.bl(), "bl psignal(t, SIGSTOP)"),
    ]


PTRACE_LAUNCHD = Patch(
    "ptrace-launchd", "PTRLNCH",
    "Let PT_ATTACH run against launchd, with nothing but cs_allow_invalid "
    "left of it. The four writes and what each one prevents are below.\n"
    "\n"
    "_ptrace was originally located by scanning for its request-code comparison "
    "sequence (cmp #0x1d, #0xc, #0x1e, #0x1f), which is unique in the "
    "image, and confirmed against the symbolised kernel.development.t8132 "
    "in the KDK. cs_allow_invalid is 0xfffffe000afda734, which has exactly "
    "four call sites, all inside _ptrace: two for PT_TRACE_ME and two for "
    "PT_ATTACH.\n"
    "\n"
    "1. 0xfffffe000b059784  b.lt <EPERM>   ->  nop\n"
    "     the `if (uap->pid < 2) return EPERM` gate. The branch target\n"
    "     0xfffffe000b0598ec is `mov w22, #1`, i.e. EPERM in the error\n"
    "     variable, which is what confirms the site.\n"
    "2. 0xfffffe000b059a80  ldset w10, w10, [x9]   ->  nop   (bit 0x80 at t+0xe28)\n"
    "   0xfffffe000b059a88  orr  w10, w10, #0xc00  ->  nop   (P_LTRACED|P_LSIGEXC\n"
    "                                                         in p_lflag, t+0x448)\n"
    "   0xfffffe000b059a94  ldset w8, w8, [x9]     ->  nop   (bit 0x100 at t+0xe28)\n"
    "     Leaves launchd untraced. While traced, ANY signal parks a process\n"
    "     in issignal waiting for a debugger that is about to walk away.\n"
    "     The str that follows the orr writes the value back unmodified.\n"
    "3. 0xfffffe000b059afc  bl proc_reparentlocked ->  nop\n"
    "     The one that does lasting damage. launchd's p_ppid is 0, so a\n"
    "     later PT_DETACH would proc_find(0), fail, and reparent launchd to\n"
    "     initproc, which is launchd. Skipping the attach-time reparent also\n"
    "     disarms the detach-time one, since p_oppid == p_ppid then.\n"
    "4. 0xfffffe000b059b4c  bl psignal(t, SIGSTOP)  ->  nop\n"
    "     Identified by `mov w4, #0x11` two instructions earlier. A stopped\n"
    "     launchd is a wedged device.\n"
    "\n"
    "What survives is cs_allow_invalid(t) at 0xfffffe000b059ac0 and "
    "cs_allow_invalid(p) at 0xfffffe000b059ac8, which is the whole point. "
    "Frida's softener neither waits for the stop nor checks PT_DETACH's "
    "result for anything but EBUSY, so it tolerates all four.\n"
    "\n"
    "Global, not pid-1 specific: ptrace behaves this way for every caller "
    "on this boot.",
    locate_ptrace_launchd)


