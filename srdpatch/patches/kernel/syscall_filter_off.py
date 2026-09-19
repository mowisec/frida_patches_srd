"""syscall-filter-off: disable the per-task syscall filters Protobox uses.

Three entry points, each rewritten to return "this task has no filter". Frida's
agent runs INSIDE the target, so its syscalls are judged against the target's
profile; this is what stops a hardened daemon denying them.
"""
from ... import arm64 as A
from ... import macho
from ...patch import Patch, Write
from .filters import kobj_filter_site, TRAP_FILTER

def _return_zero(im, func, sf, what):
    """Overwrite a function's first two instructions with `mov #0 ; ret`.

    All three targets start `pacibsp` then a frame push, so returning here
    happens before anything is signed or pushed and a plain ret is correct.
    That is asserted rather than assumed.
    """
    return [
        Write(func, A.pacibsp(), A.encode_movz(0, 0, sf=sf),
              "%s: pacibsp -> mov %s0, #0" % (what, "x" if sf else "w")),
        Write(func + 4, A.stp_pre(), A.RET, "%s: stp -> ret" % what),
    ]


def locate_syscall_filter_off(im):
    # _task_get_mach_kobj_filter_mask: the accessor ipc_kobject_server calls,
    # two instructions before its filter check.
    kobj_site = kobj_filter_site(im)
    bl = im.find_prev(kobj_site - 4, [A.bl(), A.cbz(rt=0, sf=1)], limit=4)
    if bl is None:
        raise macho.NotFound("no filter-mask accessor call above "
                                   "ipc_kobject_server's filter check")
    kobj = im.bl_target(bl)
    # _task_get_mach_trap_filter_mask: the other inlined bitstr_test, the one
    # whose accessor call is immediately followed by `cbz x0` and the shift.
    trap = im.bl_target(im.find_one(
        TRAP_FILTER, what="the mach trap filter check"))
    # _mac_proc_check_syscall_unix: its single call site, in unix_syscall.
    #   and  w1, w27, #0xffff     the syscall number
    #   mov  x0, x21
    #   bl   <mac_proc_check_syscall_unix>
    #   mov  x25, x0
    #   cbnz w0, <deny>
    unix = im.bl_target(im.find_one([
        A.and_imm_w(rd=1, imm=0xffff), A.mov_reg(rd=0), A.bl(),
        A.mov_reg(rm=0), A.cbnz(rt=0),
    ], what="unix_syscall's mac_proc_check_syscall_unix call") + 8)
    if len({kobj, trap, unix}) != 3:
        raise macho.Ambiguous(
            "the three filter entry points did not resolve to three distinct "
            "functions: kobj=%#x trap=%#x unix=%#x" % (kobj, trap, unix))
    return (_return_zero(im, trap, 1, "_task_get_mach_trap_filter_mask")
            + _return_zero(im, kobj, 1, "_task_get_mach_kobj_filter_mask")
            + _return_zero(im, unix, 0, "_mac_proc_check_syscall_unix"))


SYSCALL_FILTER_OFF = Patch(
    "syscall-filter-off", "SYSFILT",
    "Disable the per-task syscall filters that Protobox uses, by making the "
    "three entry points return 'no filter'.\n"
    "  0xfffffe000ab318a0  _task_get_mach_trap_filter_mask  -> mov x0, #0 ; ret\n"
    "  0xfffffe000ab31934  _task_get_mach_kobj_filter_mask  -> mov x0, #0 ; ret\n"
    "  0xfffffe000b31e3d0  _mac_proc_check_syscall_unix     -> mov w0, #0 ; ret\n"
    "All three functions begin with pacibsp followed by a frame push, so "
    "overwriting the first two instructions returns before anything is signed "
    "or pushed; a plain ret is correct there. Both halves of that prologue are "
    "asserted before either is overwritten.\n"
    "The first two are the accessors every filter check gates on:\n"
    "  osfmk/arm64/bsd_arm64.c:249   filter_mask = task_get_mach_trap_filter_mask(task);\n"
    "                                if (filter_mask != NULL && !bitstr_test(...)) deny\n"
    "  osfmk/kern/ipc_kobject.c:563  filter_mask = task_get_mach_kobj_filter_mask(curtask);\n"
    "                                if (filter_mask != NULL && !bitstr_test(...)) deny\n"
    "NULL means 'this task has no filter', which is the ordinary state for an "
    "unsandboxed process, so this takes the path the kernel already takes for "
    "most tasks rather than inventing a new one. The third is the MACF hook for "
    "BSD syscalls; 0 is 'allowed'.\n"
    "Motivation: frida's agent runs INSIDE the target, so its syscalls are "
    "attributed to the target. In com.apple.mobilesms.compose the agent is "
    "denied syscall-mach 45 (task_for_pid), syscall-unix 32 (getsockname) and "
    "syscall-mig 154 and 242, and frida reports 'unexpected early "
    "end-of-stream'. The same spawn of com.apple.MobileSMS produces ZERO "
    "denials and works.\n"
    "Note these denials do NOT kill the target: the trap returns MACH_PORT_NULL "
    "or KERN_DENIED and the MIG call gets an error reply. Measured: the process "
    "is still alive after the failed attach. What dies is the agent's channel.\n"
    "This supersedes the narrower patch of ipc_kobject_server's verdict alone. "
    "That one is not needed alongside this one and is not in this set: with "
    "_task_get_mach_kobj_filter_mask hard-returning NULL, _ipc_kobject_server "
    "takes its `cbz x0, <allow>` branch BEFORE reaching the instruction that "
    "patch would rewrite, and a scan of every B/B.cond/CBZ/CBNZ/TBZ/TBNZ in "
    "the image finds no other edge into the block, so that site is "
    "unreachable.\n"
    "\n"
    "The two accessors have identical prologues, so neither can be found by "
    "its own code; each is taken as the call target at its one filter check. "
    "The two checks are told apart by the KOBJ_IDX_NOT_SET test that only the "
    "kobject one has.",
    locate_syscall_filter_off)


