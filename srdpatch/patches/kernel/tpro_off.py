"""tpro-off: disable TPRO system-wide by clearing _xprr_tpro_enabled.

The only DATA write in the set. The flag cannot be matched as an instruction,
so the guard that reads it is matched instead and the address is resolved out
of the adrp+ldr pair that forms it.
"""
from ... import arm64 as A
from ... import macho
from ...patch import Patch, Write

def locate_tpro_off(im):
    # The one TPRO read that is followed by the region-flag store. The flag
    # itself is data, so it has to be resolved through the adrp+ldr rather
    # than matched.
    #   adrp x9, <page>
    #   ldr  w9, [x9, #off]      _xprr_tpro_enabled
    #   cbz  w9, <skip>
    #   ldr  w9, [x21, #0xb0]
    #   cmp  w9, w8
    #   b.lo <skip>
    #   ldrh w8, [x19, #0x6ac]
    #   orr  w8, w8, #2          VM_REGION_FLAG_TPRO_ENABLED
    #   strh w8, [x19, #0x6ac]
    va = im.find_one([
        A.adrp(), A.ldr_w(), A.cbz(), A.ldr_w(), A.cmp_reg(), A.bcc('lo'),
        A.ldrh_w(), A.orr_imm_w(imm=2), A.strh_w(),
    ], what="the VM_REGION_FLAG_TPRO_ENABLED site")
    if A.rd(im.word(va)) != A.rn(im.word(va + 4)):
        raise macho.NotFound("the adrp and ldr at %#x use different "
                                   "registers" % va)
    flag = im.adrp_ldr_target(va, va + 4, scale=4)
    const = [s for s in im.segments if s.name == "__DATA_CONST"]
    if not any(s.vmaddr <= flag < s.vmaddr + s.filesize for s in const):
        raise macho.NotFound("_xprr_tpro_enabled resolved to %#x, which "
                                   "is not in __DATA_CONST" % flag)
    return [Write(flag, (1, 0xFFFFFFFF), 0, "_xprr_tpro_enabled: 1 -> 0")]


TPRO_OFF = Patch(
    "tpro-off", "TPROOFF",
    "Disable TPRO system-wide by clearing the _xprr_tpro_enabled flag.\n"
    "  0xfffffe0007e640fc  __DATA_CONST, uint32  1 -> 0\n"
    "TPRO is thread-local protected read-only memory: dyld keeps its own state "
    "in pages whose PTEs select SPRR index 9, and flips that slot between r-- "
    "and rw- with `msr S3_6_C15_C1_5`. Every libdyld.dylib API entry point on "
    "iOS 27 asserts the slot is read-only on entry and otherwise aborts with "
    "\"TPRO regions should not be writable on entry to dyld\". Frida's spawn "
    "handshake breakpoints the ENTRY of dyld4::RuntimeState::notifyObjCInit, "
    "which is dyld bookkeeping and runs before dyld drops to read-only, so the "
    "hijacked ___CFInitialize re-enters dyld while the guard is armed and the "
    "target SIGABRTs.\n"
    "This is a DATA write, not an instruction: the flag lives in __DATA_CONST "
    "and every one of its cross-references is a read, each a plain "
    "if (xprr_tpro_enabled) guard whose false arm is the ordinary no-TPRO path "
    "-- including 0xfffffe000affd85c, which is what sets "
    "VM_REGION_FLAG_TPRO_ENABLED (orr w8, w8, #2). That site is also how the "
    "flag is located: the guard is matched as code, and the address is then "
    "resolved out of its adrp+ldr pair, checked to be inside __DATA_CONST, and "
    "checked to hold 1.\n"
    "Measured justification: of 597 live pids, 555 have TPRO and 8 do not, and "
    "in a process without it the per-process SPRR mask LOCKS nibble 9, so "
    "dyld's msr is a no-op and the guard always passes. With TPRO off, "
    "completely unmodified Frida spawns and attaches -- verified against the "
    "non-TPRO apps aslrA and caller, which work with frida-core-0007 dropped "
    "entirely while mobilesafari still aborts. So this replaces a Frida patch "
    "with a kernel patch, and keeps Frida's behaviour identical to devices "
    "that have no TPRO at all, such as a jailbroken iPhone 8.",
    locate_tpro_off)



# --- the set that gets booted --------------------------------------------

