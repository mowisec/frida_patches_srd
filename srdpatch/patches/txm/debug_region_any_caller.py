"""debug-region-any-caller: let any caller associate a debug region.

Two instructions in the failure tail of TXM selector 42's debugger check. The
site is anchored on the log STRING next to it rather than on the shape of the
code, because in a binary this small the shapes repeat and the strings do not.
"""
from ... import arm64 as A
from ... import macho
from ...patch import Patch, Write

DEBUG_MAP_LOG = "disallowed non-debugger initiated debug mapping"
TXM_RETURN_NOT_DEBUGGER = 0x25   # 37, the returnCode seen on the device

def locate_debug_region_any_caller(im):
    # The failure tail of selector 42's debugger check, taken from the log
    # string it passes to the logger. There is exactly one reference to it.
    #   adrp x0, 'disallowed non-debugger initiated debug mapping'
    #   add  x0, x0, #off
    #   bl   <log>
    #   mov  w20, #0x25      <-- write 1
    #   b    <fail tail>     <-- write 2
    anchor = im.one_adrp_add_xref(im.one_cstring(DEBUG_MAP_LOG),
                                  what="the debug-mapping log line")
    shape = [A.adrp(rd=0), A.add_imm(rd=0, rn=0), A.bl(),
             A.movz_w(imm=TXM_RETURN_NOT_DEBUGGER), A.b()]
    if not macho.match_at(im.data, im.va_to_off(anchor), shape):
        raise macho.NotFound(
            "the log call at %#x is not followed by `mov wN, #0x25 ; b`" % anchor)
    ret, br = anchor + 12, anchor + 16
    # The allow label is the target of the two entitlement/override tests above
    # the log call, so it is read out of the image rather than assumed.
    tb = im.find_prev(anchor - 4, [A.tbnz(bit=0)], limit=4)
    if tb is None:
        raise macho.NotFound("no `tbnz wN, #0` above the debug-mapping "
                                   "log call")
    allow = A.decode_tb_target(im.word(tb), tb)
    return [
        Write(ret, A.movz_w(imm=TXM_RETURN_NOT_DEBUGGER), A.encode_movz(0, 1),
              "mov wN, #0x25 -> mov w0, #1"),
        Write(br, A.b(), A.encode_b(br, allow),
              "b <fail> -> b <allow> (%#x)" % allow),
    ]


DEBUG_REGION_ANY_CALLER = Patch(
    "debug-region-any-caller", "DBGRGN1",
    "Let any caller associate a debug region, i.e. stop TXM's selector 42 "
    "(AssociateDebugRegion) from requiring the INITIATING process to hold "
    "com.apple.private.cs.debugger.\n"
    "\n"
    "sub_fffffff0170333a4 checks the entitlement on the current address "
    "space, then a global override byte at cfg+0x2cd, and if neither holds "
    "it logs and returns 0x25 (the returnCode 37 we see on the device):\n"
    "  0xfffffff0170333f8  tbnz w0, #0, 0x...420   entitled -> allow\n"
    "  0xfffffff017033408  tbnz w8, #0, 0x...420   override -> allow\n"
    "  0xfffffff017033414  bl   <log>              'disallowed non-debugger\n"
    "                                               initiated debug mapping'\n"
    "  0xfffffff017033418  mov  w20, #0x25     ->  mov w0, #1\n"
    "  0xfffffff01703341c  b    0x...500       ->  b   0x...420\n"
    "\n"
    "Patching the tail rather than either tbnz keeps the log call, so a "
    "patched TXM ANNOUNCES ITSELF: the 'disallowed non-debugger initiated "
    "debug mapping' line still appears while the association now succeeds. "
    "That is the only way to tell a working patch from a rejected image "
    "that silently fell back to stock.\n"
    "\n"
    "w0 is set to 1 so the allow path is entered with exactly the register "
    "state the legitimate path gives it (`cset w0, eq` then `tbnz w0, #0`). "
    "The association itself is left entirely alone -- TXM still walks and "
    "installs the region, so SPTM's view stays consistent.\n"
    "\n"
    "The site is found from that same log string, which has exactly one "
    "reference in the image, and the allow label is read out of the `tbnz` "
    "above the log call rather than assumed.",
    locate_debug_region_any_caller)

