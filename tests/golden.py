"""What the finders are expected to produce on the reference image.

The golden table is copied verbatim from the hardcoded scripts these finders
replaced: (va, word before, word after) for 24A5424a / iPhone18,3, the SRD image
every site was derived on by hand and the only image any of this has been booted
on. If a change to a pattern moves an address, that is either a bug or a
deliberate decision to re-derive a site -- never something to quietly update.

The module table is the other half: a kernelcache is an MH_FILESET holding the
kernel and ~300 kexts, so checking which one a site resolved into catches the
failure mode a pattern cannot, matching the right SHAPE in the wrong component.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from srdpatch import arm64 as A       # noqa: E402  (after the path fix)

NOP = A.NOP

# --- 2. the golden table, copied from the hardcoded scripts ----------------
# (va, word before, word after) for 24A5424a / iPhone18,3.
GOLDEN_KERNEL = {
    "ptrace-launchd": [
        (0xFFFFFE000B059784, 0x54000B4B, NOP),
        (0xFFFFFE000B059A80, 0xB82A312A, NOP),
        (0xFFFFFE000B059A88, 0x3216054A, NOP),
        (0xFFFFFE000B059A94, 0xB8283128, NOP),
        (0xFFFFFE000B059AFC, 0x97FEC883, NOP),
        (0xFFFFFE000B059B4C, 0x97FF43A4, NOP),
    ],
    "syscall-filter-off": [
        (0xFFFFFE000AB318A0, 0xD503237F, 0xD2800000),
        (0xFFFFFE000AB318A4, 0xA9BF7BFD, 0xD65F03C0),
        (0xFFFFFE000AB31934, 0xD503237F, 0xD2800000),
        (0xFFFFFE000AB31938, 0xA9BF7BFD, 0xD65F03C0),
        (0xFFFFFE000B31E3D0, 0xD503237F, 0x52800000),
        (0xFFFFFE000B31E3D4, 0xA9BC5FF8, 0xD65F03C0),
    ],
    "tpro-off": [
        (0xFFFFFE0007E640FC, 0x00000001, 0x00000000),      # a data word
    ],
}
# --- 4. which fileset module each kernel site has to land in ---------------
# A kernelcache is an MH_FILESET holding the kernel and ~300 kexts. Checking
# the module a site resolved into is cheap and catches the failure mode a
# pattern cannot: matching the right SHAPE in the wrong component. It is not
# hypothetical -- the bare `mov w1, #0x2a ; bl ; mov xN, x0` shape for TXM
# selector 42 also matches an AppleSEPKeyStore call in every build tested.
EXPECTED_MODULE = {
    "ptrace-launchd":           "com.apple.kernel",
    "syscall-filter-off":       "com.apple.kernel",
    "tpro-off":                 "com.apple.kernel",
}

GOLDEN_TXM = {
    "debug-region-any-caller": [
        (0xFFFFFFF017033418, 0x528004B4, 0x52800020),      # mov w0, #1
        (0xFFFFFFF01703341C, 0x14000039, 0x14000001),      # b <allow>
    ],
}
