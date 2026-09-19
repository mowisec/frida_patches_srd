"""The TXM patch set.

One patch. Its sibling allow-invalid-any-target, which drops the get-task-allow
requirement on selector 41, is not included: selector 41 has never failed on
this device, so something earlier in that function already allows it.
"""
from .debug_region_any_caller import DEBUG_REGION_ANY_CALLER

# TXM's version string ends the way the kernel's does, and is stamped the same
# way insert_kext stamps RELEASE_ARM64_T8150:
#
#   Code Signing Monitor Image4 Module Version 7.0.0: Mon Aug 10 00:23:45 PDT 2026;
#   root:AppleImage4_txm-374~7051/libimage4_TXM/RELEASE_ARM64E
#
# It appears twice, once plain and once behind the `@(#)VERSION:` what(1) prefix.
# The replacement is the same length, so nothing in the image moves.
#
# Reading it back needs a kernel memory read at the TXM load address -- a panic log
# gives that address (`TXM load address:`) alongside `TXM UUID:`, and the SPTM debug
# header reachable from _SPTMArgs carries it too. There is no cheap read path from a
# healthy device, so the LIVE signal that the patch took is behavioural: the
# `TXM [Error]: selector: 42 | 37` line stops appearing. TXM's own log lines are not
# an option -- the kernel drains its ring with printf(), which is compiled out on
# RELEASE kernels, which is exactly why txm_print_return uses IOLog instead.
STOCK_TAG = b"RELEASE_ARM64E"   # 14 bytes, appears twice

PATCHES = {p.name: p for p in [DEBUG_REGION_ANY_CALLER]}

SINGLE = [DEBUG_REGION_ANY_CALLER]
