"""The kernel patch set.

Three patches, 13 instruction words, plus the combination that gets booted.
Each patch is a module of its own; this file is the registry and the build tag.
"""
import re

from ...patch import Patch, combine
from .ptrace_launchd import PTRACE_LAUNCHD
from .syscall_filter_off import SYSCALL_FILTER_OFF
from .tpro_off import TPRO_OFF


# The build tag carries the SoC (RELEASE_ARM64_T8150 / _T8140), so it is
# discovered per image rather than hardcoded. RELEASE_ARM64E also appears in the
# kernelcache and is deliberately not matched.
TAG_RE = re.compile(rb"RELEASE_ARM64_T[0-9A-Z]+")


def stock_tag(im):
    tags = set(TAG_RE.findall(bytes(im.data)))
    if len(tags) != 1:
        raise SystemExit("expected one distinct RELEASE_ARM64_T* build tag, found %r"
                         % sorted(tags))
    return tags.pop()



# --- the set that gets booted --------------------------------------------

MINSET = Patch(
    "ptrace+tpro+sysfilter", "MINSET1",
    "The minimal kernel set: ptrace-launchd, tpro-off and syscall-filter-off, "
    "13 instruction words in total. This is what a working Frida needs on an "
    "iPhone 17 SRD running iOS 27, alongside the TXM patch from patch_txm.py.\n"
    "\n"
    "It is a reduction of twice as many patches, arrived at by removal testing "
    "on the device: build a reduced kernel, boot it, run the five-part gate, "
    "and take out whatever the gate does not notice. These three pass all "
    "five, twice. Everything that could come out has.\n"
    "\n"
    "The three that remain have NOT been removal-tested individually. Each is "
    "documented as load-bearing, but that is reasoning, not a measurement.\n"
    "\n"
    "Load the TXM too, or the result is meaningless: `srdtool research "
    "firmware` loads kernel AND TXM, and a reboot loses both. Reloading with "
    "-K alone silently leaves a patched kernel running against a stock TXM, "
    "where selector 42 still requires the initiating process to hold "
    "com.apple.private.cs.debugger and softening fails EPERM for exactly the "
    "processes that need it.",
    combine(PTRACE_LAUNCHD, TPRO_OFF, SYSCALL_FILTER_OFF))

PATCHES = {p.name: p for p in [
    PTRACE_LAUNCHD, TPRO_OFF, SYSCALL_FILTER_OFF, MINSET,
]}

SINGLE = [PTRACE_LAUNCHD, TPRO_OFF, SYSCALL_FILTER_OFF]
