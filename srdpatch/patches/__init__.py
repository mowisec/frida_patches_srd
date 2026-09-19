"""The patches themselves, one module per patch.

    kernel/   ptrace-launchd, tpro-off, syscall-filter-off, and the combination
    txm/      debug-region-any-caller

Each module holds one patch: the finder that locates its sites in whatever
image it is given, and the Patch object that carries the finder together with
the documentation of what it does and why. Each package's __init__ is the
registry the command line reads.
"""
