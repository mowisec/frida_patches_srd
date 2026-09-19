#!/usr/bin/env python3
"""Check the patchfinders against every image in corpus.py.

Four things are checked, in order of how much they would hurt to get wrong:

1. UNIQUENESS. Every patch resolves in every kernel and every TXM, which means
   every pattern behind it matched exactly once. A pattern that matches twice
   raises Ambiguous and fails here, because a patch that could land in two
   places is not a patch.

2. REGRESSION. On the reference image, the finders must produce exactly the
   addresses and exactly the words the hardcoded scripts wrote. The table lives
   in golden.py.

3. MODULE. Every kernel site resolves into the fileset module it belongs in.

4. ROUND TRIP. Patching each image with each patch succeeds, changes only the
   words the finders named plus the build tag, and does not change the file
   size.

    ./test_patchfinders.py            all of it
    ./test_patchfinders.py -v         list every resolved address
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import corpus                                       # noqa: E402
from golden import EXPECTED_MODULE, GOLDEN_KERNEL, GOLDEN_TXM   # noqa: E402
from srdpatch import macho                          # noqa: E402
from srdpatch.patch import apply_writes, stamp_tag  # noqa: E402
from srdpatch.patches import kernel, txm            # noqa: E402


class Result(object):
    def __init__(self):
        self.failures = []

    def check(self, ok, msg):
        if not ok:
            self.failures.append(msg)
            print("  FAIL  %s" % msg)
        return ok


def resolve(im, patch):
    try:
        return patch.locate(im), None
    except (macho.NotFound, macho.Ambiguous, AssertionError) as e:
        return None, e


def run_side(r, what, entries, module, verbose):
    print("\n=== %s ===" % what)
    for entry, path in entries:
        im = macho.load(path)
        stock = (kernel.stock_tag(im) if module is kernel
                 else txm.STOCK_TAG)
        pristine = bytes(im.data)
        print("  %-22s %s" % (entry.name, stock.decode()))
        for name, patch in sorted(module.PATCHES.items()):
            writes, err = resolve(im, patch)
            if not r.check(err is None, "%s / %s: %s" % (entry.name, name, err)):
                continue
            r.check(len(writes) == len({w.va for w in writes}),
                    "%s / %s: duplicate addresses" % (entry.name, name))
            # 3. round trip. The combinations are concatenations of the single
            #    patches, so only the singles are worth writing out.
            if patch in module.SINGLE:
                if module is kernel:
                    want = EXPECTED_MODULE[name]
                    got = sorted({im.module_for(w.va) for w in writes})
                    r.check(got == [want], "%s / %s: resolved into %s, expected %s"
                            % (entry.name, name, got, want))
                _round_trip(r, entry, name, im, pristine, stock, patch, writes)
                if verbose:
                    print("      %-26s %s"
                          % (name, ", ".join("%#x" % w.va for w in writes)))


def _round_trip(r, entry, name, im, pristine, stock, patch, writes):
    """Apply the patch to a scratch copy and check that ONLY the named words
    and the build tag moved. Restores the image afterwards, so the next patch
    still resolves against the stock bytes."""
    where = "%s / %s" % (entry.name, name)
    try:
        apply_writes(im, writes, verbose=False)
        stamp_tag(im, stock, patch.marker, verbose=False)
        after = bytes(im.data)
    finally:
        im.data[:] = bytearray(pristine)

    if not r.check(len(pristine) == len(after), "%s: image changed size" % where):
        return
    allowed = set()
    for w in writes:
        allowed.update(range(im.va_to_off(w.va), im.va_to_off(w.va) + 4))
    i = pristine.find(stock)
    while i != -1:
        allowed.update(range(i, i + len(stock)))
        i = pristine.find(stock, i + len(stock))
    changed = {i for i in range(len(pristine)) if pristine[i] != after[i]}
    stray = sorted(changed - allowed)
    r.check(not stray, "%s: %d unexpected byte(s) changed, first at file %s"
            % (where, len(stray), "%#x" % stray[0] if stray else "-"))
    for w in writes:
        off = im.va_to_off(w.va)
        r.check(int.from_bytes(after[off:off + 4], "little") == w.new,
                "%s: the write at %#x did not take" % (where, w.va))


def check_golden(r, path, module, golden, what):
    print("\n=== %s: regression against the hand-derived addresses ===" % what)
    im = macho.load(path)
    for name, expected in sorted(golden.items()):
        writes, err = resolve(im, module.PATCHES[name])
        if not r.check(err is None, "%s: %s" % (name, err)):
            continue
        got = [(w.va, im.word(w.va), w.new) for w in writes]
        got.sort()
        want = sorted(expected)
        if r.check(got == want, "%s: resolved %s, expected %s"
                   % (name,
                      ["(%#x,%08x,%08x)" % t for t in got],
                      ["(%#x,%08x,%08x)" % t for t in want])):
            print("  ok    %-26s %d write%s"
                  % (name, len(got), "" if len(got) == 1 else "s"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    r = Result()
    check_golden(r, corpus.REFERENCE.kernel, kernel, GOLDEN_KERNEL, "kernel")
    check_golden(r, corpus.REFERENCE.txm, txm, GOLDEN_TXM, "TXM")
    run_side(r, "kernels", corpus.kernels(), kernel, a.verbose)
    run_side(r, "TXMs", corpus.txms(), txm, a.verbose)

    print()
    if r.failures:
        print("%d FAILURE%s" % (len(r.failures), "" if len(r.failures) == 1 else "S"))
        return 1
    print("all patches resolve uniquely in %d kernels and %d TXMs, and match "
          "the hand-derived addresses on %s"
          % (len(corpus.kernels()), len(corpus.txms()),
             corpus.REFERENCE.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
