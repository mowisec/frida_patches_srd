"""What a patch is, and how one is applied.

A patch is a named set of SITES. A site is not an address: it is a rule for
finding one, plus what the instruction there has to look like and what to put in
its place. Addresses are resolved per image, which is what lets one patch set
cover several builds and several SoCs.

Pinning an image by sha256 and writing to constants would be one way to be
safe, and giving that up has to be replaced rather than dropped: every write
states what it expects to overwrite, as a MASKED pattern rather than a literal
word, because the register numbers in it are the part that legitimately moves.
"""
from . import arm64


class Write(object):
    """One 32-bit store: where, what must be there, and what replaces it."""

    def __init__(self, va, expect, new, note=""):
        self.va, self.expect, self.new, self.note = va, expect, new, note

    def check(self, current):
        match, mask = self.expect
        return (current & mask) == match

    def __repr__(self):
        return "<write %#x -> %08x %s>" % (self.va, self.new, self.note)


class Patch(object):
    def __init__(self, name, marker, doc, locate):
        self.name, self.marker, self.doc, self.locate = name, marker, doc, locate
        assert len(marker) == 7, \
            "%s: the marker replaces RELEASE in the build tag, so it is 7 characters" % name


def combine(*patches):
    """A locator that runs several patches' locators, in order, de-duplicated.

    Combined images are how these get booted -- a reboot loses whatever
    `srdtool research firmware` loaded, so everything has to travel together --
    and two patches may legitimately resolve to the same instruction.
    """
    def locate(im):
        out, seen = [], set()
        for p in patches:
            for w in p.locate(im):
                if w.va in seen:
                    continue
                seen.add(w.va)
                out.append(w)
        return sorted(out, key=lambda w: w.va)
    return locate


def nop(im, va, expect, note=""):
    return Write(va, expect, arm64.NOP, note)


def apply_writes(im, writes, verbose=True):
    """Apply every write, refusing the lot if any site does not look right."""
    for w in writes:
        cur = im.word(w.va)
        if not w.check(cur):
            match, mask = w.expect
            raise SystemExit(
                "refusing to patch: at %#x (file %#x) found %08x, which does not "
                "match the expected shape %08x/%08x%s.\nThe site was located by "
                "pattern, so this means the pattern found the wrong instruction -- "
                "a finding, not something to force."
                % (w.va, im.va_to_off(w.va), cur, match, mask,
                   " (%s)" % w.note if w.note else ""))
    for w in writes:
        cur = im.word(w.va)
        im.set_word(w.va, w.new)
        if verbose:
            print("  %#x  %08x -> %08x   %s" % (w.va, cur, w.new, w.note))
    return writes


def stamp_tag(im, stock, marker, verbose=True):
    """Replace RELEASE in the image's build tag with a 7-character marker.

    `uname -a` on the device then names which image booted. The stock tag is
    discovered rather than hardcoded, because it carries the SoC: T8150 on an
    iPhone 17 Pro, T8140 on an iPhone 16. The replacement is the same length, so
    nothing in the image moves.
    """
    assert len(marker) == 7, "marker must be exactly 7 characters"
    assert stock.startswith(b"RELEASE"), "unexpected stock tag %r" % stock
    new = marker.encode() + stock[7:]
    assert len(new) == len(stock)
    n = im.data.count(stock)
    if n != 2:
        raise SystemExit("expected 2 copies of %r, found %d" % (stock, n))
    im.data[:] = bytearray(bytes(im.data).replace(stock, new))
    if verbose:
        print("  build tag: %s -> %s  (%d copies)"
              % (stock.decode(), new.decode(), n))
    return new
