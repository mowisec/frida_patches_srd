"""Strings, and the code that refers to them.

Both TXM sites are anchored on strings rather than on code shape, because in a
binary that small the surrounding shapes repeat and the strings do not. An
ADRP+ADD pair is how arm64 code names a string, so finding the references to
one means finding those pairs.
"""
from .. import arm64
from .errors import Ambiguous, NotFound


class XrefMixin(object):
    def find_cstring(self, text):
        """Every VA of the NUL-terminated C string `text` in the image.

        The match is anchored on a preceding NUL so that "allow-jit" does not
        also report the tail of "com.apple.developer.cs.allow-jit".
        """
        needle = b"\0" + (text.encode() if isinstance(text, str) else text) + b"\0"
        out, start = [], 0
        while True:
            i = self.data.find(needle, start)
            if i == -1:
                return out
            out.append(self.off_to_va(i + 1))
            start = i + 1

    def one_cstring(self, text):
        hits = self.find_cstring(text)
        if len(hits) != 1:
            raise (NotFound if not hits else Ambiguous)(
                "the string %r appears %d times in %s" % (text, len(hits),
                                                          self.path or "image"))
        return hits[0]

    def adrp_add_xrefs(self, target, ranges=None, window=8):
        """Every VA of an ADRP whose following ADD forms the address `target`.

        This is how the kernel names a string: ADRP to the page, then ADD the
        offset. Both halves are position-dependent, so neither can be matched by
        an instruction pattern -- they have to be decoded and resolved, which is
        what makes a string a stable anchor where an encoding is not.
        """
        out = []
        page = target & ~0xFFF
        off = target & 0xFFF
        for va in self._adrp_forming(page, ranges):
            insn = self.word(va)
            reg = arm64.rd(insn)
            for i in range(1, window + 1):
                at = va + 4 * i
                w = self.word(at)
                if (w & 0xFF800000) == 0x91000000 and arm64.rn(w) == reg \
                        and ((w >> 10) & 0xFFF) == off:
                    out.append(va)
                    break
                if arm64.rd(w) == reg:      # the register was reused for something else
                    break
        return out

    def _adrp_forming(self, page, ranges=None):
        """Every ADRP in the image that forms `page`.

        Scanning for ADRP is the expensive half of a string xref, and a patch
        run does it several times, so the instructions and their decoded pages
        are worked out once and kept.
        """
        key = tuple(ranges) if ranges else None
        if self._adrp is None:
            self._adrp = {}
        if key not in self._adrp:
            vas = self.find_all([arm64.adrp()], ranges)
            pages = [arm64.decode_adrp(self.word(va), va) for va in vas]
            index = {}
            for va, pg in zip(vas, pages):
                index.setdefault(pg, []).append(va)
            self._adrp[key] = index
        return self._adrp[key].get(page, [])

    def one_adrp_add_xref(self, target, ranges=None, what="string"):
        hits = self.adrp_add_xrefs(target, ranges)
        if len(hits) != 1:
            raise (NotFound if not hits else Ambiguous)(
                "%s at %#x has %d ADRP+ADD references in %s (%s)"
                % (what, target, len(hits), self.path or "image",
                   ", ".join("%#x" % h for h in hits[:8])))
        return hits[0]

    # -- convenience -------------------------------------------------------

    def bl_target(self, va):
        return arm64.decode_branch_target(self.word(va), va)

    def adrp_ldr_target(self, adrp_va, ldr_va, scale=8):
        """Resolve the classic ADRP + LDR <x>, [<x>, #off] address pair."""
        page = arm64.decode_adrp(self.word(adrp_va), adrp_va)
        return page + arm64.decode_ldst_off(self.word(ldr_va), scale)

    def adrp_add_target(self, adrp_va, add_va):
        page = arm64.decode_adrp(self.word(adrp_va), adrp_va)
        return page + ((self.word(add_va) >> 10) & 0xFFF)
