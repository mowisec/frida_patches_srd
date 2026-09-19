"""Finding a pattern in an image: the four verbs every finder is written in.

`find_one` is the one to reach for -- it is the exactly-once contract. The
others exist for the cases where a site is identified by its distance from
another: `find_next` and `find_prev` are checkra1n KPF's find_next_insn.
"""
from .errors import Ambiguous, NotFound
from .scan import match_at, scan


class SearchMixin(object):
    def find_all(self, pattern, ranges=None):
        """Every VA where `pattern` matches. Instruction-aligned."""
        ranges = self.exec_ranges() if ranges is None else ranges
        hits = []
        for start, end in ranges:
            hits += scan(self, self.va_to_off(start),
                          self.va_to_off(end), pattern)
        return hits

    def find_one(self, pattern, ranges=None, what="pattern"):
        """The single VA where `pattern` matches. Raises unless there is exactly one."""
        hits = self.find_all(pattern, ranges)
        if not hits:
            raise NotFound("%s matched nothing in %s" % (what, self.path or "image"))
        if len(hits) > 1:
            raise Ambiguous("%s matched %d times in %s (%s); it does not identify "
                            "a site" % (what, len(hits), self.path or "image",
                                        ", ".join("%#x" % h for h in hits[:8])))
        return hits[0]

    def find_next(self, va, pattern, limit=0x100):
        """First VA at or after `va` (within `limit` instructions) matching `pattern`.

        The KPF `find_next_insn` idiom: anchor on a shape that is unique, then
        walk forward a bounded distance to the instruction actually being patched.
        """
        for i in range(limit):
            at = va + 4 * i
            if match_at(self.data, self.va_to_off(at), pattern):
                return at
        return None

    def find_prev(self, va, pattern, limit=0x100):
        for i in range(limit):
            at = va - 4 * i
            if match_at(self.data, self.va_to_off(at), pattern):
                return at
        return None

