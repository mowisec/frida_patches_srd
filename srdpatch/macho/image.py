"""Parsing a decompressed kernelcache or TXM, and translating addresses in it.

Both images map LINEARLY: for every segment that occupies file space,
vmaddr - fileoff is the same constant. That is checked here rather than
assumed, because it is what makes a single map_base correct.

The searching, the fileset module map and the string cross-references live in
their own modules and are mixed into Image, so that this file stays about the
file format and nothing else.
"""
import struct

from .fileset import FilesetMixin
from .scan import have_numpy
from .search import SearchMixin
from .xrefs import XrefMixin

try:
    import numpy as _np
except ImportError:
    _np = None


LC_REQ_DYLD = 0x80000000
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_FILESET_ENTRY = 0x35 | LC_REQ_DYLD
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
VM_PROT_EXECUTE = 4


class Section(object):
    def __init__(self, segname, sectname, addr, size, offset, flags):
        self.segname, self.sectname = segname, sectname
        self.addr, self.size, self.offset, self.flags = addr, size, offset, flags

    @property
    def executable(self):
        return bool(self.flags & S_ATTR_PURE_INSTRUCTIONS)

    def __repr__(self):
        return "<%s.%s %#x+%#x>" % (self.segname, self.sectname, self.addr, self.size)


class Segment(object):
    def __init__(self, name, vmaddr, vmsize, fileoff, filesize, initprot):
        self.name, self.vmaddr, self.vmsize = name, vmaddr, vmsize
        self.fileoff, self.filesize, self.initprot = fileoff, filesize, initprot
        self.sections = []

    @property
    def executable(self):
        return bool(self.initprot & VM_PROT_EXECUTE)

    def __repr__(self):
        return "<%s %#x+%#x @%#x>" % (self.name, self.vmaddr, self.vmsize, self.fileoff)


class Image(SearchMixin, FilesetMixin, XrefMixin):
    """A decompressed kernelcache or TXM, with VA <-> file offset translation.

    Both images map LINEARLY: for every segment that occupies file space,
    vmaddr - fileoff is the same constant. That is checked here rather than
    assumed, because it is what makes a single map_base correct.
    """

    def __init__(self, data, path=None):
        self.data = bytearray(data)
        self.path = path
        if struct.unpack_from("<I", self.data, 0)[0] != 0xFEEDFACF:
            raise ValueError("not a 64-bit little-endian Mach-O "
                             "(an IM4P must be extracted first)")
        self.filetype = struct.unpack_from("<I", self.data, 12)[0]
        self.segments = []
        self.fileset = {}
        self.symtab = None
        self._words = None
        self._adrp = None
        self._parse()
        self.map_base = self._linear_base()

    # -- parsing -----------------------------------------------------------

    def _parse(self):
        ncmds, = struct.unpack_from("<I", self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SYMTAB:
                self.symtab = struct.unpack_from("<IIII", self.data, off + 8)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8:off + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, off + 24)
                initprot = struct.unpack_from("<i", self.data, off + 60)[0]
                nsects, = struct.unpack_from("<I", self.data, off + 64)
                seg = Segment(name, vmaddr, vmsize, fileoff, filesize, initprot)
                so = off + 72
                for _ in range(nsects):
                    sect = self.data[so:so + 16].rstrip(b"\0").decode()
                    sgn = self.data[so + 16:so + 32].rstrip(b"\0").decode()
                    addr, size = struct.unpack_from("<QQ", self.data, so + 32)
                    soff, = struct.unpack_from("<I", self.data, so + 48)
                    flags, = struct.unpack_from("<I", self.data, so + 64)
                    seg.sections.append(Section(sgn, sect, addr, size, soff, flags))
                    so += 80
                self.segments.append(seg)
            elif cmd == LC_FILESET_ENTRY:
                vmaddr, fileoff = struct.unpack_from("<QQ", self.data, off + 8)
                nameoff, = struct.unpack_from("<I", self.data, off + 24)
                end = self.data.index(b"\0", off + nameoff)
                self.fileset[self.data[off + nameoff:end].decode()] = (vmaddr, fileoff)
            off += cmdsize

    def _linear_base(self):
        bases = {s.name: s.vmaddr - s.fileoff for s in self.segments if s.filesize}
        uniq = set(bases.values())
        if len(uniq) != 1:
            raise ValueError("image does not map linearly; segment bases: "
                             + ", ".join("%s=%#x" % kv for kv in bases.items()))
        return uniq.pop()

    # -- translation -------------------------------------------------------

    def va_to_off(self, va):
        off = va - self.map_base
        if not 0 <= off < len(self.data):
            raise ValueError("VA %#x is outside the image" % va)
        return off

    def off_to_va(self, off):
        return self.map_base + off

    def word(self, va):
        return struct.unpack_from("<I", self.data, self.va_to_off(va))[0]

    def word_at_off(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def set_word(self, va, value):
        struct.pack_into("<I", self.data, self.va_to_off(va), value)

    def cstring(self, va):
        off = self.va_to_off(va)
        end = self.data.index(b"\0", off)
        return bytes(self.data[off:end])

    # -- ranges ------------------------------------------------------------

    def exec_ranges(self):
        """(start_va, end_va) for every run of instructions in the image.

        Only segments the hardware will execute (initprot & VM_PROT_EXECUTE),
        narrowed to their pure-instruction sections where they have any. The
        kernelcache also carries a __PRELINK_TEXT.__text that is flagged
        pure-instructions but sits in a read-only segment; including its 14 MB
        of non-code would only manufacture false matches.
        """
        out = []
        for seg in self.segments:
            if not (seg.filesize and seg.executable):
                continue
            sects = [s for s in seg.sections if s.executable and s.size]
            if sects:
                out += [(s.addr, s.addr + s.size) for s in sects]
            else:
                out.append((seg.vmaddr, seg.vmaddr + seg.filesize))
        return sorted(out)

    def data_ranges(self):
        out = []
        for seg in self.segments:
            if seg.filesize and not seg.executable:
                out.append((seg.vmaddr, seg.vmaddr + seg.filesize))
        return sorted(out)

    def section(self, segname, sectname):
        for seg in self.segments:
            for s in seg.sections:
                if s.segname == segname and s.sectname == sectname:
                    return s
        return None

    # -- the backing store for the vectorised scan -------------------------

    def words(self):
        """The image as a uint32 array, for the vectorised scan. Built once."""
        if self._words is None and have_numpy():
            n = len(self.data) & ~3
            self._words = _np.frombuffer(bytes(self.data[:n]), dtype="<u4")
        return self._words


def load(path):
    with open(path, "rb") as f:
        return Image(f.read(), path=path)
