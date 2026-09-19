"""Reading a firmware Mach-O and locating sites in it.

    errors.py    NotFound / Ambiguous -- the exactly-once contract
    scan.py      the masked scan itself, vectorised when numpy is around
    image.py     the file format: segments, sections, VA <-> file offset
    search.py    find_all / find_one / find_next / find_prev
    fileset.py   which kext an address lives in
    xrefs.py     C strings and the ADRP+ADD pairs that name them

`Image` is assembled from the last three as mixins, so that each file stays
about one thing. Use `load(path)` to get one.
"""
from .errors import Ambiguous, NotFound
from .image import Image, Section, Segment, load
from .scan import match_at, scan
