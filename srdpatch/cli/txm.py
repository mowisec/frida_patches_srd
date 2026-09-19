"""Apply named binary patches to an iOS 27 research TXM.

Same contract as patch_kernel.py: every site is LOCATED in the image being
patched rather than hardcoded, every pattern must match exactly once, and every
write states the shape it expects to overwrite. See srdpatch.arm64 for the masking
vocabulary and srdpatch.macho for the search.

Both TXM sites are anchored on STRINGS -- the entitlement names and the log
line they sit next to -- rather than on the shape of the code, because in a
binary this small the surrounding shapes repeat and the strings do not.

TXM maps LINEARLY -- every segment's vmaddr minus its fileoff is the same
MAP_BASE -- which macho.Image checks against the segment table rather than
assuming.

The addresses quoted below are from 24A5424a, where the sites were derived by
hand. As it happens the TXM in 24A437 and 24B5084k has them at the same
addresses, and is byte-identical between iPhone17,3 and iPhone18,3 for a given
build; nothing relies on either fact.

Usage:
    patch_txm.py <decompressed-txm> <patch-name> -o <out>
    patch_txm.py <decompressed-txm> --sites
    patch_txm.py --list
"""
import sys

from . import common
from ..patches import txm

MACHO64_MAGIC = b"\xcf\xfa\xed\xfe"


def main(argv=None):
    ap = common.parser(__doc__, "decompressed TXM Mach-O")
    ap.add_argument("--marker", help="7-character tag spliced into TXM's version "
                                     "string in place of RELEASE (default: per patch)")
    ap.add_argument("--no-marker", action="store_true",
                    help="leave the version string alone")
    a = ap.parse_args(argv)

    if a.list:
        return common.describe(txm.PATCHES, "_ARM64E")

    if not a.image:
        ap.error("need an image (or --list)")
    im = common.load(ap, a.image)
    if bytes(im.data[:4]) != MACHO64_MAGIC:
        raise SystemExit("not a 64-bit little-endian Mach-O "
                         "(extract the IM4P payload first)")

    if a.sites:
        return common.sites(im, a.image, txm.SINGLE)

    patch = common.require_patch(ap, a.patch, txm.PATCHES)
    if not a.out:
        ap.error("need -o <out>")
    marker = None
    stock = None
    if not a.no_marker:
        marker = a.marker or patch.marker
        if len(marker) != 7:
            raise SystemExit("--marker must be exactly 7 characters "
                             "(the field is fixed-length)")
        stock = txm.STOCK_TAG
    tag = common.write_patched(im, patch, a.out, stock, marker)
    if tag:
        print("a panic log's `TXM load address:` plus a read of +0x508a should show "
              "...libimage4_TXM/%s" % tag.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
