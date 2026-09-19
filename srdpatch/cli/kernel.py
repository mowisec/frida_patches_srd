"""Apply named binary patches to an iOS 27 research kernelcache.

Nothing here is pinned to one image. Every site is LOCATED in the image being
patched, by matching the shape of the instructions around it with the
version-dependent fields masked out -- the approach checkra1n's KPF uses
(PongoOS checkra1n/kpf/main.c). See srdpatch.arm64 for the masking
vocabulary and srdpatch.macho for the search.

Every pattern must match EXACTLY ONCE. A pattern that matches twice is as much a
failure as one that matches nothing: it means the shape does not identify the
site, and the patch could land anywhere. Both raise rather than guess. On top of
that, every write still states what it expects to overwrite, so a pattern that
somehow found the wrong instruction is caught before anything is written.

Verified against the images in tests/corpus.py -- iOS 27.0 beta (24A5424a), 27.0
(24A437) and 27.1 beta (24B5084k), on T8150 (iPhone 17 Pro) and T8140
(iPhone 16). tests/test_patchfinders.py checks that, and that every address
the hand-derived version of these finders used is still the address found for
24A5424a.

The addresses quoted in the per-patch documentation below are the ones from
24A5424a/iPhone18,3, the SRD image the sites were originally derived on. They
are there to make the reasoning followable; nothing reads them.

Usage:
    patch_kernel.py <decompressed-kernelcache> <patch-name> -o <out>
    patch_kernel.py <decompressed-kernelcache> --sites
    patch_kernel.py --list
"""
import sys

from . import common
from ..patches import kernel

MH_FILESET = 0xC


def main(argv=None):
    ap = common.parser(__doc__, "decompressed kernelcache Mach-O")
    ap.add_argument("--no-tag", action="store_true",
                    help="leave the build tag alone")
    a = ap.parse_args(argv)

    if a.list:
        return common.describe(kernel.PATCHES, "_ARM64_T<soc>")

    if not a.image:
        ap.error("need an image (or --list)")
    im = common.load(ap, a.image)
    if im.filetype != MH_FILESET:
        print("warning: filetype %#x is not MH_FILESET; is this a kernelcache?"
              % im.filetype, file=sys.stderr)

    if a.sites:
        return common.sites(im, a.image, kernel.SINGLE,
                            extra="  build tag %s" % kernel.stock_tag(im).decode())

    patch = common.require_patch(ap, a.patch, kernel.PATCHES)
    if not a.out:
        ap.error("need -o <out>")
    stock = None if a.no_tag else kernel.stock_tag(im)
    tag = common.write_patched(im, patch, a.out, stock)
    if tag:
        print("check on device:  uname -a   must contain %s" % tag.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
