"""The plumbing both command lines share.

patch_kernel and patch_txm differ in three things -- which patch set they carry,
how the build tag is found, and what they tell you to check on the device once
the image has booted. Everything else is the same three modes: describe the
patches, resolve their sites without writing, or write a patched image.
"""
import argparse
import hashlib
import sys

from .. import macho
from ..patch import apply_writes, stamp_tag


def add_common_arguments(ap, image_help):
    ap.add_argument("image", nargs="?", help=image_help)
    ap.add_argument("patch", nargs="?", help="patch name")
    ap.add_argument("-o", "--out", help="where to write the patched image")
    ap.add_argument("--list", action="store_true",
                    help="describe every patch (no image needed)")
    ap.add_argument("--sites", action="store_true",
                    help="resolve every single patch against <image> and print "
                         "the addresses, without writing anything")


def parser(description, image_help):
    ap = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_arguments(ap, image_help)
    return ap


def describe(patches, tag_suffix):
    """--list: every patch, with the build tag it stamps."""
    for name in patches:
        p = patches[name]
        print("\n=== %s  (build tag %s%s) ===" % (name, p.marker, tag_suffix))
        print(p.doc)
    return 0


def sites(im, path, single, extra=""):
    """--sites: resolve every single patch, write nothing.

    Returns non-zero if any patch failed to resolve, which is what makes this
    usable as a check on a build nobody has tried before.
    """
    print("%s\n  sha256 %s\n  map_base %#x%s\n"
          % (path, hashlib.sha256(bytes(im.data)).hexdigest(), im.map_base, extra))
    bad = 0
    for p in single:
        try:
            writes = p.locate(im)
        except (macho.NotFound, macho.Ambiguous) as e:
            print("  %-26s FAILED: %s" % (p.name, e))
            bad += 1
            continue
        print("  %-26s %s" % (p.name, ", ".join("%#x" % w.va for w in writes)))
    return 1 if bad else 0


def write_patched(im, patch, out, stock, marker=None):
    """Apply one patch, stamp the build tag, and write the image out.

    Returns the tag that was stamped, or None if stamping was turned off.
    Nothing is written to `out` unless every site matched the shape it expects.
    """
    writes = patch.locate(im)
    apply_writes(im, writes)
    tag = None
    if stock is not None:
        tag = stamp_tag(im, stock, marker or patch.marker)
    with open(out, "wb") as f:
        f.write(bytes(im.data))
    print("\nwrote %s  (%d bytes, %d word%s changed)"
          % (out, len(im.data), len(writes), "" if len(writes) == 1 else "s"))
    return tag


def load(ap, path):
    try:
        return macho.load(path)
    except ValueError as e:
        raise SystemExit("%s: %s" % (path, e))


def require_patch(ap, name, patches):
    if not name:
        ap.error("need <image> <patch> -o <out>  (or --list, or --sites)")
    if name not in patches:
        ap.error("unknown patch %r; known: %s" % (name, ", ".join(patches)))
    return patches[name]
