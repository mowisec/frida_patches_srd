#!/usr/bin/env python3
"""The firmware images the patchfinders are tested against.

Every pattern in srdpatch.patches has to find exactly one site
in EVERY image listed here. Two builds (27.0 release and a 27.1 beta) times two
SoCs (T8150 / iPhone 17 Pro and T8140 / iPhone 16) is enough spread that a
pattern which survives all of them is matching the shape of the code rather than
one compiler's output.

  24A5424a  27.0 beta   iPhone18,3  T8150   the SRD image, where every site was
                                            originally derived by hand
  24A437    27.0        iPhone18,3  T8150
  24A437    27.0        iPhone17,3  T8140
  24B5084k  27.1 beta   iPhone18,3  T8150
  24B5084k  27.1 beta   iPhone17,3  T8140

Fetched with, per build:
  ipsw download appledb --device <dev> --os iOS -b <build> --kernel
  ipsw download appledb --device <dev> --os iOS -b <build> \
       --pattern txm.iphoneos.research.im4p
  ipsw img4 im4p extract txm.iphoneos.research.im4p

The images themselves are NOT in this repository -- they are Apple firmware. By
default they are looked for in the frida_ios27 working tree next door, which is
where they are kept; set FRIDA_IOS27 to point somewhere else.
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
ROOT = os.environ.get("FRIDA_IOS27",
                      os.path.join(os.path.dirname(REPO), "frida_ios27"))
WORK = os.path.join(ROOT, "work", "multiversion")
FIRMWARE = os.path.join(ROOT, "firmware")

# (build, device, soc, kernel path, txm path)
_ENTRIES = [
    ("24A5424a", "iPhone18,3", "T8150",
     os.path.join(FIRMWARE, "24A5424a__iPhone18,3", "kernelcache.research.v57"),
     os.path.join(FIRMWARE, "24A5424a__iPhone18,3", "Firmware", "txm.iphoneos.research")),
]
for _build in ("24A437", "24B5084k"):
    for _dev, _soc in (("iPhone18,3", "T8150"), ("iPhone17,3", "T8140")):
        _d = os.path.join(WORK, "%s__%s" % (_build, _dev))
        _ENTRIES.append((
            _build, _dev, _soc,
            os.path.join(_d, "kernelcache.research.%s" % _dev),
            os.path.join(_d, "Firmware", "txm.iphoneos.research.payload"),
        ))


class Entry(object):
    def __init__(self, build, device, soc, kernel, txm):
        self.build, self.device, self.soc = build, device, soc
        self.kernel, self.txm = kernel, txm

    @property
    def name(self):
        return "%s/%s" % (self.build, self.device)

    def __repr__(self):
        return "<%s %s>" % (self.name, self.soc)


ENTRIES = [Entry(*e) for e in _ENTRIES]
REFERENCE = ENTRIES[0]      # the SRD image; hand-derived addresses refer to it


def kernels(require=True):
    return [(e, e.kernel) for e in ENTRIES if _ok(e.kernel, e, "kernel", require)]


def txms(require=True):
    return [(e, e.txm) for e in ENTRIES if _ok(e.txm, e, "TXM", require)]


def _ok(path, entry, what, require):
    if os.path.exists(path):
        return True
    if require:
        raise SystemExit("missing %s for %s: %s\nSee the docstring of %s for how "
                         "to fetch it." % (what, entry.name, path, __file__))
    return False


if __name__ == "__main__":
    import hashlib
    for e in ENTRIES:
        print(e.name, e.soc)
        for what, path in (("kernel", e.kernel), ("txm", e.txm)):
            if os.path.exists(path):
                h = hashlib.sha256(open(path, "rb").read()).hexdigest()
                print("    %-7s %s  %s" % (what, h[:16], os.path.relpath(path, ROOT)))
            else:
                print("    %-7s MISSING  %s" % (what, path))
