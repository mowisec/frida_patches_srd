# Firmware patches for Frida on an iOS 27 Security Research Device

The minimal kernel and TXM patch set that makes Frida work on an iPhone 17 Security Research Device
running iOS 27, plus the patchfinders that locate every site in whatever firmware image they are
given.

Four instructions' worth of intent, thirteen kernel words and two TXM words in total:

| Image | Patch | Words | What it does |
| --- | --- | --- | --- |
| kernel | `ptrace-launchd` | 6 | Lets `PT_ATTACH` run against launchd, with nothing but `cs_allow_invalid` left of it |
| kernel | `tpro-off` | 1 | Clears `_xprr_tpro_enabled`, so dyld's "TPRO regions should not be writable on entry to dyld" abort stops firing during Frida's spawn handshake |
| kernel | `syscall-filter-off` | 6 | Makes the three Protobox syscall-filter entry points return "no filter", so an agent's syscalls are not denied inside a hardened daemon |
| TXM | `debug-region-any-caller` | 2 | Stops selector 42 (`AssociateDebugRegion`) requiring the *initiating* process to hold `com.apple.private.cs.debugger` |

## First: the patches are not enough on their own

One boot-arg has to be set on the device as well, or `spawn()` and spawn gating still fail no matter
which firmware is loaded:

```
thid_should_crash=0
```

Without it, iOS 27 kills any process that calls `thread_swap_exception_ports` on another task's
thread, for **any** mask. That is Frida's dyld handshake, so `frida-server` dies with `EXC_GUARD` the
moment it tries. The crash is gated on an XNU `TUNABLE` — `TUNABLE (bool, thid_should_crash,
"thid_should_crash", true)` in `ipc_tt.c` — and `set_exception_behavior_violation()` returns "ignore
the violation" when it is false, so setting the boot-arg does the whole job with no patch at all.

Read what is there first and **append, never replace**: a research device usually carries other
settings in `boot-args`, and overwriting them breaks whatever put them there.

```bash
srdtool research spawn /usr/sbin/nvram boot-args
srdtool research spawn /usr/sbin/nvram "boot-args=<what that printed> thid_should_crash=0"
```

Then reboot. Unlike a firmware load, this **survives reboots**, so it is done once — and unlike a
firmware load it has **no automatic fallback**, which makes it the riskier of the two: a boot-arg the
kernel rejects is a boot loop. This one is a plain `TUNABLE` with no AMFI involvement and booted
first time.

## The patch set

Nothing else is here. This is the reduced set: the patches that were tried along the way and turned
out not to be needed are not included, and neither is the reasoning that got there. Each patch's own
docstring carries what it does, how its site is identified and what the risk of applying it is;
`patch_kernel.py --list` prints all of them.

## Which patches are required

The kernel set was arrived at by removal testing on the device: build a reduced kernel, boot it, run
a five-part gate. Twice as many patches were booted at first; removing them one at a time left these
three, which pass all five gates, twice. Everything that could be taken out has been.

The three that remain have **not** been removal-tested individually. Each is documented as
load-bearing, but that is reasoning rather than a measurement.

On the TXM side, `debug-region-any-caller` is the patch that made Frida attach. Nothing else in TXM
needs changing: selector 41 (`AllowInvalidCode`) has never failed on this device, so the
`get-task-allow` requirement on the target is already being satisfied somewhere earlier.

## Usage

```bash
python3 patch_kernel.py --list                      # describe every patch
python3 patch_kernel.py <kernelcache> --sites       # resolve every site, write nothing
python3 patch_kernel.py <kernelcache> ptrace+tpro+sysfilter -o kc.minset1.macho
python3 patch_txm.py    <txm-payload> debug-region-any-caller -o txm.a.bin
```

Those two scripts are thin entry points into the `srdpatch` package, so a checkout runs as-is with
no install. `pip install .` is also available and puts `patch-kernel` and `patch-txm` on the path.

Both take a **decompressed** Mach-O, not an IM4P. Packaging the result back into an IM4P is
`insert_kext`'s job:

```bash
python3 ../insert_kext/insert_kext.py --stock-im4p <stock>.im4p \
    package kc.minset1.macho -o kc.minset1.im4p
```

Load kernel and TXM **together**. `srdtool research firmware` loads both, and a reboot loses both.
Reloading with `-K` alone silently leaves a patched kernel running against a stock TXM, where
softening still fails `EPERM` for exactly the processes that need it:

```bash
srdtool research firmware -e <ecid> -K kc.minset1.im4p -M txm.a.im4p --reboot
```

Each patch stamps a seven-character marker over `RELEASE` in the image's build tag, so `uname -a`
reports `MINSET1_ARM64_T8150` and names which image booted. If it still says `RELEASE_…`, the stock
kernel booted and every subsequent observation is meaningless.

## How the sites are found

Nothing is hardcoded: not the addresses, not the map base, not the build tag, not even the registers
the sites use. Every site is **located** in the image being patched by matching the shape of the
instructions around it with the version-dependent fields masked out — the approach checkra1n's KPF
uses. Every pattern must match **exactly once**; a pattern that matches twice fails as loudly as one
that matches nothing. On top of that, every write states the masked shape it expects to overwrite,
and `apply_writes` refuses the whole patch before writing anything if one does not match.

## Layout

```
patch_kernel.py            entry points, so the tools run straight out of a checkout
patch_txm.py
srdpatch/
    arm64/                 the masked instruction vocabulary
        fields.py          the (match, mask) primitives, the logical-immediate encoder
        patterns.py        the instruction patterns themselves -- what a finder MATCHES
        decode.py          reading a field back out of a matched instruction
        emit.py            building the words that get WRITTEN
    macho/                 reading a firmware image and locating a site in it
        errors.py          NotFound / Ambiguous -- the exactly-once contract
        scan.py            the masked scan, vectorised with numpy when it is available
        image.py           the file format: segments, sections, VA <-> file offset
        search.py          find_all / find_one / find_next / find_prev
        fileset.py         which kext an address lives in
        xrefs.py           C strings and the ADRP+ADD pairs that name them
    patch.py               what a patch IS: Write, Patch, combine, apply_writes, stamp_tag
    patches/
        kernel/            one module per patch, plus the registry and the build tag
            ptrace_launchd.py
            tpro_off.py
            syscall_filter_off.py
            filters.py     the inlined bitstr_test both filter checks share
        txm/
            debug_region_any_caller.py
    cli/
        common.py          the three modes both command lines share
        kernel.py
        txm.py
tests/
    corpus.py              the firmware images everything is tested against
    golden.py              what the finders must produce on the reference image
    test_patchfinders.py   the whole check, ~80 s
```

`Image` is assembled from `search.py`, `fileset.py` and `xrefs.py` as mixins, so each of those files
stays about one thing and `image.py` stays about the file format. `srdpatch.arm64` re-exports all
four of its modules, so a finder says `import srdpatch.arm64 as A` and reaches the whole vocabulary.

Adding a patch is one new module under `srdpatch/patches/<image>/` holding a `locate_*` function and
the `Patch` that carries it, one import in that package's `__init__.py`, and one entry in
`tests/golden.py`.

`numpy` makes the scan faster and is optional: without it the pure-Python fallback is correct, just
slow.

## Verification

```bash
python3 tests/test_patchfinders.py          # ~80 s
python3 tests/test_patchfinders.py -v       # plus every resolved address
```

Four things are checked across five kernels and five TXM entries — iOS 27.0 beta (`24A5424a`), 27.0
(`24A437`) and 27.1 beta (`24B5084k`), on T8150 (iPhone 17 Pro) and T8140 (iPhone 16):

1. **Uniqueness** — every patch resolves in every image, meaning every pattern matched exactly once.
2. **Regression** — on `24A5424a`/iPhone18,3, the only image any of this has been booted on, the
   finders produce exactly the addresses and exactly the words the original hand-derived scripts
   wrote.
3. **Module** — every kernel site resolves into `com.apple.kernel` rather than into one of the ~300
   kexts sharing the fileset.
4. **Round trip** — patching succeeds, the image does not change size, and only the named words and
   the build tag differ from the input, byte for byte.

The firmware images are Apple's and are not in this repository, and `.gitignore` refuses them so a
stray copy cannot be committed by accident. `tests/corpus.py` names the path it expects each one at
and fails with the `ipsw` command that fetches it if one is missing. The default root is the parent
checkout this repository sits under; set `FRIDA_IOS27` to point elsewhere.

**No image other than `24A5424a`/iPhone18,3 has been booted.** Resolving correctly is necessary, not
sufficient.

## License

Apache License 2.0, see [LICENSE](LICENSE).
