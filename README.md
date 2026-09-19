# Firmware patches for Frida on an iOS 27 Security Research Device

The minimal kernel and TXM patch set that makes Frida work on an iPhone 17 Security Research Device
(SRD) running iOS 27, plus the patchfinders that locate every site in whatever firmware image they
are given, the four Frida source patches that go with them (all filed upstream), and a ready-made
cryptex that installs the resulting `frida-server`.

Four instructions' worth of intent, thirteen kernel words and two TXM words in total:

| Image | Patch | Words | What it does |
| --- | --- | --- | --- |
| kernel | `ptrace-launchd` | 6 | Lets `PT_ATTACH` run against launchd, with nothing but `cs_allow_invalid` left of it |
| kernel | `tpro-off` | 1 | Clears `_xprr_tpro_enabled`, so dyld's "TPRO regions should not be writable on entry to dyld" abort stops firing during Frida's spawn handshake |
| kernel | `syscall-filter-off` | 6 | Makes the three Protobox syscall-filter entry points return "no filter", so an agent's syscalls are not denied inside a hardened daemon |
| TXM | `debug-region-any-caller` | 2 | Stops selector 42 (`AssociateDebugRegion`) requiring the *initiating* process to hold `com.apple.private.cs.debugger` |

Each patch's own docstring carries what it does, how its site is identified and what the risk of
applying it is. `python3 patch_kernel.py --list` and `python3 patch_txm.py --list` print all of them.

## What you need

| Tool | For |
| --- | --- |
| `srdtool` | Apple's tool for research devices, shipped with the device programme: loading firmware, installing cryptexes |
| [`ipsw`](https://github.com/blacktop/ipsw) | Fetching and unpacking firmware images (`brew install blacktop/tap/ipsw`) |
| [`insert_kext`](https://github.com/mowisec/insert_kext) | Packaging a patched image back into an IM4P the device will load |
| `libimobiledevice` | `iproxy`, to reach `frida-server` over USB |
| `frida-tools` | `frida`, `frida-ps`, `frida-trace` on the host (`pip install frida-tools`) |
| Python 3 | The patchfinders. `numpy` is optional and only makes the scan faster |

The patchfinders run straight out of a checkout, no install needed. `pip install .` is also
available and puts `patch-kernel` and `patch-txm` on the path.

# Quick start

Eight steps, in the order they have to happen: one boot-arg, a patched kernel and TXM, then Frida
itself.

## 1. Set the boot-arg

The patches are not enough on their own. One boot-arg has to be set on the device as well, or
`spawn()` and spawn gating still fail no matter which firmware is loaded:

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

## 2. Get the stock kernelcache and TXM

Both patchers take a **decompressed Mach-O**, not an IM4P, and packaging in step 4 needs the stock
IM4P as a template, so keep both forms. Straight from the IPSW for the build the device runs:

```bash
IPSW=iPhone18,3_27.0_24A5424a_Restore.ipsw
mkdir -p build

unzip -o -j "$IPSW" kernelcache.research.v57 -d build/
mv build/kernelcache.research.v57 build/kernelcache.stock.im4p
ipsw img4 im4p extract --output build/kernelcache.macho build/kernelcache.stock.im4p

unzip -o -j "$IPSW" Firmware/txm.iphoneos.research.im4p -d build/
mv build/txm.iphoneos.research.im4p build/txm.stock.im4p
ipsw img4 im4p extract --output build/txm.bin build/txm.stock.im4p
```

Without an IPSW to hand, `ipsw` fetches the same two images directly:

```bash
ipsw download appledb --device iPhone18,3 --os iOS -b 24A5424a --kernel
ipsw download appledb --device iPhone18,3 --os iOS -b 24A5424a \
     --pattern txm.iphoneos.research.im4p
```

## 3. Patch them

```bash
python3 patch_kernel.py build/kernelcache.macho ptrace+tpro+sysfilter -o build/kc.minset1.macho
python3 patch_txm.py    build/txm.bin           debug-region-any-caller -o build/txm.a.bin
```

`ptrace+tpro+sysfilter` is the name of the combined patch: all three kernel patches in one image,
which is the set that is actually flown. The three are also available individually, under the names
in the table at the top, for a bisect.

The other two modes write nothing and are worth running first:

```bash
python3 patch_kernel.py --list                 # describe every patch, no image needed
python3 patch_kernel.py build/kernelcache.macho --sites    # resolve every site, print addresses
```

`--sites` is the cheap check that the image is one the finders understand: it resolves every patch in
the image and prints the address it found, without touching a byte. `--no-tag` leaves the build tag
alone, which you almost never want — see step 5 for why the tag is the thing that tells you what
booted.

There is nothing to configure. No address, no map base, no build tag and no register is hardcoded:
every site is located in the image being handed over, by masked instruction matching, and a pattern
that matches twice fails as loudly as one that matches nothing.

## 4. Package the results back into IM4P

`insert_kext` takes the stock IM4P as a template and swaps in the patched payload, keeping the image
type and the property set the device expects:

```bash
python3 ../insert_kext/insert_kext.py --stock-im4p build/kernelcache.stock.im4p \
    package build/kc.minset1.macho -o build/kc.minset1.im4p
python3 ../insert_kext/insert_kext.py --stock-im4p build/txm.stock.im4p \
    package build/txm.a.bin -o build/txm.a.im4p
```

Payloads are packaged **uncompressed**, which is the only form `insert_kext` has confirmed to boot on
this device.

## 5. Load kernel and TXM onto the device

Load them **together**. `srdtool research firmware` loads both, and a reboot loses both. Reloading
with `-K` alone silently leaves a patched kernel running against a stock TXM, where softening still
fails `EPERM` for exactly the processes that need it:

```bash
srdtool research firmware -e <ecid> -K build/kc.minset1.im4p -M build/txm.a.im4p --reboot
```

A firmware load is a **single boot** with automatic fallback: power-cycle the device and it is back
on stock firmware. That makes this the safe half of the setup, and it also means step 5 has to be
repeated after every reboot.

Each patch stamps a seven-character marker over `RELEASE` in the image's build tag, so the booted
kernel names itself. **Check it before believing anything else:**

```bash
srdtool research spawn /usr/bin/uname -a
```

must report `MINSET1_ARM64_T8150`. If it still says `RELEASE_ARM64_T8150`, the load was rejected, the
device fell back to stock, and every subsequent observation is meaningless.

iOS ships no `uname`, so put one in `cryptex/usr/bin/` alongside `frida-server` before step 7 if you
want this check to work.

## 6. Build frida-server

The firmware patches are half of it. The other half is four source patches to Frida itself, all of
them filed upstream, so this is a stock Frida 17.18.0 checkout with four public pull requests
applied. Nothing is held back here.

| Pull request | Title | What it fixes |
| --- | --- | --- |
| [frida-core#1257](https://github.com/frida/frida-core/pull/1257) | Preserve suspension across policy softening | Policy softening `ptrace(PT_ATTACHEXC)`s the target, which resumes a task that was suspended at spawn. The suspension test right after it then reports false, the dyld handshake is skipped, and `spawn()` never gets a working session |
| [frida-core#1256](https://github.com/frida/frida-core/pull/1256) | iOS 27 kernel won't deallocate a `VM_PROT_COPY` mapping | Mapping the agent into the target forces `VM_PROT_COPY` unconditionally, producing a VM entry `mach_vm_deallocate()` will no longer remove -- about 40 MiB of address space leaked per injection |
| [frida-gum#1152](https://github.com/frida/frida-gum/pull/1152) | iOS 27 kernel refuses `VM_PROT_COPY` if memory is already writable | The same unconditional modifier in `gum_try_mprotect()`, where it makes `gum_stalker_thaw()` fail and abort the process |
| [frida-gum#1153](https://github.com/frida/frida-gum/pull/1153) | Hook functions that use both intra-procedure scratch registers | The arm64 relocator picks a scratch register the relocated instruction still needs, so hooking those functions corrupts them |

Two are iOS-27-specific workarounds and two are ordinary bugs that are merely easy to hit here. None
of them changes behaviour on a device that does not have the problem.

From a Frida checkout with those four applied:

```bash
./configure --host=ios-arm64e --enable-server --enable-inject \
            --disable-frida-tools --disable-frida-python
IOS_CERTID=- MACOS_CERTID=- make
```

`IOS_CERTID=-` makes Frida's `post-process.py` sign ad-hoc, which is what cryptex payloads use. No
re-signing afterwards: Frida's own build already signs `frida-server` with the entitlements in
`frida-server.xcent`, and those already include `research.com.apple.license-to-operate`.

The build lands at `build/subprojects/frida-core/server/frida-server`. Copy it over
`cryptex/usr/bin/frida-server` to fly your own, or skip the build entirely and use the one already in
`cryptex/`, which is exactly that: Frida 17.18.0 with those four pull requests applied.

## 7. Install the cryptex

A cryptex is how code gets onto a Security Research Device: a directory tree shaped like a filesystem
root, which `srdtool` turns into a disk image, personalises to one device's ECID and mounts over the
system volume. Anything the tree places in `System/Library/LaunchDaemons/` is started by launchd once
the cryptex is installed, and that is the entire mechanism by which `frida-server` comes up and stays
up.

`cryptex/` is such a root, holding nothing but `frida-server` and the two LaunchDaemon plists that
start it:

```
cryptex/
    usr/bin/frida-server                                       arm64e, ad-hoc signed
    System/Library/LaunchDaemons/frida-research.plist           re.frida.server
    System/Library/LaunchDaemons/frida-policyd-research.plist    re.frida.policyd
```

```bash
srdtool cryptex install --verbose --persist cryptex
```

`--persist` keeps the cryptex across reboots, so `frida-server` comes back on its own after a reboot
or a panic. Add `-e <ecid>` if more than one research device is attached. Success looks like
`[Cryptex:Install] 🎉 Success`, and the two daemons start immediately: `RunAtLoad` and `KeepAlive`
are set on both. The install rebuilds and re-personalises the whole image every time, so budget a few
minutes for it.

**There is no second binary for the policy daemon.** `server/server.vala` dispatches on
`basename(argv[0]) == "frida-policyd"`, so the daemon's plist sets `Program` to `/usr/bin/frida-server`
and `ProgramArguments[0]` to `/usr/bin/frida-policyd`. Registering that daemon is what makes
`--policy-softener=internal` work; without it every attach fails with `policy daemon is not running`.

The server's flags are not arbitrary:

- **`-C`** disables crash-reporter integration and is **load-bearing**. Without it frida-core injects
  an agent into `launchd`, TXM denies it, `launchd` dies and the kernel panics because pid 1 exited.
- **no `-D`**: launchd wants the job in the foreground.
- **`-d /tmp/frida`**, because the cryptex is mounted read-only and the server needs somewhere
  writable to stage binaries.
- **`-l 0.0.0.0:27042`** rather than the default localhost bind.

These three files are byte for byte the ones running on the test device, but they were installed
there inside a larger root that also carries an SSH daemon and a set of command-line tools. The
contents are therefore known to work, while this stripped-down root has not itself been through an
install. If it misbehaves, suspect the trimming before the files.

## 8. Connect

On macOS 27 hosts, Frida's USB device selection (`-U`) does not work as of today. Forward the port
with `iproxy` and attach over TCP instead, which does:

```bash
iproxy 27042 27042 &
frida-ps -H 127.0.0.1:27042
frida    -H 127.0.0.1:27042 -p <pid> -l script.js
frida-trace -H 127.0.0.1:27042 -p <pid> -i 'open'
```

Every Frida tool takes `-H` in place of `-U`. `iproxy` comes from `libimobiledevice`.

# Reference

## How much of this is measured

The kernel set was arrived at by removal testing on the device: build a reduced kernel, boot it, then
run a five-part acceptance test -- attach and detach against running daemons, spawn plus attach,
spawn gating, a Stalker run that survives, and symbolication returning a name rather than a bare
address. Twice as many patches were booted at first; removing them one at a time left these three,
which pass all five parts, twice. Everything that could be taken out has been, and the patches that
turned out not to be needed are not in this repository at all.

The three that remain have **not** been removal-tested individually. Each is documented as
load-bearing, but that is reasoning rather than a measurement.

On the TXM side, `debug-region-any-caller` is the patch that made Frida attach, booted on its own the
day it was written. Nothing else in TXM needs changing: selector 41 (`AllowInvalidCode`) has never
failed on this device, so the `get-task-allow` requirement on the target is already being satisfied
somewhere earlier.

The five-part test has been run against exactly what these steps produce. Earlier runs used a TXM
that also carried an `AllowInvalidCode` patch, 18 bytes different, which is not in this repository
because selector 41 has never failed. On 2026-09-20 the two images this repository builds -- the
kernel and the single-patch TXM, both byte for byte the output of steps 3 and 4 -- were booted
together on the device and passed all five parts, twice.

## How the sites are found

Nothing is hardcoded: not the addresses, not the map base, not the build tag, not even the registers
the sites use. Every site is **located** in the image being patched by matching the shape of the
instructions around it with the version-dependent fields masked out — the approach checkra1n's KPF
uses. Every pattern must match **exactly once**; a pattern that matches twice fails as loudly as one
that matches nothing. On top of that, every write states the masked shape it expects to overwrite,
and `apply_writes` refuses the whole patch before writing anything if one does not match.

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

## Project layout

```
patch_kernel.py            entry points, so the tools run straight out of a checkout
patch_txm.py
cryptex/                   the cryptex: frida-server and its two LaunchDaemon plists
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

## License

Apache License 2.0, see [LICENSE](LICENSE).
