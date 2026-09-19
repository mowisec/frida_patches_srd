"""Which fileset module an address belongs to.

A kernelcache is an MH_FILESET holding the kernel and ~300 kexts, all mapped
into one address space. Checking that a site resolved into the module it is
supposed to live in is cheap, and it catches the one failure mode a pattern
cannot: matching the right SHAPE in the wrong component.
"""
import struct


class FilesetMixin(object):
    def module_map(self):
        """(start, end, name) for every module in the fileset, code included.

        A kernelcache is an MH_FILESET: one image holding the kernel and ~300
        kexts, each with its own Mach-O header and its own slices of the shared
        segments. Attributing a patch site to a module is the cheapest strong
        check that a pattern found the same code in a different build -- the
        Sandbox policy has to be in com.apple.security.sandbox and
        ipc_kobject_server in com.apple.kernel, whatever address they moved to.
        """
        from .image import Image      # late: Image is built out of this mixin

        if getattr(self, "_modmap", None) is None:
            spans = []
            for name, (vmaddr, fileoff) in self.fileset.items():
                try:
                    sub = Image(self.data[self.va_to_off(vmaddr):self.va_to_off(vmaddr) + 0x8000])
                except (ValueError, IndexError, struct.error):
                    # a 0x8000 slice that does not parse as a Mach-O of its own
                    sub = None
                if sub is None:
                    continue
                for seg in sub.segments:
                    if seg.vmsize and seg.name != "__LINKEDIT":
                        spans.append((seg.vmaddr, seg.vmaddr + seg.vmsize, name))
            self._modmap = sorted(spans)
        return self._modmap

    def module_for(self, va):
        """The narrowest fileset module whose segments cover `va`, or None."""
        best = None
        for start, end, name in self.module_map():
            if start <= va < end and (best is None or end - start < best[0]):
                best = (end - start, name)
        return best[1] if best else None
