#!/usr/bin/env python3
"""Resolve pointers inside a chained-fixup Mach-O and walk Objective-C metadata.

iOS 16 binaries store every pointer as a dyld chained fixup, so a plain 8-byte
search for a target address finds nothing. This decodes the fixup chains
(LC_DYLD_CHAINED_FIXUPS) into an address -> target map and uses it to walk
__objc_classlist / class_ro_t / method lists, which is what a class-dump would
do. Works on dylibs extracted from the dyld shared cache and on standalone
system binaries alike.

Usage:
    python objc_walk.py <macho> classes [substring]     # list classes (and methods)
    python objc_walk.py <macho> method <ClassName> <sel> # locate one -[C sel] impl
    python objc_walk.py <macho> who <hexaddress>         # what points at this address
    python objc_walk.py <macho> sel <selector>           # locate a selector string
"""

import argparse
import os
import struct
import sys

# chained fixup pointer formats (dyld_chained_fixups.h)
DYLD_CHAINED_PTR_ARM64E = 1
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_32 = 3
DYLD_CHAINED_PTR_64_OFFSET = 6
DYLD_CHAINED_PTR_ARM64E_USERLAND = 9
DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12
ARM64E_FORMATS = {DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND,
                  DYLD_CHAINED_PTR_ARM64E_USERLAND24}
MULTI = DYLD_CHAINED_PTR_ARM64E_USERLAND24

LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034


# The shared cache is mapped at a fixed address; authenticated arm64e rebases
# only carry 32 bits of target, so they are stored relative to this base.
CACHE_BASE = 0x180000000
CACHE_SPAN = 0xAA01C000


def decode_ptr(raw):
    """Resolve one chained-fixup word to a plain address.

    arm64e cache fixups come in two rebase flavours (43-bit absolute, and
    32-bit relative to the cache base for authenticated pointers) plus bind
    entries that carry a symbol ordinal and no address at all. Rather than
    trusting a discriminator bit, both decodings are tried and the one landing
    inside the cache's address space wins; a bind entry matches neither.
    """
    if not raw:
        return None
    target43 = raw & ((1 << 43) - 1)
    high8 = (raw >> 43) & 0xFF
    candidates = (target43 | (high8 << 56) if high8 else target43,
                  CACHE_BASE + (raw & 0xFFFFFFFF))
    for cand in candidates:
        if CACHE_BASE <= cand < CACHE_BASE + CACHE_SPAN:
            return cand
    return None


class MachO:
    def __init__(self, path, cache=None):
        self.cache = cache
        self.data = open(path, "rb").read()
        self.sections = {}          # name -> (addr, size, fileoff, segname)
        self.segments = []          # (name, vmaddr, vmsize, fileoff, filesize)
        self._parse()

    def _parse(self):
        d = self.data
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _ = \
            struct.unpack_from("<IiiIIIII", d, 0)
        if magic != 0xFEEDFACF:
            raise ValueError("not a 64-bit Mach-O")
        self.base = None
        self.fixups_off = None
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                segname = d[off + 8:off + 24].rstrip(b"\x00").decode()
                vmaddr, vmsize, foff, fsize = struct.unpack_from("<QQQQ", d, off + 24)
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                self.segments.append((segname, vmaddr, vmsize, foff, fsize))
                if self.base is None and vmaddr:
                    self.base = vmaddr
                so = off + 72
                for _s in range(nsects):
                    sname = d[so:so + 16].rstrip(b"\x00").decode()
                    saddr, ssize, sfoff = struct.unpack_from("<QQI", d, so + 32)
                    self.sections.setdefault(sname, (saddr, ssize, sfoff, segname))
                    so += 80
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.fixups_off, _sz = struct.unpack_from("<II", d, off + 8)
            off += cmdsize

    # -- address helpers ----------------------------------------------------
    def read(self, addr, size):
        for _n, vmaddr, vmsize, foff, fsize in self.segments:
            if vmaddr <= addr < vmaddr + vmsize:
                fo = foff + (addr - vmaddr)
                return self.data[fo:fo + size]
        # Selectors and other strings are shared cache-wide and live outside
        # this image, so fall back to the cache when one is available.
        if self.cache is not None:
            try:
                return self.cache.read(addr, size)
            except Exception:
                pass
        return b""

    def section_at(self, addr):
        for name, (saddr, ssize, _f, _seg) in self.sections.items():
            if saddr <= addr < saddr + ssize:
                return name
        return None

    # -- chained fixups -----------------------------------------------------
    def build_fixups(self):
        """Map slot address -> (kind, value) where kind is 'rebase' or 'bind'."""
        self.fixups = {}
        if self.fixups_off is None:
            return self.fixups
        d = self.data
        base_off = self.fixups_off
        version, starts_off, imports_off, symbols_off, imports_count, imports_fmt, symbols_fmt = \
            struct.unpack_from("<IIIIIII", d, base_off)
        self.imports = []
        if imports_count:
            import_offsets = {1: (4, 4), 2: (4, 4), 3: (8, 4)}.get(imports_fmt, (4, 4))
            io = base_off + imports_off
            for i in range(imports_count):
                if imports_fmt == 3:
                    lib_ord, weak, name_off = struct.unpack_from("<iiI", d, io)
                    sz = 12
                else:
                    lib_ord, weak, name_off = struct.unpack_from("<iiI", d, io)
                    sz = 8 if imports_fmt == 1 else 8
                n_off = base_off + symbols_off + name_off
                name = d[n_off:d.find(b"\x00", n_off)].decode("utf-8", "replace")
                self.imports.append(name)
                io += sz
        start = base_off + starts_off
        seg_count = struct.unpack_from("<I", d, start)[0]
        entry_off = start + 4
        page_size = 0x4000
        for _ in range(seg_count):
            seg_offset, max_valid, page_count, _pad = struct.unpack_from("<IIHH", d, entry_off)
            pages = struct.unpack_from(f"<{page_count}H", d, entry_off + 12)
            for pi, page_start in enumerate(pages):
                slot = self.base + seg_offset + pi * page_size + page_start * 4
                chain_end = self.base + seg_offset + (pi + 1) * page_size
                while slot < chain_end:
                    raw = struct.unpack_from("<Q", self.read(slot, 8))[0]
                    if raw == 0:
                        break
                    # arm64e userland pointer formats share this layout
                    bind = (raw >> 63) & 1
                    if bind:
                        ordinal = raw & 0xFFFFFF
                        next_stride = (raw >> 51) & 0x7FF
                        self.fixups[slot] = ("bind", ordinal)
                    else:
                        next_stride = (raw >> 51) & 0x7FF
                        self.fixups[slot] = ("rebase", decode_ptr(raw))
                    if next_stride == 0:
                        break
                    slot += next_stride * 4
            entry_off += 12 + page_count * 2
        return self.fixups

    def read_ptr(self, addr):
        """Read a pointer that the extractor already flattened to a plain address."""
        if not addr:
            return None
        raw = self.read(addr, 8)
        if len(raw) < 8:
            return None
        val = struct.unpack("<Q", raw)[0]
        return val or None

    def pointers(self):
        """All (slot, target) pairs inside pointer-bearing sections."""
        out = []
        for name, (saddr, ssize, foff, seg) in self.sections.items():
            if seg not in ("__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH",
                           "__AUTH_CONST", "__OBJC_CONST", "__OBJC_DATA"):
                continue
            blob = self.data[foff:foff + ssize]
            for i in range(0, len(blob) - 7, 8):
                val = struct.unpack_from("<Q", blob, i)[0]
                if val:
                    out.append((saddr + i, val))
        return out

    def resolve(self, slot):
        if not hasattr(self, "fixups"):
            self.build_fixups()
        ent = self.fixups.get(slot)
        if not ent:
            return None
        return ent[1] if ent[0] == "rebase" else ("bind:" + self.imports[ent[1]]
                                                  if ent[1] < len(self.imports) else "bind")

    def who_points_to(self, addr):
        return [slot for slot, val in self.pointers() if val == addr]

    # -- Objective-C --------------------------------------------------------
    def cstr(self, addr, limit=200):
        return self.read(addr, limit).split(b"\x00")[0].decode("utf-8", "replace")

    def method_list(self, methods_p):
        """Parse a method_list_t, handling both the absolute-pointer and the
        iOS 16 relative-offset (flag 0x80000000) entry encodings."""
        out = []
        head = self.read(methods_p, 8)
        if len(head) != 8:
            return out
        entsize_flags, count = struct.unpack("<II", head)
        relative = bool(entsize_flags & 0x80000000)
        entsize = entsize_flags & 0xFFFF or 12
        for m in range(min(count, 4000)):
            e = methods_p + 8 + m * entsize
            if relative:
                name_off, _types_off, imp_off = struct.unpack("<iii", self.read(e, 12))
                sel_p = e + name_off if name_off else 0
                imp = (e + 8 + imp_off) if imp_off else None
            else:
                sel_p = self.read_ptr(e)
                imp = self.read_ptr(e + 16) if entsize >= 24 else None
            if sel_p:
                out.append((self.cstr(sel_p), imp))
        return out

    def classes(self):
        out = []
        sec = self.sections.get("__objc_classlist")
        if not sec:
            return out
        saddr, ssize, _f, _seg = sec
        for i in range(ssize // 8):
            cls = self.read_ptr(saddr + i * 8)
            if not cls:
                continue
            data = self.read_ptr(cls + 32)          # class_data_bits_t
            if not data:
                continue
            base = data & ~0x7
            name_p = self.read_ptr(base + 24)
            methods_p = self.read_ptr(base + 32)
            name = self.cstr(name_p) if isinstance(name_p, int) else "?"
            methods = []
            if methods_p:
                methods = self.method_list(methods_p)
            out.append((cls, name, methods))
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("macho")
    ap.add_argument("cmd", choices=["classes", "method", "who", "sel", "info"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()
    cache = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import dsc_extract
        cache = dsc_extract.Cache()
    except Exception as exc:
        print(f"# no dyld cache available ({exc}); out-of-image strings will be empty")
    m = MachO(a.macho, cache=cache)
    print(f"# {a.macho}: base=0x{m.base:x} sections={len(m.sections)} "
          f"fixups_off={m.fixups_off}")

    if a.cmd == "info":
        for name, (addr, size, foff, seg) in sorted(m.sections.items()):
            print(f"  {seg:16} {name:24} addr=0x{addr:x} size=0x{size:x} fileoff=0x{foff:x}")
        return
    m.build_fixups()
    print(f"# fixup slots: {len(m.fixups)}  imports: {len(getattr(m, 'imports', []))}")

    if a.cmd == "who":
        addr = int(a.args[0], 16)
        for slot in m.who_points_to(addr):
            print(f"  0x{slot:x} -> 0x{addr:x}   [{m.section_at(slot)}]")
    elif a.cmd == "sel":
        need = a.args[0]
        sec = m.sections.get("__objc_methname")
        if sec:
            saddr, ssize, _f, _seg = sec
            blob = m.read(saddr, ssize)
            pos = blob.find(need.encode())
            while pos != -1:
                print(f"  selector at 0x{saddr + pos:x}: {m.cstr(saddr + pos)}")
                pos = blob.find(need.encode(), pos + 1)
    elif a.cmd == "classes":
        needle = a.args[0] if a.args else ""
        for cls, name, methods in m.classes():
            if needle and needle.lower() not in name.lower():
                continue
            print(f"  {name} @0x{cls:x}  ({len(methods)} methods)")
            if needle:
                for sel, imp in methods:
                    print(f"      -[{name} {sel}] -> {hex(imp) if imp else None}")
    elif a.cmd == "method":
        cls_name, sel = a.args[0], a.args[1]
        for cls, name, methods in m.classes():
            if name != cls_name:
                continue
            for s, imp in methods:
                if s == sel:
                    print(f"  -[{name} {s}] impl = 0x{imp:x}" if imp else
                          f"  -[{name} {s}] impl = ?")


if __name__ == "__main__":
    main()
