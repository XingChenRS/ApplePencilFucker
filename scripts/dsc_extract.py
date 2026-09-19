#!/usr/bin/env python3
"""Extract individual dylibs from a split (dyld4) dyld shared cache.

The iOS 16 cache lives in the OS cryptex and is stored in the clear, so no
decryption key is involved. Every image in the cache still begins with a real
mach_header_64; extraction is therefore an address-mapping exercise: resolve
each segment's cache address through the subcache mapping tables, copy the
bytes out, and rewrite the segment file offsets for the new standalone file.

Usage:
    python dsc_extract.py list [substring]            # list dylibs (path contains substring)
    python dsc_extract.py extract <substring> [...]   # extract matching dylibs to analysis/out/
    python dsc_extract.py info                        # dump cache header details
"""

import argparse
import mmap
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DSC_DIR = os.path.join(ROOT, "analysis", "dsc")
OUT_DIR = os.path.join(ROOT, "analysis", "out")
MAIN_NAME = "dyld_shared_cache_arm64e"

PAGE = 0x4000          # output segment alignment
IMAGE_ALIGN = 0x1000   # images inside the cache are 4 KB aligned
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_ID_DYLIB = 0xD
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29

CACHE_BASE = 0x180000000
CACHE_SPAN = 0xAA01C000   # shared region size reported by the cache header
# Segments whose contents are chained-fixup pointers rather than plain values.
POINTER_SEGMENTS = {"__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH", "__AUTH_CONST",
                    "__OBJC_CONST", "__OBJC_DATA", "__const"}


def decode_fixup(raw):
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


class SubCache:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:7] != b"dyld_v1":
            raise ValueError(f"{path}: not a dyld cache (bad magic)")
        mapping_off, mapping_count = struct.unpack_from("<II", self.mm, 16)
        self.mappings = []
        for i in range(mapping_count):
            addr, size, foff, maxprot, initprot = struct.unpack_from(
                "<QQQII", self.mm, mapping_off + i * 32)
            self.mappings.append((addr, size, foff))

    def read(self, addr, size):
        """Read `size` bytes of the cache address space starting at `addr`."""
        out = bytearray()
        remaining = size
        cur = addr
        while remaining > 0:
            for maddr, msize, foff in self.mappings:
                if maddr <= cur < maddr + msize:
                    chunk = min(remaining, maddr + msize - cur)
                    off = foff + (cur - maddr)
                    out += self.mm[off:off + chunk]
                    cur += chunk
                    remaining -= chunk
                    break
            else:
                # Unmapped gap (rare); keep the image layout intact with zeros.
                out += b"\x00" * min(remaining, PAGE)
                cur += min(remaining, PAGE)
                remaining -= min(remaining, PAGE)
        return bytes(out)

    def contains(self, addr):
        return any(maddr <= addr < maddr + msize for maddr, msize, _ in self.mappings)

    def close(self):
        self.mm.close()
        self.f.close()


class Cache:
    def __init__(self, dsc_dir=DSC_DIR):
        names = [MAIN_NAME] + sorted(
            n for n in os.listdir(dsc_dir)
            if n.startswith(MAIN_NAME + ".") and not n.endswith(".symbols"))
        self.subcaches = []
        for n in names:
            p = os.path.join(dsc_dir, n)
            if os.path.getsize(p) < 128:
                continue
            try:
                self.subcaches.append(SubCache(p))
            except ValueError:
                pass
        if not self.subcaches:
            raise SystemExit(f"no dyld cache found in {dsc_dir}")
        self.main = self.subcaches[0]
        self._find_image_array()
        self._load_images()

    # -- header -------------------------------------------------------------
    def _find_image_array(self):
        """Locate (addr,size) of the dylib image array in the main cache header.

        Layout offsets drift between dyld versions, so the pair is validated
        structurally instead of hard-coded: the array must divide evenly into
        32-byte image records whose first entries name real cache paths.
        Newer caches zero this field (the dylib list moved into the trie), in
        which case self.image_array_addr stays None and _scan_images() is used.
        """
        for off in range(0x78, 0x300, 8):
            addr, size = struct.unpack_from("<QQ", self.main.mm, off)
            if not addr or not size or size % 32 or not (200 <= size // 32 <= 20000):
                continue
            if not any(sc.contains(addr) for sc in self.subcaches):
                continue
            try:
                rec = self.read(addr, 32)
                img_addr, _mt, _ino, path_off, _pad = struct.unpack("<QQQII", rec)
                p = self.read(path_off, 64).split(b"\x00")[0]
                if not p.startswith(b"/") or b"." not in p:
                    continue
                if not any(sc.contains(img_addr) for sc in self.subcaches):
                    continue
            except Exception:
                continue
            self.image_array_off, self.image_array_addr, self.image_array_size = off, addr, size
            return
        self.image_array_off = self.image_array_addr = self.image_array_size = None

    def _load_images(self):
        if self.image_array_addr is not None:
            self._load_images_from_array()
        else:
            self._scan_images()

    def _load_images_from_array(self):
        count = self.image_array_size // 32
        raw = self.read(self.image_array_addr, self.image_array_size)
        self.images = []
        for i in range(count):
            addr, modtime, inode, path_off, _pad = struct.unpack_from("<QQQII", raw, i * 32)
            path = self.read(path_off, 256).split(b"\x00")[0].decode("utf-8", "replace")
            if not path.startswith("/"):
                continue
            self.images.append({"addr": addr, "path": path})
        self.images.sort(key=lambda e: e["addr"])

    def _scan_images(self):
        """Recover the image list by scanning for page-aligned mach_header_64s.

        Every image in the cache starts with a real Mach-O header whose
        LC_ID_DYLIB names the library, which is enough to map path -> address
        without depending on the trie payload format.
        """
        self.images = []
        magic = struct.pack("<I", MH_MAGIC_64)
        for sc in self.subcaches:
            for maddr, msize, foff in sc.mappings:
                blob = sc.mm[foff:foff + msize]
                pos = blob.find(magic)
                while pos != -1:
                    addr = maddr + pos
                    if addr % IMAGE_ALIGN == 0:
                        name = self._image_name(addr)
                        if name:
                            self.images.append({"addr": addr, "path": name})
                    pos = blob.find(magic, pos + 4)
        self.images.sort(key=lambda e: e["addr"])

    def _image_name(self, addr):
        try:
            hdr = self.read(addr, 32)
            magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, _flags, _res = \
                struct.unpack("<IiiIIIII", hdr)
            if magic != MH_MAGIC_64 or filetype != 6 or not (0 < ncmds < 200) \
                    or not (0 < sizeofcmds < 0x100000):
                return None
            lcs = self.read(addr + 32, sizeofcmds)
            off = 0
            while off + 8 <= len(lcs):
                cmd, cmdsize = struct.unpack_from("<II", lcs, off)
                if cmdsize < 8 or off + cmdsize > len(lcs):
                    return None
                if cmd == LC_ID_DYLIB:
                    name_off = struct.unpack_from("<I", lcs, off + 8)[0]
                    if name_off < cmdsize:
                        return lcs[off + name_off:off + cmdsize].split(b"\x00")[0] \
                            .decode("utf-8", "replace")
                off += cmdsize
        except Exception:
            return None
        return None

    def read(self, addr, size):
        for sc in self.subcaches:
            if sc.contains(addr):
                return sc.read(addr, size)
        raise ValueError(f"address 0x{addr:x} is not mapped in any subcache")

    def subcache_of(self, addr):
        for sc in self.subcaches:
            if sc.contains(addr):
                return sc
        return None

    def find(self, needle):
        needle = needle.lower()
        return [img for img in self.images if needle in img["path"].lower()]

    # -- extraction ---------------------------------------------------------
    def extract(self, image, out_dir=OUT_DIR):
        addr = image["addr"]
        sc = self.subcache_of(addr)
        hdr = sc.read(addr, 32)
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack("<IiiIIIII", hdr)
        if magic != MH_MAGIC_64:
            raise ValueError(f"{image['path']}: image does not start with mach_header_64 "
                             f"(magic 0x{magic:x})")
        lcs = bytearray(sc.read(addr + 32, sizeofcmds))

        # First pass: locate the linkedit segment in cache-file coordinates so
        # that file-offset fields inside the load commands can be translated.
        segs = []
        off = 0
        while off + 8 <= len(lcs):
            cmd, cmdsize = struct.unpack_from("<II", lcs, off)
            if cmdsize < 8 or off + cmdsize > len(lcs):
                break
            if cmd == LC_SEGMENT_64:
                segname = lcs[off + 8:off + 24].rstrip(b"\x00").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", lcs, off + 24)
                segs.append({"lc_off": off, "name": segname, "vmaddr": vmaddr,
                             "vmsize": vmsize, "old_fileoff": fileoff, "old_filesize": filesize})
            off += cmdsize

        linkedit = next((s for s in segs if s["name"] == "__LINKEDIT"), None)
        le_base = linkedit["old_fileoff"] if linkedit else 0
        le_addr = linkedit["vmaddr"] if linkedit else 0

        def le_data(old_off, size):
            """Read [old_off, old_off+size) out of the shared __LINKEDIT region.

            Every load-command offset field shares the segment fileoff coordinate
            system, so a field value maps back to a cache address through the
            __LINKEDIT base. The region itself is shared by all dylibs, so only
            the ranges actually referenced are carried over.
            """
            if not size or not le_base:
                return b""
            return self.read(le_addr + (old_off - le_base), size)

        header = bytearray(hdr)
        body = bytearray()
        cursor = len(hdr) + sizeofcmds

        def append(data):
            nonlocal cursor
            if cursor % PAGE:
                pad = PAGE - (cursor % PAGE)
                body.extend(b"\x00" * pad)
                cursor += pad
            start = cursor
            body.extend(data)
            cursor += len(data)
            return start

        # Non-linkedit segments first; __LINKEDIT gets rebuilt from the tables below.
        for s in segs:
            if s["vmsize"] == 0 or s["name"] == "__LINKEDIT":
                continue
            # Segments of one image can live in different subcaches, so
            # reads must go through the cache-wide address space.
            new_fo = append(self.read(s["vmaddr"], s["vmsize"]))
            s["new_fo"] = new_fo
            struct.pack_into("<QQQQ", lcs, s["lc_off"] + 24, s["vmaddr"], s["vmsize"],
                             new_fo, s["vmsize"])
            # Section offsets are absolute file offsets and must follow the
            # segment they live in, otherwise the ObjC metadata is unreadable.
            nsects = struct.unpack_from("<I", lcs, s["lc_off"] + 64)[0]
            for i in range(nsects):
                so = s["lc_off"] + 72 + i * 80
                if so + 80 > len(lcs):
                    break
                sect_addr = struct.unpack_from("<Q", lcs, so + 32)[0]
                struct.pack_into("<I", lcs, so + 48, new_fo + (sect_addr - s["vmaddr"]))
        new_le_fo = cursor if cursor % PAGE == 0 else cursor + (PAGE - cursor % PAGE)

        # Relocate every table that lives in the shared __LINKEDIT.
        off = 0
        while off + 8 <= len(lcs):
            cmd, cmdsize = struct.unpack_from("<II", lcs, off)
            if cmdsize < 8 or off + cmdsize > len(lcs):
                break
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", lcs, off + 8)
                new_pool_off, new_pool_size = 0, 0
                if strsize:
                    sym_bytes = bytearray(le_data(symoff, nsyms * 16))
                    strxs = [struct.unpack_from("<I", sym_bytes, i * 16)[0] for i in range(nsyms)] \
                        if nsyms else []
                    if strxs:
                        # String indices point into a pool shared by the whole
                        # cache, so rebuild a compact pool holding just the names
                        # this dylib's symbols use and rebase the indices.
                        pool = bytearray()
                        new_index = {}
                        for i, sx in enumerate(strxs):
                            if sx not in new_index:
                                s = le_data(stroff + sx, 512).split(b"\x00")[0]
                                new_index[sx] = len(pool)
                                pool += s + b"\x00"
                            struct.pack_into("<I", sym_bytes, i * 16, new_index[sx])
                        new_pool_off, new_pool_size = append(bytes(pool)), len(pool)
                    new_sym_off = append(bytes(sym_bytes)) if sym_bytes else 0
                    struct.pack_into("<IIII", lcs, off + 8, new_sym_off, nsyms,
                                     new_pool_off, new_pool_size)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                vals = list(struct.unpack_from("<IIIIIIIIII", lcs, off + 8))
                for i in (0, 2, 4, 6, 8):
                    vals[i] = append(le_data(vals[i], vals[i + 1])) if vals[i] and vals[i + 1] else 0
                struct.pack_into("<IIIIIIIIII", lcs, off + 8, *vals)
            elif cmd in (LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE,
                         LC_FUNCTION_STARTS, LC_DATA_IN_CODE):
                o, s = struct.unpack_from("<II", lcs, off + 8)
                struct.pack_into("<II", lcs, off + 8,
                                 append(le_data(o, s)) if o and s else 0, s)
            elif cmd == LC_DYSYMTAB:
                v = list(struct.unpack_from("<18I", lcs, off + 8))
                for i, entry_size in ((6, 8), (8, 56), (10, 4), (12, 4), (14, 8), (16, 8)):
                    v[i] = append(le_data(v[i], v[i + 1] * entry_size)) \
                        if v[i] and v[i + 1] else 0
                struct.pack_into("<18I", lcs, off + 8, *v)
            off += cmdsize

        linkedit_filesize = cursor - new_le_fo
        if linkedit:
            struct.pack_into("<QQQQ", lcs, linkedit["lc_off"] + 24, linkedit["vmaddr"],
                             max(linkedit["vmsize"], linkedit_filesize), new_le_fo,
                             linkedit_filesize)

        # Turn chained-fixup words into plain addresses so that downstream
        # tools (IDA and our own ObjC walker) can follow references without
        # reimplementing the cache's fixup metadata.
        body_base = len(hdr) + sizeofcmds
        for s in segs:
            if s.get("new_fo") is None or s["name"] not in POINTER_SEGMENTS:
                continue
            start = s["new_fo"] - body_base
            for o in range(start, min(start + s["vmsize"], len(body)) - 7, 8):
                raw = struct.unpack_from("<Q", body, o)[0]
                addr = decode_fixup(raw)
                if addr:
                    struct.pack_into("<Q", body, o, addr)

        os.makedirs(out_dir, exist_ok=True)
        name = image["path"].rsplit("/", 1)[-1]
        out_path = os.path.join(out_dir, name)
        with open(out_path, "wb") as f:
            f.write(header)
            f.write(lcs)
            f.write(body)
        return out_path, len(header) + len(lcs) + len(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list"); p.add_argument("substring", nargs="?", default="")
    p = sub.add_parser("extract"); p.add_argument("substrings", nargs="+")
    sub.add_parser("info")
    args = ap.parse_args()

    cache = Cache()
    if args.cmd == "info":
        print(f"subcaches: {len(cache.subcaches)}")
        print(f"images:    {len(cache.images)}")
        if cache.image_array_addr is None:
            print("image array: none (recovered by scanning for mach_header_64)")
        else:
            print(f"image array at header offset 0x{cache.image_array_off:x}, "
                  f"addr 0x{cache.image_array_addr:x}, {cache.image_array_size} bytes")
    elif args.cmd == "list":
        hits = cache.find(args.substring) if args.substring else cache.images
        print(f"{len(hits)} images match {args.substring!r}")
        for img in hits:
            print(f"  0x{img['addr']:012x}  {img['path']}")
    else:
        for needle in args.substrings:
            hits = cache.find(needle)
            if not hits:
                print(f"!! no image matches {needle!r}", file=sys.stderr)
                continue
            for img in hits:
                try:
                    path, size = cache.extract(img)
                    print(f"extracted {img['path']} -> {path} ({size:,} bytes)")
                except Exception as exc:
                    print(f"!! failed {img['path']}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
