#!/usr/bin/env python3
"""Read the dyld shared cache's local symbol table (`dyld_shared_cache_arm64e.symbols`).

Cache dylibs ship stripped, but the cache carries a side-car symbol file with
nlist entries for every local symbol, including Objective-C method names. That
turns an address into a name, which is what makes the extracted images readable.

Usage:
    python dsc_symbols.py find <substring> [limit]
    python dsc_symbols.py addr <hex-address> [hex-address ...]
    python dsc_symbols.py range <start-hex> <end-hex> [limit]
    python dsc_symbols.py dump-ida <file> <start-hex> <end-hex>   # names for IDA
"""

import mmap
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SYMBOLS = os.path.join(ROOT, "analysis", "dsc", "dyld_shared_cache_arm64e.symbols")


class Symbols:
    def __init__(self, path=SYMBOLS):
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:7] != b"dyld_v1":
            raise ValueError(f"{path}: not a dyld cache header")
        local_off, local_size = struct.unpack_from("<QQ", self.mm, 0x48)
        if not local_off:
            raise ValueError("cache has no local symbol table")
        self.local_off = local_off
        (self.nlist_offset, self.nlist_count, self.strings_offset,
         self.strings_size, self.entries_offset, self.entries_count) = \
            struct.unpack_from("<6I", self.mm, local_off)
        self.by_addr = {}
        self._load()

    def _load(self):
        base = self.local_off
        nlist = base + self.nlist_offset
        strings = base + self.strings_offset
        for i in range(self.nlist_count):
            n_strx, n_type, n_sect, n_desc, n_value = \
                struct.unpack_from("<IBBHQ", self.mm, nlist + i * 16)
            if not n_value:
                continue
            end = self.mm.find(b"\x00", strings + n_strx)
            if end < 0:
                continue
            name = self.mm[strings + n_strx:end].decode("utf-8", "replace")
            if name:
                self.by_addr.setdefault(n_value, name)

    def entries(self):
        base = self.local_off + self.entries_offset
        out = []
        for i in range(self.entries_count):
            dylib_offset, nlist_start, nlist_count = struct.unpack_from("<III", self.mm, base + i * 12)
            out.append((dylib_offset, nlist_start, nlist_count))
        return out

    def name(self, addr):
        return self.by_addr.get(addr)

    def find(self, needle, limit=40):
        needle = needle.lower()
        return sorted((n, a) for a, n in self.by_addr.items() if needle in n.lower())[:limit]

    def in_range(self, start, end, limit=100000):
        return sorted(((a, n) for a, n in self.by_addr.items() if start <= a < end))[:limit]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    s = Symbols()
    cmd = sys.argv[1]
    if cmd == "find":
        for name, addr in s.find(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 40):
            print(f"0x{addr:x}  {name}")
    elif cmd == "addr":
        for arg in sys.argv[2:]:
            a = int(arg, 16)
            print(f"0x{a:x}  {s.name(a)}")
    elif cmd == "range":
        start, end = int(sys.argv[2], 16), int(sys.argv[3], 16)
        limit = int(sys.argv[4]) if len(sys.argv) > 4 else 300
        for a, n in s.in_range(start, end, limit):
            print(f"0x{a:x}  {n}")
    elif cmd == "dump-ida":
        out_path, start, end = sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4], 16)
        lines = [f"0x{a:x} {n}" for a, n in s.in_range(start, end)]
        open(out_path, "w").write("\n".join(lines) + "\n")
        print(f"wrote {len(lines)} symbols to {out_path}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
