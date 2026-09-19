#!/usr/bin/env python3
"""Relabel arm64e slices in a Mach-O as pointer-auth ABI v2.

The Linux Theos toolchain's linker emits arm64e slices with cpusubtype
0x00000002 ("arm64e.old", the pre-iOS-14 ABI). Every iOS 16 system binary is
built with ABI v2 (cpusubtype 0x80000002 = CPU_SUBTYPE_ARM64E |
CPU_SUBTYPE_PTRAUTH_ABI), and when dyld loads an old-ABI slice into such a
process it applies the chained-fixup / pointer-auth fixups with the wrong
scheme: the tweak comes up holding garbage pointers and the host daemon dies
with SIGBUS the first time one is touched.

Plain C/Objective-C code contains no pointer-auth instructions of its own —
the authenticated pointers are produced by dyld — so declaring the slice as
ABI v2 is what makes the loader fix it up correctly.

The file must be re-signed afterwards (the Mach-O header is inside the signed
range); the Makefile hook does that.

Usage: fix_arm64e_abi.py <macho> [<macho> ...]
"""

import struct
import sys

CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 0x00000002
CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF


def patch_slice(data, offset, label):
    cputype, cpusubtype = struct.unpack_from("<ii", data, offset + 4)
    if cputype != CPU_TYPE_ARM64:
        return False
    subtype = cpusubtype & 0xFFFFFFFF
    if subtype != CPU_SUBTYPE_ARM64E:
        return False
    struct.pack_into("<I", data, offset + 8, subtype | CPU_SUBTYPE_PTRAUTH_ABI)
    print(f"    {label}: cpusubtype 0x{subtype:08x} -> "
          f"0x{subtype | CPU_SUBTYPE_PTRAUTH_ABI:08x}")
    return True


def patch_file(path):
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    if len(data) < 8:
        return False
    magic_be, = struct.unpack_from(">I", data, 0)
    patched = False
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        # Fat headers store every field big-endian.
        is64 = magic_be == FAT_MAGIC_64
        narch, = struct.unpack_from(">I", data, 4)
        for i in range(narch):
            entry = 8 + i * (32 if is64 else 20)
            if is64:
                offset, = struct.unpack_from(">Q", data, entry + 8)
            else:
                offset, = struct.unpack_from(">I", data, entry + 8)
            patched |= patch_slice(data, offset, f"{path} slice {i}")
    elif magic_be == MH_MAGIC_64 or struct.unpack_from("<I", data, 0)[0] == MH_MAGIC_64:
        patched = patch_slice(data, 0, path)
    if patched:
        with open(path, "wb") as fh:
            fh.write(data)
    return patched


def main(paths):
    for path in paths:
        if not patch_file(path):
            print(f"    {path}: no old-ABI arm64e slice to patch")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
