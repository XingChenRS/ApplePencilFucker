#!/usr/bin/env python3
"""Pull the on-device dyld shared cache (all subcaches) to analysis/dsc/.

The cache lives in the OS cryptex on iOS 16 and is plaintext (no decryption
key needed); the sysctl `kern.sysctl`-style key dance used on older iOS is gone.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dev import Device

REMOTE_DIR = "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld"
LOCAL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis", "dsc")


def main():
    os.makedirs(LOCAL_DIR, exist_ok=True)
    dev = Device().connect()
    try:
        sftp = dev.sftp()
        entries = [e for e in sftp.listdir_attr(REMOTE_DIR)
                   if e.filename.startswith("dyld_shared_cache")]
        entries.sort(key=lambda e: e.filename)
        total = sum(e.st_size for e in entries)
        print(f"{len(entries)} cache files, {total:,} bytes total", flush=True)
        done = 0
        t0 = time.time()
        for e in entries:
            local = os.path.join(LOCAL_DIR, e.filename)
            if os.path.exists(local) and os.path.getsize(local) == e.st_size:
                print(f"  skip (exists) {e.filename}", flush=True)
                done += e.st_size
                continue
            t1 = time.time()
            sftp.get(f"{REMOTE_DIR}/{e.filename}", local)
            dt = time.time() - t1
            done += e.st_size
            print(f"  {e.filename}  {e.st_size:,} B  {dt:5.1f}s  "
                  f"({done/total*100:5.1f}%)  {e.st_size/dt/1e6:6.1f} MB/s", flush=True)
        print(f"done in {time.time()-t0:.1f}s -> {LOCAL_DIR}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
