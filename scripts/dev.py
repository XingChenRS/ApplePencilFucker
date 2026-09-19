#!/usr/bin/env python3
"""Device helper for the appencil project.

Connects to the iPad over SSH (mobile@<host>, password auth), escalates to root
with sudo, runs commands, and pushes/pulls files.

Usage:
    python dev.py sh   "<shell command>"        # run as mobile
    python dev.py root "<shell command>"        # run as root via sudo
    python dev.py pull <remote> <local>         # fetch a file (as root if needed)
    python dev.py push <local> <remote>         # upload a file
    python dev.py probe                         # quick connectivity/jailbreak probe

Credentials come from the environment so they never end up in the repo:
PENCIL_HOST, PENCIL_USER, PENCIL_PASS (see README for an example).
"""

import argparse
import os
import shlex
import sys
import time

import paramiko

HOST = os.environ.get("PENCIL_HOST", "")
USER = os.environ.get("PENCIL_USER", "")
PASS = os.environ.get("PENCIL_PASS", "")
PORT = int(os.environ.get("PENCIL_PORT", "22"))

# Rootless jailbreaks keep their tools under /var/jb; the mobile user's PATH
# usually does not include it for root, so sudo and sh are looked up explicitly.
# iOS ships no /bin/sh (the device login shell is zsh); the POSIX shell only
# exists once the jailbreak provides it.
SUDO_CANDIDATES = ["/var/jb/usr/bin/sudo", "/usr/bin/sudo", "sudo"]
SHELL_CANDIDATES = ["/var/jb/bin/sh", "/var/jb/usr/bin/dash", "/bin/sh", "sh"]


class Device:
    def __init__(self, host=HOST, user=USER, password=PASS, port=PORT):
        self.host, self.user, self.password, self.port = host, user, password, port
        self.client = None
        self._sudo = None
        self._shell = None

    def connect(self, timeout=20):
        if not (self.host and self.user and self.password):
            raise RuntimeError("device credentials are not configured; set "
                               "PENCIL_HOST, PENCIL_USER and PENCIL_PASS")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host, port=self.port, username=self.user, password=self.password,
            look_for_keys=False, allow_agent=False, timeout=timeout,
            banner_timeout=timeout, auth_timeout=timeout,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
        )
        return self

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def run(self, command, as_root=False, timeout=180, get_pty=False, stdin_data=None):
        """Run a command, returning (exit_status, stdout, stderr).

        The login shell on the device is zsh, so the command is always handed to
        a POSIX shell to keep quoting and glob semantics predictable.
        """
        command = f"{self.sh_path()} -c {shlex.quote(command)}"
        if as_root:
            command = f"{self.sudo_path()} -S -p '' env LC_ALL=C LANG=C {command}"
            stdin_data = (self.password + "\n") + (stdin_data or "")
        chan = self.client.get_transport().open_session(timeout=timeout)
        chan.settimeout(timeout)
        if get_pty:
            # Some tools (log stream, tail -f) only emit line-buffered output on a tty.
            chan.get_pty()
        chan.exec_command(command)
        if stdin_data:
            chan.sendall(stdin_data)
        chan.shutdown_write()
        out, err = b"", b""
        while True:
            if chan.recv_ready():
                out += chan.recv(65536)
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.02)
        status = chan.recv_exit_status()
        chan.close()
        return status, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def sudo_path(self):
        if self._sudo:
            return self._sudo
        for cand in SUDO_CANDIDATES:
            _, out, _ = self._raw(f"command -v {cand} 2>/dev/null || true")
            if out.strip():
                self._sudo = out.strip().splitlines()[0]
                return self._sudo
        raise RuntimeError("no sudo found on device")

    def sh_path(self):
        if self._shell:
            return self._shell
        for cand in SHELL_CANDIDATES:
            _, out, err = self._raw(f"ls -l {cand} 2>/dev/null || true")
            if out.strip():
                self._shell = cand
                return self._shell
        raise RuntimeError("no POSIX shell found on device")

    def _raw(self, command, timeout=60):
        """Run a command verbatim through the login shell, no wrapping."""
        chan = self.client.get_transport().open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.exec_command(command)
        chan.shutdown_write()
        out, err = b"", b""
        while True:
            if chan.recv_ready():
                out += chan.recv(65536)
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.02)
        chan.recv_exit_status()
        chan.close()
        return 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def sftp(self):
        return self.client.open_sftp()

    def pull(self, remote, local, as_root=False):
        """Fetch one file. Root-owned system files are staged into /tmp first."""
        os.makedirs(os.path.dirname(os.path.abspath(local)) or ".", exist_ok=True)
        if as_root:
            staged = f"/tmp/.appencil_pull_{os.path.basename(remote)}"
            cmd = f"cp {shlex.quote(remote)} {shlex.quote(staged)} && chmod 644 {shlex.quote(staged)}"
            status, _, err = self.run(cmd, as_root=True)
            if status != 0:
                raise RuntimeError(f"staging {remote} failed: {err.strip() or status}")
            remote = staged
        with self.sftp() as sftp:
            sftp.get(remote, local)
        size = os.path.getsize(local)
        print(f"pulled {remote} -> {local} ({size:,} bytes)")
        return local

    def pull_tree(self, remote_dir, local_dir):
        """Recursively fetch a directory (used for bundles and plists)."""
        count = 0
        with self.sftp() as sftp:
            stack = [(remote_dir, local_dir)]
            while stack:
                rdir, ldir = stack.pop()
                os.makedirs(ldir, exist_ok=True)
                for entry in sftp.listdir_attr(rdir):
                    rpath = f"{rdir.rstrip('/')}/{entry.filename}"
                    lpath = os.path.join(ldir, entry.filename)
                    if entry.st_mode & 0o40000:
                        stack.append((rpath, lpath))
                    elif entry.st_size < 64 * 1024 * 1024:
                        sftp.get(rpath, lpath)
                        count += 1
        print(f"pulled tree {remote_dir} -> {local_dir} ({count} files)")
        return count

    def push(self, local, remote, mode=0o644):
        with self.sftp() as sftp:
            sftp.put(local, remote)
            sftp.chmod(remote, mode)
        print(f"pushed {local} -> {remote}")
        return remote


def cmd_probe(dev, args):
    """Report device identity, jailbreak layout, and the tools we rely on."""
    script = r"""
echo "## identity"
uname -a
echo "sw_vers: $(sw_vers 2>/dev/null | tr '\n' ' ')"
echo "product: $(cat /System/Library/CoreServices/SystemVersion.plist 2>/dev/null | tr -d '\n' | head -c 400)"
echo "hw.machine: $(sysctl -n hw.machine 2>/dev/null)  hw.model: $(sysctl -n hw.model 2>/dev/null)"
echo "## jailbreak"
ls -d /var/jb 2>/dev/null && ls /var/jb | head -20
echo "dpkg: $(command -v dpkg || echo none)"
echo "ellekit: $(ls /var/jb/usr/lib/libellekit.dylib /var/jb/usr/lib/libsubstrate.dylib /var/jb/usr/lib/libhooker.dylib 2>/dev/null | tr '\n' ' ')"
echo "tweak inject dirs:"; ls -d /var/jb/Library/TweakInject /var/jb/usr/lib/TweakInject 2>/dev/null
echo "## tools"
for t in sudo ssh scp ldid frida frida-server python3 class-dump class-dump-z jtool otool gdb debugserver log idevicesyslog plutil; do
  printf "%-14s %s\n" "$t" "$(command -v $t 2>/dev/null || echo -)";
done
echo "## bluetooth prefs"
ls -la /var/mobile/Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null
ls -la /var/preferences/SystemConfiguration/com.apple.Bluetooth* 2>/dev/null
echo "## processes"
ps ax 2>/dev/null | grep -iE "bluetoothd|backboardd|SpringBoard" | grep -v grep
"""
    status, out, err = dev.run(script, as_root=True)
    print(out)
    if err.strip():
        print("[stderr]", err.strip()[:2000], file=sys.stderr)
    return status


def main():
    ap = argparse.ArgumentParser(description="appencil device helper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sh"); p.add_argument("command"); p.set_defaults(func=lambda d, a: print(d.run(a.command)[1], end=""))
    p = sub.add_parser("root"); p.add_argument("command"); p.set_defaults(func=lambda d, a: print(d.run(a.command, as_root=True)[1], end=""))
    p = sub.add_parser("probe"); p.set_defaults(func=cmd_probe)

    p = sub.add_parser("pull"); p.add_argument("remote"); p.add_argument("local")
    p.add_argument("-r", "--root", action="store_true", help="copy as root first")
    p.set_defaults(func=lambda d, a: d.pull(a.remote, a.local, as_root=a.root))

    p = sub.add_parser("pull-tree"); p.add_argument("remote_dir"); p.add_argument("local_dir")
    p.set_defaults(func=lambda d, a: d.pull_tree(a.remote_dir, a.local_dir))

    p = sub.add_parser("push"); p.add_argument("local"); p.add_argument("remote")
    p.add_argument("-m", "--mode", default="644")
    p.set_defaults(func=lambda d, a: d.push(a.local, a.remote, int(a.mode, 8)))

    args = ap.parse_args()
    with Device() as dev:
        rc = args.func(dev, args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
