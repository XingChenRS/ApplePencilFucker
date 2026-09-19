#!/usr/bin/env python3
"""idamcp — drive one or more idalib MCP servers (ida_pro_mcp.idalib_server).

Replaces the headless idat + bootstrap workflow. Each server process = one
active IDA database; run several on different ports for parallel analysis.

Usage:
    idamcp.py start <binary> [--port 8745] [--name NAME] [--analyze 0|1]
    idamcp.py stop  [--port 8745 | --name NAME | --all]
    idamcp.py list-servers
    idamcp.py session <subcommand>  (open|switch|close|list|current)
    idamcp.py call <tool> <json-arguments> [--port 8745] [--session SID]
    idamcp.py eval <python-code> [--port 8745]   # py_eval shorthand
    idamcp.py sweep <sweeps.json> [--port 8745]  # batch anchor sweep -> JSON

Server registry lives in <repo>/.idamcp/servers.json (gitignored by caller).
The idalib_server module is located relative to the running interpreter (or via
IDAMCP_SERVER); the interpreter defaults to the one running this script.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

def _default_server():
    """Locate idalib_server.py in the running interpreter's site-packages."""
    try:
        import ida_pro_mcp
    except ImportError:
        return ""
    return os.path.join(os.path.dirname(ida_pro_mcp.__file__), "idalib_server.py")


# Overridable via IDAMCP_PYTHON / IDAMCP_SERVER; nothing machine specific is
# baked in, so this file is safe to publish alongside the project.
DEFAULT_PYTHON = os.environ.get("IDAMCP_PYTHON") or sys.executable
DEFAULT_SERVER = os.environ.get("IDAMCP_SERVER") or _default_server()


STATE_DIR = Path(__file__).resolve().parent / ".idamcp"
SERVERS_FILE = STATE_DIR / "servers.json"


def http_json(port, payload, timeout=120):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def rpc(port, method, params=None, timeout=120):
    return http_json(port, {
        "jsonrpc": "2.0", "id": int(time.time() * 1000) % 1000000,
        "method": method, "params": params or {},
    }, timeout=timeout)


def call_tool(port, name, arguments, timeout=300):
    result = rpc(port, "tools/call",
                 {"name": name, "arguments": arguments}, timeout=timeout)
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    content = result["result"].get("content", [])
    text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
    try:
        parsed = json.loads(text) if text else None
    except json.JSONDecodeError:
        parsed = text
    if isinstance(parsed, dict) and parsed.get("isError"):
        raise RuntimeError(f"Tool error: {parsed}")
    return parsed


def eval_py(port, code, timeout=300):
    out = call_tool(port, "py_eval", {"code": code}, timeout=timeout)
    if isinstance(out, dict) and out.get("stderr"):
        print(f"[py_eval stderr] {out['stderr']}", file=sys.stderr)
    return out.get("stdout") or out.get("result") or out


def load_registry():
    if not SERVERS_FILE.exists():
        return {}
    return json.loads(SERVERS_FILE.read_text(encoding="utf-8"))


def save_registry(reg):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SERVERS_FILE.write_text(json.dumps(reg, indent=2), encoding="utf-8")


def find_server(reg, port=None, name=None):
    if port:
        return port
    if name:
        for p, info in reg.items():
            if info.get("name") == name:
                return int(p)
        raise RuntimeError(f"no server named {name}")
    if len(reg) == 1:
        return int(next(iter(reg)))
    raise RuntimeError("multiple servers; pass --port or --name")


def cmd_start(args):
    reg = load_registry()
    port = args.port
    if str(port) in reg:
        info = reg[str(port)]
        raise RuntimeError(f"port {port} already registered: {info}")
    if not Path(args.binary).exists():
        raise RuntimeError(f"binary not found: {args.binary}")
    log = args.log or str(STATE_DIR / f"idalib-{port}.log")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(log, "ab") as logf:
        proc = subprocess.Popen(
            [args.python, args.server, "--port", str(port),
             Path(args.binary).resolve().as_posix()],
            stdout=logf, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    # Poll for the MCP endpoint
    deadline = time.time() + (3600 if args.analyze else 120)
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"server exited early (code {proc.returncode}); see {log}")
        try:
            call_tool(port, "idalib_list", {}, timeout=10)
            # The endpoint responded, but make sure it is OUR process and not
            # a pre-existing server that already owned the port.
            time.sleep(0.5)
            if proc.poll() is not None:
                raise RuntimeError(
                    f"port {port} already in use by another server; "
                    f"spawned process exited (code {proc.returncode}). "
                    "Pick a free --port.")
            break
        except RuntimeError:
            raise
        except Exception:
            time.sleep(5)
    else:
        proc.terminate()
        raise RuntimeError(f"server did not come up in time; see {log}")
    reg[str(port)] = {
        "name": args.name or Path(args.binary).name,
        "binary": Path(args.binary).resolve().as_posix(),
        "pid": proc.pid, "log": log, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_registry(reg)
    print(f"started idalib MCP on http://127.0.0.1:{port} (pid {proc.pid})")
    print(f"  binary: {Path(args.binary).resolve()}")
    print(f"  log:    {log}")


def cmd_register(args):
    """Register an already-running idalib server (started outside this CLI)."""
    reg = load_registry()
    if str(args.port) in reg:
        raise RuntimeError(f"port {args.port} already registered: {reg[str(args.port)]}")
    try:
        call_tool(args.port, "idalib_list", {}, timeout=10)
    except Exception as exc:
        raise RuntimeError(f"no live idalib server on port {args.port}: {exc}")
    reg[str(args.port)] = {
        "name": args.name or f"external-{args.port}",
        "binary": args.binary or "",
        "pid": args.pid,
        "log": "",
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_registry(reg)
    print(f"registered live server on port {args.port}")


def cmd_stop(args):
    reg = load_registry()
    if args.all:
        targets = list(reg.items())
    else:
        port = find_server(reg, port=args.port, name=args.name)
        targets = [(str(port), reg[str(port)])]
    for port_str, info in targets:
        pid = info.get("pid")
        if pid:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True)
        del reg[port_str]
        print(f"stopped server on port {port_str} (pid {pid})")
    save_registry(reg)


def cmd_list_servers(args):
    reg = load_registry()
    if not reg:
        print("no registered servers")
        return
    for port in sorted(reg, key=int):
        info = reg[port]
        alive = ""
        try:
            call_tool(int(port), "idalib_list", {}, timeout=5)
            alive = "up"
        except Exception:
            alive = "down"
        print(f"  {port:>6}  {alive:4}  {info['name']:<20} {info['binary']}")


def cmd_session(args):
    port = find_server(load_registry(), port=args.port, name=args.name)
    sub = args.subcommand
    if sub == "list":
        print(json.dumps(call_tool(port, "idalib_list", {}), indent=2))
    elif sub == "current":
        print(json.dumps(call_tool(port, "idalib_current", {}), indent=2))
    elif sub == "open":
        out = call_tool(port, "idalib_open",
                        {"input_path": Path(args.path).resolve().as_posix(),
                         "run_auto_analysis": bool(args.analyze)},
                        timeout=3600)
        print(json.dumps(out, indent=2))
    elif sub == "switch":
        print(json.dumps(call_tool(port, "idalib_switch",
                                   {"session_id": args.session_id}), indent=2))
    elif sub == "close":
        print(json.dumps(call_tool(port, "idalib_close",
                                   {"session_id": args.session_id}), indent=2))
    else:
        raise RuntimeError(f"unknown session subcommand: {sub}")


def cmd_call(args):
    port = find_server(load_registry(), port=args.port, name=args.name)
    arguments = json.loads(args.arguments)
    print(json.dumps(call_tool(port, args.tool, arguments), indent=2))


def cmd_eval(args):
    port = find_server(load_registry(), port=args.port, name=args.name)
    out = eval_py(port, args.code)
    print(out if isinstance(out, str) else json.dumps(out, indent=2))


def cmd_sweep(args):
    """Batch anchor sweep: {name: {"type": "string"|"immediate", "targets": [...]}}"""
    port = find_server(load_registry(), port=args.port, name=args.name)
    sweeps = json.loads(Path(args.sweeps).read_text(encoding="utf-8"))
    results = {}
    for name, spec in sweeps.items():
        try:
            results[name] = call_tool(
                port, "find",
                {"type": spec.get("type", "string"),
                 "targets": spec["targets"],
                 "limit": spec.get("limit", 5)}, timeout=180)
        except Exception as exc:
            results[name] = {"error": str(exc)}
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Drive idalib MCP servers")
    parser.add_argument("--python", default=os.environ.get("IDAMCP_PYTHON", DEFAULT_PYTHON))
    parser.add_argument("--server", default=os.environ.get("IDAMCP_SERVER", DEFAULT_SERVER))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start")
    p.add_argument("binary")
    p.add_argument("--port", type=int, default=8745)
    p.add_argument("--name")
    p.add_argument("--analyze", type=int, default=1, choices=[0, 1])
    p.add_argument("--log")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("register")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--name")
    p.add_argument("--binary")
    p.add_argument("--pid", type=int)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("stop")
    p.add_argument("--port", type=int)
    p.add_argument("--name")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("list-servers")
    p.set_defaults(func=cmd_list_servers)

    p = sub.add_parser("session")
    p.add_argument("subcommand", choices=["open", "switch", "close", "list", "current"])
    p.add_argument("--path")
    p.add_argument("--session-id")
    p.add_argument("--analyze", type=int, default=1, choices=[0, 1])
    p.add_argument("--port", type=int)
    p.add_argument("--name")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("call")
    p.add_argument("tool")
    p.add_argument("arguments")
    p.add_argument("--port", type=int)
    p.add_argument("--name")
    p.set_defaults(func=cmd_call)

    p = sub.add_parser("eval")
    p.add_argument("code")
    p.add_argument("--port", type=int)
    p.add_argument("--name")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("sweep")
    p.add_argument("sweeps")
    p.add_argument("--port", type=int)
    p.add_argument("--name")
    p.set_defaults(func=cmd_sweep)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
