import importlib.util
import os
import sys
import time
from pathlib import Path

import ida_auto
import ida_kernwin

PLUGIN_INSTANCE = None


def _plugin_root() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set")
    return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"


def _load_plugin_loader():
    plugin_root = _plugin_root()
    loader_path = plugin_root / "ida_mcp.py"
    if not loader_path.exists():
        raise RuntimeError(f"ida_mcp loader not found: {loader_path}")

    plugin_root_str = str(plugin_root)
    if plugin_root_str not in sys.path:
        sys.path.insert(0, plugin_root_str)

    spec = importlib.util.spec_from_file_location("ida_mcp_plugin_loader", loader_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to create module spec for {loader_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    host = os.environ.get("IDA_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("IDA_MCP_PORT", "8745"))
    base_url = os.environ.get("IDA_MCP_URL", f"http://{host}:{port}")

    os.environ["IDA_MCP_URL"] = base_url

    print("[IDA_HEADLESS_MCP] Waiting for auto-analysis...")
    ida_auto.auto_wait()
    print("[IDA_HEADLESS_MCP] Auto-analysis complete")

    plugin_loader = _load_plugin_loader()
    plugin_loader.MCP.HOST = host
    plugin_loader.MCP.PORT = port

    global PLUGIN_INSTANCE
    PLUGIN_INSTANCE = plugin_loader.MCP()
    PLUGIN_INSTANCE.init()
    PLUGIN_INSTANCE.run(0)

    if getattr(PLUGIN_INSTANCE, "mcp", None) is None:
        raise RuntimeError(f"ida_mcp server failed to start on {base_url}/mcp")

    print(f"[IDA_HEADLESS_MCP] Streamable HTTP: {base_url}/mcp")
    print(f"[IDA_HEADLESS_MCP] SSE: {base_url}/sse")
    print("[IDA_HEADLESS_MCP] Process will stay alive until terminated")

    # The plugin executes every MCP tool via execute_sync(MFF_WRITE), which
    # posts the work to the IDA kernel queue and blocks until the main thread
    # runs it (same deadlock the official idalib server warns about with
    # background=True). This loop IS the IDA main thread, so it must keep
    # pumping kernel events; a bare sleep would stall every tools/call.
    while True:
        ida_kernwin.wait_for_inner_event(-1)


if __name__ == "__main__":
    main()
