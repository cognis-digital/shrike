"""Discover the AI-stack surfaces on this machine — the MCP servers and agent tools your
assistants are actually wired to — plus any manifests under a path you point at.

This is what makes shrike an *agent* and not just a linter: you don't tell it what to scan,
it finds your attack surface the way an attacker would enumerate it.
"""
from __future__ import annotations
import json, os
from typing import Dict, List

# Well-known client config locations that register MCP servers.
def _client_configs() -> List[str]:
    home = os.path.expanduser("~")
    ad = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    candidates = [
        os.path.join(ad, "Claude", "claude_desktop_config.json"),
        os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        os.path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        os.path.join(home, ".cursor", "mcp.json"),
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        os.path.join(os.getcwd(), ".mcp.json"),
        os.path.join(os.getcwd(), ".vscode", "mcp.json"),
    ]
    return [c for c in candidates if os.path.isfile(c)]


def _servers_from_client_config(path: str) -> List[Dict]:
    """Extract per-server manifests from a client config's mcpServers/servers block."""
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return []
    block = data.get("mcpServers") or data.get("servers") or {}
    out = []
    for name, spec in (block.items() if isinstance(block, dict) else []):
        if not isinstance(spec, dict):
            continue
        m = {"name": name, "_source": path}
        if "command" in spec:
            m["transport"] = {"type": "stdio", "command": spec.get("command"),
                              "args": spec.get("args", [])}
        elif "url" in spec:
            m["transport"] = {"type": "http", "url": spec["url"]}
        if "env" in spec:
            m["auth"] = {"env": spec["env"]}
        out.append(m)
    return out


def discover(path: str | None = None, scan_clients: bool = True) -> Dict[str, List]:
    """Return {'manifests': [file paths], 'client_servers': [inline manifests], 'sources': [...]}.

    - manifests: standalone *.mcp.json / server-manifest files found under `path`
    - client_servers: servers declared inline inside client configs (Claude/Cursor/Windsurf)
    """
    result = {"manifests": [], "client_servers": [], "sources": []}
    if path:
        if os.path.isfile(path):
            result["manifests"].append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith((".json",)) and ("mcp" in f.lower() or "server" in f.lower()
                                                    or os.path.basename(root).lower() in ("fleet", "servers")):
                        result["manifests"].append(os.path.join(root, f))
            # also any *.json directly in the dir (fixtures)
            for f in os.listdir(path):
                fp = os.path.join(path, f)
                if os.path.isfile(fp) and f.endswith(".json") and fp not in result["manifests"]:
                    result["manifests"].append(fp)
    if scan_clients:
        for cfg in _client_configs():
            servers = _servers_from_client_config(cfg)
            if servers:
                result["client_servers"].extend(servers)
                result["sources"].append(cfg)
    result["manifests"] = sorted(set(result["manifests"]))
    return result
