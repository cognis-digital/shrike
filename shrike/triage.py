"""Triage — turn a pile of findings into a prioritized plan.

Two jobs:
  1. Blast-radius scoring: rank each finding by severity x reachability x capability, so the
     one finding that actually gets you owned floats to the top.
  2. Cross-server correlation: the failures that only appear when you look at the whole fleet —
     a shared credential, a tool-name collision, an RCE server next to an unauth'd peer. No
     single-server scan can see these; they are where real incidents start.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

_SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1}
_SECRET_RE = re.compile(r"(sk_live_[A-Za-z0-9]{6,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                        r"|xox[baprs]-[A-Za-z0-9\-]{8,}|AKIA[0-9A-Z]{12,})")


def _tport(m: Dict[str, Any]) -> Dict[str, Any]:
    """Transport as a dict, whether the manifest stored it as a string or an object."""
    t = m.get("transport")
    if isinstance(t, str):
        return {"type": t}
    return t if isinstance(t, dict) else {}


def _reachable(m: Dict[str, Any]) -> bool:
    return (_tport(m).get("type") or "").lower() in ("http", "sse", "ws", "websocket")


def _rce_prone(m: Dict[str, Any]) -> bool:
    for tool in (m.get("tools") or []):
        n = (tool.get("name", "") + " " + tool.get("description", "")).lower()
        if any(k in n for k in ("exec", "shell", "command", "run_", "eval", "subprocess", "os.system")):
            return True
    t = _tport(m)
    return t.get("type") == "stdio" and bool(t.get("command"))


def blast_radius(finding_rule: str, severity: str, manifest: Dict[str, Any]) -> int:
    """0-100 blast-radius score for one finding on one server."""
    score = _SEV_WEIGHT.get(severity, 1)
    if _reachable(manifest):
        score = int(score * 1.6)
    if _rce_prone(manifest):
        score = int(score * 1.5)
    if finding_rule.startswith(("transport.no_auth", "tool.shell_exec", "manifest.embedded_secret",
                                "tool.injection_in_description", "tool.auto_approve")):
        score += 15
    return min(score, 100)


def _find_secrets(m: Dict[str, Any]) -> List[str]:
    blob = str(m)
    return sorted(set(_SECRET_RE.findall(blob)))


def correlate(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """items: [{'name','manifest','report'}]. Return fleet-level correlation findings."""
    out: List[Dict[str, Any]] = []
    reachable = [i for i in items if _reachable(i["manifest"])]

    # 1. shared credential across servers
    secret_owners: Dict[str, List[str]] = {}
    for i in items:
        for s in _find_secrets(i["manifest"]):
            secret_owners.setdefault(s, []).append(i["name"])
    for secret, owners in secret_owners.items():
        if len(set(owners)) > 1:
            out.append({"rule": "fleet.shared_secret", "severity": "critical",
                        "servers": sorted(set(owners)),
                        "message": f"The same embedded credential ({secret[:8]}…) appears in "
                        f"{len(set(owners))} manifests ({', '.join(sorted(set(owners)))}); compromise of any "
                        "one server exposes a credential whose blast radius is the whole fleet.",
                        "remediation": "Move it to a per-server secret store with distinct, "
                        "least-privilege, independently-rotatable tokens; never share one key."})

    # 2. tool-name collision across servers (confused-deputy / shadowing precondition)
    tool_owners: Dict[str, List[str]] = {}
    for i in items:
        for tool in (i["manifest"].get("tools") or []):
            if tool.get("name"):
                tool_owners.setdefault(tool["name"], []).append(i["name"])
    for tool, owners in tool_owners.items():
        if len(set(owners)) > 1:
            out.append({"rule": "fleet.tool_collision", "severity": "high",
                        "servers": sorted(set(owners)),
                        "message": f"Tool '{tool}' is registered by {len(set(owners))} servers "
                        f"({', '.join(sorted(set(owners)))}); the agent cannot deterministically "
                        "disambiguate which implementation runs — the precondition for tool shadowing.",
                        "remediation": "Namespace tools per server (server prefix) or remove the "
                        "duplicate registration so each tool name resolves to exactly one server."})

    # 3. lateral movement: an RCE-prone server next to under-protected reachable peers
    rce = [i["name"] for i in items if _rce_prone(i["manifest"])]
    weak_peers = [i["name"] for i in reachable
                  if not (_tport(i["manifest"]).get("auth"))]
    if rce and weak_peers:
        out.append({"rule": "fleet.lateral_movement", "severity": "high",
                    "servers": sorted(set(rce + weak_peers)),
                    "message": f"{', '.join(rce)} expose RCE-prone tools while "
                    f"{len(set(weak_peers))} network-reachable peer(s) are under-protected "
                    f"({', '.join(sorted(set(weak_peers)))}); code-exec on one host pivots to the "
                    "peers — a lateral-movement surface no single manifest reveals.",
                    "remediation": "Isolate RCE-capable servers (separate host / namespace), require "
                    "auth+TLS on every network transport, and bind to localhost."})

    # 4. trust-tier inconsistency across reachable peers
    authed = [i["name"] for i in reachable if _tport(i["manifest"]).get("auth")]
    unauthed = [i["name"] for i in reachable if not _tport(i["manifest"]).get("auth")]
    if authed and unauthed:
        out.append({"rule": "fleet.trust_tier_inconsistency", "severity": "high",
                    "servers": sorted(set(authed + unauthed)),
                    "message": f"On network transports, {len(authed)} server(s) require auth but "
                    f"{len(unauthed)} peer(s) do not ({', '.join(sorted(set(unauthed)))}); the fleet is "
                    "only as strong as its weakest reachable member, and the unauth'd peer is the way in.",
                    "remediation": "Bring every network-reachable server to the same trust tier: "
                    "auth + TLS everywhere, or move the laggards behind the auth gateway."})
    return out
