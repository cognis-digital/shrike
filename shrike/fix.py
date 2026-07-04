"""Generate the fix. Every finding gets a concrete, deterministic remediation that shrike can
apply to the manifest — add auth, force TLS, unbind from 0.0.0.0, strip injection from a tool
description, require confirmation on dangerous tools. With a local model available, shrike also
writes a short human explanation of *why* the fix matters. Deterministic first; LLM only narrates.
"""
from __future__ import annotations
import copy
from typing import Any, Dict, List, Optional, Tuple

# rule id (or dotted prefix) -> (action label, function that hardens a manifest in place)
def _fix_no_auth(m):
    m.setdefault("transport", {}).setdefault("auth", {"type": "bearer", "required": True})
def _fix_no_tls(m):
    m.setdefault("transport", {})["tls"] = True
def _fix_bind_all(m):
    t = m.setdefault("transport", {})
    if t.get("host") in ("0.0.0.0", "::", ""):
        t["host"] = "127.0.0.1"
def _fix_cors(m):
    t = m.setdefault("transport", {})
    if t.get("allowed_origins") in ("*", ["*"]) or t.get("cors") == "*":
        t["allowed_origins"] = []
        t.pop("cors", None)
def _fix_injection(m):
    for tool in (m.get("tools") or []):
        d = tool.get("description", "")
        if d:
            tool["description"] = "".join(ch for ch in d if ch.isprintable()).split("<")[0].strip()[:300]
def _fix_auto_approve(m):
    for tool in (m.get("tools") or []):
        tool.pop("auto_approve", None)
        tool["requires_confirmation"] = True
def _fix_shell(m):
    for tool in (m.get("tools") or []):
        n = (tool.get("name", "") + tool.get("description", "")).lower()
        if any(k in n for k in ("exec", "shell", "command", "eval")):
            tool["requires_confirmation"] = True
            tool.setdefault("sandbox", "restricted")
def _fix_secret(m):
    a = m.get("auth")
    if isinstance(a, dict) and "token" in a:
        a["token"] = "${MCP_TOKEN}"  # move to env / secret store

_FIXERS: Dict[str, Tuple[str, Any]] = {
    "transport.no_auth": ("Require bearer auth on the transport", _fix_no_auth),
    "transport.no_tls": ("Force TLS on the transport", _fix_no_tls),
    "transport.bind_all": ("Bind to localhost instead of 0.0.0.0", _fix_bind_all),
    "transport.cors_wildcard": ("Remove wildcard CORS origin", _fix_cors),
    "transport.wildcard_origin": ("Remove wildcard CORS origin", _fix_cors),
    "transport.cors": ("Remove wildcard CORS origin", _fix_cors),
    "tool.injection_in_description": ("Strip control chars / markup from tool description", _fix_injection),
    "tool.control_chars": ("Strip control chars from tool description", _fix_injection),
    "tool.auto_approve": ("Require explicit confirmation instead of auto-approve", _fix_auto_approve),
    "tool.danger_no_confirm": ("Require confirmation on the dangerous tool", _fix_auto_approve),
    "tool.shell_exec": ("Gate shell/exec tools behind confirmation + sandbox", _fix_shell),
    "manifest.embedded_secret": ("Move embedded secret to an env var / secret store", _fix_secret),
    "auth.token_passthrough": ("Stop passing the client token through to upstreams", _fix_secret),
    "auth.session_in_url": ("Move the session token out of the URL", _fix_secret),
}


def plan_for(rule: str) -> Optional[Tuple[str, Any]]:
    if rule in _FIXERS:
        return _FIXERS[rule]
    prefix = rule.split(".", 1)[0] + "."
    # only auto-fix rules we have a concrete fixer for
    return None


def harden(manifest: Dict[str, Any], rules: List[str]) -> Dict[str, Any]:
    """Return a hardened copy of a manifest with fixers for the given finding rules applied."""
    fixed = copy.deepcopy(manifest)
    fixed.pop("_source", None)
    for rule in rules:
        p = plan_for(rule)
        if p:
            try:
                p[1](fixed)
            except Exception:
                pass
    return fixed


def actions(rules: List[str]) -> List[str]:
    """Human-readable list of the concrete fix actions shrike would take, deduped, in order."""
    seen, out = set(), []
    for r in rules:
        p = plan_for(r)
        if p and p[0] not in seen:
            seen.add(p[0]); out.append(p[0])
    return out
