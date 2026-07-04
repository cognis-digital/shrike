"""Core hardening engine for MCP server manifests.

The linter consumes an MCP server descriptor (the JSON object a server
advertises during initialize / tools-list) and applies a rule set spanning
three domains:

  * transport   — stdio vs http/sse, TLS, bind address, auth
  * capability  — declared capabilities vs. tools actually exposed
  * tooling     — per-tool descriptions, schemas, danger surface

No network access; everything is computed locally from the manifest.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Tool identity (re-exported from the package __init__).
TOOL_NAME = "mcpharden"
TOOL_VERSION = "0.4.0"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Verbs in a tool name/description that imply a dangerous side effect and
# therefore demand an explicit, non-trivial description + input schema.
_DANGEROUS_VERBS = (
    "delete", "remove", "drop", "destroy", "exec", "execute", "run",
    "shell", "spawn", "write", "update", "patch", "kill", "truncate",
    "deploy", "transfer", "send", "pay", "purchase", "sudo", "eval",
)

# Match dangerous verbs on word boundaries so that, e.g., "pay" does not fire
# inside "payload", "run" inside "runtime", or "send" inside "sender".
_DANGEROUS_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(v) for v in _DANGEROUS_VERBS) + r")\b",
    re.IGNORECASE,
)

# Patterns that look like secrets baked into a manifest. Two independent
# strategies, OR'd together:
#   1. a credential-ish KEY (possibly inside JSON quotes, with a suffix such as
#      ``upstream_api_key``) assigned a long opaque VALUE, e.g.
#      ``"upstream_api_key": "sk_live_..."`` — note the closing quote of the
#      JSON key sits between the keyword and the ``:`` separator;
#   2. a recognizable high-entropy token PREFIX anywhere (sk_live_, ghp_, AKIA…).
_SECRET_RE = re.compile(
    r"(?i)"
    # strategy 1: key = value
    r"(?:[\"']?[A-Za-z0-9_\-]*"
    r"(?:api[_-]?key|secret|token|password|passwd|bearer|authorization|access[_-]?key)"
    r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+]{8,})"
    # strategy 2: well-known token prefixes
    r"|(?:\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,})"
    r"|(?:\bghp_[A-Za-z0-9]{16,})"
    r"|(?:\bgithub_pat_[A-Za-z0-9_]{20,})"
    r"|(?:\bxox[baprs]-[A-Za-z0-9\-]{8,})"
    r"|(?:\bAKIA[0-9A-Z]{12,})"
    r"|(?:\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,})"
)


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    server_name: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def score(self) -> int:
        """0-100 hardening score; critical/high dominate the penalty."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "server_name": self.server_name,
            "score": self.score,
            "failed": self.failed,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


class ManifestError(ValueError):
    """Raised when a manifest cannot be parsed or is structurally invalid."""


def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")
    # Stash the raw text so secret-scanning can see formatting/whitespace.
    data.setdefault("_raw_text", raw)
    return data


# --------------------------------------------------------------------------
# Rule implementations
# --------------------------------------------------------------------------

def _normalize_transport(m: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce the many real-world transport spellings into one object shape.

    Real manifests express transport as either an object
    ``{"type": "http", "host": "0.0.0.0", "tls": false, "auth": ...}`` or as a
    bare string ``"http"`` / ``"stdio"`` with sibling top-level keys such as
    ``auth``, ``host``, ``tls`` and ``allowed_origins``. Normalize both into a
    single dict so the rule logic only has to reason about one form.
    """
    raw = m.get("transport")
    norm: Dict[str, Any]
    if isinstance(raw, dict):
        norm = dict(raw)
    elif isinstance(raw, str):
        norm = {"type": raw}
    elif raw is None:
        norm = {}
    else:
        # numbers, lists, etc. — genuinely malformed.
        return {"__malformed__": True}

    # Fold sibling top-level keys in when the object form omits them.
    for key in ("host", "port", "tls", "auth", "allowed_origins"):
        if key not in norm and key in m:
            norm[key] = m[key]

    # "auth": "none"/"" means *no* auth — collapse to a falsey marker so the
    # no_auth rule fires instead of being silently satisfied by the string.
    auth = norm.get("auth")
    if isinstance(auth, str) and auth.strip().lower() in ("", "none", "no", "false", "0"):
        norm["auth"] = None
    return norm


def _check_transport(m: Dict[str, Any], out: List[Finding]) -> None:
    transport = _normalize_transport(m)
    if transport.get("__malformed__"):
        out.append(Finding(
            "transport.malformed", "high",
            "`transport` is present but is not an object or a known string.",
            "transport",
            "Declare transport as an object, e.g. {\"type\": \"stdio\"}.",
        ))
        return

    ttype = str(transport.get("type", "")).lower()
    if not ttype:
        out.append(Finding(
            "transport.undeclared", "medium",
            "No transport type declared; clients cannot reason about exposure.",
            "transport.type",
            "Set transport.type to one of stdio, sse, http.",
        ))
        return

    if ttype in ("http", "sse", "streamable-http"):
        host = str(transport.get("host", "")).lower()
        if host in ("0.0.0.0", "::", "*"):
            out.append(Finding(
                "transport.bind_all", "critical",
                f"HTTP transport binds to {host or '0.0.0.0'} (all interfaces); "
                "the MCP server is reachable off-host.",
                "transport.host",
                "Bind to 127.0.0.1 unless remote access is required, and front "
                "with an authenticating reverse proxy.",
            ))
        if not transport.get("tls", False):
            out.append(Finding(
                "transport.no_tls", "high",
                "Network transport without TLS; tool traffic and tokens are "
                "sent in cleartext.",
                "transport.tls",
                "Enable TLS (transport.tls=true) or terminate TLS at a proxy.",
            ))
        if not transport.get("auth"):
            out.append(Finding(
                "transport.no_auth", "high",
                "Network transport without an auth declaration; any client that "
                "reaches the port can invoke tools.",
                "transport.auth",
                "Require a bearer token / OAuth and declare it in transport.auth.",
            ))
        origins = transport.get("allowed_origins")
        if origins in ("*", ["*"]):
            out.append(Finding(
                "transport.wildcard_origin", "medium",
                "Wildcard allowed_origins enables DNS-rebinding / cross-origin "
                "access to the server.",
                "transport.allowed_origins",
                "Pin allowed_origins to explicit, trusted origins.",
            ))
    elif ttype == "stdio":
        pass  # stdio is the least-exposed transport; nothing to flag.
    else:
        out.append(Finding(
            "transport.unknown_type", "low",
            f"Unrecognized transport type '{ttype}'.",
            "transport.type",
            "Use a known transport: stdio, sse, http.",
        ))


def _check_capabilities(m: Dict[str, Any], out: List[Finding]) -> None:
    caps = m.get("capabilities")
    tools = m.get("tools") or []
    if caps is None:
        out.append(Finding(
            "capability.undeclared", "medium",
            "No `capabilities` block; clients cannot gate on advertised features.",
            "capabilities",
            "Declare a capabilities object mirroring what the server exposes.",
        ))
        return
    if not isinstance(caps, dict):
        out.append(Finding(
            "capability.malformed", "high",
            "`capabilities` must be an object.", "capabilities",
            "Use the MCP capabilities object shape.",
        ))
        return

    # Tools exist but capability not advertised — client may refuse or, worse,
    # the server is lying about its surface.
    if tools and "tools" not in caps:
        out.append(Finding(
            "capability.tools_mismatch", "high",
            f"{len(tools)} tool(s) exposed but `capabilities.tools` is not "
            "advertised — capability declaration and surface disagree.",
            "capabilities.tools",
            "Advertise every capability you actually serve.",
        ))
    # Advertised but unused capabilities widen the trust surface needlessly.
    if "tools" in caps and not tools:
        out.append(Finding(
            "capability.tools_empty", "low",
            "Advertises tools capability but exposes zero tools.",
            "capabilities.tools",
            "Drop unused capability advertisements to minimize attack surface.",
        ))
    if caps.get("experimental"):
        out.append(Finding(
            "capability.experimental", "low",
            "Experimental capabilities are enabled.", "capabilities.experimental",
            "Disable experimental capabilities in production deployments.",
        ))


def _check_tools(m: Dict[str, Any], out: List[Finding]) -> None:
    tools = m.get("tools")
    if tools is None:
        return
    if not isinstance(tools, list):
        out.append(Finding(
            "tool.malformed", "high", "`tools` must be an array.", "tools",
            "Express tools as a list of tool objects.",
        ))
        return

    seen: Dict[str, int] = {}
    for idx, tool in enumerate(tools):
        loc = f"tools[{idx}]"
        if not isinstance(tool, dict):
            out.append(Finding(
                "tool.malformed", "high", "Tool entry is not an object.", loc,
                "Each tool must be an object with name + description.",
            ))
            continue
        name = str(tool.get("name", "")).strip()
        if name:
            loc = f"tools[{idx}]:{name}"
            seen[name] = seen.get(name, 0) + 1
        else:
            out.append(Finding(
                "tool.no_name", "high", "Tool has no name.", loc,
                "Give every tool a stable, unique name.",
            ))

        desc = str(tool.get("description", "")).strip()
        if not desc:
            out.append(Finding(
                "tool.no_description", "medium",
                "Tool has no description; agents cannot judge safe usage and "
                "are prone to misuse.",
                loc,
                "Add a clear description stating purpose and side effects.",
            ))
        elif len(desc) < 12:
            out.append(Finding(
                "tool.thin_description", "low",
                f"Tool description is very short ('{desc}').", loc,
                "Describe inputs, outputs, and side effects in full.",
            ))

        # Prompt-injection / instruction-smuggling in descriptions.
        low_desc = desc.lower()
        if any(p in low_desc for p in (
            "ignore previous", "ignore all previous", "system prompt",
            "do not tell", "without informing", "bypass",
        )):
            out.append(Finding(
                "tool.injection_in_description", "critical",
                "Tool description contains instruction-smuggling text that can "
                "hijack the calling agent.",
                loc,
                "Remove imperative/meta instructions from tool descriptions.",
            ))

        schema = tool.get("inputSchema") or tool.get("input_schema")
        haystack = name + " " + desc
        dangerous = bool(_DANGEROUS_RE.search(haystack))
        if dangerous:
            if not schema:
                out.append(Finding(
                    "tool.danger_no_schema", "high",
                    "Side-effecting tool exposes no inputSchema; arguments are "
                    "unvalidated and unconstrained.",
                    loc,
                    "Provide a strict JSON Schema (types, enums, required).",
                ))
            if not tool.get("confirm") and not tool.get("requiresConfirmation"):
                out.append(Finding(
                    "tool.danger_no_confirm", "medium",
                    "Side-effecting tool does not request user confirmation.",
                    loc,
                    "Set requiresConfirmation=true for destructive operations.",
                ))

        if isinstance(schema, dict):
            if schema.get("additionalProperties") is True:
                out.append(Finding(
                    "tool.schema_open", "medium",
                    "inputSchema sets additionalProperties=true; unexpected "
                    "fields are accepted.",
                    loc,
                    "Set additionalProperties=false to reject unknown args.",
                ))

    for dup_name, count in seen.items():
        if count > 1:
            out.append(Finding(
                "tool.duplicate_name", "high",
                f"Tool name '{dup_name}' is declared {count} times; clients "
                "cannot disambiguate which implementation runs.",
                f"tools:{dup_name}",
                "Make every tool name unique.",
            ))


def _check_secrets(m: Dict[str, Any], out: List[Finding]) -> None:
    raw = m.get("_raw_text", "")
    if raw and _SECRET_RE.search(raw):
        out.append(Finding(
            "manifest.embedded_secret", "critical",
            "Manifest appears to contain an embedded credential / token.",
            "<manifest>",
            "Move secrets to environment variables or a secret store; never "
            "ship them in the manifest.",
        ))


# Control / ANSI escape characters (excluding tab/newline/CR) — line-jumping.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Shell/exec indicators for command-injection-prone tools.
_SHELL_RE = re.compile(
    r"\b(?:os\.system|subprocess|shell\s*=\s*true|/bin/sh|/bin/bash|\bsh\s+-c\b|"
    r"\bexec\b|\beval\b|\bspawn\b|child_process|popen)\b", re.IGNORECASE)
_SHELL_NAME_RE = re.compile(r"(?:^|[_\-])(?:exec|shell|run|cmd|command|terminal|bash)(?:$|[_\-])",
                            re.IGNORECASE)


def _check_mcp_vuln_classes(m: Dict[str, Any], out: List[Finding]) -> None:
    """Detect the documented MCP attack classes catalogued in :mod:`vulndb`.

    Covers line-jumping, cross-server shadowing, command-injection-prone tools,
    rug-pull/dynamic registration, token passthrough, OAuth session-in-URL,
    SSE/HTTP CORS-wildcard (DNS rebinding), auto-approval, unpinned server
    commands, and unbounded sampling.
    """
    transport = m.get("transport") if isinstance(m.get("transport"), dict) else {}
    ttype = str(transport.get("type", "")).lower()
    caps = m.get("capabilities") if isinstance(m.get("capabilities"), dict) else {}

    # MCP-SSE-01 — permissive CORS on a network transport (DNS rebinding).
    if ttype in ("http", "sse", "streamable-http"):
        cors = transport.get("cors", transport.get("allow_origins"))
        origins = cors.get("allow_origins") if isinstance(cors, dict) else cors
        wild = origins == "*" or (isinstance(origins, list) and "*" in origins) or cors == "*"
        if wild:
            out.append(Finding(
                "transport.cors_wildcard", "critical",
                "Network transport allows any Origin (CORS '*'); vulnerable to "
                "DNS-rebinding into internal MCP services.",
                "transport.cors",
                "Validate the Origin header, drop wildcard CORS, bind to localhost, "
                "and require auth on every request.",
            ))

    # MCP-SC-01 — unpinned stdio launch command (supply-chain RCE).
    cmd = str(transport.get("command", "")).lower()
    args = transport.get("args") if isinstance(transport.get("args"), list) else []
    argstr = " ".join(str(a) for a in args)
    if cmd in ("npx", "uvx", "pipx", "bunx") or cmd.endswith(("npx", "uvx")):
        pinned = "@" in argstr or "==" in argstr
        if not pinned:
            out.append(Finding(
                "transport.unpinned_command", "high",
                f"Server launched via '{cmd}' without a pinned version; a poisoned "
                "release would execute on the host.",
                "transport.command",
                "Pin the package to an exact version/hash and lock dependencies.",
            ))

    # MCP-RP-01 — mutable/dynamic tool registration (rug pull channel).
    tools_cap = caps.get("tools") if isinstance(caps.get("tools"), dict) else {}
    if tools_cap.get("listChanged") is True or m.get("dynamicRegistration") is True \
            or m.get("dynamic_registration") is True:
        out.append(Finding(
            "tool.mutable_registration", "high",
            "Server can change its tool definitions at runtime (listChanged / "
            "dynamic registration); the rug-pull channel for tool poisoning.",
            "capabilities.tools.listChanged",
            "Pin tool definitions with a hash and re-prompt the user on any change.",
        ))

    # MCP-SAMP-01 — sampling exposed without rate limiting.
    if "sampling" in caps and not (m.get("rateLimit") or m.get("rate_limit")
                                   or (isinstance(caps.get("sampling"), dict)
                                       and caps["sampling"].get("rateLimit"))):
        out.append(Finding(
            "capabilities.sampling_unbounded", "medium",
            "Sampling capability is exposed with no rate limit/quota; enables "
            "credit-drain and denial-of-service.",
            "capabilities.sampling",
            "Rate-limit and quota sampling; require auth; alert on spend anomalies.",
        ))

    # MCP-TPT-01 — token passthrough / authority forwarding.
    auth = m.get("auth") if isinstance(m.get("auth"), dict) else {}
    if auth.get("passthrough") is True or m.get("token_passthrough") is True \
            or auth.get("forward_token") is True:
        out.append(Finding(
            "auth.token_passthrough", "high",
            "Server forwards the upstream/user token to tools; collapses the auth "
            "boundary (confused-deputy risk).",
            "auth.passthrough",
            "Mint short-lived, audience-scoped tokens per tool; never forward the "
            "user's bearer token downstream.",
        ))

    # MCP-OAUTH-01 — session id in URL or OAuth without PKCE/state binding.
    if auth.get("session_in_url") is True or "session=" in str(auth.get("url", "")).lower():
        out.append(Finding(
            "auth.session_in_url", "high",
            "Session identifier carried in a URL; enables session hijacking/fixation.",
            "auth.url",
            "Keep session ids out of URLs; use rotating unguessable tokens.",
        ))
    if str(auth.get("type", "")).lower() in ("oauth", "oauth2") and not (
            auth.get("pkce") or auth.get("state")):
        out.append(Finding(
            "auth.oauth_unbound", "high",
            "OAuth configured without PKCE/state; authorization codes are not bound "
            "to the session (CSRF-style takeover).",
            "auth",
            "Require PKCE and a state parameter bound to the session.",
        ))

    # MCP-AA-01 — auto-approved tool execution (server-level).
    if m.get("auto_approve") is True or m.get("autoApprove") is True:
        out.append(Finding(
            "tool.auto_approve", "high",
            "Server auto-approves tool calls; removes the human review that catches "
            "poisoned descriptions before execution.",
            "auto_approve",
            "Require explicit per-tool consent for sensitive/dangerous tools.",
        ))

    # Per-tool checks: line-jumping, shadowing, shell-exec, per-tool auto-approve.
    tools = m.get("tools")
    if isinstance(tools, list):
        for idx, tool in enumerate(tools):
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", "")).strip()
            loc = f"tools[{idx}]:{name}" if name else f"tools[{idx}]"
            desc = str(tool.get("description", ""))
            low = desc.lower()

            if _CTRL_RE.search(desc) or _CTRL_RE.search(name):
                out.append(Finding(
                    "tool.control_chars", "high",
                    "Tool metadata contains control/ANSI escape characters; can hide "
                    "instructions from human review (line jumping).",
                    loc,
                    "Reject control/ANSI sequences in tool descriptions and outputs.",
                ))
            if any(p in low for p in (
                "instead of using", "other tools", "override the", "do not use the",
                "when calling any", "for all tools", "before using any other tool",
            )):
                out.append(Finding(
                    "tool.shadowing", "high",
                    "Tool description references the behavior of other tools "
                    "(cross-server tool shadowing).",
                    loc,
                    "Namespace tools per server; reject metadata that references "
                    "other tools/servers.",
                ))
            command_field = str(tool.get("command", "")) + " " + str(tool.get("run", ""))
            if _SHELL_RE.search(desc) or _SHELL_RE.search(command_field) \
                    or (name and _SHELL_NAME_RE.search(name) and ("{" in command_field or "$" in command_field)):
                out.append(Finding(
                    "tool.shell_exec", "critical",
                    "Tool appears to pass arguments to a shell/exec; command-injection "
                    "(RCE) risk on the server host.",
                    loc,
                    "Never pass tool input to a shell; use argv arrays / parameterized "
                    "APIs and allow-list inputs.",
                ))
            if tool.get("auto_approve") is True or tool.get("autoApprove") is True:
                out.append(Finding(
                    "tool.auto_approve", "high",
                    f"Tool '{name or idx}' is auto-approved; no human review before it runs.",
                    loc,
                    "Require explicit consent for this tool.",
                ))


def audit_manifest(manifest: Dict[str, Any], source: str = "<manifest>") -> Report:
    """Run every rule against a parsed manifest and return a Report."""
    name = str(manifest.get("name") or manifest.get("server_name") or "unknown")
    findings: List[Finding] = []
    _check_transport(manifest, findings)
    _check_capabilities(manifest, findings)
    _check_tools(manifest, findings)
    _check_secrets(manifest, findings)
    _check_mcp_vuln_classes(manifest, findings)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return Report(source=source, server_name=name, findings=findings)


def audit_path(path: str) -> Report:
    """Load a single manifest file and audit it."""
    manifest = load_manifest(path)
    return audit_manifest(manifest, source=path)


def _iter_manifest_files(target: str) -> List[str]:
    """Resolve ``target`` to a sorted list of candidate manifest JSON files.

    Accepts a single ``.json`` file or a directory (walked recursively). Files
    named ``package.json`` / ``tsconfig.json`` and anything under ``node_modules``
    or dot-dirs are skipped so directory scans stay focused on MCP manifests.
    """
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        raise ManifestError(f"no such file or directory: {target}")

    skip_names = {"package.json", "package-lock.json", "tsconfig.json", "composer.json"}
    found: List[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fn in files:
            if fn.lower().endswith(".json") and fn not in skip_names:
                found.append(os.path.join(root, fn))
    return sorted(found)


def scan(target: str) -> List[Report]:
    """Audit a file or every manifest in a directory.

    This is the high-level entry point used by the CLI ``scan`` subcommand and
    by the MCP server. Files that are not valid MCP manifests (bad JSON, wrong
    root type) are reported as a single ``manifest.unreadable`` finding rather
    than aborting the whole scan.
    """
    reports: List[Report] = []
    for path in _iter_manifest_files(target):
        try:
            reports.append(audit_path(path))
        except (OSError, ManifestError) as exc:
            reports.append(Report(
                source=path,
                server_name=os.path.basename(path),
                findings=[Finding(
                    "manifest.unreadable", "high",
                    f"Manifest could not be parsed: {exc}",
                    path,
                    "Ensure the file is a valid MCP server manifest (JSON object).",
                )],
            ))
    return reports


def scan_to_dict(target: str) -> Dict[str, Any]:
    """Run :func:`scan` and return a single JSON-serializable result object.

    Stable shape for the MCP capability and ``--format json`` over a scan:
    aggregate counts + per-server reports.
    """
    reports = scan(target)
    agg = {k: 0 for k in SEVERITY_ORDER}
    for r in reports:
        for sev, n in r.counts.items():
            agg[sev] += n
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "servers_scanned": len(reports),
        "servers_failed": sum(1 for r in reports if r.failed),
        "total_findings": sum(len(r.findings) for r in reports),
        "counts": agg,
        "failed": any(r.failed for r in reports),
        "reports": [r.to_dict() for r in reports],
    }


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------

def _max_severity(reports: List[Report]) -> Optional[str]:
    best: Optional[str] = None
    for r in reports:
        for f in r.findings:
            if best is None or SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(best, 99):
                best = f.severity
    return best


# GitHub code-scanning maps SARIF "level" to four values.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def to_sarif(reports: List[Report]) -> Dict[str, Any]:
    """Render scan reports as a SARIF 2.1.0 log (GitHub code-scanning ready)."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for report in reports:
        for f in report.findings:
            if f.rule not in rules:
                rules[f.rule] = {
                    "id": f.rule,
                    "name": f.rule,
                    "shortDescription": {"text": f.rule},
                    "fullDescription": {"text": f.remediation or f.message},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {"security-severity": _security_severity(f.severity)},
                }
            results.append({
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message
                            + (f"\nRemediation: {f.remediation}" if f.remediation else "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(report.source)},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.location or report.server_name}],
                }],
                "properties": {"severity": f.severity, "server": report.server_name},
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/mcpharden",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _security_severity(sev: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(sev, "5.0")


def _uri(path: str) -> str:
    return path.replace(os.sep, "/")


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


_SEV_COLOR = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
              "low": "#3498db", "info": "#95a5a6"}


def to_html(reports: List[Report]) -> str:
    """Render scan reports as a self-contained, shareable HTML page."""
    agg = {k: 0 for k in SEVERITY_ORDER}
    for r in reports:
        for sev, n in r.counts.items():
            agg[sev] += n
    failed = any(r.failed for r in reports)

    rows: List[str] = []
    for report in reports:
        status = "FAIL" if report.failed else "PASS"
        scolor = "#c0392b" if report.failed else "#27ae60"
        rows.append(
            f'<h2>{_html_escape(report.server_name)} '
            f'<small style="color:{scolor}">[{status}] score {report.score}/100</small></h2>'
            f'<p class="src">{_html_escape(report.source)}</p>'
        )
        if not report.findings:
            rows.append('<p class="clean">No findings — passes hardening checks.</p>')
            continue
        rows.append('<table><thead><tr><th>Severity</th><th>Rule</th>'
                    '<th>Message</th><th>Location</th><th>Remediation</th></tr></thead><tbody>')
        for f in report.findings:
            color = _SEV_COLOR.get(f.severity, "#777")
            rows.append(
                f'<tr><td><span class="sev" style="background:{color}">'
                f'{f.severity.upper()}</span></td>'
                f'<td><code>{_html_escape(f.rule)}</code></td>'
                f'<td>{_html_escape(f.message)}</td>'
                f'<td><code>{_html_escape(f.location)}</code></td>'
                f'<td>{_html_escape(f.remediation)}</td></tr>'
            )
        rows.append('</tbody></table>')

    summary = " ".join(
        f'<span class="sev" style="background:{_SEV_COLOR[s]}">{s}:{agg[s]}</span>'
        for s in SEVERITY_ORDER
    )
    overall = "FAIL" if failed else "PASS"
    ocolor = "#c0392b" if failed else "#27ae60"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{TOOL_NAME} report</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222;background:#fafafa}}
 h1{{margin-bottom:.2rem}} h2{{margin-top:2rem}}
 .src{{color:#888;font-size:12px;margin-top:-.4rem}}
 .clean{{color:#27ae60}}
 table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
 th,td{{border:1px solid #e1e1e1;padding:.5rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f3f4f6}}
 code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
 .sev{{color:#fff;padding:.1rem .4rem;border-radius:.25rem;font-size:11px;font-weight:600}}
 .overall{{font-size:18px;font-weight:700;color:{ocolor}}}
</style></head><body>
<h1>{TOOL_NAME} — MCP hardening report</h1>
<p class="overall">RESULT: {overall}</p>
<p>{summary} &nbsp;|&nbsp; {len(reports)} server(s) scanned, {sum(1 for r in reports if r.failed)} failing.</p>
{''.join(rows)}
<hr><p style="color:#999;font-size:12px">Generated by {TOOL_NAME} {TOOL_VERSION} — Cognis Neural Suite.</p>
</body></html>
"""
