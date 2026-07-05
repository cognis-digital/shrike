"""The agent loop. This is the whole product in one function: point shrike at your stack (or
nothing, and it finds it), and it runs discover -> scan -> triage -> map-to-ATLAS -> fix,
returning one prioritized, framework-tagged, fix-ready result. Deterministic end to end; the
optional local model only adds an executive summary.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import engine, triage, atlas, fix
from .discover import discover
from .llm import LocalModel
from .sigs import Library as SigLibrary

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SIGLIB_CACHE = None


def _siglib() -> SigLibrary:
    global _SIGLIB_CACHE
    if _SIGLIB_CACHE is None:
        _SIGLIB_CACHE = SigLibrary()
    return _SIGLIB_CACHE


@dataclass
class ServerAudit:
    name: str
    source: str
    manifest: Dict[str, Any]
    findings: List[Dict[str, Any]]        # each: rule, severity, message, location, remediation, atlas, owasp, blast
    score: int
    fix_actions: List[str]

    @property
    def hardened(self) -> Dict[str, Any]:
        return fix.harden(self.manifest, [f["rule"] for f in self.findings])


@dataclass
class AuditResult:
    servers: List[ServerAudit] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    summary: str = ""

    @property
    def all_findings(self) -> List[Dict[str, Any]]:
        fs = [dict(f, server=s.name) for s in self.servers for f in s.findings]
        fs += [dict(c, server=", ".join(c.get("servers", [])), blast=90, atlas=atlas.label(c["rule"]))
               for c in self.correlations]
        return sorted(fs, key=lambda f: (-f.get("blast", 0), _SEV_ORDER.get(f["severity"], 9)))

    @property
    def stats(self) -> Dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.all_findings:
            c[f["severity"]] = c.get(f["severity"], 0) + 1
        c["servers"] = len(self.servers)
        c["fixable"] = sum(len(s.fix_actions) for s in self.servers)
        return c


def _server_name(rep, path: str) -> str:
    return rep.server_name or os.path.splitext(os.path.basename(path))[0]


def audit(path: Optional[str] = None, scan_clients: bool = True,
          use_llm: bool = False, model: Optional[str] = None) -> AuditResult:
    inv = discover(path, scan_clients=scan_clients)
    items: List[Dict[str, Any]] = []

    for p in inv["manifests"]:
        try:
            m = engine.load_manifest(p)
        except Exception:
            continue
        rep = engine.audit_manifest(m, source=p)
        items.append({"name": _server_name(rep, p), "source": p, "manifest": m, "report": rep})
    for m in inv["client_servers"]:
        src = m.get("_source", "<client-config>")
        rep = engine.audit_manifest(m, source=src)
        items.append({"name": m.get("name") or _server_name(rep, src), "source": src,
                      "manifest": m, "report": rep})

    correlations = triage.correlate(items)

    siglib = _siglib()
    servers: List[ServerAudit] = []
    for it in items:
        enriched = []
        for f in it["report"].findings:
            lbl = atlas.label(f.rule)
            enriched.append({"rule": f.rule, "severity": f.severity, "message": f.message,
                             "location": f.location, "remediation": f.remediation,
                             "atlas": lbl, "owasp": lbl["owasp_id"],
                             "blast": triage.blast_radius(f.rule, f.severity, it["manifest"])})
        # content scan: run the signature library over tool names + descriptions to catch
        # prompt-injection / tool-poisoning that a structural check can't see.
        for tool in (it["manifest"].get("tools") or []):
            text = (tool.get("name", "") + "\n" + tool.get("description", "")).strip()
            if not text:
                continue
            for m in siglib.scan_text(text):
                s = m.signature
                enriched.append({
                    "rule": f"content.{s.category}.{s.id}", "severity": s.severity,
                    "message": f"{s.name} in tool '{tool.get('name','?')}' description: \"{m.excerpt}\"",
                    "location": f"tools[{tool.get('name','?')}].description", "remediation":
                    "Treat tool descriptions as untrusted input; sanitize or reject servers whose "
                    "tool metadata carries model-directed instructions.",
                    "atlas": {"atlas_id": s.atlas, "atlas_name": "", "owasp_id": s.owasp, "owasp_name": ""},
                    "owasp": s.owasp,
                    "blast": triage.blast_radius("tool.injection_in_description", s.severity, it["manifest"])})
        servers.append(ServerAudit(
            name=it["name"], source=it["source"], manifest=it["manifest"],
            findings=enriched, score=it["report"].score,
            fix_actions=fix.actions([f["rule"] for f in enriched])))

    result = AuditResult(servers=servers, correlations=correlations, sources=inv["sources"])

    if use_llm:
        lm = LocalModel(model=model) if model else LocalModel()
        top = result.all_findings[:8]
        if top:
            bullets = "\n".join(f"- [{f['severity']}] {f['server']}: {f['message'][:140]}" for f in top)
            summary = lm.ask(
                f"You are a security engineer. Findings from an AI-agent stack audit:\n{bullets}\n\n"
                "Write a 3-sentence executive summary: the single worst risk, the theme across "
                "findings, and the first action to take. Be concrete, no preamble.",
                num_predict=260)
            result.summary = summary or ""
    return result
