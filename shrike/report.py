"""Render an AuditResult: a terminal report (the demo), plus JSON, Markdown, and SARIF."""
from __future__ import annotations
import json
from typing import Any, Dict

from . import engine

_SEV_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def terminal(result) -> str:
    s = result.stats
    L = []
    L.append("shrike — AI-stack security audit")
    L.append("=" * 72)
    scanned = len(result.servers)
    L.append(f"{scanned} server(s) audited"
             + (f" from {len(result.sources)} client config(s)" if result.sources else "")
             + f".  {s['critical']} critical / {s['high']} high / {s['medium']} medium.")
    if result.summary:
        L.append(""); L.append(result.summary.strip())
    L.append("-" * 72)
    for sv in sorted(result.servers, key=lambda x: x.score):
        L.append(f"  score {sv.score:>3}/100   {sv.name}   ({len(sv.findings)} findings)")
    if result.correlations:
        L.append("-" * 72)
        L.append(f"CROSS-SERVER CORRELATIONS ({len(result.correlations)}) — the fleet-level risks:")
        for c in result.correlations:
            L.append(f"{_SEV_TAG.get(c['severity'],'')} {c['rule']}")
            L.append(f"      {c['message']}")
            L.append(f"      fix: {c['remediation']}")
    L.append("-" * 72)
    L.append("TOP RISKS (by blast radius):")
    for f in result.all_findings[:10]:
        atl = f.get("atlas", {})
        tag = f"{atl.get('atlas_id','')}/{atl.get('owasp_id','')}"
        L.append(f"{_SEV_TAG.get(f['severity'],'')} blast {f.get('blast',0):>3}  {f['server']:<16} "
                 f"{f['rule']:<28} {tag}")
    fixable = s.get("fixable", 0)
    if fixable:
        L.append("-" * 72)
        L.append(f"{fixable} fix action(s) ready — run `shrike fix <path> --write` to apply hardened manifests.")
    return "\n".join(L)


def to_json(result) -> str:
    return json.dumps({
        "stats": result.stats,
        "sources": result.sources,
        "summary": result.summary,
        "servers": [{"name": sv.name, "source": sv.source, "score": sv.score,
                     "findings": sv.findings, "fix_actions": sv.fix_actions} for sv in result.servers],
        "correlations": result.correlations,
    }, indent=2)


def to_markdown(result) -> str:
    s = result.stats
    L = [f"# shrike — AI-stack security audit\n",
         f"**{s['servers']} servers** · {s['critical']} critical · {s['high']} high · "
         f"{s['medium']} medium · {s['fixable']} fixes ready\n"]
    if result.summary:
        L.append(f"> {result.summary.strip()}\n")
    if result.correlations:
        L.append("## Cross-server correlations\n")
        for c in result.correlations:
            L.append(f"- **[{c['severity']}] {c['rule']}** — {c['message']}  \n  _Fix:_ {c['remediation']}")
        L.append("")
    L.append("## Top risks\n")
    L.append("| Blast | Severity | Server | Finding | ATLAS | OWASP |")
    L.append("|---:|---|---|---|---|---|")
    for f in result.all_findings[:15]:
        a = f.get("atlas", {})
        L.append(f"| {f.get('blast',0)} | {f['severity']} | {f['server']} | `{f['rule']}` "
                 f"| {a.get('atlas_id','')} | {a.get('owasp_id','')} |")
    return "\n".join(L)


def to_sarif(result) -> str:
    reports = [engine.audit_manifest(sv.manifest, source=sv.source) for sv in result.servers]
    return json.dumps(engine.to_sarif(reports), indent=2)
