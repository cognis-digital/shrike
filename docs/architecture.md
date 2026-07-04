# Architecture

shrike is a five-stage pipeline. Each stage is a small, independently-testable module; the
`agent.audit()` function wires them into one call. Everything is deterministic — the optional
local model only writes prose on top of results the pipeline already produced.

```
                shrike audit
                     │
        ┌────────────▼─────────────┐
        │  discover.py             │   find MCP servers in client configs
        │  (Claude/Cursor/Windsurf │   (claude_desktop_config.json, .mcp.json, …)
        │   + manifests under path)│   and standalone manifests
        └────────────┬─────────────┘
                     │  inventory
        ┌────────────▼─────────────┐
        │  engine.py               │   30+ checks per manifest: transport exposure,
        │  (vendored, tested)      │   tool poisoning, prompt injection, unsafe trust,
        └────────────┬─────────────┘   embedded secrets, excessive agency
                     │  per-server Reports
        ┌────────────▼─────────────┐
        │  triage.py               │   blast-radius scoring +
        │                          │   CROSS-SERVER correlation
        └────────────┬─────────────┘
                     │  prioritized findings + fleet correlations
        ┌────────────▼─────────────┐
        │  atlas.py                │   map each finding → MITRE ATLAS + OWASP LLM Top 10
        └────────────┬─────────────┘
                     │
        ┌────────────▼─────────────┐
        │  fix.py                  │   deterministic hardening per rule → hardened manifest
        │  llm.py (optional)       │   local model writes the "why"
        └────────────┬─────────────┘
                     │  AuditResult
                 report.py            text / json / markdown / sarif
```

## Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `discover.py` | Enumerate the AI-stack attack surface | stdlib only |
| `engine.py` | Per-manifest security checks (the scanner) | stdlib only |
| `triage.py` | Blast-radius scoring + cross-server correlation | stdlib only |
| `atlas.py` | Framework mapping (ATLAS / OWASP LLM) | stdlib only |
| `fix.py` | Deterministic remediation → hardened manifests | stdlib only |
| `llm.py` | Optional local-model client (never raises) | stdlib only |
| `agent.py` | Orchestrates the loop, builds `AuditResult` | all of the above |
| `report.py` | Render text / json / markdown / sarif | `engine` |
| `cli.py` | `audit` / `discover` / `scan` / `fix` | `agent`, `report` |

## Design principles

1. **Deterministic first.** Every score, correlation, and fix is computed without a model.
   The LLM is a garnish, never a dependency. A CI run with no model produces identical findings.
2. **The fleet is the unit.** Single-server scanning is a solved, commoditized problem. shrike's
   value is `triage.correlate()` — the risks that emerge across servers.
3. **Fixes, not just findings.** `fix.py` maps rules to concrete manifest transforms, so shrike
   closes the loop instead of handing you homework.
4. **Local by construction.** No network calls except to a model endpoint *you* configure on your
   own network. Auditing production config never leaks it.

## Extending

- **A new check** → add a `_check_*` in `engine.py` that appends `Finding(rule, severity, …)`.
- **A framework mapping** → add the rule (or dotted prefix) to `atlas._MAP`.
- **An auto-fix** → add a fixer function + entry in `fix._FIXERS`.
- **A cross-server correlation** → add a block to `triage.correlate()`.

Each is a few lines and independently unit-tested. See [findings-reference.md](findings-reference.md)
for the current coverage.
