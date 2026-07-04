# Contributing to shrike

shrike gets better the more of the AI-stack attack surface it knows. The highest-value
contributions are **new checks, new framework mappings, new auto-fixes, and new cross-server
correlations** — each is a few lines and independently testable.

## Add a check
In `shrike/engine.py`, add or extend a `_check_*` function that appends a `Finding`:
```python
out.append(Finding(
    "tool.my_new_risk", "high",
    "Human-readable description of the risk.",
    location="tools[3].description",
    remediation="What to do about it."))
```
Then map it and (optionally) give it a fix (below), and add a case to the tests.

## Map it to a framework
In `shrike/atlas.py`, add the rule (or its dotted prefix) to `_MAP`:
```python
"tool.my_new_risk": ("AML.T0053", "LLM06"),
```
Use real [MITRE ATLAS](https://atlas.mitre.org) technique IDs and
[OWASP LLM Top 10](https://genai.owasp.org) categories.

## Give it an auto-fix
In `shrike/fix.py`, add a fixer that hardens a manifest in place, and register it:
```python
def _fix_my_risk(m): ...
_FIXERS["tool.my_new_risk"] = ("Do the concrete thing", _fix_my_risk)
```

## Add a cross-server correlation
The crown jewels live in `triage.correlate()`. If you can describe a risk that only exists across
multiple servers, add a block that emits a `fleet.*` finding.

## Ground rules
- **Deterministic.** No check may depend on a model being present.
- **No exploitation.** shrike reads config; it never connects to or attacks a server.
- **Real threats only.** Every rule must map to a genuine, explainable attack. No filler.
- **Tests required.** Add a case to `tests/` that proves your rule fires (and doesn't false-positive
  on the clean `jira-mcp` fixture).

## Run the suite
```bash
pip install -e ".[dev]"
pytest -q
shrike audit demos/vulnerable-stack   # sanity check the demo still reports as expected
```

Discussions and design proposals: **[GitHub Discussions](https://github.com/cognis-digital/shrike/discussions)**.
