<div align="center">

# shrike

**The autonomous security agent for your AI stack.** Point it at your machine and it finds the MCP servers and agent tools your assistants are wired to, uncovers the vulnerabilities, ranks them by blast radius, maps each to MITRE ATLAS + OWASP LLM Top 10 — **and writes the fixes.** All on a local model. Nothing leaves your box.

[![PyPI](https://img.shields.io/pypi/v/shrike-sec.svg)](https://pypi.org/project/shrike-sec/)
[![CI](https://github.com/cognis-digital/shrike/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/shrike/actions)
[![License: COCL 1.0](https://img.shields.io/badge/license-COCL%201.0-blue.svg)](LICENSE)
![Self-hosted](https://img.shields.io/badge/AI-100%25%20local-success)
![Deps](https://img.shields.io/badge/runtime%20deps-none%20(stdlib)-success)

</div>

Every other AI-security scanner looks at one server, needs a cloud LLM, and stops at "here's a list." **shrike** enumerates your whole stack the way an attacker would, correlates the failures that only appear across servers (a shared credential, a tool-name collision, an RCE server next to an unauth'd peer), and hands you hardened manifests you can apply. The reasoning runs on a model on *your* machine — so you can point it at production config without a single byte going to a vendor.

```bash
pip install shrike-sec
shrike audit                 # discovers your MCP servers + agent tools, then audits them
```

Zero runtime dependencies (Python stdlib). Works fully offline. A local model (Ollama or any OpenAI-compatible endpoint) is *optional* — it only adds prose; every scan, score, and fix is deterministic without it.

## See it work

`shrike audit` on a four-server stack. Notice the **cross-server correlations** — the risks no single-server scanner can see — and that every finding is blast-ranked and framework-tagged:

```console
$ shrike audit demos/vulnerable-stack
shrike — AI-stack security audit
========================================================================
4 server(s) audited.  6 critical / 7 high / 1 medium.
------------------------------------------------------------------------
  score   0/100   files-mcp    (6 findings)
  score  20/100   weather-mcp  (3 findings)
  score  60/100   github-mcp   (1 findings)
  score 100/100   jira-mcp     (0 findings)
------------------------------------------------------------------------
CROSS-SERVER CORRELATIONS (4) — the fleet-level risks:
[CRIT] fleet.shared_secret
      The same embedded credential (sk_live_…) appears in 2 manifests
      (files-mcp, github-mcp); compromise of any one server exposes a
      credential whose blast radius is the whole fleet.
[HIGH] fleet.lateral_movement
      files-mcp exposes RCE-prone tools while 2 reachable peers are
      under-protected; code-exec on one host pivots to the peers.
[HIGH] fleet.tool_collision
      Tool 'read_file' is registered by 2 servers; the agent cannot
      disambiguate which runs — the precondition for tool shadowing.
------------------------------------------------------------------------
TOP RISKS (by blast radius):
[CRIT] blast 100  files-mcp   manifest.embedded_secret  AML.T0055/LLM02
[CRIT] blast 100  files-mcp   tool.shell_exec           AML.T0053/LLM06
[CRIT] blast  96  files-mcp   transport.bind_all        AML.T0049/LLM06
------------------------------------------------------------------------
9 fix action(s) ready — run `shrike fix <path> --write` to apply hardened manifests.
```

Then let it fix them:

```console
$ shrike fix demos/vulnerable-stack --write --out ./hardened
files-mcp: 5 fix(es)
  - Move embedded secret to an env var / secret store
  - Gate shell/exec tools behind confirmation + sandbox
  - Bind to localhost instead of 0.0.0.0
  - Force TLS on the transport
  - Require confirmation on the dangerous tool
  -> wrote ./hardened/files-mcp.hardened.json
```

## Why shrike

| | single-server scanners | cloud AI pentest tools | **shrike** |
|---|:---:|:---:|:---:|
| Discovers your stack automatically | ✗ | partial | ✅ |
| **Cross-server correlation** (shared secrets, shadowing, lateral movement) | ✗ | ✗ | ✅ |
| Blast-radius prioritization | ✗ | partial | ✅ |
| MITRE ATLAS + OWASP LLM Top 10 mapping | ✗ | rare | ✅ |
| **Writes the fixes** (hardened manifests) | ✗ | ✗ | ✅ |
| Runs on a **local** model — nothing leaves your box | ✗ | ✗ | ✅ |
| Zero deps, offline, CI-ready (SARIF) | rare | ✗ | ✅ |

## The loop

```
discover → scan → triage → map → fix
```

1. **discover** — finds MCP servers in Claude Desktop / Cursor / Windsurf / VS Code configs and any manifests under a path.
2. **scan** — a tested engine (30+ checks: transport exposure, tool poisoning, prompt injection in descriptions, unsafe trust settings, embedded secrets, excessive agency).
3. **triage** — blast-radius scoring + the cross-server correlations that reveal how one weak server compromises the fleet.
4. **map** — every finding tagged with a MITRE ATLAS technique and an OWASP LLM Top 10 category.
5. **fix** — concrete, deterministic hardening applied to a copy of each manifest; a local model (optional) explains *why*.

## Usage

```bash
shrike audit                      # discover this machine's AI stack, then audit it
shrike audit ./mcp-configs        # audit manifests under a path
shrike audit --llm --model llama3.1   # add a local-model executive summary
shrike audit -f sarif > shrike.sarif  # SARIF straight into GitHub's Security tab
shrike discover                   # just show the attack surface it found
shrike fix ./configs --write      # write *.hardened.json next to each manifest
```

Output formats: `text` (default), `json`, `markdown`, `sarif`. Exit code is non-zero when critical/high findings exist, so it drops straight into CI.

## Self-hosted by design

shrike's reasoning layer talks to a local endpoint (`http://127.0.0.1:11434` by default — Ollama, LM Studio, vLLM, anything OpenAI-compatible). Set `SHRIKE_LLM_ENDPOINT` / `SHRIKE_LLM_MODEL` to point elsewhere *on your network*. No API keys, no telemetry, no outbound calls. If no model is reachable, shrike runs its full deterministic pipeline anyway — you just don't get the prose.

## Documentation

- [Architecture](docs/architecture.md) — how the loop is wired
- [Threat model](docs/threat-model.md) — the AI-stack attack surface shrike covers
- [Findings reference](docs/findings-reference.md) — every rule, its ATLAS/OWASP mapping, and its fix
- [Self-hosting the model](docs/self-hosting.md)
- [Wiki](https://github.com/cognis-digital/shrike/wiki) · [Discussions](https://github.com/cognis-digital/shrike/discussions)

## Defensive use

shrike is a defensive tool for AI infrastructure **you operate or are authorized to assess**. It reads configuration and manifests; it does not exploit. Use it on your own stack or under a written engagement.

## License

[COCL 1.0](LICENSE) — Cognis Open Collaboration License. See [DISCLAIMER.md](DISCLAIMER.md).

<div align="center"><sub>Pairs with <a href="https://github.com/cognis-digital/mcpscan">mcpscan</a> (deep per-server scanning) — shrike is the agent, mcpscan is the engine.</sub></div>
