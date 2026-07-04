# Demos

## vulnerable-stack

A four-server MCP fleet with realistic, planted weaknesses — the reproducible demo from the
README. Run:

```bash
shrike audit demos/vulnerable-stack
```

| Server | Planted problem(s) |
|---|---|
| `files-mcp` | bound to `0.0.0.0`, no TLS, a shell/exec tool with no confirmation, an embedded secret |
| `weather-mcp` | network transport with no auth, no TLS |
| `github-mcp` | embedded credential — **the same one** as files-mcp (shared-secret correlation) |
| `jira-mcp` | clean, local stdio — the control case (scores 100/100) |

The interesting part isn't any single server — it's what shrike correlates *across* them:
a shared credential, a `read_file` tool-name collision between `files-mcp` and `github-mcp`,
a lateral-movement path from the RCE-prone `files-mcp` to its under-protected peers, and a
trust-tier split across the reachable servers.

Then watch it fix them:

```bash
shrike fix demos/vulnerable-stack --write --out ./hardened
shrike audit ./hardened          # re-audit: the mechanical risks are gone
```
