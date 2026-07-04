# Findings reference

Every rule shrike can raise, its MITRE ATLAS technique, its OWASP LLM Top 10 category, and whether shrike can auto-fix it. Generated from the code — this table is the source of truth.

## Per-server findings

| Rule | ATLAS | OWASP | Auto-fix |
|---|---|---|:---:|
| `auth.oauth_unbound` | AML.T0012 Valid Accounts | LLM06 Excessive Agency | — |
| `auth.passthrough` | AML.T0012 Valid Accounts | LLM06 Excessive Agency | — |
| `auth.session_in_url` | AML.T0055 Unsecured Credentials | LLM02 Sensitive Information Disclosure | ✅ Move the session token out of the URL |
| `auth.token_passthrough` | AML.T0012 Valid Accounts | LLM06 Excessive Agency | ✅ Stop passing the client token through to upstreams |
| `auth.url` | AML.T0055 Unsecured Credentials | LLM02 Sensitive Information Disclosure | — |
| `capabilities.experimental` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `capabilities.sampling` | AML.T0025 Exfiltration via Cyber Means | LLM10 Unbounded Consumption | — |
| `capabilities.sampling_unbounded` | AML.T0025 Exfiltration via Cyber Means | LLM10 Unbounded Consumption | — |
| `capability.experimental` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `capability.malformed` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `capability.tools_empty` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `capability.tools_mismatch` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `capability.undeclared` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `manifest.embedded_secret` | AML.T0055 Unsecured Credentials | LLM02 Sensitive Information Disclosure | ✅ Move embedded secret to an env var / secret store |
| `manifest.unreadable` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `tool.auto_approve` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | ✅ Require explicit confirmation instead of auto-approve |
| `tool.control_chars` | AML.T0051 LLM Prompt Injection | LLM01 Prompt Injection | ✅ Strip control chars from tool description |
| `tool.danger_no_confirm` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | ✅ Require confirmation on the dangerous tool |
| `tool.danger_no_schema` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.duplicate_name` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.injection_in_description` | AML.T0051 LLM Prompt Injection | LLM01 Prompt Injection | ✅ Strip control chars / markup from tool description |
| `tool.malformed` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.mutable_registration` | AML.T0053 LLM Plugin Compromise | LLM03 Supply Chain | — |
| `tool.no_description` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.no_name` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.schema_open` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.shadowing` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | — |
| `tool.shell_exec` | AML.T0053 LLM Plugin Compromise | LLM06 Excessive Agency | ✅ Gate shell/exec tools behind confirmation + sandbox |
| `tool.thin_description` | AML.T0051 LLM Prompt Injection | LLM01 Prompt Injection | — |
| `transport.bind_all` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | ✅ Bind to localhost instead of 0.0.0.0 |
| `transport.command` | AML.T0053 LLM Plugin Compromise | LLM03 Supply Chain | — |
| `transport.cors` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | ✅ Remove wildcard CORS origin |
| `transport.cors_wildcard` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | ✅ Remove wildcard CORS origin |
| `transport.malformed` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `transport.no_auth` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | ✅ Require bearer auth on the transport |
| `transport.no_tls` | AML.T0049 Exploit Public-Facing Application | LLM02 Sensitive Information Disclosure | ✅ Force TLS on the transport |
| `transport.undeclared` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `transport.unknown_type` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | — |
| `transport.unpinned_command` | AML.T0053 LLM Plugin Compromise | LLM03 Supply Chain | — |
| `transport.wildcard_origin` | AML.T0049 Exploit Public-Facing Application | LLM06 Excessive Agency | ✅ Remove wildcard CORS origin |

## Cross-server (fleet) findings

These are shrike's differentiator — they only exist when you look at more than one server at once.

| Rule | ATLAS | OWASP | What it means |
|---|---|---|---|
| `fleet.shared_secret` | AML.T0049 | LLM06 | One credential embedded in multiple servers — blast radius is the whole fleet. |
| `fleet.tool_collision` | AML.T0049 | LLM06 | Same tool name on multiple servers — the precondition for tool shadowing / confused-deputy routing. |
| `fleet.lateral_movement` | AML.T0049 | LLM06 | An RCE-prone server sitting next to under-protected reachable peers. |
| `fleet.trust_tier_inconsistency` | AML.T0049 | LLM06 | Reachable servers at different auth tiers — the weakest is the way in. |

## Frameworks

- **MITRE ATLAS** — adversarial threat landscape for AI systems. https://atlas.mitre.org
- **OWASP LLM Top 10 (2025)** — the top risks for LLM applications. https://genai.owasp.org
