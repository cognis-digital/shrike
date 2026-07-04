# The AI-stack threat model

When you connect an assistant to MCP servers and agent tools, you are wiring a language model to
code execution, file systems, APIs, and networks — often through configuration that no one
security-reviews. shrike is built around the attack surface that creates. This document is the
map; [findings-reference.md](findings-reference.md) is the exact rule list.

## 1. Transport exposure
An MCP server bound to `0.0.0.0` with no auth and no TLS is a network service that hands out
tool execution to anyone who can reach it. Sub-risks: bound-to-all-interfaces, no auth, no TLS,
wildcard CORS, unpinned stdio command (a path an attacker can shadow).
> ATLAS **AML.T0049 Exploit Public-Facing Application** · OWASP **LLM06 Excessive Agency**

## 2. Tool poisoning & prompt injection
An MCP tool's `description` is fed to the model as trusted instruction text. If it contains
hidden directives, control characters, or markup, it becomes an **indirect prompt-injection**
vector that steers the agent — the tool doesn't have to do anything malicious itself.
> ATLAS **AML.T0051 LLM Prompt Injection** · OWASP **LLM01 Prompt Injection**

## 3. Excessive agency
Tools that shell out, run code, or are auto-approved give the model far more authority than it
needs. A single injected instruction plus an auto-approved `exec` tool is remote code execution.
> ATLAS **AML.T0053 LLM Plugin Compromise** · OWASP **LLM06 Excessive Agency**

## 4. Confused deputy / tool shadowing
When two servers register the same tool name, the agent cannot deterministically choose which
runs. A malicious server can shadow a trusted tool and intercept its calls.
> ATLAS **AML.T0053** · OWASP **LLM06**

## 5. Credential exposure
Tokens embedded directly in manifests, tokens passed through to upstreams, or session tokens in
URLs. Worse at fleet scale: one shared secret across servers means one compromise exposes all.
> ATLAS **AML.T0055 Unsecured Credentials** · OWASP **LLM02 Sensitive Information Disclosure**

## 6. Unbounded consumption
Servers that grant unbounded `sampling` (the server can make the client's model generate) are a
cost/DoS amplifier and a covert exfiltration channel.
> ATLAS **AML.T0025 Exfiltration** · OWASP **LLM10 Unbounded Consumption**

---

## Why the fleet view matters
Every risk above is worse in combination, and the dangerous combinations only appear when you
look at more than one server:

- **Shared secret** across servers — blast radius multiplies.
- **Tool collision** across servers — shadowing becomes possible.
- **Lateral movement** — an RCE-prone server beside an under-protected reachable peer.
- **Trust-tier inconsistency** — the weakest reachable server is the entry point for all of them.

A per-server scanner reports each server as "mostly fine." shrike reports that server A's shell
tool plus server B's missing auth plus their shared token is a single-hop path to your whole
stack. That correlation — `triage.correlate()` — is the product.

## Scope
shrike is a **configuration and manifest auditor**. It reads; it does not exploit, connect to, or
send traffic to your servers. It is for infrastructure you operate or are authorized to assess.
