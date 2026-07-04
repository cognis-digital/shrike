"""Map engine findings to MITRE ATLAS techniques and the OWASP LLM Top 10 (2025).

A defender's finding is worth far more when it carries a framework ID: it slots straight
into a coverage matrix, a report to leadership, or a detection backlog. Every rule the
engine emits is mapped here to a real ATLAS technique and an OWASP LLM category.
"""
from __future__ import annotations
from typing import Dict, Tuple

# OWASP LLM Top 10 (2025) categories
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}
# MITRE ATLAS technique IDs (real)
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0012": "Valid Accounts",
}

# rule id (or dotted prefix) -> (ATLAS id, OWASP id)
_MAP: Dict[str, Tuple[str, str]] = {
    # transport exposure -> reachable, exploitable surface
    "transport.no_auth":         ("AML.T0049", "LLM06"),
    "transport.no_tls":          ("AML.T0049", "LLM02"),
    "transport.bind_all":        ("AML.T0049", "LLM06"),
    "transport.cors_wildcard":   ("AML.T0049", "LLM06"),
    "transport.cors":            ("AML.T0049", "LLM06"),
    "transport.wildcard_origin": ("AML.T0049", "LLM06"),
    "transport.unpinned_command":("AML.T0053", "LLM03"),
    "transport.command":         ("AML.T0053", "LLM03"),
    "transport.":                ("AML.T0049", "LLM06"),   # prefix fallback
    # credentials
    "manifest.embedded_secret":  ("AML.T0055", "LLM02"),
    "auth.token_passthrough":    ("AML.T0012", "LLM06"),
    "auth.passthrough":          ("AML.T0012", "LLM06"),
    "auth.oauth_unbound":        ("AML.T0012", "LLM06"),
    "auth.session_in_url":       ("AML.T0055", "LLM02"),
    "auth.":                     ("AML.T0055", "LLM02"),
    # tool poisoning / prompt injection surfaces
    "tool.injection_in_description": ("AML.T0051", "LLM01"),
    "tool.control_chars":        ("AML.T0051", "LLM01"),
    "tool.thin_description":     ("AML.T0051", "LLM01"),
    # excessive agency
    "tool.shell_exec":           ("AML.T0053", "LLM06"),
    "tool.danger_no_confirm":    ("AML.T0053", "LLM06"),
    "tool.danger_no_schema":     ("AML.T0053", "LLM06"),
    "tool.auto_approve":         ("AML.T0053", "LLM06"),
    "tool.schema_open":          ("AML.T0053", "LLM06"),
    # confused deputy / shadowing
    "tool.shadowing":            ("AML.T0053", "LLM06"),
    "tool.duplicate_name":       ("AML.T0053", "LLM06"),
    "tool.mutable_registration": ("AML.T0053", "LLM03"),
    "tool.":                     ("AML.T0053", "LLM06"),
    # capabilities / resource
    "capabilities.sampling_unbounded": ("AML.T0025", "LLM10"),
    "capabilities.sampling":     ("AML.T0025", "LLM10"),
    "capability.":               ("AML.T0049", "LLM06"),
    "capabilities.":             ("AML.T0049", "LLM06"),
}


def classify(rule: str) -> Tuple[str, str]:
    """Return (atlas_id, owasp_id) for a finding rule, matching exact id then dotted prefix."""
    if rule in _MAP:
        return _MAP[rule]
    prefix = rule.split(".", 1)[0] + "."
    if prefix in _MAP:
        return _MAP[prefix]
    return ("AML.T0049", "LLM06")


def label(rule: str) -> Dict[str, str]:
    """Full framework labels for a rule."""
    a, o = classify(rule)
    return {"atlas_id": a, "atlas_name": ATLAS.get(a, ""),
            "owasp_id": o, "owasp_name": OWASP.get(o, "")}
