"""Cross-server correlation tests — shrike's differentiator. Each fleet is built to trip exactly
one correlation (or none), verifying the fleet-level logic precisely."""
import pytest

from shrike import triage

SHARED = "sk_live_SHARED0123456789"


def _item(name, manifest):
    return {"name": name, "manifest": manifest, "report": None}


def _fleet(*items):
    return triage.correlate(list(items))


def _rules(correlations):
    return {c["rule"] for c in correlations}


def test_shared_secret_detected():
    f = _fleet(
        _item("a", {"name": "a", "transport": {"type": "http"}, "auth": {"token": SHARED}}),
        _item("b", {"name": "b", "transport": {"type": "http"}, "auth": {"token": SHARED}}))
    assert "fleet.shared_secret" in _rules(f)


def test_shared_secret_not_flagged_when_distinct():
    f = _fleet(
        _item("a", {"name": "a", "auth": {"token": "sk_live_AAAAAAAAAAAA"}}),
        _item("b", {"name": "b", "auth": {"token": "sk_live_BBBBBBBBBBBB"}}))
    assert "fleet.shared_secret" not in _rules(f)


def test_tool_collision_detected():
    f = _fleet(
        _item("a", {"name": "a", "tools": [{"name": "read_file", "description": "x"}]}),
        _item("b", {"name": "b", "tools": [{"name": "read_file", "description": "y"}]}))
    assert "fleet.tool_collision" in _rules(f)


def test_tool_collision_not_flagged_when_unique():
    f = _fleet(
        _item("a", {"name": "a", "tools": [{"name": "read_a"}]}),
        _item("b", {"name": "b", "tools": [{"name": "read_b"}]}))
    assert "fleet.tool_collision" not in _rules(f)


def test_lateral_movement_detected():
    f = _fleet(
        _item("rce", {"name": "rce", "transport": {"type": "stdio", "command": "srv"},
                      "tools": [{"name": "exec", "description": "run a shell command"}]}),
        _item("weak", {"name": "weak", "transport": {"type": "http"}}))
    assert "fleet.lateral_movement" in _rules(f)


def test_trust_tier_inconsistency_detected():
    f = _fleet(
        _item("authed", {"name": "authed", "transport": {"type": "http", "auth": {"type": "bearer"}}}),
        _item("open", {"name": "open", "transport": {"type": "http"}}))
    assert "fleet.trust_tier_inconsistency" in _rules(f)


def test_single_clean_server_no_correlations():
    f = _fleet(_item("solo", {"name": "solo", "transport": {"type": "stdio"},
                              "tools": [{"name": "titlecase"}]}))
    assert f == []


@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
def test_blast_radius_bounded(sev):
    m = {"transport": {"type": "http"}, "tools": [{"name": "exec", "description": "shell"}]}
    assert 0 <= triage.blast_radius("transport.no_auth", sev, m) <= 100
