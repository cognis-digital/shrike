"""End-to-end tests for the shrike agent against the bundled vulnerable stack."""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
DEMO = os.path.join(ROOT, "demos", "vulnerable-stack")
N_SERVERS = len([f for f in os.listdir(DEMO) if f.endswith(".json")])

from shrike import atlas, fix, triage           # noqa: E402
from shrike.agent import audit                   # noqa: E402
from shrike.cli import main                      # noqa: E402
from shrike import report as report_mod          # noqa: E402


@pytest.fixture(scope="module")
def result():
    return audit(DEMO, scan_clients=False)


class TestAudit:
    def test_finds_all_servers(self, result):
        assert len(result.servers) == N_SERVERS

    def test_finds_criticals(self, result):
        assert result.stats["critical"] >= 1
        assert result.stats["high"] >= 1

    def test_cross_server_correlations(self, result):
        rules = {c["rule"] for c in result.correlations}
        assert "fleet.shared_secret" in rules          # same token in 2 manifests
        assert "fleet.tool_collision" in rules          # read_file in 2 servers

    def test_findings_carry_framework_labels(self, result):
        for f in result.all_findings:
            assert f["atlas"]["atlas_id"].startswith("AML.T")
            assert f["atlas"]["owasp_id"].startswith("LLM")

    def test_top_risk_is_blast_ranked(self, result):
        blasts = [f.get("blast", 0) for f in result.all_findings]
        assert blasts == sorted(blasts, reverse=True)


class TestFix:
    def test_fix_actions_present(self, result):
        assert any(sv.fix_actions for sv in result.servers)

    def test_hardening_reduces_risk(self, result, tmp_path):
        for sv in result.servers:
            if sv.fix_actions:
                (tmp_path / f"{sv.name}.json").write_text(json.dumps(sv.hardened))
        after = audit(str(tmp_path), scan_clients=False)
        # hardened copies must not be *worse* than the originals
        assert after.stats["critical"] <= result.stats["critical"]

    def test_hardened_is_valid_json(self, result):
        for sv in result.servers:
            json.dumps(sv.hardened)  # must serialize


class TestAtlas:
    def test_known_rules_map(self):
        assert atlas.classify("tool.injection_in_description") == ("AML.T0051", "LLM01")
        assert atlas.classify("manifest.embedded_secret") == ("AML.T0055", "LLM02")

    def test_unknown_rule_falls_back(self):
        a, o = atlas.classify("some.unknown_rule")
        assert a.startswith("AML.T") and o.startswith("LLM")


class TestReportFormats:
    def test_all_formats_render(self, result):
        assert "AI-stack security audit" in report_mod.terminal(result)
        assert json.loads(report_mod.to_json(result))["stats"]["servers"] == N_SERVERS
        assert report_mod.to_markdown(result).startswith("# shrike")
        assert json.loads(report_mod.to_sarif(result))["version"] == "2.1.0"


class TestCli:
    def test_audit_exit_nonzero_on_findings(self):
        assert main(["audit", DEMO, "--no-clients"]) == 1

    def test_discover_runs_clean(self, capsys):
        assert main(["discover", DEMO]) == 0
        out = json.loads(capsys.readouterr().out)
        assert len(out["manifests"]) == N_SERVERS

    def test_scan_json(self, capsys):
        main(["scan", DEMO, "-f", "json"])
        assert json.loads(capsys.readouterr().out)["stats"]["servers"] == N_SERVERS
