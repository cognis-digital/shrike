"""Corpus-driven engine tests: each crafted manifest must raise its expected structural rule,
and each clean manifest must raise no critical/high structural finding."""
import pytest

from shrike import engine
from corpus import MANIFEST_CASES, CLEAN_MANIFESTS


@pytest.mark.parametrize("manifest,expected_rule", MANIFEST_CASES)
def test_manifest_raises_expected_rule(manifest, expected_rule):
    rep = engine.audit_manifest(manifest, source="<test>")
    rules = {f.rule for f in rep.findings}
    assert expected_rule in rules, f"expected {expected_rule}, got {sorted(rules)}"


@pytest.mark.parametrize("manifest", CLEAN_MANIFESTS)
def test_clean_manifest_no_high(manifest):
    rep = engine.audit_manifest(manifest, source="<test>")
    highs = [f.rule for f in rep.findings if f.severity in ("critical", "high")]
    assert not highs, f"clean manifest raised {highs}"


@pytest.mark.parametrize("manifest,expected_rule", MANIFEST_CASES)
def test_every_finding_is_atlas_mapped(manifest, expected_rule):
    from shrike import atlas
    rep = engine.audit_manifest(manifest, source="<test>")
    for f in rep.findings:
        a, o = atlas.classify(f.rule)
        assert a.startswith("AML.T") and o.startswith("LLM")


@pytest.mark.parametrize("manifest,expected_rule", MANIFEST_CASES)
def test_score_is_bounded(manifest, expected_rule):
    rep = engine.audit_manifest(manifest, source="<test>")
    assert 0 <= rep.score <= 100
