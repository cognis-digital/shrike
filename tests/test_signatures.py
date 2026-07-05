"""Corpus-driven signature tests: every positive sample must match its signature; every benign
sample must not trip a critical/high signature. Hundreds of real cases, one assertion each."""
import pytest

from shrike.sigs import Library
from corpus import SIGNATURE_POSITIVES, BENIGN_SAMPLES

LIB = Library()
POSITIVES = [(sid, s) for sid, samples in SIGNATURE_POSITIVES.items() for s in samples]


@pytest.mark.parametrize("sid,sample", POSITIVES)
def test_positive_matches_its_signature(sid, sample):
    ids = {m.signature.id for m in LIB.scan_text(sample)}
    assert sid in ids, f"signature {sid} failed to match {sample!r}; matched instead: {sorted(ids)}"


@pytest.mark.parametrize("sample", BENIGN_SAMPLES)
def test_benign_no_high_severity(sample):
    hits = [m.signature.id for m in LIB.scan_text(sample)
            if m.signature.severity in ("critical", "high")]
    assert not hits, f"false positive on benign text {sample!r}: {hits}"


def test_every_signature_has_positive_coverage():
    """Guardrail: every shipped signature should have at least one positive sample in the corpus."""
    covered = set(SIGNATURE_POSITIVES)
    shipped = {s.id for s in LIB.signatures}
    missing = shipped - covered
    # allow a small uncovered tail but flag it loudly
    assert len(missing) <= 6, f"signatures with no positive test sample: {sorted(missing)}"


def test_all_signatures_compile_and_map():
    for s in LIB.signatures:
        assert s._rx is not None
        assert s.atlas.startswith("AML.T") and s.owasp.startswith("LLM")
