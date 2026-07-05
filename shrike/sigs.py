"""Load the signature library and apply it to text. Stdlib only, no yaml, no network."""
from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

SIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class Signature:
    id: str
    name: str
    category: str
    severity: str
    pattern: str
    atlas: str
    owasp: str
    _rx: Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self) -> "Signature":
        self._rx = re.compile(self.pattern)
        return self


@dataclass
class Match:
    signature: Signature
    excerpt: str
    start: int
    line: int

    def to_dict(self) -> Dict:
        s = self.signature
        return {"id": s.id, "name": s.name, "category": s.category, "severity": s.severity,
                "atlas": s.atlas, "owasp": s.owasp, "line": self.line, "offset": self.start,
                "excerpt": self.excerpt}


def load_signatures(extra_dirs: Optional[Iterable[str]] = None) -> List[Signature]:
    """Load every signature from the bundled library (and any extra dirs of *.json)."""
    sigs: List[Signature] = []
    dirs = [SIG_DIR] + list(extra_dirs or [])
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(d, fn), encoding="utf-8"))
            except Exception:
                continue
            cat = doc.get("category", os.path.splitext(fn)[0])
            atlas, owasp = doc.get("atlas", ""), doc.get("owasp", "")
            for s in doc.get("signatures", []):
                try:
                    sigs.append(Signature(
                        id=s["id"], name=s["name"], category=cat, severity=s.get("severity", "medium"),
                        pattern=s["pattern"], atlas=s.get("atlas", atlas), owasp=s.get("owasp", owasp),
                    ).compile())
                except re.error:
                    continue  # skip a malformed pattern rather than crash the whole load
    return sigs


class Library:
    """The compiled signature set + scanning operations."""

    def __init__(self, extra_dirs: Optional[Iterable[str]] = None):
        self.signatures = load_signatures(extra_dirs)

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {"total": len(self.signatures)}
        for s in self.signatures:
            out[s.category] = out.get(s.category, 0) + 1
        return out

    def scan_text(self, text: str, categories: Optional[Iterable[str]] = None) -> List[Match]:
        cats = set(categories) if categories else None
        # precompute line offsets for line numbers
        line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                line_starts.append(i + 1)
        def line_of(pos: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= pos:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1
        matches: List[Match] = []
        for sig in self.signatures:
            if cats and sig.category not in cats:
                continue
            m = sig._rx.search(text)
            if m:
                start = m.start()
                ex = text[max(0, start - 20): start + 60].replace("\n", " ").strip()
                matches.append(Match(sig, ex[:100], start, line_of(start)))
        matches.sort(key=lambda x: SEVERITY_ORDER.index(x.signature.severity)
                     if x.signature.severity in SEVERITY_ORDER else 9)
        return matches

    def scan_file(self, path: str, categories: Optional[Iterable[str]] = None) -> List[Match]:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            return []
        return self.scan_text(text, categories)

    def scan_path(self, path: str, categories: Optional[Iterable[str]] = None) -> Dict[str, List[Match]]:
        results: Dict[str, List[Match]] = {}
        if os.path.isfile(path):
            results[path] = self.scan_file(path, categories)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith((".json", ".txt", ".md", ".yaml", ".yml", ".log", ".jsonl")):
                        fp = os.path.join(root, f)
                        m = self.scan_file(fp, categories)
                        if m:
                            results[fp] = m
        return results
