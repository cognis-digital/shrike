"""shrike command line.

    shrike audit [PATH]     discover + scan + triage + map + plan fixes  (the whole loop)
    shrike discover         show the AI-stack surface shrike found on this machine
    shrike scan PATH        scan manifests without discovery
    shrike fix PATH         write hardened copies of vulnerable manifests

Exit code is non-zero when critical/high findings exist (CI-friendly).
"""
from __future__ import annotations
import argparse, json, os, sys
from typing import List, Optional

from . import __version__, engine, report as report_mod
from .agent import audit
from .discover import discover


def _emit(result, fmt: str) -> None:
    if fmt == "json":
        print(report_mod.to_json(result))
    elif fmt == "markdown":
        print(report_mod.to_markdown(result))
    elif fmt == "sarif":
        print(report_mod.to_sarif(result))
    else:
        print(report_mod.terminal(result))


def _exit_code(result) -> int:
    s = result.stats
    return 1 if (s["critical"] or s["high"]) else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="shrike",
        description="The autonomous security agent for your AI stack.")
    p.add_argument("--version", action="version", version=f"shrike {__version__}")
    sub = p.add_subparsers(dest="cmd")

    pa = sub.add_parser("audit", help="discover + scan + triage + map + plan fixes")
    pa.add_argument("path", nargs="?", default=None, help="a manifest file or directory")
    pa.add_argument("--format", "-f", default="text", choices=["text", "json", "markdown", "sarif"])
    pa.add_argument("--no-clients", action="store_true", help="skip scanning installed client configs")
    pa.add_argument("--llm", action="store_true", help="use a local model for an executive summary")
    pa.add_argument("--model", default=None, help="local model name (default: env SHRIKE_LLM_MODEL)")

    pd = sub.add_parser("discover", help="show discovered AI-stack surface")
    pd.add_argument("path", nargs="?", default=None)

    ps = sub.add_parser("scan", help="scan manifests (no discovery)")
    ps.add_argument("path")
    ps.add_argument("--format", "-f", default="text", choices=["text", "json", "markdown", "sarif"])

    pf = sub.add_parser("fix", help="write hardened copies of vulnerable manifests")
    pf.add_argument("path")
    pf.add_argument("--write", action="store_true", help="write *.hardened.json next to each manifest")
    pf.add_argument("--out", default=None, help="directory to write hardened manifests into")

    pg = sub.add_parser("sigs", help="scan text/files against the bundled AI-threat signature library")
    pg.add_argument("path", help="file, directory, or - for stdin")
    pg.add_argument("--format", "-f", default="text", choices=["text", "json"])
    pg.add_argument("--list", action="store_true", help="list the signature library instead of scanning")

    args = p.parse_args(argv)
    cmd = args.cmd or "audit"

    if cmd == "discover":
        inv = discover(getattr(args, "path", None))
        print(json.dumps({"manifests": inv["manifests"],
                          "client_servers": [s.get("name") for s in inv["client_servers"]],
                          "sources": inv["sources"]}, indent=2))
        return 0

    if cmd == "scan":
        result = audit(args.path, scan_clients=False)
        _emit(result, args.format)
        return _exit_code(result)

    if cmd == "sigs":
        from .sigs import Library, SEVERITY_ORDER
        lib = Library()
        if args.list:
            for s in lib.signatures:
                print(f"  [{s.severity:<8}] {s.id:<7} {s.category:<18} {s.atlas}/{s.owasp}  {s.name}")
            return 0
        if args.path == "-":
            results = {"<stdin>": lib.scan_text(sys.stdin.read())}
        else:
            results = lib.scan_path(args.path)
        if args.format == "json":
            print(json.dumps({f: [m.to_dict() for m in ms] for f, ms in results.items() if ms}, indent=2))
            worst = [m.signature.severity for ms in results.values() for m in ms]
        else:
            worst = []
            for f, ms in results.items():
                if not ms:
                    continue
                print(f"\n{f}")
                for m in ms:
                    s = m.signature
                    print(f"  [{s.severity:<8}] {s.id:<7} {s.category:<16} {s.atlas}/{s.owasp}  {s.name}")
                    worst.append(s.severity)
            print(f"\n{len(worst)} signature match(es).")
        return 1 if any(w in ("critical", "high") for w in worst) else 0

    if cmd == "fix":
        result = audit(args.path, scan_clients=False)
        wrote = 0
        for sv in result.servers:
            if not sv.fix_actions:
                continue
            hardened = sv.hardened
            print(f"\n{sv.name}: {len(sv.fix_actions)} fix(es)")
            for a in sv.fix_actions:
                print(f"  - {a}")
            if args.write:
                base = os.path.basename(sv.source)
                outdir = args.out or os.path.dirname(sv.source) or "."
                os.makedirs(outdir, exist_ok=True)
                dst = os.path.join(outdir, base.replace(".json", "") + ".hardened.json")
                json.dump(hardened, open(dst, "w", encoding="utf-8"), indent=2)
                print(f"  -> wrote {dst}"); wrote += 1
        if args.write:
            print(f"\nwrote {wrote} hardened manifest(s).")
        return 0

    # audit (default)
    result = audit(getattr(args, "path", None), scan_clients=not getattr(args, "no_clients", False),
                   use_llm=getattr(args, "llm", False), model=getattr(args, "model", None))
    _emit(result, getattr(args, "format", "text"))
    return _exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
