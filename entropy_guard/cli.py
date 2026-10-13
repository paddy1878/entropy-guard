from __future__ import annotations

import argparse
import json
import sys

from . import __version__, report, scanner, smoke


def _scan(args):
    findings, files = scanner.scan(args.path, excludes=args.exclude)
    findings = [f for f in findings
                if scanner.SEVERITY_ORDER[f.severity] >= scanner.SEVERITY_ORDER[args.min_severity]]
    out = report.FORMATS[args.format](findings, files)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    if not args.output or args.format == "github":
        sys.stdout.write(out)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(report.sarif(findings, files))
    if args.fail_on == "never":
        return 0
    threshold = scanner.SEVERITY_ORDER[args.fail_on]
    return 1 if any(scanner.SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


def _smoke(args):
    res = smoke.run(args.cmd, runs=args.runs, kind=args.kind, timeout=args.timeout,
                    shell=args.shell, alpha=args.alpha)
    if args.format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(f"entropy-guard smoke: {res.samples} {res.kind} samples from {res.runs} runs")
        for name, passed, detail in res.checks:
            print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")
        print("RESULT:", "PASS" if res.ok else "FAIL")
        if not res.ok and args.github:
            print(f"::error title=entropy-guard smoke::Entropy smoke test failed for `{args.cmd}`")
    return 0 if res.ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="entropy-guard",
                                description="Catch entropy-path bugs before they ship.")
    p.add_argument("--version", action="version", version=f"entropy-guard {__version__}")
    sub = p.add_subparsers(dest="cmd_name", required=True)

    s = sub.add_parser("scan", help="static scan of a source tree")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--format", choices=sorted(report.FORMATS), default="text")
    s.add_argument("--output", "-o")
    s.add_argument("--sarif", help="also write SARIF to this path")
    s.add_argument("--exclude", action="append", default=[], help="glob to skip (repeatable)")
    s.add_argument("--fail-on", choices=["error", "warning", "note", "never"], default="error")
    s.add_argument("--min-severity", choices=["error", "warning", "note"], default="note")
    s.set_defaults(func=_scan)

    m = sub.add_parser("smoke", help="run a seed/key generator N times and test the outputs")
    m.add_argument("--cmd", required=True, help="command that prints one seed/key per run")
    m.add_argument("--runs", type=int, default=200)
    m.add_argument("--kind", choices=["auto", "hex", "mnemonic"], default="auto")
    m.add_argument("--timeout", type=float, default=30)
    m.add_argument("--alpha", type=float, default=1e-4, help="p-value threshold for statistical checks")
    m.add_argument("--shell", action="store_true", help="run --cmd through the shell")
    m.add_argument("--format", choices=["text", "json"], default="text")
    m.add_argument("--github", action="store_true", help="emit workflow annotations")
    m.set_defaults(func=_smoke)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
