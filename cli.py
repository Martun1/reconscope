#!/usr/bin/env python3
"""ReconScope command-line entry point.

    python3 cli.py example.com              # scan and print a report card
    python3 cli.py example.com --json       # machine-readable output
    python3 cli.py example.com --demo       # offline sample data (no network)
    python3 cli.py --serve                  # launch the web GUI
"""
from __future__ import annotations

import argparse
import json
import sys

from reconscope.engine import scan
from reconscope.report_text import render


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="reconscope",
        description="Attack Surface Report Card — passive-OSINT security posture for a domain.")
    ap.add_argument("domain", nargs="?", help="domain or URL to assess")
    ap.add_argument("--json", action="store_true", help="output JSON instead of a report card")
    ap.add_argument("--demo", action="store_true", help="use built-in sample data (no network)")
    ap.add_argument("--verbose", "-v", action="store_true", help="show passing checks too")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--serve", action="store_true", help="launch the local web GUI")
    ap.add_argument("--port", type=int, default=8787, help="port for --serve (default 8787)")
    args = ap.parse_args(argv)

    if args.serve:
        from reconscope.server import serve
        serve(port=args.port)
        return 0

    if not args.domain:
        ap.error("give a DOMAIN, or use --serve for the web GUI")

    try:
        report = scan(args.domain, demo=args.demo)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(render(report, use_color, verbose=args.verbose))
    # exit code reflects posture: 0 for A/B, 1 for C/D, 2 for F (handy in CI)
    return {"A": 0, "B": 0, "C": 1, "D": 1, "F": 2}.get(report.overall_grade, 1)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
