"""Render a Report as a colorful terminal card."""
from __future__ import annotations

from .model import Report
from .scoring import top_recommendations

ANSI = {"red": "\x1b[31m", "grn": "\x1b[32m", "yel": "\x1b[33m", "blu": "\x1b[34m",
        "mag": "\x1b[35m", "cyn": "\x1b[36m", "gry": "\x1b[90m", "wht": "\x1b[97m",
        "bld": "\x1b[1m", "rst": "\x1b[0m"}

GRADE_COLOR = {"A": "grn", "B": "grn", "C": "yel", "D": "yel", "F": "red"}
SEV_COLOR = {"good": "grn", "info": "gry", "low": "cyn", "medium": "yel",
             "high": "mag", "critical": "red"}
SEV_MARK = {"good": "+", "info": "·", "low": "•", "medium": "!", "high": "!!", "critical": "X"}


def c(t, color, use):
    return f"{ANSI[color]}{t}{ANSI['rst']}" if use else t


def render(report: Report, use_color: bool, verbose: bool = False) -> str:
    L = []
    bar = c("═" * 68, "gry", use_color)
    L.append(bar)
    L.append(f"  {c('ReconScope', 'cyn', use_color)}  ·  Attack Surface Report Card")
    L.append(bar)
    gcol = GRADE_COLOR.get(report.overall_grade, "yel")
    L.append(f"  domain : {c(report.domain, 'wht', use_color)}"
             + ("   " + c("[DEMO DATA]", "mag", use_color) if report.meta.get("demo") else ""))
    L.append(f"  grade  : {c(' ' + report.overall_grade + ' ', gcol, use_color)}  "
             f"({report.overall_score}/100)")
    if report.meta.get("addresses"):
        L.append(f"  hosts  : {c(', '.join(report.meta['addresses']), 'gry', use_color)}")
    L.append("")

    for cat in report.categories:
        if cat.error:
            L.append(f"  {c('○', 'gry', use_color)} {c(cat.title, 'bld', use_color)}  "
                     f"{c('not assessed — ' + cat.error, 'gry', use_color)}")
            continue
        gc = GRADE_COLOR.get(cat.grade, "yel")
        L.append(f"  {c(' ' + cat.grade + ' ', gc, use_color)} {c(cat.title, 'bld', use_color)}"
                 f"  {c('— ' + cat.summary, 'gry', use_color)}")
        shown = cat.findings if verbose else [f for f in cat.findings if f.severity not in ("good", "info")]
        for f in shown:
            mark = SEV_MARK.get(f.severity, "·")
            L.append(f"      {c(mark, SEV_COLOR.get(f.severity, 'gry'), use_color)} {f.message}")
        if not shown and not verbose:
            L.append(f"      {c('all checks passed', 'grn', use_color)}")
        L.append("")

    recs = top_recommendations(report, limit=6)
    if recs:
        L.append(f"  {c('Top fixes', 'wht', use_color)} (highest impact first):")
        for i, r in enumerate(recs, 1):
            L.append(f"   {c(str(i) + '.', 'bld', use_color)} [{c(r['severity'].upper(), SEV_COLOR.get(r['severity'], 'gry'), use_color)}] "
                     f"{r['recommendation']}")
        L.append("")
    L.append(c("  Passive OSINT on public data — scan only domains you own or are authorized to assess.", "gry", use_color))
    L.append(bar)
    return "\n".join(L)
