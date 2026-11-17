"""Core data model for ReconScope — the shared vocabulary of a scan.

A scan produces a Report. A Report has several CategoryResults (DNS & mail,
transport, HTTP headers, attack surface, domain intel). Each category has a
letter grade and a list of Findings, where a Finding is one observation plus,
when something is wrong, a concrete recommendation to fix it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# Severity ranks — higher is worse. "good" is a passed check (shown in green).
SEVERITY_RANK = {"good": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Points deducted from a category's 100 for a finding of each severity.
SEVERITY_PENALTY = {"good": 0, "info": 0, "low": 4, "medium": 10, "high": 20, "critical": 35}


@dataclass
class Finding:
    severity: str              # good | info | low | medium | high | critical
    message: str               # what was observed, in plain language
    recommendation: str = ""   # how to fix it (empty for good/info)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CategoryResult:
    key: str                   # machine id, e.g. "headers"
    title: str                 # human title, e.g. "HTTP security headers"
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""          # one-line human summary
    score: int = 100           # 0..100, computed from findings
    grade: str = "A"           # A..F, computed from score
    error: str = ""            # set if the category could not be assessed

    def add(self, severity: str, message: str, recommendation: str = "") -> None:
        self.findings.append(Finding(severity, message, recommendation))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class Report:
    domain: str
    scanned_at: str
    categories: list[CategoryResult] = field(default_factory=list)
    overall_score: int = 100
    overall_grade: str = "A"
    meta: dict[str, Any] = field(default_factory=dict)  # resolved IPs, registrar, etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "scanned_at": self.scanned_at,
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "meta": self.meta,
            "categories": [c.to_dict() for c in self.categories],
        }
