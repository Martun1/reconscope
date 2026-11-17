"""Turn findings into scores and letter grades, and roll categories up into one
overall posture grade.

The scheme is deliberately simple and transparent — a user should be able to see
exactly why they got a C. Each category starts at 100 and loses points per
finding by severity (capped at 0). The overall score is a weighted average of
category scores, so a great TLS setup can't fully hide a missing SPF record.
"""
from __future__ import annotations

from .model import CategoryResult, Report, SEVERITY_PENALTY

# How much each category counts toward the overall grade.
CATEGORY_WEIGHTS = {
    "dns_mail": 1.3,      # email spoofing is the #1 phishing enabler
    "headers": 1.1,
    "transport": 1.2,
    "surface": 1.0,
    "domain": 0.8,
}


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_category(cat: CategoryResult) -> CategoryResult:
    """Compute cat.score and cat.grade from its findings (in place)."""
    if cat.error:
        cat.score = 0
        cat.grade = "F"
        return cat
    score = 100
    for f in cat.findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    cat.score = max(0, min(100, score))
    cat.grade = grade_for(cat.score)
    return cat


def finalize(report: Report) -> Report:
    """Score every category, then compute the weighted overall grade (in place)."""
    for cat in report.categories:
        score_category(cat)

    weighted_sum = 0.0
    weight_total = 0.0
    for cat in report.categories:
        if cat.error:
            # An un-assessable category shouldn't tank the whole grade; skip it,
            # but note it in meta so the UI can show "not assessed".
            report.meta.setdefault("not_assessed", []).append(cat.key)
            continue
        w = CATEGORY_WEIGHTS.get(cat.key, 1.0)
        weighted_sum += cat.score * w
        weight_total += w

    report.overall_score = round(weighted_sum / weight_total) if weight_total else 0
    report.overall_grade = grade_for(report.overall_score)
    return report


def top_recommendations(report: Report, limit: int = 6) -> list[dict]:
    """The highest-impact fixes across all categories, worst first."""
    from .model import SEVERITY_RANK
    items = []
    for cat in report.categories:
        for f in cat.findings:
            if f.recommendation and SEVERITY_RANK.get(f.severity, 0) >= 2:
                items.append({
                    "severity": f.severity,
                    "category": cat.title,
                    "message": f.message,
                    "recommendation": f.recommendation,
                    "_rank": SEVERITY_RANK.get(f.severity, 0),
                })
    items.sort(key=lambda x: -x["_rank"])
    for it in items:
        del it["_rank"]
    return items[:limit]
