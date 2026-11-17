"""Offline tests for ReconScope — no network, deterministic.

Covers domain normalization, each analyser against crafted fixtures (both the
good and the bad path), the scoring roll-up, and the end-to-end demo scan.
Run:  python3 tests/test_reconscope.py   (or python3 -m pytest -q)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconscope import checks, scoring  # noqa: E402
from reconscope.engine import normalize_domain, is_valid_domain, scan  # noqa: E402
from reconscope.model import CategoryResult  # noqa: E402


def grades(cat):
    return {f.severity for f in cat.findings}


# ── normalization ────────────────────────────────────────────────────────────
def test_normalize_strips_scheme_path_www():
    assert normalize_domain("https://www.Example.com/path?q=1") == "example.com"
    assert normalize_domain("http://sub.example.co.uk:8080/") == "sub.example.co.uk"
    assert normalize_domain("user@mail.example.org") == "mail.example.org"


def test_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("a.b.c.example.io")
    assert not is_valid_domain("not_a_domain")
    assert not is_valid_domain("example")
    assert not is_valid_domain("-bad.com")


# ── DNS & mail ───────────────────────────────────────────────────────────────
def test_dns_missing_spf_and_dmarc_are_high():
    cat = checks.check_dns_mail({
        "A": ["1.2.3.4"], "NS": ["a", "b"], "TXT": [], "dmarc_txt": [], "dkim_found": False})
    msgs = " ".join(f.message for f in cat.findings)
    assert "No SPF" in msgs and "No DMARC" in msgs
    assert "high" in grades(cat)


def test_dns_strict_spf_dmarc_are_good():
    cat = checks.check_dns_mail({
        "A": ["1.2.3.4"], "NS": ["a", "b"],
        "TXT": ["v=spf1 include:x -all"],
        "dmarc_txt": ["v=DMARC1; p=reject"], "dkim_found": True})
    scoring.score_category(cat)
    assert cat.grade == "A"
    assert "high" not in grades(cat) and "medium" not in grades(cat)


# ── headers ──────────────────────────────────────────────────────────────────
def test_headers_all_missing_is_F():
    cat = checks.check_headers({"headers": {"content-type": "text/html"}})
    scoring.score_category(cat)
    assert cat.grade == "F"
    assert "high" in grades(cat)  # HSTS + CSP missing


def test_headers_version_leak_flagged():
    cat = checks.check_headers({"headers": {"server": "nginx/1.18.0"}})
    assert any("leaks a version" in f.message for f in cat.findings)


def test_headers_all_present_is_A():
    cat = checks.check_headers({"headers": {
        "strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()"}})
    scoring.score_category(cat)
    assert cat.grade == "A"


# ── transport ────────────────────────────────────────────────────────────────
def test_tls_expired_is_critical():
    cat = checks.check_transport({"valid": True, "issuer": "X", "days_left": -3, "tls_version": "TLSv1.3"})
    assert "critical" in grades(cat)


def test_tls_weak_protocol_flagged():
    cat = checks.check_transport({"valid": True, "issuer": "X", "days_left": 90, "tls_version": "TLSv1.0"})
    assert any("weak protocol" in f.message for f in cat.findings)


# ── surface ──────────────────────────────────────────────────────────────────
def test_surface_flags_sensitive_subdomains():
    cat = checks.check_surface({"subdomains": [
        "www.x.com", "admin.x.com", "phpmyadmin.x.com", "blog.x.com"]})
    flagged = [f for f in cat.findings if "exposed" in f.message]
    assert len(flagged) == 2  # admin + phpmyadmin


def test_surface_clean_when_boring():
    cat = checks.check_surface({"subdomains": ["www.x.com", "blog.x.com", "shop.x.com"]})
    assert "medium" not in grades(cat)


# ── domain intel ─────────────────────────────────────────────────────────────
def test_domain_new_is_flagged():
    cat = checks.check_domain({"age_days": 5, "expires_days": 300, "dnssec": True})
    assert any("very new" in f.message for f in cat.findings)


def test_domain_no_dnssec_low():
    cat = checks.check_domain({"age_days": 2000, "expires_days": 300, "dnssec": False})
    assert any("DNSSEC" in f.message for f in cat.findings)


# ── scoring ──────────────────────────────────────────────────────────────────
def test_grade_boundaries():
    assert scoring.grade_for(90) == "A"
    assert scoring.grade_for(89) == "B"
    assert scoring.grade_for(59) == "F"


def test_error_category_does_not_tank_overall():
    from reconscope.model import Report
    r = Report("x.com", "now")
    good = CategoryResult("headers", "H")
    good.add("good", "ok")
    err = CategoryResult("transport", "T")
    err.error = "unreachable"
    r.categories = [good, err]
    scoring.finalize(r)
    assert r.overall_grade == "A"              # error category skipped
    assert "transport" in r.meta["not_assessed"]


# ── end to end ───────────────────────────────────────────────────────────────
def test_demo_weak_scan():
    r = scan("acme-shop.example", demo=True)
    assert r.overall_grade in ("C", "D")
    assert r.meta["demo"] is True
    keys = {c.key for c in r.categories}
    assert keys == {"dns_mail", "transport", "headers", "surface", "domain"}
    assert scoring.top_recommendations(r)       # has actionable fixes


def test_demo_strong_scan_is_A():
    r = scan("securebank.example", demo=True)
    assert r.overall_grade == "A"
    assert r.overall_score >= 95


def test_scan_rejects_bad_domain():
    try:
        scan("nope", demo=True)
        assert False, "should have raised"
    except ValueError:
        pass


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}  {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}  {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    return passed == len(fns)


if __name__ == "__main__":
    sys.exit(0 if _run() else 1)
