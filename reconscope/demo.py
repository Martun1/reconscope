"""Offline sample data so `--demo` (and the test suite, and screenshots) work with
no network. Two profiles: a weak shop that fails several checks, and a hardened
domain that passes them — enough to show the full range of the report.
"""
from __future__ import annotations


def demo_raw(domain: str) -> dict:
    if domain in ("securebank.example", "hardened.example"):
        return _strong()
    return _weak()


def _weak() -> dict:
    return {
        "dns": {
            "A": ["203.0.113.24"], "AAAA": [], "MX": ["10 mail.acme-shop.example."],
            "NS": ["ns1.budgethost.example.", "ns2.budgethost.example."],
            "TXT": ["v=spf1 include:_spf.budgethost.example ~all"],
            "dmarc_txt": ["v=DMARC1; p=none; rua=mailto:dmarc@acme-shop.example"],
            "dkim_found": False,
        },
        "tls": {
            "valid": True, "subject": "acme-shop.example",
            "issuer": "Let's Encrypt", "not_after": "Dec 20 12:00:00 2026 GMT",
            "days_left": 24, "tls_version": "TLSv1.2",
            "sans": ["acme-shop.example", "www.acme-shop.example"],
        },
        "headers": {
            "status": 200, "final_url": "https://acme-shop.example/",
            "headers": {
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/7.4.3",
                "content-type": "text/html; charset=UTF-8",
                "x-content-type-options": "nosniff",
            },
        },
        "surface": {"subdomains": [
            "www.acme-shop.example", "shop.acme-shop.example", "blog.acme-shop.example",
            "admin.acme-shop.example", "staging.acme-shop.example", "phpmyadmin.acme-shop.example",
            "vpn.acme-shop.example", "mail.acme-shop.example", "cdn.acme-shop.example",
            "old.acme-shop.example", "api.acme-shop.example",
        ]},
        "rdap": {
            "registrar": "BudgetHost Registrar", "created": "2019-03-11T00:00:00Z",
            "expires": "2027-03-11T00:00:00Z", "age_days": 2800, "expires_days": 480,
            "dnssec": False,
        },
    }


def _strong() -> dict:
    return {
        "dns": {
            "A": ["198.51.100.10"], "AAAA": ["2001:db8::10"],
            "MX": ["10 aspmx.securebank.example."],
            "NS": ["ns1.securebank.example.", "ns2.securebank.example.", "ns3.securebank.example."],
            "TXT": ["v=spf1 include:_spf.securebank.example -all"],
            "dmarc_txt": ["v=DMARC1; p=reject; rua=mailto:dmarc@securebank.example"],
            "dkim_found": True,
        },
        "tls": {
            "valid": True, "subject": "securebank.example",
            "issuer": "DigiCert Inc", "not_after": "Jun 01 12:00:00 2027 GMT",
            "days_left": 196, "tls_version": "TLSv1.3",
            "sans": ["securebank.example", "www.securebank.example"],
        },
        "headers": {
            "status": 200, "final_url": "https://securebank.example/",
            "headers": {
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=(), camera=()",
                "content-type": "text/html; charset=UTF-8",
            },
        },
        "surface": {"subdomains": [
            "www.securebank.example", "app.securebank.example", "status.securebank.example",
        ]},
        "rdap": {
            "registrar": "MarkMonitor Inc.", "created": "2004-06-01T00:00:00Z",
            "expires": "2029-06-01T00:00:00Z", "age_days": 8200, "expires_days": 1290,
            "dnssec": True,
        },
    }
