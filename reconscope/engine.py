"""Orchestration: fetch every source concurrently, analyse, score, assemble.

The engine is the one place that knows the full pipeline. It fans the five
fetchers out across threads (network latency dominates, so this roughly 5×'s a
scan), feeds each result to its analyser, then finalises the grades.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import checks, fetchers
from .model import Report
from .scoring import finalize

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def normalize_domain(raw: str) -> str:
    """Accept a URL or bare host and return the registrable hostname."""
    raw = (raw or "").strip()
    raw = re.sub(r"^[a-zA-Z]+://", "", raw)      # strip scheme
    raw = raw.split("/")[0].split("?")[0]        # strip path/query
    raw = raw.split("@")[-1]                      # strip userinfo
    raw = raw.split(":")[0]                       # strip port
    raw = raw.strip(".").lower()
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def scan(domain: str, demo: bool = False) -> Report:
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        raise ValueError(f"'{domain}' is not a valid domain name.")

    if demo:
        from .demo import demo_raw
        raw = demo_raw(domain)
    else:
        raw = _gather(domain)

    report = Report(domain=domain, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    report.categories = [
        checks.check_dns_mail(raw["dns"]),
        checks.check_transport(raw["tls"]),
        checks.check_headers(raw["headers"]),
        checks.check_surface(raw["surface"]),
        checks.check_domain(raw["rdap"]),
    ]
    report.meta.update({
        "addresses": (raw["dns"].get("A", []) + raw["dns"].get("AAAA", []))[:8],
        "registrar": raw["rdap"].get("registrar"),
        "issuer": raw["tls"].get("issuer"),
        "subdomain_count": len(raw["surface"].get("subdomains", [])),
        "demo": demo,
    })
    return finalize(report)


def _gather(domain: str) -> dict:
    jobs = {
        "dns": lambda: fetchers.fetch_dns(domain),
        "tls": lambda: fetchers.fetch_tls(domain),
        "headers": lambda: fetchers.fetch_headers(domain),
        "surface": lambda: fetchers.fetch_subdomains(domain),
        "rdap": lambda: fetchers.fetch_rdap(domain),
    }
    out: dict = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(fn): key for key, fn in jobs.items()}
        for fut, key in [(f, futures[f]) for f in futures]:
            try:
                out[key] = fut.result()
            except Exception as e:  # noqa: BLE001
                out[key] = {"error": str(e)}
    return out
