"""The network layer: gather raw recon data about a domain from public sources.

Everything here is passive OSINT — DNS over HTTPS, certificate-transparency logs,
RDAP, and a single HTTPS HEAD/GET for headers. No port scanning, no exploitation,
no authentication, nothing intrusive. Each function returns a plain dict and
never raises: on failure it returns {"error": "..."} so one dead source can't
sink the whole scan. Standard library only.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "ReconScope/1.0 (+https://github.com/Martun1/reconscope)"
TIMEOUT = 10

# DNS-over-HTTPS resolvers (JSON API). Tried in order.
DOH_ENDPOINTS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]


def _get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _doh(name: str, rtype: str) -> list[str]:
    """Resolve a DNS record type via DoH, returning the record data strings."""
    last = None
    for ep in DOH_ENDPOINTS:
        try:
            q = urllib.parse.urlencode({"name": name, "type": rtype})
            data = _get_json(f"{ep}?{q}", headers={"Accept": "application/dns-json"})
            out = []
            for ans in data.get("Answer", []):
                val = ans.get("data", "")
                if rtype == "TXT":
                    val = val.strip('"').replace('" "', "")
                out.append(val)
            return out
        except Exception as e:  # noqa: BLE001
            last = e
    if last:
        raise last
    return []


def fetch_dns(domain: str) -> dict:
    out: dict = {}
    try:
        for rt in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                out[rt] = _doh(domain, rt)
            except Exception:  # noqa: BLE001
                out[rt] = []
        # DMARC lives at _dmarc.<domain>
        try:
            out["dmarc_txt"] = _doh(f"_dmarc.{domain}", "TXT")
        except Exception:  # noqa: BLE001
            out["dmarc_txt"] = []
        # DKIM: probe a few common selectors
        found = False
        for sel in COMMON_DKIM_SELECTORS:
            try:
                recs = _doh(f"{sel}._domainkey.{domain}", "TXT")
                if any("p=" in r for r in recs):
                    found = True
                    break
            except Exception:  # noqa: BLE001
                pass
        out["dkim_found"] = found
        if not any(out.get(k) for k in ("A", "AAAA", "NS")):
            out["error"] = "DNS lookups returned nothing (is the domain correct and online?)."
    except Exception as e:  # noqa: BLE001
        out["error"] = f"DNS lookup failed: {e}"
    return out


def fetch_tls(domain: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
        return {
            "valid": True,
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName") or issuer.get("commonName", "?"),
            "not_after": not_after,
            "days_left": days_left,
            "tls_version": version,
            "sans": sans,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "tls_version": "", "error": "", "verify_error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Could not establish TLS to {domain}:{port}: {e}"}


def fetch_headers(domain: str) -> dict:
    url = f"https://{domain}/"
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            return {"status": r.status, "final_url": r.url, "headers": headers}
    except urllib.error.HTTPError as e:
        # Still useful — the response carries headers even on 4xx/5xx.
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return {"status": e.code, "final_url": url, "headers": headers}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Could not fetch HTTPS headers: {e}"}


def fetch_subdomains(domain: str) -> dict:
    """Passive subdomain discovery from crt.sh certificate-transparency logs."""
    try:
        q = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
        data = _get_json(f"https://crt.sh/?{q}")
        subs = set()
        for row in data:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith("." + domain) and name != domain:
                    subs.add(name)
        return {"subdomains": sorted(subs)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Certificate-transparency lookup failed: {e}"}


def fetch_rdap(domain: str) -> dict:
    try:
        data = _get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
        registrar = None
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                for v in ent.get("vcardArray", [[], []])[1]:
                    if v and v[0] == "fn":
                        registrar = v[3]
        created = expires = None
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
            elif ev.get("eventAction") == "expiration":
                expires = ev.get("eventDate")
        age_days = _days_since(created)
        expires_days = _days_until(expires)
        dnssec = bool(data.get("secureDNS", {}).get("delegationSigned"))
        return {"registrar": registrar, "created": created, "expires": expires,
                "age_days": age_days, "expires_days": expires_days, "dnssec": dnssec}
    except Exception as e:  # noqa: BLE001
        return {"error": f"RDAP lookup failed: {e}"}


def _parse_iso(s: str | None):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def _days_since(s: str | None):
    dt = _parse_iso(s)
    return (datetime.now(timezone.utc) - dt).days if dt else None


def _days_until(s: str | None):
    dt = _parse_iso(s)
    return (dt - datetime.now(timezone.utc)).days if dt else None
