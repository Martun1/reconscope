"""Pure analysis: raw recon data in, graded CategoryResult out.

Every function here is deterministic and network-free — it takes already-fetched
data and decides what's good, what's risky, and how to fix it. That keeps the
security judgement in one place and makes the whole thing unit-testable offline.
"""
from __future__ import annotations

import re
from .model import CategoryResult

# Subdomain labels that are worth flagging when exposed in certificate logs:
# they often point at non-production or high-value systems.
INTERESTING_LABELS = {
    "dev", "test", "staging", "stage", "qa", "uat", "preprod", "sandbox",
    "admin", "adminpanel", "panel", "cpanel", "whm", "manage", "dashboard",
    "vpn", "remote", "rdp", "citrix", "portal", "gateway",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "db", "database", "sql", "phpmyadmin", "pma", "mongo", "redis",
    "backup", "old", "legacy", "internal", "intranet", "corp",
    "mail", "webmail", "smtp", "imap", "owa", "exchange",
    "api", "dev-api", "test-api", "ftp", "sftp", "s3", "jenkins",
}

# Security headers we grade, with the severity of their absence.
HEADER_SPECS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", "high",
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' so browsers refuse to talk to the site over plain HTTP."),
    ("content-security-policy", "Content-Security-Policy", "high",
     "Add a Content-Security-Policy to limit where scripts and resources can load from — the strongest defence against cross-site scripting."),
    ("x-frame-options", "X-Frame-Options / frame-ancestors", "medium",
     "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to block clickjacking."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Add 'X-Content-Type-Options: nosniff' so browsers don't guess (and mis-execute) content types."),
    ("referrer-policy", "Referrer-Policy", "low",
     "Add 'Referrer-Policy: strict-origin-when-cross-origin' to stop leaking full URLs to other sites."),
    ("permissions-policy", "Permissions-Policy", "low",
     "Add a Permissions-Policy to switch off browser features (camera, geolocation…) the site doesn't use."),
]

# Headers that leak stack details and invite targeted attacks.
VERSION_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
VERSION_NUMBER = re.compile(r"\d+\.\d+")


# ─────────────────────────────────────────────────────────────────────────────
def check_dns_mail(dns: dict) -> CategoryResult:
    c = CategoryResult("dns_mail", "DNS & email security")
    if dns.get("error"):
        c.error = dns["error"]
        return c

    a = dns.get("A", []) + dns.get("AAAA", [])
    mx = dns.get("MX", [])
    ns = dns.get("NS", [])
    txt = dns.get("TXT", [])

    if a:
        c.add("good", f"Resolves to {len(a)} host address(es).")
    else:
        c.add("medium", "No A/AAAA records — the domain does not resolve to a web host.",
              "If this domain should host a site, add an A or AAAA record.")
    if len(ns) < 2:
        c.add("medium", f"Only {len(ns)} nameserver(s) found.",
              "Use at least two nameservers (ideally on different networks) for resilience.")
    else:
        c.add("good", f"{len(ns)} nameservers configured.")

    # SPF
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        c.add("high", "No SPF record — anyone can send email claiming to be from this domain.",
              "Publish a TXT SPF record, e.g. 'v=spf1 include:_spf.yourprovider.com -all'.")
    else:
        rec = spf[0].lower()
        if rec.rstrip().endswith("-all"):
            c.add("good", "SPF present with a strict '-all' (hard fail) policy.")
        elif "~all" in rec:
            c.add("low", "SPF ends with '~all' (soft fail) — spoofed mail is marked, not rejected.",
                  "Tighten the SPF record to end with '-all' once you're sure all senders are listed.")
        else:
            c.add("medium", "SPF present but without a clear fail policy.",
                  "End the SPF record with '-all' to reject unauthorized senders.")

    # DMARC
    dmarc = [t for t in dns.get("dmarc_txt", []) if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        c.add("high", "No DMARC record — receivers get no instruction on handling spoofed mail.",
              "Publish '_dmarc.<domain>' TXT, starting with 'v=DMARC1; p=none; rua=mailto:you@domain' then move to p=reject.")
    else:
        rec = dmarc[0].lower()
        if "p=reject" in rec:
            c.add("good", "DMARC present with an enforcing 'p=reject' policy.")
        elif "p=quarantine" in rec:
            c.add("low", "DMARC set to 'p=quarantine' — spoofed mail goes to spam, not blocked.",
                  "Move DMARC to 'p=reject' once reports look clean.")
        else:
            c.add("medium", "DMARC set to 'p=none' — monitoring only, no protection yet.",
                  "Progress DMARC from 'p=none' to 'p=quarantine' then 'p=reject'.")

    # DKIM (best-effort: did any common selector resolve?)
    if dns.get("dkim_found"):
        c.add("good", "A DKIM public key was found — outgoing mail can be signed.")
    else:
        c.add("low", "No DKIM key found at common selectors.",
              "Enable DKIM signing in your mail provider and publish the selector's public key.")

    if not mx:
        c.add("info", "No MX records — domain does not receive email (fine for a web-only domain).")

    worst = _worst(c)
    c.summary = "Email spoofing protection is solid." if worst in ("good", "info", "low") \
        else "Email can likely be spoofed — fix SPF/DMARC."
    return c


def check_transport(tls: dict) -> CategoryResult:
    c = CategoryResult("transport", "TLS / certificate")
    if tls.get("error"):
        c.error = tls["error"]
        return c

    if not tls.get("valid"):
        c.add("critical", "The TLS certificate did not validate.",
              "Install a valid certificate (e.g. free via Let's Encrypt) matching the hostname.")
    else:
        c.add("good", f"Valid certificate issued by {tls.get('issuer','?')}.")

    days = tls.get("days_left")
    if isinstance(days, int):
        if days < 0:
            c.add("critical", "The certificate has expired.", "Renew the certificate immediately.")
        elif days < 15:
            c.add("high", f"Certificate expires in {days} days.", "Renew now and automate renewal.")
        elif days < 30:
            c.add("medium", f"Certificate expires in {days} days.", "Schedule renewal / enable auto-renew.")
        else:
            c.add("good", f"Certificate valid for {days} more days.")

    ver = (tls.get("tls_version") or "")
    if ver:
        if any(b in ver for b in ("1.0", "1.1", "SSL")):
            c.add("high", f"Negotiated a weak protocol ({ver}).",
                  "Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or higher.")
        else:
            c.add("good", f"Modern transport protocol in use ({ver}).")

    c.summary = "Transport security looks healthy." if _worst(c) in ("good", "info", "low") \
        else "Certificate/TLS needs attention."
    return c


def check_headers(headers: dict) -> CategoryResult:
    c = CategoryResult("headers", "HTTP security headers")
    if headers.get("error"):
        c.error = headers["error"]
        return c

    present = {k.lower(): v for k, v in headers.get("headers", {}).items()}
    for key, title, severity, rec in HEADER_SPECS:
        if key in present:
            c.add("good", f"{title} is set.")
        else:
            c.add(severity, f"{title} is missing.", rec)

    for h in VERSION_LEAK_HEADERS:
        val = present.get(h, "")
        if val and VERSION_NUMBER.search(val):
            c.add("low", f"'{h}' header leaks a version ({val}).",
                  f"Strip the version from the '{h}' header so attackers can't target known CVEs.")

    c.summary = "Good header hygiene." if _worst(c) in ("good", "info", "low") \
        else "Several protective headers are missing."
    return c


def check_surface(surface: dict) -> CategoryResult:
    c = CategoryResult("surface", "Attack surface (subdomains)")
    if surface.get("error"):
        c.error = surface["error"]
        return c

    subs = sorted(set(surface.get("subdomains", [])))
    c.summary = f"{len(subs)} subdomain(s) visible in certificate transparency logs."
    if not subs:
        c.add("good", "No extra subdomains found in public certificate logs.")
        return c

    c.add("info", f"{len(subs)} subdomain(s) are publicly discoverable via certificate transparency.")
    flagged = []
    for s in subs:
        label = s.split(".")[0].lower()
        if label in INTERESTING_LABELS or any(label.startswith(p + "-") or label.endswith("-" + p)
                                              for p in INTERESTING_LABELS):
            flagged.append(s)
    for s in flagged[:12]:
        c.add("medium", f"Sensitive-looking host exposed: {s}",
              "Confirm this host should be internet-facing; if not, restrict it to a VPN/allowlist.")
    if len(flagged) > 12:
        c.add("info", f"...and {len(flagged) - 12} more sensitive-looking hostnames.")
    if not flagged:
        c.add("good", "None of the exposed subdomains look like admin/dev/internal systems.")
    return c


def check_domain(rdap: dict) -> CategoryResult:
    c = CategoryResult("domain", "Domain intelligence")
    if rdap.get("error"):
        c.error = rdap["error"]
        return c

    reg = rdap.get("registrar")
    if reg:
        c.add("info", f"Registered via {reg}.")
    age = rdap.get("age_days")
    if isinstance(age, int):
        if age < 30:
            c.add("medium", f"Domain is very new ({age} days old).",
                  "Brand-new domains are common in scams; if this is yours, be aware recipients may distrust it.")
        else:
            years = age // 365
            c.add("good", f"Established domain (~{years} year(s), {age} days old).")
    exp = rdap.get("expires_days")
    if isinstance(exp, int):
        if exp < 0:
            c.add("high", "Domain registration appears expired.", "Renew the domain registration immediately.")
        elif exp < 30:
            c.add("medium", f"Domain registration expires in {exp} days.",
                  "Renew the domain and enable auto-renew to avoid losing it.")
        else:
            c.add("good", f"Registration valid for {exp} more days.")
    if rdap.get("dnssec"):
        c.add("good", "DNSSEC is enabled.")
    else:
        c.add("low", "DNSSEC is not enabled.",
              "Enable DNSSEC at your registrar to stop DNS answers from being forged.")

    c.summary = "Domain registration looks stable." if _worst(c) in ("good", "info", "low") \
        else "Domain registration needs attention."
    return c


def _worst(c: CategoryResult) -> str:
    from .model import SEVERITY_RANK
    worst = "good"
    for f in c.findings:
        if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(worst, 0):
            worst = f.severity
    return worst
