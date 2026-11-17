"""ReconScope — Attack Surface Report Card.

Passive-OSINT security posture scanner: see your domain the way an attacker
does, graded A–F, with concrete fixes. Standard library only.
"""
__version__ = "1.0.0"

from .engine import scan, normalize_domain, is_valid_domain  # noqa: F401
