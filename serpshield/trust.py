"""Domain reputation + trust tags: high | medium | low | unknown, plus trust_reasons."""

from typing import Any, List
from serpshield.models import Finding
from serpshield.config import SerpShieldConfig

def assess_trust(domain: str, findings: List[Finding], config: SerpShieldConfig) -> dict:
    """Returns a dict with 'trust' (str) and 'trust_reasons' (list)."""
    allowlist = config.trust.allowlist
    allowlist_tld = config.trust.allowlist_tld
    
    trust = "unknown"
    reasons = []
    
    in_allowlist = False
    if domain in allowlist:
        in_allowlist = True
    else:
        for tld in allowlist_tld:
            if domain.endswith(tld):
                in_allowlist = True
                break
                
    has_injection_signals = any(not f.signal_id.startswith("S6") for f in findings)
    has_s6 = any(f.signal_id.startswith("S6") for f in findings)
    
    if in_allowlist:
        reasons.append("domain in allowlist")
    
    if not findings:
        reasons.append("no injection signals")
        
    if in_allowlist and not has_injection_signals and not has_s6:
        trust = "high"
    elif not in_allowlist and not has_injection_signals and not has_s6:
        trust = "medium"
    else:
        trust = "low"
        
    return {
        "trust": trust,
        "trust_reasons": reasons
    }
