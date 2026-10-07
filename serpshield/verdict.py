"""Scoring + verdict + redaction. Deterministic.

0 CLEAN | 1-2 SUSPICIOUS | 3-5 FLAGGED (snippet redacted) | >=6 or any S4/S5 BLOCKED (removed)
Includes context discount (-2) and cross-field title+snippet check.
"""

from typing import Any
from serpshield.models import ResultItem, Verdict
from serpshield.config import SerpShieldConfig
from serpshield.patterns import DISCUSSION_REGEXES, S1_STRONG_REGEXES, S1_WEAK_REGEXES

def _has_discussion_words(text: str) -> bool:
    if not text:
        return False
    text = text.lower()
    for regex in DISCUSSION_REGEXES:
        if regex.search(text):
            return True
    return False

def score_result(item: ResultItem, config: SerpShieldConfig) -> int:
    """Calculates the score of a ResultItem based on findings and config."""
    score = 0
    full_text = (item.title or "") + " " + (item.snippet or "")
    
    has_s1 = False
    has_s2_s5 = False
    
    for finding in item.findings:
        weight = config.weights.get(finding.signal_id, 0)
        score += weight
        
        if finding.signal_id in ["S1_STRONG", "S1_WEAK"]:
            has_s1 = True
        elif finding.signal_id.startswith(("S2", "S3", "S4", "S5")):
            has_s2_s5 = True

    # Cross-field check for split payloads
    if not has_s1:
        for regex in S1_STRONG_REGEXES:
            if regex.search(full_text):
                weight = config.weights.get("S1_STRONG", 3)
                score += weight
                has_s1 = True
                break
        if not has_s1:
            for regex in S1_WEAK_REGEXES:
                if regex.search(full_text):
                    weight = config.weights.get("S1_WEAK", 1)
                    score += weight
                    has_s1 = True
                    break
                
    # Context discount
    if has_s1 and not has_s2_s5 and _has_discussion_words(full_text):
        score += config.context_discount
        
    return max(0, score)

def decide_verdict(score: int, item: ResultItem, config: SerpShieldConfig) -> Verdict:
    """Decides the Verdict based on score and specific signals."""
    has_s4_s5 = False
    for finding in item.findings:
        if finding.signal_id.startswith(("S4", "S5")):
            has_s4_s5 = True
            break
            
    if has_s4_s5:
        return Verdict.BLOCKED
    elif score >= config.thresholds.blocked:
        return Verdict.BLOCKED
    elif score >= config.thresholds.flagged:
        return Verdict.FLAGGED
    elif score >= config.thresholds.suspicious:
        return Verdict.SUSPICIOUS
    else:
        return Verdict.CLEAN

def apply_verdict(item: ResultItem, config: SerpShieldConfig) -> ResultItem:
    """Pass through / tag / redact / drop."""
    score = score_result(item, config)
    item.verdict = decide_verdict(score, item, config)
    
    # Redaction for FLAGGED
    if item.verdict == Verdict.FLAGGED:
        reasons = sorted(list(set([f.signal_id for f in item.findings])))
        reason_str = ", ".join(reasons)
        if not reason_str:
            reason_str = "S1_STRONG" # Fallback if cross-field caught it
        if item.snippet is not None:
            item.snippet = f"[redacted: {reason_str}]"
            
    return item
