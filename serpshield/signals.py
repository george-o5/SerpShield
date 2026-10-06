"""Signals S1-S6. Pure functions: (normalized_text_bundle) -> list[Finding].

S1 instruction intent | S2 fake control markers | S3 hidden delivery
S4 encoded payload    | S5 exfiltration plumbing | S6 URL provenance (tag only)
Pattern lists live in config/constants, not hard-coded here.
Evidence is hashed, never echoed.
"""


import hashlib
from typing import List
from serpshield.models import Finding
from serpshield.normalize import NormalizedBundle
from serpshield.patterns import (
    S1_REGEXES, DISCUSSION_REGEXES, S2_REGEXES,
    S5_TEXT_REGEXES, S5_MD_LINK_REGEX, S5_PLACEHOLDER_REGEXES,
    S6_POPULAR_DOMAINS, S6_RISKY_TLDS, S6_IP_REGEX
)
from serpshield.config import get_config

def hash_evidence(text: str) -> str:
    """Returns truncated SHA-256 hash of the evidence."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

def s1_instruction_intent(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    cfg = get_config()
    weight = cfg.weights.get("S1", 3)
    max_findings = cfg.thresholds.blocked // weight if weight > 0 else 2
    
    distinct_matches = set()
    for regex in S1_REGEXES:
        for match in regex.finditer(bundle.evidence_view):
            matched_text = match.group(0).lower()
            if matched_text not in distinct_matches:
                distinct_matches.add(matched_text)
                
    for i, match_text in enumerate(list(distinct_matches)):
        if i >= max_findings:
            break
        findings.append(Finding(
            signal_id="S1",
            field=field,
            evidence_hash=hash_evidence(match_text),
            detail="Instruction intent pattern detected"
        ))
            
    return findings

def s2_fake_control_markers(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    distinct_matches = set()
    for regex in S2_REGEXES:
        for match in regex.finditer(bundle.evidence_view):
            matched_text = match.group(0).lower()
            if matched_text not in distinct_matches:
                distinct_matches.add(matched_text)
                findings.append(Finding(
                    signal_id="S2",
                    field=field,
                    evidence_hash=hash_evidence(matched_text),
                    detail="Fake control marker detected"
                ))
    return findings

def s3_hidden_delivery(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    has_bidi = False
    zw_count = 0
    
    for info in bundle.invisible_chars:
        if info.kind == "bidi":
            has_bidi = True
        elif info.kind == "zero_width":
            zw_count += 1
            
    if has_bidi:
        findings.append(Finding(
            signal_id="S3_BIDI",
            field=field,
            evidence_hash=hash_evidence("bidi_override"),
            detail="Bidi override control character detected"
        ))
        
    if zw_count >= 1:
        findings.append(Finding(
            signal_id="S3",
            field=field,
            evidence_hash=hash_evidence(f"zw_count_{zw_count}"),
            detail=f"{zw_count} zero-width character(s) detected"
        ))
        
    return findings

def s4_encoded_payload(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    for payload in bundle.decoded_payloads:
        matched_s1 = False
        matched_s2 = False
        
        for regex in S1_REGEXES:
            if regex.search(payload.decoded):
                matched_s1 = True
                break
                
        for regex in S2_REGEXES:
            if regex.search(payload.decoded):
                matched_s2 = True
                break
                
        if matched_s1:
            findings.append(Finding(
                signal_id="S4",
                field=field,
                evidence_hash=hash_evidence(payload.original),
                detail="S1 pattern matched in decoded payload"
            ))
            
        if matched_s2:
            findings.append(Finding(
                signal_id="S4",
                field=field,
                evidence_hash=hash_evidence(payload.original),
                detail="S2 pattern matched in decoded payload"
            ))
            
    return findings

def s5_exfiltration(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    distinct_matches = set()
    
    for regex in S5_TEXT_REGEXES:
        for match in regex.finditer(bundle.evidence_view):
            matched_text = match.group(0).lower()
            if matched_text not in distinct_matches:
                distinct_matches.add(matched_text)
                findings.append(Finding(
                    signal_id="S5",
                    field=field,
                    evidence_hash=hash_evidence(matched_text),
                    detail="Exfiltration text pattern detected"
                ))
                
    for match in S5_MD_LINK_REGEX.finditer(bundle.evidence_view):
        matched_text = match.group(0).lower()
        if matched_text in distinct_matches:
            continue
            
        url = match.group(1)
        has_placeholder = False
        for ph_regex in S5_PLACEHOLDER_REGEXES:
            if ph_regex.search(url):
                has_placeholder = True
                break
        if has_placeholder:
            distinct_matches.add(matched_text)
            findings.append(Finding(
                signal_id="S5",
                field=field,
                evidence_hash=hash_evidence(match.group(0)),
                detail="Exfiltration placeholder in markdown link/image detected"
            ))
            
    return findings

def _edit_distance(s1: str, s2: str) -> int:
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for index2, char2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, char1 in enumerate(s1):
            if char1 == char2:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1], distances[index1+1], new_distances[-1])))
        distances = new_distances
    return distances[-1]

def s6_url_provenance(field: str, bundle: NormalizedBundle) -> list[Finding]:
    findings = []
    
    for url_info in bundle.urls:
        host = url_info.host.lower()
        
        if url_info.mixed_script:
            findings.append(Finding(
                signal_id="S6",
                field=field,
                evidence_hash=hash_evidence(host),
                detail="URL host contains mixed script characters"
            ))
            
        if S6_IP_REGEX.match(host):
            findings.append(Finding(
                signal_id="S6",
                field=field,
                evidence_hash=hash_evidence(host),
                detail="URL host is an IP literal"
            ))
            
        parts = host.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in S6_RISKY_TLDS:
                findings.append(Finding(
                    signal_id="S6",
                    field=field,
                    evidence_hash=hash_evidence(host),
                    detail=f"URL uses risky TLD: .{tld}"
                ))
                
        for part in parts:
            for pop in S6_POPULAR_DOMAINS:
                if part == pop:
                    continue
                if abs(len(part) - len(pop)) <= 2:
                    dist = _edit_distance(part, pop)
                    if (len(pop) >= 6 and dist <= 2) or (len(pop) < 6 and dist == 1):
                        findings.append(Finding(
                            signal_id="S6",
                            field=field,
                            evidence_hash=hash_evidence(host),
                            detail=f"URL host resembles popular domain: {pop}"
                        ))
                        break
                        
    return findings

ALL_SIGNALS = {
    "S1": s1_instruction_intent,
    "S2": s2_fake_control_markers,
    "S3": s3_hidden_delivery,
    "S4": s4_encoded_payload,
    "S5": s5_exfiltration,
    "S6": s6_url_provenance,
}

