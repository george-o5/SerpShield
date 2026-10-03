"""Scoring + verdict + redaction. Deterministic.

0 CLEAN | 1-2 SUSPICIOUS | 3-5 FLAGGED (snippet redacted) | >=6 or any S4/S5 BLOCKED (removed)
Includes context discount (-2) and cross-field title+snippet check.
"""


def score_result(findings, config) -> int:
    raise NotImplementedError


def decide_verdict(score: int, findings, config) -> str:
    raise NotImplementedError


def apply_verdict(result, verdict: str, findings):
    """Pass through / tag / redact / drop."""
    raise NotImplementedError
