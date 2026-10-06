"""Tests for verdict.py boundary scores and redaction."""

import pytest
from serpshield.models import ResultItem, Finding, Verdict
from serpshield.config import get_config
from serpshield.verdict import score_result, decide_verdict, apply_verdict

@pytest.fixture
def config():
    return get_config("balanced")

def test_score_0_clean(config):
    item = ResultItem(position=1, title="clean", link="http://clean")
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.CLEAN

def test_score_1_2_suspicious(config):
    # S3 weight is 2
    item = ResultItem(position=1, title="S3", link="http://S3")
    item.findings.append(Finding(signal_id="S3", field="title", evidence_hash="abc"))
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.SUSPICIOUS

def test_score_3_flagged(config):
    # S1 weight is 3
    item = ResultItem(position=1, title="S1", link="http://S1", snippet="snip")
    item.findings.append(Finding(signal_id="S1", field="title", evidence_hash="abc"))
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.FLAGGED
    assert item.snippet == "[redacted: S1]"

def test_score_5_flagged(config):
    # S1 (3) + S3 (2) = 5
    item = ResultItem(position=1, title="S1 and S3", link="http://S1", snippet="snip")
    item.findings.extend([
        Finding(signal_id="S1", field="title", evidence_hash="abc"),
        Finding(signal_id="S3", field="title", evidence_hash="def")
    ])
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.FLAGGED
    assert "S1" in item.snippet
    assert "S3" in item.snippet

def test_score_6_blocked(config):
    # S1 (3) + S1 (3) = 6
    item = ResultItem(position=1, title="S1 and S1", link="http://S1", snippet="snip")
    item.findings.extend([
        Finding(signal_id="S1", field="title", evidence_hash="abc"),
        Finding(signal_id="S1", field="snippet", evidence_hash="def")
    ])
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.BLOCKED

def test_s4_s5_blocked(config):
    # Any S4/S5 -> BLOCKED, even if score is 4
    item = ResultItem(position=1, title="S4", link="http://S4")
    item.findings.append(Finding(signal_id="S4", field="title", evidence_hash="abc"))
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.BLOCKED
    
def test_context_discount(config):
    # S1 (3) in context with discussion words -> 3 - 2 = 1 (SUSPICIOUS)
    item = ResultItem(position=1, title="example prompt injection", link="http://ctx")
    item.findings.append(Finding(signal_id="S1", field="title", evidence_hash="abc"))
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.SUSPICIOUS

def test_split_payload(config):
    # S1 across title + snippet
    # "ignore previous instructions"
    item = ResultItem(position=1, title="ignore previous", link="http://ctx", snippet="instructions")
    item = apply_verdict(item, config)
    assert item.verdict == Verdict.FLAGGED # caught by cross-field check
