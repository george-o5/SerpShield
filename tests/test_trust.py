"""Tests for trust.py."""

import pytest
from serpshield.models import Finding
from serpshield.config import get_config
from serpshield.trust import assess_trust

@pytest.fixture
def config():
    return get_config("balanced")

def test_trust_high(config):
    # Domain in allowlist, no signals
    res = assess_trust("github.com", [], config)
    assert res["trust"] == "high"
    assert "domain in allowlist" in res["trust_reasons"]
    assert "no injection signals" in res["trust_reasons"]

def test_trust_medium(config):
    # Domain not in allowlist, no signals
    res = assess_trust("example.com", [], config)
    assert res["trust"] == "medium"
    assert "no injection signals" in res["trust_reasons"]

def test_trust_low_allowlist_with_signal(config):
    # Domain in allowlist, but has signal
    findings = [Finding(signal_id="S1", field="title", evidence_hash="abc")]
    res = assess_trust("github.com", findings, config)
    assert res["trust"] == "low"

def test_trust_low_unknown_with_signal(config):
    # Domain not in allowlist, has signal
    findings = [Finding(signal_id="S1", field="title", evidence_hash="abc")]
    res = assess_trust("example.com", findings, config)
    assert res["trust"] == "low"

def test_trust_low_allowlist_with_s6(config):
    # Domain in allowlist, but has S6
    findings = [Finding(signal_id="S6", field="title", evidence_hash="abc")]
    res = assess_trust("github.com", findings, config)
    assert res["trust"] == "low"
