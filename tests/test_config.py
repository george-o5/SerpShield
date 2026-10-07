"""Tests for serpshield/config.py — config loading, both presets, all fields."""

import pytest

from serpshield.config import (
    AuditConfig,
    BudgetConfig,
    SerpShieldConfig,
    Thresholds,
    TrustConfig,
    get_config,
    load_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_SIGNAL_IDS = {"S1", "S2", "S3", "S4", "S5", "S6"}


# ---------------------------------------------------------------------------
# Smoke test — both presets load without error
# ---------------------------------------------------------------------------

class TestPresetLoading:
    def test_balanced_loads(self):
        cfg = get_config("balanced")
        assert isinstance(cfg, SerpShieldConfig)
        assert cfg.preset == "balanced"

    def test_strict_loads(self):
        cfg = get_config("strict")
        assert isinstance(cfg, SerpShieldConfig)
        assert cfg.preset == "strict"

    def test_default_is_balanced(self):
        cfg = get_config()
        assert cfg.preset == "balanced"

    def test_load_config_alias(self):
        """load_config is the legacy alias for get_config."""
        cfg = load_config("balanced")
        assert isinstance(cfg, SerpShieldConfig)

    def test_unknown_preset_raises(self):
        with pytest.raises(KeyError, match="unknown_preset"):
            get_config("unknown_preset")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------

class TestWeights:
    def test_balanced_weights(self):
        cfg = get_config("balanced")
        assert cfg.weights == {"S1_STRONG": 3, "S1_WEAK": 1, "S2": 3, "S3": 2, "S3_BIDI": 3, "S4": 4, "S5": 4, "S6": 0}

    def test_strict_weights(self):
        cfg = get_config("strict")
        assert cfg.weights == {"S1_STRONG": 3, "S1_WEAK": 1, "S2": 3, "S3": 2, "S3_BIDI": 3, "S4": 4, "S5": 4, "S6": 0}

    def test_weights_cover_all_signals(self):
        cfg = get_config("balanced")
        # Updated to include new signal IDs
        expected = {"S1_STRONG", "S1_WEAK", "S2", "S3", "S3_BIDI", "S4", "S5", "S6"}
        assert expected.issubset(cfg.weights.keys())

    def test_s4_weight_is_4(self):
        cfg = get_config("balanced")
        assert cfg.weights["S4"] == 4

    def test_s6_weight_is_0(self):
        """S6 is tag-only; its weight should be 0."""
        cfg = get_config("balanced")
        assert cfg.weights["S6"] == 0


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

class TestThresholds:
    def test_balanced_thresholds(self):
        th = get_config("balanced").thresholds
        assert isinstance(th, Thresholds)
        assert th.suspicious == 1
        assert th.flagged == 3
        assert th.blocked == 6

    def test_strict_thresholds(self):
        th = get_config("strict").thresholds
        assert th.suspicious == 1
        assert th.flagged == 2
        assert th.blocked == 5

    def test_strict_is_stricter_than_balanced(self):
        balanced = get_config("balanced").thresholds
        strict = get_config("strict").thresholds
        # Lower thresholds mean flags trigger sooner
        assert strict.flagged < balanced.flagged
        assert strict.blocked < balanced.blocked


# ---------------------------------------------------------------------------
# Context discount
# ---------------------------------------------------------------------------

class TestContextDiscount:
    def test_balanced_discount(self):
        assert get_config("balanced").context_discount == -2

    def test_strict_discount(self):
        assert get_config("strict").context_discount == 0

    def test_strict_has_no_discount(self):
        """Strict preset offers no leniency for contextual signals."""
        assert get_config("strict").context_discount == 0


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------

class TestBudget:
    def test_budget_type(self):
        assert isinstance(get_config("balanced").budget, BudgetConfig)

    def test_budget_values(self):
        b = get_config("balanced").budget
        assert b.cache_ttl_seconds == 3600
        assert b.session_cap == 20
        assert b.daily_cap == 50
        assert b.hard_max == 100

    def test_hard_max_greater_than_daily_cap(self):
        b = get_config("balanced").budget
        assert b.hard_max >= b.daily_cap

    def test_same_budget_across_presets(self):
        """Budget is global; it should not differ between presets."""
        b_bal = get_config("balanced").budget
        b_str = get_config("strict").budget
        assert b_bal == b_str


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

class TestEngines:
    def test_engines_is_list(self):
        assert isinstance(get_config("balanced").engines, list)

    def test_engines_contains_google(self):
        assert "google" in get_config("balanced").engines

    def test_engines_contains_google_news(self):
        assert "google_news" in get_config("balanced").engines


# ---------------------------------------------------------------------------
# Trust / allowlist
# ---------------------------------------------------------------------------

class TestTrust:
    def test_trust_type(self):
        assert isinstance(get_config("balanced").trust, TrustConfig)

    def test_allowlist_contains_wikipedia(self):
        assert "wikipedia.org" in get_config("balanced").trust.allowlist

    def test_allowlist_contains_github(self):
        assert "github.com" in get_config("balanced").trust.allowlist

    def test_allowlist_contains_owasp(self):
        assert "owasp.org" in get_config("balanced").trust.allowlist

    def test_allowlist_tld(self):
        tlds = get_config("balanced").trust.allowlist_tld
        assert ".gov.in" in tlds
        assert ".edu" in tlds
        assert ".ac.in" in tlds


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class TestAudit:
    def test_audit_type(self):
        assert isinstance(get_config("balanced").audit, AuditConfig)

    def test_audit_path(self):
        assert get_config("balanced").audit.path == "logs/audit.jsonl"

    def test_audit_max_bytes(self):
        assert get_config("balanced").audit.max_bytes == 5_000_000
