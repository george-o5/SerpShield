"""Loads config/default.yaml via Pydantic (weights, thresholds, allowlist, caps, presets).

Usage::

    from serpshield.config import get_config
    cfg = get_config("balanced")   # or "strict"
    cfg.weights["S4"]              # → 4
    cfg.thresholds.blocked         # → 6 (balanced) / 5 (strict)
"""

from __future__ import annotations

import pathlib
from functools import lru_cache
from typing import Literal

import yaml
from pydantic import BaseModel, Field

# Resolve path relative to this file so it works regardless of cwd.
_CONFIG_PATH = pathlib.Path(__file__).parent.parent / "config" / "default.yaml"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class Thresholds(BaseModel):
    """Score thresholds that determine verdict boundaries."""

    suspicious: int
    flagged: int
    blocked: int


class PresetConfig(BaseModel):
    """One named preset (balanced / strict)."""

    weights: dict[str, int]          # e.g. {"S1": 3, "S2": 3, ...}
    thresholds: Thresholds
    context_discount: int = 0        # score adjustment when context signals fire


class BudgetConfig(BaseModel):
    """API-call budget caps."""

    cache_ttl_seconds: int = 3600
    session_cap: int = 20
    daily_cap: int = 50
    hard_max: int = 100


class TrustConfig(BaseModel):
    """Allowlist configuration for trusted domains / TLDs."""

    allowlist: list[str] = Field(default_factory=list)
    allowlist_tld: list[str] = Field(default_factory=list)


class AuditConfig(BaseModel):
    """Audit log settings."""

    path: str = "logs/audit.jsonl"
    max_bytes: int = 5_000_000


# ---------------------------------------------------------------------------
# Top-level config object returned to callers
# ---------------------------------------------------------------------------

class SerpShieldConfig(BaseModel):
    """Fully-resolved config for one preset."""

    preset: str

    # --- from the chosen preset ---
    weights: dict[str, int]
    thresholds: Thresholds
    context_discount: int

    # --- global sections ---
    budget: BudgetConfig
    engines: list[str]
    trust: TrustConfig
    audit: AuditConfig


# ---------------------------------------------------------------------------
# Raw YAML loader (cached)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_yaml() -> dict:
    """Read and parse config/default.yaml exactly once."""
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_config(preset: Literal["balanced", "strict"] = "balanced") -> SerpShieldConfig:
    """
    Return a validated :class:`SerpShieldConfig` for the requested preset.

    Parameters
    ----------
    preset:
        ``"balanced"`` (default) or ``"strict"``.

    Raises
    ------
    KeyError
        If *preset* is not present in ``config/default.yaml``.
    """
    raw = _load_yaml()

    if preset not in raw.get("presets", {}):
        available = list(raw.get("presets", {}).keys())
        raise KeyError(
            f"Unknown preset {preset!r}. Available presets: {available}"
        )

    preset_raw = raw["presets"][preset]
    chosen = PresetConfig(
        weights=preset_raw["weights"],
        thresholds=Thresholds(**preset_raw["thresholds"]),
        context_discount=preset_raw.get("context_discount", 0),
    )

    return SerpShieldConfig(
        preset=preset,
        weights=chosen.weights,
        thresholds=chosen.thresholds,
        context_discount=chosen.context_discount,
        budget=BudgetConfig(**raw.get("budget", {})),
        engines=raw.get("engines", []),
        trust=TrustConfig(**raw.get("trust", {})),
        audit=AuditConfig(**raw.get("audit", {})),
    )


# Legacy alias used by the original stub
load_config = get_config
