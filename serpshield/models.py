"""Pydantic models for results, findings, verdicts, responses.

Field names are taken verbatim from the recorded/*.json SerpApi responses:
  - Google organic:  position, title, link, snippet, displayed_link, source
  - Google News:     position, title, link, source (dict), date, iso_date, thumbnail
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    """Result-level risk classification (matches verdict.py scoring bands)."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    FLAGGED = "FLAGGED"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Finding (signal hit on a single result item)
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """One signal hit detected on a ResultItem."""

    signal_id: str = Field(..., description="Signal identifier, e.g. 'S1', 'S4'")
    field: str = Field(..., description="Which field triggered the signal, e.g. 'snippet'")
    evidence_hash: str = Field(
        ...,
        description="SHA-256 hex of the matched evidence — never the raw text",
    )
    detail: str = Field(default="", description="Human-readable description of the hit")


# ---------------------------------------------------------------------------
# ResultItem — unified across Google organic and Google News
# ---------------------------------------------------------------------------

class NewsSource(BaseModel):
    """Nested source object found in google_news results."""

    name: str
    icon: str | None = None
    authors: list[str] = Field(default_factory=list)


class ResultItem(BaseModel):
    """
    A single search-result row, covering both engine shapes:

    Google organic  → position, title, link, snippet, displayed_link, source (str)
    Google News     → position, title, link, source (NewsSource), date, iso_date, thumbnail
    """

    # --- common fields (always present) ---
    position: int
    title: str
    link: str

    # --- Google organic fields (optional for news) ---
    snippet: str | None = None
    displayed_link: str | None = None

    # --- source can be a plain string (organic) or a structured dict (news).
    #     We store both possibilities.  Callers should check source_structured
    #     first when engine == "google_news".
    source: str | None = None                    # organic: e.g. "Reddit · r/AI_Agents"
    source_structured: NewsSource | None = None  # news: {name, icon, authors}

    # --- Google News extra fields ---
    date: str | None = None
    iso_date: str | None = None
    thumbnail: str | None = None
    thumbnail_small: str | None = None

    # --- SerpShield-added verdict fields (written back after scoring) ---
    verdict: Verdict = Verdict.CLEAN
    findings: list[Finding] = Field(default_factory=list)

    # Keep any extra raw fields so we don't silently drop them.
    model_config = {"extra": "allow"}

    @classmethod
    def from_organic(cls, raw: dict[str, Any]) -> "ResultItem":
        """Construct from a google organic_results item."""
        return cls(
            position=raw["position"],
            title=raw.get("title", ""),
            link=raw.get("link", ""),
            snippet=raw.get("snippet"),
            displayed_link=raw.get("displayed_link"),
            source=raw.get("source"),
        )

    @classmethod
    def from_news(cls, raw: dict[str, Any]) -> "ResultItem":
        """Construct from a google_news news_results item."""
        src = raw.get("source")
        structured: NewsSource | None = None
        if isinstance(src, dict):
            structured = NewsSource(**src)
            src_str = src.get("name")
        else:
            src_str = src

        return cls(
            position=raw["position"],
            title=raw.get("title", ""),
            link=raw.get("link", ""),
            source=src_str,
            source_structured=structured,
            date=raw.get("date"),
            iso_date=raw.get("iso_date"),
            thumbnail=raw.get("thumbnail"),
            thumbnail_small=raw.get("thumbnail_small"),
        )


# ---------------------------------------------------------------------------
# Meta — search_metadata + search_parameters from SerpApi response
# ---------------------------------------------------------------------------

class SearchMeta(BaseModel):
    """Top-level metadata attached to a SerpApi JSON response."""

    id: str | None = None
    status: str | None = None
    created_at: str | None = None
    processed_at: str | None = None
    total_time_taken: float | None = None
    # engine-specific URL keys — keep both possibilities
    google_url: str | None = None
    google_news_url: str | None = None

    model_config = {"extra": "allow"}


class SearchParameters(BaseModel):
    """search_parameters block from a SerpApi response."""

    engine: str
    q: str
    google_domain: str | None = None
    device: str | None = None

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# SearchResponse — the full envelope returned by SerpShield
# ---------------------------------------------------------------------------

class SearchResponse(BaseModel):
    """
    SerpShield's sanitised response envelope.

    Contains the original query metadata, the filtered/annotated result items,
    and a top-level summary verdict.
    """

    query: str = Field(..., description="The original search query")
    engine: str = Field(..., description="'google' or 'google_news'")
    meta: SearchMeta | None = None
    parameters: SearchParameters | None = None

    # Sanitised result list (BLOCKED items are dropped or replaced with a stub)
    results: list[ResultItem] = Field(default_factory=list)

    # Aggregate verdict for the whole response
    overall_verdict: Verdict = Verdict.CLEAN

    # How many items were dropped / flagged
    stats: dict[str, int] = Field(
        default_factory=lambda: {
            "total": 0,
            "clean": 0,
            "suspicious": 0,
            "flagged": 0,
            "blocked": 0,
        }
    )
