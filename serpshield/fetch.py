"""SerpApi client (live) + replay loader (recorded/ and scenarios/).

- Live: GET https://serpapi.com/search.json, timeout 15s, 1 retry on network error, no retry on 4xx.
- Replay: SERPSHIELD_MODE=replay. meta.mode = "live" | "replay" | "replay-simulated".
- API key from env SERPAPI_API_KEY only. Never log it.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

from serpshield.models import ResultItem


class FetchError(Exception):
    """Error during fetch (live or replay)."""

    pass


def _slugify(text: str) -> str:
    """Convert query string to a safe filename slug."""
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = text.strip("_")
    return text[:60]


def _sanitize_error(exc: httpx.HTTPError, api_key: str) -> str:
    """
    Create a safe error message that NEVER contains the API key or full URL.
    Only extract status code and SerpApi's error field if available.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            error_data = exc.response.json()
            error_msg = error_data.get("error", "Unknown error")
            return f"SerpApi HTTP {exc.response.status_code}: {error_msg}"
        except Exception:
            return f"SerpApi HTTP {exc.response.status_code}"
    else:
        # Generic network/transport error - avoid exposing URL
        return f"Network error: {type(exc).__name__}"


def _strip_api_key_from_dict(data: dict) -> dict:
    """Remove api_key from search_parameters if present."""
    if "search_parameters" in data and isinstance(data["search_parameters"], dict):
        data["search_parameters"].pop("api_key", None)
    return data


def fetch(engine: str, query: str, num: int = 10) -> tuple[dict, str]:
    """
    Fetch search results, choosing mode from SERPSHIELD_MODE env var.
    
    Returns:
        (raw_data, mode) where mode is "live", "replay", or "replay-simulated"
    """
    mode_env = os.environ.get("SERPSHIELD_MODE", "live").lower()
    
    if mode_env == "replay":
        return fetch_replay(engine, query)
    else:
        raw = fetch_live(engine, query, num)
        return raw, "live"


def fetch_live(engine: str, query: str, num: int) -> dict:
    """
    Fetch live results from SerpApi.
    
    - Timeout: 15s
    - Retry: once on network error (httpx.TransportError) only
    - Never retry on 4xx/5xx
    - Sanitize all exceptions to never expose API key
    """
    api_key = os.environ.get("SERPAPI_API_KEY", "").strip()
    if not api_key:
        raise FetchError("SERPAPI_API_KEY not set in environment")
    
    params: dict[str, Any] = {
        "engine": engine,
        "q": query,
        "api_key": api_key,
    }
    
    # Only add num for google engine (google_news ignores it)
    if engine == "google":
        params["num"] = num
    
    url = "https://serpapi.com/search.json"
    max_attempts = 2
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                raw = response.json()
                # Strip api_key from returned dict
                return _strip_api_key_from_dict(raw)
        except httpx.TransportError as exc:
            # Network error - retry once
            if attempt < max_attempts:
                continue
            else:
                raise FetchError(_sanitize_error(exc, api_key)) from None
        except httpx.HTTPStatusError as exc:
            # 4xx/5xx - no retry, sanitize and raise immediately
            raise FetchError(_sanitize_error(exc, api_key)) from None
        except Exception as exc:
            # Unexpected error - sanitize
            raise FetchError(f"Unexpected error: {type(exc).__name__}") from None
    
    # Should never reach here
    raise FetchError("Failed to fetch after retries")


def fetch_replay(engine: str, query: str) -> tuple[dict, str]:
    """
    Load recorded or simulated data from disk.
    
    Returns:
        (raw_data, mode) where mode is "replay" or "replay-simulated"
    """
    slug = _slugify(query)
    filename = f"{engine}_{slug}.json"
    
    # Check scenarios/ first (may be simulated)
    project_root = Path(__file__).parent.parent
    scenarios_path = project_root / "scenarios" / filename
    recorded_path = project_root / "recorded" / filename
    
    # Try scenarios first
    if scenarios_path.exists():
        data = json.loads(scenarios_path.read_text(encoding="utf-8"))
        mode = "replay-simulated" if data.get("_simulated") else "replay"
        return data, mode
    
    # Try recorded
    if recorded_path.exists():
        data = json.loads(recorded_path.read_text(encoding="utf-8"))
        return data, "replay"
    
    # Not found - list available files
    recorded_dir = project_root / "recorded"
    available = []
    if recorded_dir.exists():
        for f in recorded_dir.glob(f"{engine}_*.json"):
            available.append(f.stem)
    
    scenarios_dir = project_root / "scenarios"
    if scenarios_dir.exists():
        for f in scenarios_dir.glob(f"{engine}_*.json"):
            available.append(f"scenarios/{f.stem}")
    
    available_str = ", ".join(sorted(available)[:10]) if available else "none"
    raise FetchError(
        f"No recorded fixture for engine={engine!r} query={query!r} in replay mode. "
        f"Available (first 10): {available_str}"
    )


def extract_results(engine: str, raw: dict, num: int | None = None) -> list[ResultItem]:
    """
    Extract result items from raw SerpApi response.
    
    - google: reads organic_results
    - google_news: reads news_results
    - Truncates to num if provided (google_news ignores num in recorded files but we truncate here)
    - Skips malformed rows instead of crashing
    """
    if engine == "google":
        results_key = "organic_results"
        from_method = ResultItem.from_organic
    elif engine == "google_news":
        results_key = "news_results"
        from_method = ResultItem.from_news
    else:
        raise ValueError(f"Unknown engine: {engine!r}")
    
    raw_results = raw.get(results_key, [])
    
    items: list[ResultItem] = []
    for row in raw_results:
        try:
            item = from_method(row)
            items.append(item)
        except Exception:
            # Skip malformed rows
            continue
    
    # Truncate to num (even for google_news in replay mode)
    if num is not None and num > 0:
        items = items[:num]
    
    return items
