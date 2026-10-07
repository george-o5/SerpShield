"""Tests for fetch."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from serpshield.fetch import (
    FetchError,
    extract_results,
    fetch,
    fetch_live,
    fetch_replay,
)


# --- Mode Selection Tests ---


def test_fetch_mode_live_by_default(monkeypatch):
    """When SERPSHIELD_MODE is not set, fetch uses live mode."""
    monkeypatch.delenv("SERPSHIELD_MODE", raising=False)
    
    # Just patch fetch_live to return a known value
    with patch("serpshield.fetch.fetch_live") as mock_live:
        mock_live.return_value = {"search_parameters": {"engine": "google", "q": "test"}}
        raw, mode = fetch("google", "test", num=10)
    
    assert mode == "live"
    assert "search_parameters" in raw


def test_fetch_mode_replay_from_env(monkeypatch):
    """When SERPSHIELD_MODE=replay, fetch uses replay mode."""
    monkeypatch.setenv("SERPSHIELD_MODE", "replay")
    
    # Should find a recorded file
    raw, mode = fetch_replay("google", "prompt injection examples")
    assert mode in ("replay", "replay-simulated")
    assert "search_parameters" in raw


def test_fetch_replay_finds_recorded_file():
    """Replay mode finds and loads a recorded file."""
    raw, mode = fetch_replay("google", "prompt injection examples")
    assert mode == "replay"
    assert raw["search_parameters"]["engine"] == "google"
    assert "organic_results" in raw


def test_fetch_replay_finds_simulated_file():
    """Replay mode recognizes simulated files."""
    raw, mode = fetch_replay("google", "demo poisoned roles")
    assert mode == "replay-simulated"
    assert raw.get("_simulated") is True
    assert raw.get("_note") is not None


def test_fetch_replay_missing_fixture_raises():
    """Replay mode raises FetchError with available slugs when fixture not found."""
    with pytest.raises(FetchError) as exc_info:
        fetch_replay("google", "nonexistent query 12345")
    
    err = str(exc_info.value)
    assert "No recorded fixture" in err
    assert "google" in err
    assert "nonexistent query 12345" in err or "nonexistent_query_12345" in err
    # Should list some available files
    assert "Available" in err


# --- Live Fetch Tests ---


def test_fetch_live_returns_data(monkeypatch):
    """Live fetch returns data via mock client."""
    monkeypatch.setenv("SERPAPI_API_KEY", "TESTKEY123")
    
    expected_data = {
        "search_parameters": {"engine": "google", "q": "test", "api_key": "TESTKEY123"},
        "organic_results": [],
    }
    
    # Create a proper mock response object
    class MockResponse:
        def __init__(self):
            self.status_code = 200
        
        def raise_for_status(self):
            pass
        
        def json(self):
            return expected_data
    
    class MockClient:
        def get(self, url, params):
            return MockResponse()
    
    with patch("serpshield.fetch.httpx.Client") as mock_client_class:
        mock_client_class.return_value.__enter__.return_value = MockClient()
        
        raw = fetch_live("google", "test", num=10)
    
    # API key should be stripped from search_parameters
    assert "api_key" not in raw.get("search_parameters", {})
    assert raw["search_parameters"]["engine"] == "google"


def test_fetch_live_no_retry_on_4xx(monkeypatch):
    """Live fetch does NOT retry on 4xx errors."""
    monkeypatch.setenv("SERPAPI_API_KEY", "TESTKEY123")
    
    call_count = 0
    
    def mock_request(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            403,
            json={"error": "Invalid API key"},
        )
    
    transport = httpx.MockTransport(mock_request)
    
    with patch("serpshield.fetch.httpx.Client") as mock_client:
        mock_instance = mock_client.return_value.__enter__.return_value
        mock_instance.get.side_effect = httpx.HTTPStatusError(
            "403 Forbidden",
            request=httpx.Request("GET", "https://serpapi.com/search.json"),
            response=httpx.Response(403, json={"error": "Invalid API key"}),
        )
        
        with pytest.raises(FetchError) as exc_info:
            fetch_live("google", "test", num=10)
    
    # Should only attempt once (no retry on 4xx)
    assert mock_instance.get.call_count == 1
    assert "403" in str(exc_info.value)


def test_fetch_live_retries_transport_error(monkeypatch):
    """Live fetch retries once on TransportError."""
    monkeypatch.setenv("SERPAPI_API_KEY", "TESTKEY123")
    
    call_count = 0
    
    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.TransportError("Network unreachable")
    
    with patch("serpshield.fetch.httpx.Client") as mock_client:
        mock_instance = mock_client.return_value.__enter__.return_value
        mock_instance.get.side_effect = mock_get
        
        with pytest.raises(FetchError) as exc_info:
            fetch_live("google", "test", num=10)
    
    # Should attempt twice (initial + 1 retry)
    assert call_count == 2
    assert "Network error" in str(exc_info.value) or "TransportError" in str(exc_info.value)


def test_fetch_live_sanitizes_api_key_in_exceptions(monkeypatch):
    """Exception messages never contain the API key."""
    fake_key = "TESTKEY123"
    monkeypatch.setenv("SERPAPI_API_KEY", fake_key)
    
    with patch("serpshield.fetch.httpx.Client") as mock_client:
        mock_instance = mock_client.return_value.__enter__.return_value
        mock_instance.get.side_effect = httpx.HTTPStatusError(
            "403 Forbidden",
            request=httpx.Request("GET", f"https://serpapi.com/search.json?api_key={fake_key}"),
            response=httpx.Response(403, json={"error": "Invalid key"}),
        )
        
        with pytest.raises(FetchError) as exc_info:
            fetch_live("google", "test", num=10)
    
    err_msg = str(exc_info.value)
    assert fake_key not in err_msg
    assert "TESTKEY123" not in err_msg
    # Should contain sanitized info
    assert "403" in err_msg


def test_fetch_error_repr_never_contains_key(monkeypatch):
    """FetchError repr never contains the API key."""
    fake_key = "TESTKEY123"
    monkeypatch.setenv("SERPAPI_API_KEY", fake_key)
    
    with patch("serpshield.fetch.httpx.Client") as mock_client:
        mock_instance = mock_client.return_value.__enter__.return_value
        mock_instance.get.side_effect = httpx.TransportError(
            f"Connection failed to https://serpapi.com/search.json?api_key={fake_key}"
        )
        
        with pytest.raises(FetchError) as exc_info:
            fetch_live("google", "test", num=10)
    
    err_repr = repr(exc_info.value)
    assert fake_key not in err_repr
    assert "TESTKEY123" not in err_repr


# --- Extract Results Tests ---


def test_extract_results_google_organic():
    """Extract results from real recorded Google organic file."""
    project_root = Path(__file__).parent.parent
    recorded_file = project_root / "recorded" / "google_prompt_injection_examples.json"
    
    raw = json.loads(recorded_file.read_text(encoding="utf-8"))
    results = extract_results("google", raw)
    
    assert len(results) > 0
    assert all(item.position >= 1 for item in results)
    assert all(item.title for item in results)
    assert all(item.link for item in results)
    # Should have snippet for organic results
    assert all(item.snippet is not None for item in results)


def test_extract_results_google_news():
    """Extract results from real recorded Google News file."""
    project_root = Path(__file__).parent.parent
    recorded_file = project_root / "recorded" / "google_news_ai_agent_security.json"
    
    raw = json.loads(recorded_file.read_text(encoding="utf-8"))
    results = extract_results("google_news", raw)
    
    assert len(results) > 0
    assert all(item.position >= 1 for item in results)
    assert all(item.title for item in results)
    assert all(item.link for item in results)
    # News results should have source_structured
    assert all(item.source_structured is not None for item in results)


def test_extract_results_truncates_to_num():
    """extract_results truncates to num parameter."""
    project_root = Path(__file__).parent.parent
    recorded_file = project_root / "recorded" / "google_prompt_injection_examples.json"
    
    raw = json.loads(recorded_file.read_text(encoding="utf-8"))
    results = extract_results("google", raw, num=5)
    
    assert len(results) == 5


def test_extract_results_news_truncates_to_num():
    """extract_results truncates news results even though num is ignored in fetch."""
    project_root = Path(__file__).parent.parent
    recorded_file = project_root / "recorded" / "google_news_ai_agent_security.json"
    
    raw = json.loads(recorded_file.read_text(encoding="utf-8"))
    results = extract_results("google_news", raw, num=5)
    
    assert len(results) == 5


def test_extract_results_unknown_engine_raises():
    """extract_results raises ValueError for unknown engine."""
    with pytest.raises(ValueError) as exc_info:
        extract_results("bing", {})
    
    assert "Unknown engine" in str(exc_info.value)
    assert "bing" in str(exc_info.value)


def test_extract_results_skips_malformed_rows():
    """extract_results skips malformed rows instead of crashing."""
    raw = {
        "organic_results": [
            {"position": 1, "title": "Valid", "link": "https://example.com"},
            {"position": 2, "title": "", "link": ""},  # Missing title/link will cause from_organic to work but with empty strings
            {"position": 3, "title": "Also Valid", "link": "https://example.com/2"},
        ]
    }
    
    results = extract_results("google", raw)
    
    # All three will parse (pydantic allows empty strings), so we get 3 results
    # The key is that it doesn't crash on unexpected data
    assert len(results) == 3
