"""Complete SerpShield pipeline: validate -> cache -> budget -> fetch -> scan -> verdict -> trust -> audit."""

import copy
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from serpshield.audit import log_search, hash_evidence
from serpshield.budget import Budget, Cache
from serpshield.config import get_config
from serpshield.fetch import FetchError, extract_results, fetch
from serpshield.models import ResultItem, Verdict
from serpshield.normalize import normalize_text
from serpshield.signals import ALL_SIGNALS
from serpshield.slim import wrap_envelope
from serpshield.trust import assess_trust
from serpshield.verdict import apply_verdict


def _validate_input(query: str, engine: str, num_results: int, config) -> str | None:
    """Validate input parameters. Returns error string or None if valid."""
    # Engine validation
    if engine not in config.engines:
        return f"Invalid engine: {engine!r}. Allowed: {config.engines}"
    
    # Query validation
    query = query.strip()
    if not query:
        return "Query cannot be empty"
    if len(query) < 1 or len(query) > 300:
        return f"Query length must be 1-300 characters, got: {len(query)}"
    
    # Check for control characters
    if any(ord(ch) < 32 and ch not in '\t\n\r' for ch in query):
        return "Query contains invalid control characters"
    
    # num_results validation
    if not isinstance(num_results, int) or num_results < 1 or num_results > 10:
        return f"num_results must be integer 1-10, got: {num_results}"
    
    return None


def _normalize_cache_key(query: str) -> str:
    """Normalize query for cache key (lowercase)."""
    return query.strip().lower()


def run_pipeline(
    query: str,
    engine: str = "google",
    num_results: int = 10,
    preset: str = "balanced",
    *,
    cache: Cache | None = None,
    budget: Budget | None = None,
) -> dict:
    """
    Run the complete SerpShield pipeline.
    
    Steps:
    1. Validate input (engine, query length/chars, num_results)
    2. Cache lookup (keyed by engine, normalized lowercase query, num)
    3. Budget check (only in live mode, before fetch)
    4. Fetch (live or replay)
    5. Extract results
    6. For each result: normalize -> run S1-S6 -> apply verdict -> assess trust
    7. Drop BLOCKED items
    8. Record budget (live mode only)
    9. Wrap envelope with metadata
    10. Audit log (evidence hashes only)
    11. Store in cache
    12. Return final dict
    
    Returns:
        dict with {"query", "engine", "results", "meta", "notice"} on success,
        or {"error", "meta"} on failure. Never raises to caller.
    """
    try:
        start_time = time.time()
        
        # Validate preset
        try:
            config = get_config(preset)
        except KeyError as e:
            return {
                "error": f"Unknown preset: {preset!r}. Use 'balanced' or 'strict'.",
                "meta": {
                    "mode": "error",
                    "blocked_count": 0,
                    "flagged_count": 0,
                    "suspicious_count": 0,
                    "cache_hit": False,
                    "credits_used": 0,
                    "credits_remaining_today": 0,
                    "latency_ms": 0,
                    "raw_bytes": 0,
                    "slim_bytes": 0,
                }
            }
        
        # Initialize cache and budget if not provided
        if cache is None:
            cache = Cache(ttl_seconds=config.budget.cache_ttl_seconds)
        if budget is None:
            budget = Budget(config=config)
        
        # 1. Validate input
        validation_error = _validate_input(query, engine, num_results, config)
        if validation_error:
            return {
                "error": validation_error,
                "meta": {
                    "mode": "error",
                    "blocked_count": 0,
                    "flagged_count": 0,
                    "suspicious_count": 0,
                    "cache_hit": False,
                    "credits_used": 0,
                    "credits_remaining_today": budget.daily_cap - budget.daily_used,
                    "latency_ms": int((time.time() - start_time) * 1000),
                    "raw_bytes": 0,
                    "slim_bytes": 0,
                }
            }
        
        # 2. Cache lookup
        cache_key = (engine, _normalize_cache_key(query), num_results)
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            # Return a deep copy to prevent mutation
            result_copy = copy.deepcopy(cached_result)
            # Update cache hit flag and return
            result_copy["meta"]["cache_hit"] = True
            result_copy["meta"]["credits_used"] = 0
            result_copy["meta"]["credits_remaining_today"] = budget.daily_cap - budget.daily_used
            result_copy["meta"]["latency_ms"] = int((time.time() - start_time) * 1000)
            
            # Audit the cache hit
            audit_entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "query": query,
                "engine": engine,
                "mode": result_copy["meta"]["mode"],
                "cache_hit": True,
                "results": [],
                "credits_used": 0,
            }
            try:
                log_search(audit_entry)
            except Exception:
                pass
            
            return result_copy
        
        # 3. Budget check (only for live mode)
        mode_env = os.environ.get("SERPSHIELD_MODE", "live").strip().lower()
        if mode_env == "live":
            if not budget.check():
                return {
                    "error": "API call budget exceeded",
                    "meta": {
                        "mode": "live",
                        "blocked_count": 0,
                        "flagged_count": 0,
                        "suspicious_count": 0,
                        "cache_hit": False,
                        "credits_used": 0,
                        "credits_remaining_today": budget.daily_cap - budget.daily_used,
                        "latency_ms": int((time.time() - start_time) * 1000),
                        "raw_bytes": 0,
                        "slim_bytes": 0,
                    }
                }
        
        # 4. Fetch
        try:
            raw, mode = fetch(engine, query, num_results)
        except FetchError as e:
            return {
                "error": str(e),
                "meta": {
                    "mode": mode_env,
                    "blocked_count": 0,
                    "flagged_count": 0,
                    "suspicious_count": 0,
                    "cache_hit": False,
                    "credits_used": 0,
                    "credits_remaining_today": budget.daily_cap - budget.daily_used,
                    "latency_ms": int((time.time() - start_time) * 1000),
                    "raw_bytes": 0,
                    "slim_bytes": 0,
                }
            }
        
        # 5. Extract results
        try:
            items = extract_results(engine, raw, num_results)
        except Exception as e:
            return {
                "error": f"Failed to extract results: {e}",
                "meta": {
                    "mode": mode,
                    "blocked_count": 0,
                    "flagged_count": 0,
                    "suspicious_count": 0,
                    "cache_hit": False,
                    "credits_used": 0,
                    "credits_remaining_today": budget.daily_cap - budget.daily_used,
                    "latency_ms": int((time.time() - start_time) * 1000),
                    "raw_bytes": 0,
                    "slim_bytes": 0,
                }
            }
        
        # 6. Process each result: normalize -> signals -> verdict -> trust
        processed_items = []
        for item in items:
            try:
                # Normalize title and snippet
                if item.title:
                    title_bundle = normalize_text(item.title)
                    item.title = title_bundle.clean_view
                    # Run S1-S5 on title
                    for signal_func in [ALL_SIGNALS["S1"], ALL_SIGNALS["S2"], ALL_SIGNALS["S3"], 
                                        ALL_SIGNALS["S4"], ALL_SIGNALS["S5"]]:
                        item.findings.extend(signal_func("title", title_bundle))
                
                if item.snippet:
                    snippet_bundle = normalize_text(item.snippet)
                    item.snippet = snippet_bundle.clean_view
                    # Run S1-S5 on snippet
                    for signal_func in [ALL_SIGNALS["S1"], ALL_SIGNALS["S2"], ALL_SIGNALS["S3"], 
                                        ALL_SIGNALS["S4"], ALL_SIGNALS["S5"]]:
                        item.findings.extend(signal_func("snippet", snippet_bundle))
                
                # Run S1 and S5 on URL-decoded link + S6 on raw link
                if item.link:
                    # URL-decode the link and scan with S1 and S5
                    decoded_link = urllib.parse.unquote(item.link)
                    link_bundle = normalize_text(decoded_link)
                    item.findings.extend(ALL_SIGNALS["S1"]("link", link_bundle))
                    item.findings.extend(ALL_SIGNALS["S5"]("link", link_bundle))
                    # Also run S6 on the link
                    item.findings.extend(ALL_SIGNALS["S6"]("link", link_bundle))
                
                # Apply verdict
                item = apply_verdict(item, config)
                
                # Assess trust
                try:
                    parsed = urllib.parse.urlparse(item.link)
                    domain = parsed.netloc.lower()
                    if domain.startswith("www."):
                        domain = domain[4:]
                except Exception:
                    domain = ""
                
                trust_result = assess_trust(domain, item.findings, config)
                item.trust = trust_result["trust"]
                
                processed_items.append(item)
            except Exception:
                # On error processing an individual item, skip it silently
                pass
        
        # 7. Drop BLOCKED items
        blocked_count = sum(1 for item in processed_items if item.verdict == Verdict.BLOCKED)
        flagged_count = sum(1 for item in processed_items if item.verdict == Verdict.FLAGGED)
        suspicious_count = sum(1 for item in processed_items if item.verdict == Verdict.SUSPICIOUS)
        
        filtered_items = [item for item in processed_items if item.verdict != Verdict.BLOCKED]
        
        # 8. Record budget (only for live mode)
        credits_used = 0
        if mode == "live":
            budget.record_live_call()
            credits_used = 1
        
        # 9. Wrap envelope
        import json
        raw_bytes = len(json.dumps(raw).encode("utf-8"))
        
        meta = {
            "mode": mode,
            "blocked_count": blocked_count,
            "flagged_count": flagged_count,
            "suspicious_count": suspicious_count,
            "cache_hit": False,
            "credits_used": credits_used,
            "credits_remaining_today": budget.daily_cap - budget.daily_used,
            "latency_ms": int((time.time() - start_time) * 1000),
            "raw_bytes": raw_bytes,
            "slim_bytes": 0,  # Will be updated after wrapping
        }
        
        result = wrap_envelope(query, engine, filtered_items, meta)
        
        # Update slim_bytes
        result["meta"]["slim_bytes"] = len(json.dumps(result).encode("utf-8"))
        
        # 10. Audit log
        audit_entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "query": query,
            "engine": engine,
            "mode": mode,
            "cache_hit": False,
            "results": [
                {
                    "position": item.position,
                    "verdict": item.verdict.value,
                    "signals": [f.signal_id for f in item.findings],
                    "evidence_hashes": [f.evidence_hash for f in item.findings],
                }
                for item in processed_items
            ],
            "credits_used": credits_used,
        }
        try:
            log_search(audit_entry)
        except Exception:
            pass  # Never fail on audit error
        
        # 11. Store in cache (deep copy before storing)
        cache.set(cache_key, copy.deepcopy(result))
        
        # 12. Return
        return result
        
    except Exception:
        # Catch any unexpected error and return error dict
        return {
            "error": "internal error",
            "meta": {
                "mode": "error",
                "blocked_count": 0,
                "flagged_count": 0,
                "suspicious_count": 0,
                "cache_hit": False,
                "credits_used": 0,
                "credits_remaining_today": 0,
                "latency_ms": 0,
                "raw_bytes": 0,
                "slim_bytes": 0,
            }
        }
