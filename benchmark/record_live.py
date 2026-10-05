"""Captures real SerpApi responses to recorded/ (strips api_key). Run sparingly: costs credits.

Usage:
    python benchmark/record_live.py --engine google --queries "prompt injection examples" "OWASP LLM01"
    python benchmark/record_live.py --engine google_news --queries "LLM security"

Rules:
- Reads SERPAPI_API_KEY from env only (never accepts it as CLI arg).
- Strips api_key from search_parameters and any URLs before saving.
- Refuses to overwrite existing files.
- Prints a running call count so you know how many credits you've used.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import httpx
from dotenv import load_dotenv

load_dotenv()

RECORDED_DIR = Path(__file__).parent.parent / "recorded"
SERPAPI_URL = "https://serpapi.com/search.json"
_call_count = 0


def _slugify(text: str) -> str:
    """Convert query string to a safe filename slug."""
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = text.strip("_")
    return text[:60]  # keep filenames reasonable


def _strip_api_key_from_params(params: dict) -> dict:
    """Remove api_key from any dict of parameters."""
    return {k: v for k, v in params.items() if k.lower() != "api_key"}


def _strip_api_key_from_url(url: str) -> str:
    """Remove api_key query parameter from a URL string."""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs.pop("api_key", None)
        qs.pop("API_KEY", None)
        # Rebuild query string preserving original order as much as possible
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        cleaned = urlunparse(parsed._replace(query=new_query))
        return cleaned
    except Exception:
        return url


def _scrub_response(data: dict) -> dict:
    """
    Recursively strip api_key from the response JSON:
    - Removes api_key from 'search_parameters' and any nested dicts.
    - Cleans api_key from URL strings anywhere in the response.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k.lower() == "api_key":
                continue  # drop entirely
            cleaned[k] = _scrub_response(v)
        return cleaned
    elif isinstance(data, list):
        return [_scrub_response(item) for item in data]
    elif isinstance(data, str):
        # Strip api_key from embedded URL strings
        if "api_key=" in data.lower():
            return _strip_api_key_from_url(data)
        return data
    else:
        return data


def fetch_and_record(engine: str, query: str, num: int = 10) -> Path:
    """
    Call SerpApi for the given engine+query, scrub the key, and save to recorded/.
    Returns the path written.
    Raises FileExistsError if the output file already exists.
    """
    global _call_count

    api_key = os.environ.get("SERPAPI_API_KEY", "").strip()
    if not api_key:
        print("ERROR: SERPAPI_API_KEY not set in environment.", file=sys.stderr)
        sys.exit(1)

    slug = _slugify(query)
    output_path = RECORDED_DIR / f"{engine}_{slug}.json"

    if output_path.exists():
        raise FileExistsError(
            f"File already exists, refusing to overwrite: {output_path}\n"
            "Delete it manually if you want to re-record."
        )

    params = {
        "engine": engine,
        "q": query,
        "num": num,
        "api_key": api_key,  # sent in request, never saved
    }

    _call_count += 1
    print(f"[call #{_call_count}] {engine!r} | {query!r} -> {output_path.name}")

    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(SERPAPI_URL, params=params)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        print(f"  HTTP error {exc.response.status_code}: {exc.response.text[:200]}", file=sys.stderr)
        raise
    except httpx.RequestError as exc:
        print(f"  Network error: {exc}", file=sys.stderr)
        raise

    raw_data = response.json()

    # Scrub api_key from every field before persisting
    clean_data = _scrub_response(raw_data)

    # Double-check: api_key must NOT appear in the serialized JSON
    serialized = json.dumps(clean_data, ensure_ascii=False, indent=2)
    if api_key in serialized:
        print("CRITICAL: api_key still found in serialized output. Aborting save.", file=sys.stderr)
        sys.exit(1)

    RECORDED_DIR.mkdir(parents=True, exist_ok=True)
    output_path.write_text(serialized, encoding="utf-8")
    print(f"  [OK] Saved {len(serialized):,} bytes  (running total: {_call_count} call(s))")

    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Record live SerpApi responses to recorded/ (strips api_key, no overwrites)."
    )
    parser.add_argument(
        "--engine",
        default="google",
        choices=["google", "google_news", "bing"],
        help="SerpApi engine to use (default: google)",
    )
    parser.add_argument(
        "--queries",
        nargs="+",
        required=True,
        metavar="QUERY",
        help="One or more search queries to record.",
    )
    parser.add_argument(
        "--num",
        type=int,
        default=10,
        help="Number of results to request (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds to sleep between calls (default: 1.0 — be polite).",
    )
    args = parser.parse_args()

    print(f"Engine: {args.engine}  |  Queries: {len(args.queries)}  |  Delay: {args.delay}s")
    print(f"Output dir: {RECORDED_DIR.resolve()}")
    print("-" * 60)

    errors = []
    for i, query in enumerate(args.queries):
        try:
            fetch_and_record(engine=args.engine, query=query, num=args.num)
        except FileExistsError as exc:
            print(f"  SKIP: {exc}")
        except Exception as exc:
            print(f"  ERROR for {query!r}: {exc}", file=sys.stderr)
            errors.append(query)

        if i < len(args.queries) - 1:
            time.sleep(args.delay)

    print("-" * 60)
    print(f"Done. Total live calls made this run: {_call_count}")
    if errors:
        print(f"Failed queries ({len(errors)}): {errors}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
