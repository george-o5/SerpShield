"""SerpApi client (live) + replay loader (recorded/ and scenarios/).

- Live: GET https://serpapi.com/search.json, timeout 15s, 1 retry on network error, no retry on 4xx.
- Replay: SERPSHIELD_MODE=replay. meta.mode = "live" | "replay" | "replay-simulated".
- API key from env SERPAPI_API_KEY only. Never log it.
"""


def fetch_live(engine: str, query: str, num: int) -> dict:
    raise NotImplementedError


def fetch_replay(engine: str, query: str) -> dict:
    raise NotImplementedError


def extract_results(engine: str, raw: dict) -> list:
    """google -> organic_results; google_news -> news_results. [VERIFY] against recorded JSON."""
    raise NotImplementedError
