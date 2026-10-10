"""Scan every REAL recorded SerpApi result in recorded/ and report verdicts. 0 credits, no network."""
import json, sys, collections
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import os
os.environ["SERPSHIELD_MODE"] = "replay"
from serpshield import pipeline
from serpshield.fetch import extract_results as real_extract
from serpshield.budget import Budget, Cache

total = collections.Counter()
for f in sorted((ROOT / "recorded").glob("*.json")):
    raw = json.loads(f.read_text(encoding="utf-8"))
    engine = "google_news" if f.name.startswith("google_news_") else "google"
    with patch.object(pipeline, "fetch", return_value=(raw, "replay")), \
         patch.object(pipeline, "extract_results", lambda e, r, n=None: real_extract(e, r, None)), \
         patch.object(pipeline, "log_search", lambda entry: None):
        out = pipeline.run_pipeline("scan " + f.stem, engine, 10, cache=Cache(), budget=Budget(persist=False))
    m = out["meta"]
    n = len(out["results"]) + m["blocked_count"]
    c = collections.Counter(r["verdict"] for r in out["results"])
    c["BLOCKED"] += m["blocked_count"]
    total.update(c)
    print(f"{f.stem[:44]:<44} results={n:<4} " + " ".join(f"{k}={v}" for k, v in sorted(c.items())))
n = sum(total.values())
print("-" * 70)
print(f"TOTAL real results scanned: {n}   " + "   ".join(f"{k}={v}" for k, v in sorted(total.items())))
