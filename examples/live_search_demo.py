"""Live demo: one real SerpApi search through the SerpShield pipeline (costs 1 credit)."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass
from serpshield.pipeline import run_pipeline
from serpshield.budget import Budget, Cache

query = " ".join(sys.argv[1:]) or "what is indirect prompt injection"
out = run_pipeline(query, "google", 5, cache=Cache(), budget=Budget(persist=False))
print(f'Query: "{query}"   mode={out["meta"]["mode"]}   credits_used={out["meta"]["credits_used"]}')
print(out["notice"])
for r in out["results"]:
    print(f'  [{r["position"]}] {r["verdict"]:<10} trust={r["trust"]:<7} {r["domain"]}')
    print(f'      {r["title"][:80]}')
print(json.dumps({k: out["meta"][k] for k in ("blocked_count","flagged_count","suspicious_count","raw_bytes","slim_bytes") if k in out["meta"]}))
