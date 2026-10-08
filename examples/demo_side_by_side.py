"""Primary demo: raw vs protected context the agent receives.

Uses simulated poisoned scenarios (scenarios/google_demo_poisoned_*.json).
Canary string FAKE_SECRET_123 is present in one result — shows it is blocked.
Zero live API calls. Zero credits.

Usage:
    python examples/demo_side_by_side.py
    python examples/demo_side_by_side.py --scenario roles
    python examples/demo_side_by_side.py --scenario encoded
    python examples/demo_side_by_side.py --scenario exfil
    python examples/demo_side_by_side.py --all
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

os.environ["SERPSHIELD_MODE"] = "replay"

sys.path.insert(0, str(Path(__file__).parent.parent))

from serpshield.pipeline import run_pipeline
from serpshield.budget import Budget, Cache
from serpshield.fetch import extract_results

ROOT = Path(__file__).parent.parent
SCENARIOS_DIR = ROOT / "scenarios"

SCENARIO_MAP = {
    "roles":   ("google", "demo poisoned roles"),
    "encoded": ("google", "demo poisoned encoded"),
    "exfil":   ("google", "demo poisoned exfil"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hr(char: str = "─", width: int = 70) -> str:
    return char * width


def _load_raw(engine: str, query: str) -> list[dict]:
    """Load the raw organic_results from the scenario file without running pipeline."""
    import re
    slug = re.sub(r"[^a-z0-9]+", "_", query.lower().strip()).strip("_")[:60]
    path = SCENARIOS_DIR / f"{engine}_{slug}.json"
    if not path.exists():
        raise FileNotFoundError(f"Scenario not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("organic_results", [])


def _format_raw_result(r: dict, idx: int) -> list[str]:
    lines = [
        f"  [{idx}] {r.get('title', '(no title)')}",
        f"      {r.get('link', '')}",
    ]
    snippet = r.get("snippet", "")
    if snippet:
        # Wrap long snippets
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        lines.append(f"      {snippet}")
    return lines


def _format_protected_result(r: dict, idx: int) -> list[str]:
    verdict = r.get("verdict", r.get("trust", "?"))
    trust = r.get("trust", "?")
    findings = r.get("findings", [])
    signal_ids = ", ".join(sorted({f["signal_id"] for f in findings})) if findings else "—"

    lines = [
        f"  [{idx}] {r.get('title', '(no title)')}  [{verdict}]",
        f"      {r.get('link', '')}  trust={trust}",
    ]
    snippet = r.get("snippet", "")
    if snippet:
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        lines.append(f"      {snippet}")
    if findings:
        lines.append(f"      signals: {signal_ids}")
    return lines


# ---------------------------------------------------------------------------
# Run one scenario
# ---------------------------------------------------------------------------

def demo_scenario(name: str) -> None:
    engine, query = SCENARIO_MAP[name]

    print()
    print(_hr("═"))
    print(f"  SCENARIO: {name.upper()}")
    print(f"  Query   : \"{query}\"")
    print(_hr("═"))

    # Load raw results for the "naive agent" side
    try:
        raw_results = _load_raw(engine, query)
    except FileNotFoundError as e:
        print(f"  ERROR: {e}")
        return

    # Run through SerpShield
    cache = Cache(ttl_seconds=3600)
    budget = Budget()
    protected = run_pipeline(query=query, engine=engine, preset="balanced",
                             cache=cache, budget=budget)

    if "error" in protected:
        print(f"  Pipeline error: {protected['error']}")
        return

    meta = protected.get("meta", {})
    protected_results = protected.get("results", [])

    # ── RAW (what a naive agent would receive) ──────────────────────────
    print()
    print("  ┌── NAIVE AGENT RECEIVES (raw SerpApi output) " + "─" * 23 + "┐")
    for i, r in enumerate(raw_results, 1):
        for line in _format_raw_result(r, i):
            print(line)
        print()
    print("  └" + "─" * 68 + "┘")

    # ── PROTECTED (what SerpShield delivers) ────────────────────────────
    blocked = meta.get("blocked_count", 0)
    flagged = meta.get("flagged_count", 0)
    suspicious = meta.get("suspicious_count", 0)

    print()
    print("  ┌── SERPSHIELD DELIVERS " + "─" * 46 + "┐")
    if not protected_results:
        print("  (all results blocked)")
    else:
        for i, r in enumerate(protected_results, 1):
            for line in _format_protected_result(r, i):
                print(line)
            print()
    print("  └" + "─" * 68 + "┘")

    # ── Summary diff ────────────────────────────────────────────────────
    print()
    print(f"  Summary:")
    print(f"    Raw results  : {len(raw_results)}")
    print(f"    Delivered    : {len(protected_results)}")
    print(f"    Blocked      : {blocked}  (removed entirely)")
    print(f"    Flagged      : {flagged}  (snippet redacted)")
    print(f"    Suspicious   : {suspicious}  (tagged, passed through)")
    print(f"    Mode         : {meta.get('mode', '?')}")
    print(f"    Latency      : {meta.get('latency_ms', 0)} ms")

    # ── Canary check ────────────────────────────────────────────────────
    canary = "FAKE_SECRET_123"
    raw_text = json.dumps(raw_results)
    protected_text = json.dumps(protected_results)

    if canary in raw_text:
        if canary not in protected_text:
            print(f"\n  ✓ Canary [{canary}] present in raw — BLOCKED by SerpShield")
        else:
            print(f"\n  ✗ Canary [{canary}] leaked into protected output (check signals)")
    else:
        print(f"\n  (Canary not present in this scenario)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SerpShield side-by-side demo: naive vs protected agent context"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_MAP),
        default=None,
        help="Run a specific scenario (default: roles)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scenarios",
    )
    args = parser.parse_args()

    print(_hr("═"))
    print("  SerpShield — Side-by-Side Demo")
    print("  Simulated poisoned results  |  SERPSHIELD_MODE=replay  |  0 credits")
    print(_hr("═"))

    if args.all:
        for name in SCENARIO_MAP:
            demo_scenario(name)
    else:
        name = args.scenario or "roles"
        demo_scenario(name)

    print()
    print(_hr("─"))
    print("  Note: All scenarios use simulated data marked _simulated=true.")
    print("  FAKE_SECRET_123 is a harmless canary — no real secrets involved.")
    print(_hr("─"))


if __name__ == "__main__":
    main()
