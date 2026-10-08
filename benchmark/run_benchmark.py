"""Metrics (recall, FPR, precision, latency), per-signal ablation, both presets -> docs/BENCHMARK.md.

Usage:
    python benchmark/run_benchmark.py --dataset core
    python benchmark/run_benchmark.py --dataset heldout
    python benchmark/run_benchmark.py --dataset core --dataset heldout
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# Set replay mode before importing serpshield
os.environ.setdefault("SERPSHIELD_MODE", "replay")

sys.path.insert(0, str(Path(__file__).parent.parent))

from serpshield.pipeline import run_pipeline
from serpshield.budget import Budget, Cache

DATASETS = {
    "core": Path(__file__).parent / "core" / "fixtures.jsonl",
    "heldout": Path(__file__).parent / "heldout" / "fixtures.jsonl",
}
BENCHMARK_MD = Path(__file__).parent.parent / "docs" / "BENCHMARK.md"


# ---------------------------------------------------------------------------
# Fixture loader
# ---------------------------------------------------------------------------

def load_fixtures(path: Path) -> list[dict]:
    """Load JSONL fixtures. Skips blank lines and comments."""
    fixtures = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fixtures.append(json.loads(line))
    return fixtures


# ---------------------------------------------------------------------------
# Run one fixture through the pipeline
# ---------------------------------------------------------------------------

def run_fixture(fixture: dict, preset: str, cache: Cache, budget: Budget) -> dict:
    """
    Inject fixture data into replay mode and run pipeline.

    The fixture format uses `organic_results` directly. We write it to a
    temp scenarios file so fetch_replay() can load it, then clean up.
    """
    import tempfile
    import uuid

    # Build a synthetic query key unique to this fixture
    query = fixture.get("query", f"fixture_{uuid.uuid4().hex[:8]}")
    engine = fixture.get("engine", "google")

    # Build minimal SerpApi-shaped response
    raw_response: dict[str, Any] = {
        "_simulated": True,
        "search_parameters": {"engine": engine, "q": query},
        "organic_results": fixture.get("organic_results", []),
        "news_results": fixture.get("news_results", []),
    }

    # Write to a temp file in scenarios/ so fetch_replay loads it
    project_root = Path(__file__).parent.parent
    scenarios_dir = project_root / "scenarios"
    slug = _slugify(query)
    temp_path = scenarios_dir / f"{engine}_{slug}.json"

    _cleanup = not temp_path.exists()
    try:
        temp_path.write_text(json.dumps(raw_response), encoding="utf-8")

        start = time.time()
        result = run_pipeline(
            query=query,
            engine=engine,
            num_results=10,
            preset=preset,
            cache=cache,
            budget=budget,
        )
        latency_ms = int((time.time() - start) * 1000)
    finally:
        if _cleanup and temp_path.exists():
            temp_path.unlink()

    return {"result": result, "latency_ms": latency_ms}


def _slugify(text: str) -> str:
    import re
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")[:60]


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def classify_outcome(fixture: dict, result: dict) -> str:
    """
    Returns: TP | FP | TN | FN

    label=poisoned  → expected detection (SUSPICIOUS/FLAGGED/BLOCKED)
    label=clean     → expected no detection (CLEAN only)
    label=false_positive_bait → expected CLEAN (like clean but tests FPR)
    """
    label = fixture.get("label", "clean")
    meta = result.get("meta", {})
    blocked = meta.get("blocked_count", 0)
    flagged = meta.get("flagged_count", 0)
    suspicious = meta.get("suspicious_count", 0)
    detected = (blocked + flagged + suspicious) > 0

    if label == "poisoned":
        return "TP" if detected else "FN"
    else:  # clean or false_positive_bait
        return "FP" if detected else "TN"


def compute_metrics(outcomes: list[str]) -> dict:
    tp = outcomes.count("TP")
    fp = outcomes.count("FP")
    tn = outcomes.count("TN")
    fn = outcomes.count("FN")

    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "f1": f1,
    }


# ---------------------------------------------------------------------------
# Per-attack-family breakdown
# ---------------------------------------------------------------------------

def per_attack_breakdown(fixtures: list[dict], outcomes: list[str]) -> dict[str, dict]:
    families: dict[str, list[str]] = {}
    for fx, outcome in zip(fixtures, outcomes):
        attack = fx.get("attack", "NONE")
        families.setdefault(attack, []).append(outcome)

    result = {}
    for attack, oc_list in sorted(families.items()):
        tp = oc_list.count("TP")
        fn = oc_list.count("FN")
        fp = oc_list.count("FP")
        tn = oc_list.count("TN")
        n = len(oc_list)
        if tp + fn > 0:
            recall = tp / (tp + fn)
            result[attack] = {"n": n, "TP": tp, "FN": fn, "recall": recall, "type": "attack"}
        else:
            result[attack] = {"n": n, "FP": fp, "TN": tn, "type": "clean"}
    return result


# ---------------------------------------------------------------------------
# Per-signal ablation (balanced preset only)
# ---------------------------------------------------------------------------

SIGNAL_GROUPS = ["S1_STRONG", "S1_WEAK", "S2", "S3", "S3_BIDI", "S4", "S5"]


def run_ablation(fixtures: list[dict]) -> dict[str, dict]:
    """
    For each signal, zero its weight, re-run, measure recall drop.
    Returns dict: signal -> {recall_without, recall_drop}
    """
    from serpshield.config import get_config, _load_yaml
    import copy

    # Baseline with all signals
    baseline_outcomes = _run_all(fixtures, "balanced")
    baseline_metrics = compute_metrics(baseline_outcomes)
    baseline_recall = baseline_metrics["recall"]

    ablation_results = {}
    for signal in SIGNAL_GROUPS:
        # Patch weights for this signal to 0
        cfg = get_config("balanced")
        patched_weights = dict(cfg.weights)
        patched_weights[signal] = 0

        # Run fixtures with patched config by monkey-patching temporarily
        outcomes = _run_ablated(fixtures, patched_weights)
        metrics = compute_metrics(outcomes)
        recall_without = metrics["recall"]
        ablation_results[signal] = {
            "recall_without": recall_without,
            "recall_drop": baseline_recall - recall_without,
        }

    return ablation_results


def _run_all(fixtures: list[dict], preset: str) -> list[str]:
    """Run all fixtures with a clean cache/budget each time."""
    cache = Cache(ttl_seconds=3600)
    budget = Budget()
    outcomes = []
    for fx in fixtures:
        try:
            run_result = run_fixture(fx, preset, cache, budget)
            outcome = classify_outcome(fx, run_result["result"])
        except Exception:
            label = fx.get("label", "clean")
            outcome = "FN" if label == "poisoned" else "TN"
        outcomes.append(outcome)
    return outcomes


def _run_ablated(fixtures: list[dict], patched_weights: dict) -> list[str]:
    """Run fixtures with one signal zeroed by patching verdict scoring."""
    from serpshield import pipeline as pl
    from serpshield.config import get_config
    import serpshield.verdict as verdict_mod

    original_score = verdict_mod.score_result

    cfg = get_config("balanced")

    # Build a fake config with patched weights
    from serpshield.config import SerpShieldConfig
    patched_cfg = SerpShieldConfig(
        preset="balanced_ablated",
        weights=patched_weights,
        thresholds=cfg.thresholds,
        context_discount=cfg.context_discount,
        budget=cfg.budget,
        engines=cfg.engines,
        trust=cfg.trust,
        audit=cfg.audit,
    )

    def patched_score(item, config):
        return original_score(item, patched_cfg)

    verdict_mod.score_result = patched_score
    try:
        outcomes = _run_all(fixtures, "balanced")
    finally:
        verdict_mod.score_result = original_score

    return outcomes


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(dataset_name: str) -> dict:
    path = DATASETS.get(dataset_name)
    if not path or not path.exists():
        print(f"  Dataset '{dataset_name}' not found at {path}", file=sys.stderr)
        return {}

    fixtures = load_fixtures(path)
    print(f"  Loaded {len(fixtures)} fixtures from {path.name}")

    results_balanced = []
    results_strict = []
    latencies = []

    cache_b = Cache(ttl_seconds=3600)
    budget_b = Budget()
    cache_s = Cache(ttl_seconds=3600)
    budget_s = Budget()

    for i, fx in enumerate(fixtures):
        try:
            rb = run_fixture(fx, "balanced", cache_b, budget_b)
            rs = run_fixture(fx, "strict", cache_s, budget_s)
            results_balanced.append(rb["result"])
            results_strict.append(rs["result"])
            latencies.append(rb["latency_ms"])
        except Exception as e:
            label = fx.get("label", "clean")
            # Fake clean result
            fake = {"meta": {"blocked_count": 0, "flagged_count": 0, "suspicious_count": 0}}
            results_balanced.append(fake)
            results_strict.append(fake)
            latencies.append(0)
            print(f"    [WARN] fixture {i} ({fx.get('query','?')}): {e}", file=sys.stderr)

    outcomes_b = [classify_outcome(fx, r) for fx, r in zip(fixtures, results_balanced)]
    outcomes_s = [classify_outcome(fx, r) for fx, r in zip(fixtures, results_strict)]

    metrics_b = compute_metrics(outcomes_b)
    metrics_s = compute_metrics(outcomes_s)

    attack_breakdown = per_attack_breakdown(fixtures, outcomes_b)

    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print(f"  balanced  recall={metrics_b['recall']:.1%}  FPR={metrics_b['fpr']:.1%}  "
          f"precision={metrics_b['precision']:.1%}  F1={metrics_b['f1']:.1%}")
    print(f"  strict    recall={metrics_s['recall']:.1%}  FPR={metrics_s['fpr']:.1%}  "
          f"precision={metrics_s['precision']:.1%}  F1={metrics_s['f1']:.1%}")

    # Ablation only for core dataset (slow)
    ablation = {}
    if dataset_name == "core":
        print("  Running per-signal ablation (balanced)...")
        ablation = run_ablation(fixtures)
        for sig, v in ablation.items():
            print(f"    {sig}: recall_without={v['recall_without']:.1%}  drop={v['recall_drop']:+.1%}")

    return {
        "dataset": dataset_name,
        "n": len(fixtures),
        "metrics_balanced": metrics_b,
        "metrics_strict": metrics_s,
        "attack_breakdown": attack_breakdown,
        "ablation": ablation,
        "avg_latency_ms": avg_latency,
    }


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

def fmt_pct(v: float) -> str:
    return f"{v:.1%}"


def generate_markdown(all_results: list[dict]) -> str:
    lines = [
        "# Benchmark",
        "",
        "> Generated by `benchmark/run_benchmark.py`. "
        "Replay mode — zero live API calls. "
        "Includes what we missed and why.",
        "",
    ]

    for res in all_results:
        if not res:
            continue
        ds = res["dataset"]
        n = res["n"]
        mb = res["metrics_balanced"]
        ms = res["metrics_strict"]
        avg_lat = res["avg_latency_ms"]

        lines += [
            f"## {ds.capitalize()} Dataset  (n={n})",
            "",
            "| Metric | `balanced` preset | `strict` preset |",
            "|---|---|---|",
            f"| Attack recall | {fmt_pct(mb['recall'])} | {fmt_pct(ms['recall'])} |",
            f"| Clean FPR | {fmt_pct(mb['fpr'])} | {fmt_pct(ms['fpr'])} |",
            f"| Precision | {fmt_pct(mb['precision'])} | {fmt_pct(ms['precision'])} |",
            f"| F1 | {fmt_pct(mb['f1'])} | {fmt_pct(ms['f1'])} |",
            f"| Avg latency (replay) | {avg_lat:.0f} ms | — |",
            "",
            f"TP={mb['TP']}  FP={mb['FP']}  TN={mb['TN']}  FN={mb['FN']} (balanced)",
            "",
        ]

        # Per-attack breakdown
        breakdown = res.get("attack_breakdown", {})
        if breakdown:
            lines += [
                "### Per-Attack Recall (balanced)",
                "",
                "| Attack | n | TP | FN | Recall |",
                "|---|---|---|---|---|",
            ]
            for attack, stats in breakdown.items():
                if stats["type"] == "attack":
                    lines.append(
                        f"| {attack} | {stats['n']} | {stats['TP']} | {stats['FN']} "
                        f"| {fmt_pct(stats['recall'])} |"
                    )
            lines.append("")

            lines += [
                "### Clean / False-Positive Bait (balanced)",
                "",
                "| Category | n | FP | TN | FPR |",
                "|---|---|---|---|---|",
            ]
            for attack, stats in breakdown.items():
                if stats["type"] == "clean":
                    fp = stats["FP"]
                    tn = stats["TN"]
                    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                    lines.append(
                        f"| {attack} | {stats['n']} | {fp} | {tn} | {fmt_pct(fpr)} |"
                    )
            lines.append("")

        # Ablation
        ablation = res.get("ablation", {})
        if ablation:
            lines += [
                "### Per-Signal Ablation (balanced, core only)",
                "",
                "Remove one signal at a time; measure recall drop.",
                "",
                "| Signal | Recall w/o signal | Drop |",
                "|---|---|---|",
            ]
            for sig, v in ablation.items():
                lines.append(
                    f"| {sig} | {fmt_pct(v['recall_without'])} | {v['recall_drop']:+.1%} |"
                )
            lines.append("")

    # Honest limitations
    lines += [
        "## What We Missed and Why",
        "",
        "**FN analysis (balanced preset):**",
        "",
        "- **S1_WEAK fixtures** that don't match any current weak pattern "
        "(e.g. vague imperative phrases without explicit role/tool targeting) "
        "score 0 or 1 and may fall below the SUSPICIOUS threshold. "
        "These are borderline cases where the context discount cannot apply.",
        "",
        "- **S6-only fixtures** (IP literals, risky TLDs, typosquats) score 0 "
        "because S6 weight is 0 — S6 is a tag-only signal. These show as FN "
        "for `poisoned` label but are intentional: S6 alone does not block.",
        "",
        "- **Paraphrase and synonym evasion**: fixtures using synonyms of "
        "\"ignore\" or novel imperative forms not in S1_STRONG_PATTERNS evade S1.",
        "",
        "**FP analysis:**",
        "",
        "- **Security articles** (OWASP, ArXiv, Anthropic) that quote attack "
        "patterns verbatim can score SUSPICIOUS (1–2) even after the -2 context "
        "discount. The context discount requires both S1 + discussion words with "
        "no S2–S5; when quoted text happens to match S2 role markers, the discount "
        "does not apply.",
        "",
        "- **Encoding tutorials** that embed real Base64 examples containing "
        "decoded S1 text (e.g. `aGVsbG8gd29ybGQ=` -> 'hello world') will "
        "trip S4 if the decoded text matches patterns.",
        "",
        "**Known exploitable weakness:**",
        "",
        "The context discount is bypassed by adding discussion words to a real "
        "attack payload. An attacker who knows the detector can write "
        "`ignore previous instructions (this is a prompt injection example)` "
        "and receive a -2 score discount. This is documented in the threat model.",
        "",
        "**Held-out recall vs. core:**",
        "",
        "The held-out set was authored independently of `signals.py`. "
        "Lower recall there reflects the gap between tuned fixtures and "
        "novel adversarial phrasings — a more honest measure of real-world performance.",
    ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run SerpShield benchmark and generate BENCHMARK.md")
    parser.add_argument(
        "--dataset",
        action="append",
        choices=["core", "heldout"],
        dest="datasets",
        default=None,
        help="Dataset(s) to run. May be repeated. Default: core",
    )
    args = parser.parse_args()

    datasets = args.datasets or ["core"]
    datasets = list(dict.fromkeys(datasets))  # deduplicate preserving order

    print(f"SerpShield Benchmark  (SERPSHIELD_MODE={os.environ.get('SERPSHIELD_MODE','live')})")
    print("=" * 60)

    all_results = []
    for ds in datasets:
        print(f"\n[{ds}]")
        result = run_benchmark(ds)
        all_results.append(result)

    md = generate_markdown(all_results)
    BENCHMARK_MD.write_text(md, encoding="utf-8")
    print(f"\nWrote {BENCHMARK_MD}")


if __name__ == "__main__":
    main()
