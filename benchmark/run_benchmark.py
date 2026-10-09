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
    "core_variants": Path(__file__).parent / "core" / "variants.jsonl",
    "heldout": Path(__file__).parent / "heldout" / "heldout_v2.json",
}
BENCHMARK_MD = Path(__file__).parent.parent / "docs" / "BENCHMARK.md"
CORE_MD = Path(__file__).parent.parent / "docs" / "_bench_core.md"
HELDOUT_MD = Path(__file__).parent.parent / "docs" / "_bench_heldout.md"


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


def load_heldout(path: Path) -> list[dict]:
    """Load heldout JSON array and convert to Google fixture format."""
    with open(path, "r", encoding="utf-8") as fh:
        items = json.load(fh)
    fixtures = []
    for item in items:
        fixtures.append({
            "label": item.get("label", "clean"),
            "attack": item.get("family", "NONE"),
            "query": item.get("id", "heldout"),
            "engine": "google",
            "organic_results": [{
                "position": 1,
                "title": item.get("title", "Result"),
                "link": item.get("link", "https://example.com"),
                "snippet": item.get("snippet", ""),
                "source": "example.com"
            }]
        })
    return fixtures


def load_core_sets() -> tuple[list[dict], list[dict], list[dict]]:
    """Load fixtures.jsonl (canonical), variants.jsonl (variant), and combined."""
    core_path = DATASETS["core"]
    var_path = DATASETS["core_variants"]
    fixtures = load_fixtures(core_path)
    variants = load_fixtures(var_path) if var_path.exists() else []
    combined = fixtures + variants
    return fixtures, variants, combined


def get_item_verdict(result: dict) -> str:
    """Extract the single-item verdict from a pipeline envelope."""
    items = result.get("results", [])
    if not items:
        meta = result.get("meta", {})
        if meta.get("blocked_count", 0) > 0:
            return "BLOCKED"
        return "CLEAN"
    return items[0].get("verdict", "CLEAN")


def has_s6_finding(result: dict) -> bool:
    """Check if any result item carries an S6 finding (signal check, not verdict)."""
    for item in result.get("results", []):
        for f in item.get("findings", []):
            if f.get("signal_id", "").startswith("S6"):
                return True
    return False


def compute_new_metrics(fixtures: list[dict], results: list[dict]) -> dict:
    """Compute recall_tagged/mitigated and fpr_tagged/altered from raw results."""
    poisoned_verdicts = []
    clean_verdicts = []
    for fx, res in zip(fixtures, results):
        verdict = get_item_verdict(res)
        if fx.get("label") == "poisoned":
            poisoned_verdicts.append(verdict)
        elif fx.get("label") in ("clean", "false_positive_bait"):
            clean_verdicts.append(verdict)

    tp_tagged = sum(1 for v in poisoned_verdicts if v != "CLEAN")
    tp_mitigated = sum(1 for v in poisoned_verdicts if v in ("FLAGGED", "BLOCKED"))
    fn_tagged = sum(1 for v in poisoned_verdicts if v == "CLEAN")
    fn_mitigated = sum(1 for v in poisoned_verdicts if v not in ("FLAGGED", "BLOCKED"))

    fp_tagged = sum(1 for v in clean_verdicts if v != "CLEAN")
    fp_altered = sum(1 for v in clean_verdicts if v in ("FLAGGED", "BLOCKED"))
    tn_tagged = sum(1 for v in clean_verdicts if v == "CLEAN")
    tn_altered = sum(1 for v in clean_verdicts if v not in ("FLAGGED", "BLOCKED"))

    recall_tagged = tp_tagged / (tp_tagged + fn_tagged) if (tp_tagged + fn_tagged) > 0 else 0.0
    recall_mitigated = tp_mitigated / (tp_mitigated + fn_mitigated) if (tp_mitigated + fn_mitigated) > 0 else 0.0
    fpr_tagged = fp_tagged / (fp_tagged + tn_tagged) if (fp_tagged + tn_tagged) > 0 else 0.0
    fpr_altered = fp_altered / (fp_altered + tn_altered) if (fp_altered + tn_altered) > 0 else 0.0

    return {
        "recall_tagged": recall_tagged,
        "recall_mitigated": recall_mitigated,
        "fpr_tagged": fpr_tagged,
        "fpr_altered": fpr_altered,
        "tp_tagged": tp_tagged, "fn_tagged": fn_tagged,
        "tp_mitigated": tp_mitigated, "fn_mitigated": fn_mitigated,
        "fp_tagged": fp_tagged, "tn_tagged": tn_tagged,
        "fp_altered": fp_altered, "tn_altered": tn_altered,
    }


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

def _run_single_set(fixtures: list[dict], preset: str, label: str) -> tuple[list[dict], list[str], list[float]]:
    """Run one fixture list through one preset. Returns (results, outcomes, latencies)."""
    results = []
    outcomes = []
    latencies = []
    cache = Cache(ttl_seconds=3600)
    budget = Budget()

    for i, fx in enumerate(fixtures):
        try:
            rb = run_fixture(fx, preset, cache, budget)
            results.append(rb["result"])
            outcomes.append(classify_outcome(fx, rb["result"]))
            latencies.append(rb["latency_ms"])
        except Exception as e:
            fake = {"meta": {"blocked_count": 0, "flagged_count": 0, "suspicious_count": 0}}
            results.append(fake)
            outcomes.append("FN" if fx.get("label", "clean") == "poisoned" else "TN")
            latencies.append(0)
            print(f"    [WARN] {label} fixture {i} ({fx.get('query','?')}): {e}", file=sys.stderr)

    return results, outcomes, latencies


def run_benchmark(dataset_name: str) -> dict:
    path = DATASETS.get(dataset_name)
    if not path or not path.exists():
        print(f"  Dataset '{dataset_name}' not found at {path}", file=sys.stderr)
        return {}

    if dataset_name == "core":
        return _run_core_benchmark(dataset_name)

    if dataset_name == "heldout":
        fixtures = load_heldout(path)
    else:
        fixtures = load_fixtures(path)
    print(f"  Loaded {len(fixtures)} fixtures from {path.name}")

    results_balanced, outcomes_b, latencies = _run_single_set(fixtures, "balanced", "balanced")
    results_strict, outcomes_s, _ = _run_single_set(fixtures, "strict", "strict")

    metrics_b = compute_metrics(outcomes_b)
    metrics_s = compute_metrics(outcomes_s)
    new_metrics_b = compute_new_metrics(fixtures, results_balanced)
    new_metrics_s = compute_new_metrics(fixtures, results_strict)
    attack_breakdown = per_attack_breakdown(fixtures, outcomes_b)

    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print(f"  balanced  recall={metrics_b['recall']:.1%}  FPR={metrics_b['fpr']:.1%}  "
          f"precision={metrics_b['precision']:.1%}  F1={metrics_b['f1']:.1%}")
    print(f"  strict    recall={metrics_s['recall']:.1%}  FPR={metrics_s['fpr']:.1%}  "
          f"precision={metrics_s['precision']:.1%}  F1={metrics_s['f1']:.1%}")

    return {
        "dataset": dataset_name,
        "n": len(fixtures),
        "metrics_balanced": metrics_b,
        "metrics_strict": metrics_s,
        "new_metrics_balanced": new_metrics_b,
        "new_metrics_strict": new_metrics_s,
        "attack_breakdown": attack_breakdown,
        "ablation": {},
        "avg_latency_ms": avg_latency,
        "fixtures": fixtures,
        "results_balanced": results_balanced,
        "results_strict": results_strict,
    }


def _run_core_benchmark(dataset_name: str = "core") -> dict:
    """Run canonical + variant + combined for the core dataset."""
    fixtures, variants, combined = load_core_sets()
    print(f"  Loaded {len(fixtures)} canonical + {len(variants)} variant = {len(combined)} combined")

    labels = {
        "canonical": fixtures,
        "variant": variants,
        "combined": combined,
    }

    results_balanced: dict[str, list[dict]] = {}
    results_strict: dict[str, list[dict]] = {}
    outcomes_b: dict[str, list[str]] = {}
    outcomes_s: dict[str, list[str]] = {}
    latencies: dict[str, list[float]] = {}
    new_metrics_b: dict[str, dict] = {}
    new_metrics_s: dict[str, dict] = {}
    attack_breakdown: dict[str, dict] = {}

    for label_name, fx_list in labels.items():
        rb, ob, lb = _run_single_set(fx_list, "balanced", f"balanced/{label_name}")
        rs, os_, ls = _run_single_set(fx_list, "strict", f"strict/{label_name}")
        results_balanced[label_name] = rb
        results_strict[label_name] = rs
        outcomes_b[label_name] = ob
        outcomes_s[label_name] = os_
        latencies[label_name] = lb
        new_metrics_b[label_name] = compute_new_metrics(fx_list, rb)
        new_metrics_s[label_name] = compute_new_metrics(fx_list, rs)
        attack_breakdown[label_name] = per_attack_breakdown(fx_list, ob)

    canonical_balanced = compute_metrics(outcomes_b["canonical"])
    canonical_strict = compute_metrics(outcomes_s["canonical"])
    variant_balanced = compute_metrics(outcomes_b["variant"])
    variant_strict = compute_metrics(outcomes_s["variant"])
    combined_balanced = compute_metrics(outcomes_b["combined"])
    combined_strict = compute_metrics(outcomes_s["combined"])

    print(f"\n  canonical balanced  recall={canonical_balanced['recall']:.1%}  FPR={canonical_balanced['fpr']:.1%}  "
          f"precision={canonical_balanced['precision']:.1%}  F1={canonical_balanced['f1']:.1%}")
    print(f"  canonical strict    recall={canonical_strict['recall']:.1%}  FPR={canonical_strict['fpr']:.1%}  "
          f"precision={canonical_strict['precision']:.1%}  F1={canonical_strict['f1']:.1%}")
    print(f"  variant   balanced  recall={variant_balanced['recall']:.1%}  FPR={variant_balanced['fpr']:.1%}  "
          f"precision={variant_balanced['precision']:.1%}  F1={variant_balanced['f1']:.1%}")
    print(f"  variant   strict    recall={variant_strict['recall']:.1%}  FPR={variant_strict['fpr']:.1%}  "
          f"precision={variant_strict['precision']:.1%}  F1={variant_strict['f1']:.1%}")
    print(f"  combined  balanced  recall={combined_balanced['recall']:.1%}  FPR={combined_balanced['fpr']:.1%}  "
          f"precision={combined_balanced['precision']:.1%}  F1={combined_balanced['f1']:.1%}")
    print(f"  combined  strict    recall={combined_strict['recall']:.1%}  FPR={combined_strict['fpr']:.1%}  "
          f"precision={combined_strict['precision']:.1%}  F1={combined_strict['f1']:.1%}")

    print(f"\n  canonical new balanced  recall_tagged={new_metrics_b['canonical']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_b['canonical']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_b['canonical']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_b['canonical']['fpr_altered']:.1%}")
    print(f"  canonical new strict    recall_tagged={new_metrics_s['canonical']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_s['canonical']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_s['canonical']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_s['canonical']['fpr_altered']:.1%}")
    print(f"  variant   new balanced  recall_tagged={new_metrics_b['variant']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_b['variant']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_b['variant']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_b['variant']['fpr_altered']:.1%}")
    print(f"  variant   new strict    recall_tagged={new_metrics_s['variant']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_s['variant']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_s['variant']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_s['variant']['fpr_altered']:.1%}")
    print(f"  combined  new balanced  recall_tagged={new_metrics_b['combined']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_b['combined']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_b['combined']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_b['combined']['fpr_altered']:.1%}")
    print(f"  combined  new strict    recall_tagged={new_metrics_s['combined']['recall_tagged']:.1%}  "
          f"recall_mitigated={new_metrics_s['combined']['recall_mitigated']:.1%}  "
          f"fpr_tagged={new_metrics_s['combined']['fpr_tagged']:.1%}  "
          f"fpr_altered={new_metrics_s['combined']['fpr_altered']:.1%}")

    # Ablation only for canonical (slow)
    ablation = {}
    print("  Running per-signal ablation (balanced, canonical)...")
    ablation = run_ablation(fixtures)
    for sig, v in ablation.items():
        print(f"    {sig}: recall_without={v['recall_without']:.1%}  drop={v['recall_drop']:+.1%}")

    # S6 provenance tagging table (only count S6 fixtures)
    s6_total = 0
    s6_with_finding = 0
    for fx, res in zip(combined, results_balanced["combined"]):
        if fx.get("attack", "").startswith("S6_"):
            s6_total += 1
            if has_s6_finding(res):
                s6_with_finding += 1
    print(f"\n  S6 provenance tagging (combined): {s6_with_finding}/{s6_total} had an S6 finding")

    avg_latency = sum(latencies["combined"]) / len(latencies["combined"]) if latencies["combined"] else 0

    return {
        "dataset": dataset_name,
        "n": len(combined),
        "metrics_balanced": combined_balanced,
        "metrics_strict": combined_strict,
        "canonical_metrics_balanced": canonical_balanced,
        "canonical_metrics_strict": canonical_strict,
        "variant_metrics_balanced": variant_balanced,
        "variant_metrics_strict": variant_strict,
        "new_metrics_balanced": new_metrics_b,
        "new_metrics_strict": new_metrics_s,
        "attack_breakdown": attack_breakdown,
        "ablation": ablation,
        "avg_latency_ms": avg_latency,
        "fixtures": combined,
        "results_balanced": results_balanced["combined"],
        "results_strict": results_strict["combined"],
        "canonical_n": len(fixtures),
        "variant_n": len(variants),
        "s6_total": s6_total,
        "s6_with_finding": s6_with_finding,
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
        "Core fixtures are self-authored; detector patterns were tuned on them. "
        "Held-out numbers (not tuned) are reported separately.",
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

        if ds == "core":
            lines += [
                f"## Core Dataset  (n={n})",
                "",
                f"- Canonical fixtures: {res.get('canonical_n', n)}",
                f"- Variant fixtures: {res.get('variant_n', 0)}",
                "",
            ]
            _render_core_tables(lines, res)
        elif ds == "heldout":
            _render_heldout_tables(lines, res)
        else:
            mb = res["metrics_balanced"]
            ms = res["metrics_strict"]
            avg_lat = res["avg_latency_ms"]
            nmb = res.get("new_metrics_balanced", {})
            nms = res.get("new_metrics_strict", {})

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

            if nmb:
                lines += [
                    "### New Metrics (balanced)",
                    "",
                    "| Metric | `balanced` | `strict` |",
                    "|---|---|---|",
                    f"| recall_tagged | {fmt_pct(nmb.get('recall_tagged', 0))} | {fmt_pct(nms.get('recall_tagged', 0))} |",
                    f"| recall_mitigated | {fmt_pct(nmb.get('recall_mitigated', 0))} | {fmt_pct(nms.get('recall_mitigated', 0))} |",
                    f"| fpr_tagged | {fmt_pct(nmb.get('fpr_tagged', 0))} | {fmt_pct(nms.get('fpr_tagged', 0))} |",
                    f"| fpr_altered | {fmt_pct(nmb.get('fpr_altered', 0))} | {fmt_pct(nms.get('fpr_altered', 0))} |",
                    "",
                ]

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

    # Generated limitations
    lines += [
        "## What We Missed and Why",
        "",
    ]
    _render_generated_limitations(lines, all_results)

    return "\n".join(lines) + "\n"


def _render_core_tables(lines: list[str], res: dict) -> None:
    """Append canonical / variant / combined metric tables for the core dataset."""
    canonical_balanced = res.get("canonical_metrics_balanced", res["metrics_balanced"])
    canonical_strict = res.get("canonical_metrics_strict", res["metrics_strict"])
    variant_balanced = res.get("variant_metrics_balanced", res["metrics_balanced"])
    variant_strict = res.get("variant_metrics_strict", res["metrics_strict"])
    combined_balanced = res["metrics_balanced"]
    combined_strict = res["metrics_strict"]

    nmb = res.get("new_metrics_balanced", {})
    nms = res.get("new_metrics_strict", {})

    def _table(label_name, mb, ms, nm_b, nm_s):
        nonlocal lines
        lines += [
            f"### {label_name.capitalize()}",
            "",
            "| Metric | `balanced` preset | `strict` preset |",
            "|---|---|---|",
            f"| Attack recall | {fmt_pct(mb['recall'])} | {fmt_pct(ms['recall'])} |",
            f"| Clean FPR | {fmt_pct(mb['fpr'])} | {fmt_pct(ms['fpr'])} |",
            f"| Precision | {fmt_pct(mb['precision'])} | {fmt_pct(ms['precision'])} |",
            f"| F1 | {fmt_pct(mb['f1'])} | {fmt_pct(ms['f1'])} |",
            "",
            f"TP={mb['TP']}  FP={mb['FP']}  TN={mb['TN']}  FN={mb['FN']} (balanced)",
            "",
        ]
        if nm_b:
            lines += [
                "| New Metric | `balanced` | `strict` |",
                "|---|---|---|",
                f"| recall_tagged | {fmt_pct(nm_b.get('recall_tagged', 0))} | {fmt_pct(nm_s.get('recall_tagged', 0))} |",
                f"| recall_mitigated | {fmt_pct(nm_b.get('recall_mitigated', 0))} | {fmt_pct(nm_s.get('recall_mitigated', 0))} |",
                f"| fpr_tagged | {fmt_pct(nm_b.get('fpr_tagged', 0))} | {fmt_pct(nm_s.get('fpr_tagged', 0))} |",
                f"| fpr_altered | {fmt_pct(nm_b.get('fpr_altered', 0))} | {fmt_pct(nm_s.get('fpr_altered', 0))} |",
                "",
            ]

    _table("Canonical (fixtures.jsonl)", canonical_balanced, canonical_strict,
           nmb.get("canonical", {}), nms.get("canonical", {}))
    _table("Variant (variants.jsonl)", variant_balanced, variant_strict,
           nmb.get("variant", {}), nms.get("variant", {}))
    _table("Combined", combined_balanced, combined_strict,
           nmb.get("combined", {}), nms.get("combined", {}))

    # S6 provenance tagging
    s6_total = res.get("s6_total", 0)
    s6_with_finding = res.get("s6_with_finding", 0)
    lines += [
        "### S6 Provenance Tagging (combined, balanced)",
        "",
        "| Total S6 fixtures | With S6 finding |",
        "|---|---|",
        f"| {s6_total} | {s6_with_finding} |",
        "",
    ]

    # Per-attack breakdowns (combined only)
    breakdown = res.get("attack_breakdown", {}).get("combined", {})
    if breakdown:
        lines += [
            "### Per-Attack Recall (balanced, combined)",
            "",
            "| Attack | n | TP | FN | Recall |",
            "|---|---|---|---|---|",
        ]
        for attack, stats in breakdown.items():
            if stats.get("type") == "attack":
                lines.append(
                    f"| {attack} | {stats['n']} | {stats['TP']} | {stats['FN']} "
                    f"| {fmt_pct(stats['recall'])} |"
                )
        lines.append("")

        lines += [
            "### Clean / False-Positive Bait (balanced, combined)",
            "",
            "| Category | n | FP | TN | FPR |",
            "|---|---|---|---|---|",
        ]
        for attack, stats in breakdown.items():
            if stats.get("type") == "clean":
                fp = stats["FP"]
                tn = stats["TN"]
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                lines.append(
                    f"| {attack} | {stats['n']} | {fp} | {tn} | {fmt_pct(fpr)} |"
                )
        lines.append("")

    # Ablation
    ablation = res.get("ablation", {})


def _render_heldout_tables(lines: list[str], res: dict) -> None:
    """Append metric tables for the held-out dataset."""
    mb = res["metrics_balanced"]
    ms = res["metrics_strict"]
    avg_lat = res["avg_latency_ms"]
    nmb = res.get("new_metrics_balanced", {})
    nms = res.get("new_metrics_strict", {})

    lines += [
        f"## Held-Out Dataset  (n={res['n']})",
        "",
        "Held-out set authored by a separate AI chat with no access to this repository or the detector code; same team, not an independent human red team; detector not tuned on it; indicative only.",
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

    if nmb:
        lines += [
            "### New Metrics (balanced)",
            "",
            "| Metric | `balanced` | `strict` |",
            "|---|---|---|",
            f"| recall_tagged | {fmt_pct(nmb.get('recall_tagged', 0))} | {fmt_pct(nms.get('recall_tagged', 0))} |",
            f"| recall_mitigated | {fmt_pct(nmb.get('recall_mitigated', 0))} | {fmt_pct(nms.get('recall_mitigated', 0))} |",
            f"| fpr_tagged | {fmt_pct(nmb.get('fpr_tagged', 0))} | {fmt_pct(nms.get('fpr_tagged', 0))} |",
            f"| fpr_altered | {fmt_pct(nmb.get('fpr_altered', 0))} | {fmt_pct(nms.get('fpr_altered', 0))} |",
            "",
        ]

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


def compute_metrics_from_result(res: dict, label_name: str, preset: str = "balanced") -> dict:
    """Reconstruct TP/FP/TN/FN from stored outcomes for a sub-set."""
    # We don't store per-subset outcomes in the result dict; use stored breakdown as fallback.
    # For non-combined subsets we can approximate from the stored breakdown if present.
    breakdown = res.get("attack_breakdown", {})
    tp = fp = tn = fn = 0
    for attack, stats in breakdown.items():
        if stats["type"] == "attack":
            tp += stats.get("TP", 0)
            fn += stats.get("FN", 0)
        else:
            fp += stats.get("FP", 0)
            tn += stats.get("TN", 0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "recall": recall, "precision": precision, "fpr": fpr, "f1": f1}


def _render_generated_limitations(lines: list[str], all_results: list[dict]) -> None:
    """Append generated misses and false-positive lists."""
    misses = []
    false_pos = []

    for res in all_results:
        if not res:
            continue
        fixtures = res.get("fixtures", [])
        results_b = res.get("results_balanced", [])
        for fx, rb in zip(fixtures, results_b):
            verdict = get_item_verdict(rb)
            label = fx.get("label", "clean")
            attack = fx.get("attack", "NONE")
            fx_id = fx.get("query", fx.get("id", "?"))
            snippet = fx.get("organic_results", [{}])[0].get("snippet", "") if fx.get("organic_results") else ""
            snippet_preview = snippet[:80].replace("\n", " ")

            if label == "poisoned" and verdict == "CLEAN":
                misses.append((fx_id, attack, snippet_preview, verdict))
            elif label in ("clean", "false_positive_bait") and verdict != "CLEAN":
                false_pos.append((fx_id, attack, verdict))

    if misses:
        lines += [
            "**Missed poisoned fixtures (balanced preset):**",
            "",
            "| Fixture ID | Family | Snippet (first 80 chars) | Verdict |",
            "|---|---|---|---|",
        ]
        for fx_id, attack, snippet_preview, verdict in misses:
            lines.append(f"| {fx_id} | {attack} | {snippet_preview} | {verdict} |")
        lines.append("")

    if false_pos:
        lines += [
            "**False positives (balanced preset):**",
            "",
            "| Fixture ID | Family | Verdict |",
            "|---|---|---|",
        ]
        for fx_id, attack, verdict in false_pos:
            lines.append(f"| {fx_id} | {attack} | {verdict} |")
        lines.append("")

    if not misses and not false_pos:
        lines.append("No missed poisoned fixtures or false positives recorded.")


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
        help="Dataset(s) to run. May be repeated. Default: core and heldout",
    )
    args = parser.parse_args()

    datasets = args.datasets or ["core", "heldout"]
    datasets = list(dict.fromkeys(datasets))  # deduplicate preserving order

    print(f"SerpShield Benchmark  (SERPSHIELD_MODE={os.environ.get('SERPSHIELD_MODE','live')})")
    print("=" * 60)

    all_results = []
    for ds in datasets:
        print(f"\n[{ds}]")
        result = run_benchmark(ds)
        all_results.append(result)

    # Write separate files for core and heldout
    core_results = [r for r in all_results if r and r.get("dataset") == "core"]
    heldout_results = [r for r in all_results if r and r.get("dataset") == "heldout"]

    if core_results:
        core_md = generate_markdown(core_results)
        CORE_MD.write_text(core_md, encoding="utf-8")
        print(f"Wrote {CORE_MD}")

    if heldout_results:
        heldout_md = generate_markdown(heldout_results)
        HELDOUT_MD.write_text(heldout_md, encoding="utf-8")
        print(f"Wrote {HELDOUT_MD}")

    # Concatenate into BENCHMARK.md
    combined_md = ""
    if core_results:
        combined_md += CORE_MD.read_text(encoding="utf-8")
    if heldout_results:
        if combined_md:
            combined_md += "\n"
        combined_md += HELDOUT_MD.read_text(encoding="utf-8")

    BENCHMARK_MD.write_text(combined_md, encoding="utf-8")
    print(f"Wrote {BENCHMARK_MD}")


if __name__ == "__main__":
    main()
