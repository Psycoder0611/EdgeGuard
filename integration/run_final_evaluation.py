"""
Block 5 evidence (build plan S9): the ONE-TIME, held-out v1-vs-v2 comparison
on final_test.

part3/evidence_gate.py's own docstring: "Run this only after model training,
threshold selection, and Red Team development are complete... this module
cannot independently prove [the final-test IDs'] provenance or enforce that
a human has not already examined the final test." CLAUDE.md's "Decisions the
team must confirm" section lists five open questions the team should ideally
settle first. This script does not and cannot enforce any of that -- it only
enforces the narrower, mechanical half of "once": every call to RoadData
with final_evaluation=True in this whole codebase lives HERE and nowhere
else, and it refuses to silently overwrite a report that already exists.

Usage:
    python -m integration.run_final_evaluation \\
        --baseline-version v1 --updated-version v2 --data-dir ~/Downloads/road

Prints and saves a paired report for both versions: recall (overall and by
attack family), false-alarm rate, precision, f1 and mean inference latency,
via part3.evidence_gate.compare_final_models. It does NOT compute detection
delay or edge/end-to-end latency percentiles across a replayed sequence --
CLAUDE.md's "report the plan's metrics" item is still open beyond what
evidence_gate.py itself reports.
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict

from defender.defender import Defender
from part1.pipeline import RoadData, preprocess
from part1.split_manifest import MANIFEST_PATH, load_manifest
from part3.evaluator import evaluate_batch
from part3.evidence_gate import EvidenceReport, compare_final_models
from part3.metrics import MetricsReport, compute_metrics
from shared.schemas import DefenderOutput, GroundTruthLabel


class FinalEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data_dir: str
    final_test_captures: List[str]
    windows: int
    baseline_version: str
    updated_version: str
    baseline: Dict[str, Optional[float]]
    updated: Dict[str, Optional[float]]
    baseline_recall_by_family: Dict[str, Optional[float]]
    updated_recall_by_family: Dict[str, Optional[float]]


def _metrics_dict(report: MetricsReport) -> Dict[str, Optional[float]]:
    return {
        "windows": report.windows, "tp": report.tp, "fp": report.fp,
        "tn": report.tn, "fn": report.fn, "recall": report.recall,
        "false_alarm_rate": report.false_alarm_rate, "precision": report.precision,
        "f1": report.f1, "mean_inference_ms": report.mean_inference_ms,
    }


def _recall_by_family(outputs: List[DefenderOutput],
                      labels: List[GroundTruthLabel]) -> Dict[str, Optional[float]]:
    results = evaluate_batch(outputs, labels)
    families = sorted({r.family for r in results if r.family is not None})
    return {family: compute_metrics([r for r in results if r.family == family]).recall
           for family in families}


def _training_window_ids(data_dir, manifest) -> List[str]:
    """Window IDs from train/validation/development, to prove to
    compare_final_models() that none of them overlap final_test. Cheap: no
    Defender, no labels -- just window_id strings, via an ordinary (NOT
    final_evaluation=True) RoadData."""
    road = RoadData(data_dir, manifest=manifest)
    ids: List[str] = []
    for group in ("train", "validation", "development"):
        for name in manifest.names(group):
            ids.extend(window.window_id for window in road.windows(name))
    return ids


def run_final_evaluation(baseline: Defender, updated: Defender, data_dir,
                         manifest_path) -> FinalEvaluationReport:
    manifest = load_manifest(manifest_path)
    names = manifest.names("final_test")
    if not names:
        raise ValueError("manifest has no final_test captures")

    # The only place in the codebase allowed to pass final_evaluation=True.
    road = RoadData(data_dir, manifest=manifest, final_evaluation=True)

    window_ids: List[str] = []
    baseline_outputs: List[DefenderOutput] = []
    updated_outputs: List[DefenderOutput] = []
    labels: List[GroundTruthLabel] = []
    for name in names:
        for window, label in road.labelled_windows(name):
            processed = preprocess(window)
            baseline_outputs.append(baseline.score_window(processed))
            updated_outputs.append(updated.score_window(processed))
            labels.append(label)
            window_ids.append(window.window_id)

    if not window_ids:
        raise ValueError("final_test captures produced no windows")

    training_ids = _training_window_ids(data_dir, manifest)

    report: EvidenceReport = compare_final_models(
        baseline_outputs, updated_outputs, labels,
        final_test_window_ids=window_ids, training_window_ids=training_ids,
    )

    return FinalEvaluationReport(
        data_dir=str(data_dir),
        final_test_captures=names,
        windows=len(window_ids),
        baseline_version=report.baseline_version,
        updated_version=report.updated_version,
        baseline=_metrics_dict(report.baseline),
        updated=_metrics_dict(report.updated),
        baseline_recall_by_family=_recall_by_family(baseline_outputs, labels),
        updated_recall_by_family=_recall_by_family(updated_outputs, labels),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Block 5: the ONE-TIME final v1-vs-v2 comparison on final_test."
    )
    parser.add_argument("--baseline-version", default="v1")
    parser.add_argument("--updated-version", default="v2")
    parser.add_argument("--data-dir", default="data/road",
                        help="ROAD folder with ambient/ attacks/ (default data/road)")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--output", default="results/final_evaluation.json")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing final evaluation report")
    args = parser.parse_args(argv)

    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        parser.error(
            f"{output_path} already exists -- this is the ONE-TIME final comparison "
            "(build plan S6/S9). If you really mean to redo it, pass --force and say "
            "why in your commit message."
        )
    if args.baseline_version == args.updated_version:
        parser.error("--baseline-version and --updated-version must differ")

    baseline = Defender.load(args.model_dir, args.baseline_version)
    updated = Defender.load(args.model_dir, args.updated_version)
    report = run_final_evaluation(baseline, updated, args.data_dir, args.manifest)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")

    print("=== Block 5: FINAL evaluation (final_test, read once) ===")
    print(f"Captures ({len(report.final_test_captures)}): "
         f"{', '.join(report.final_test_captures)}")
    print(f"Windows: {report.windows}")
    print(f"\n{report.baseline_version} (baseline): {report.baseline}")
    print(f"  recall by family: {report.baseline_recall_by_family}")
    print(f"\n{report.updated_version} (updated):  {report.updated}")
    print(f"  recall by family: {report.updated_recall_by_family}")
    print(f"\nSaved to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
