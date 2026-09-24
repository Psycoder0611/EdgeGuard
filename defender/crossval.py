"""
Cross-validation for the EdgeGuard Defender (Part 2).

Two protocols, both grouped by CAPTURE, never by window (windows overlap,
so a window-level split would put near-copies on both sides).

1. ambient -- leave-one-capture-out (LOCO) false-alarm estimate.
   Pool = train + validation ambient captures. For each held-out capture H:
     a. inner LOCO over the rest: fit on (rest minus J), score J. This gives
        OUT-OF-FOLD scores for every capture in the rest, and the threshold
        is chosen on those (choose_threshold, same false-alarm target).
        Never on in-sample scores: held-out drives score higher than the
        drives a model was fitted on.
     b. fit on all of the rest, score H, count false alarms at that threshold.
   It answers: "trained and calibrated our way, how often does the Defender
   false-alarm on a drive it has never seen?" v1 (Stage 1) and v2 (Stage 1 +
   Stage 2, fused) are both measured from the same fits.

2. attacks -- 2-fold index-out CV (the cv_folds of splits.json). Fold k holds
   out every _k attack recording. The Stage 2 watch-list comes from the
   target IDs of the OTHER fold's attacks only. Stage 1 and Stage 2 are
   fitted on train ambient and the threshold on validation ambient, exactly
   as run_training does. Detection is measured on the held-out fold.
   Needs a split file with cv_folds: the provisional split has none (its _2
   and _3 attack captures are final_test).
   A masquerade capture is byte-identical to its fabrication twin outside the
   injection interval, so it contributes only its attacked windows; normal
   windows are counted once, from the fabrication capture.

What this is NOT: a replacement for the frozen-model final-test number. It
estimates the PROCEDURE (each fold has its own models and threshold).
Report both, labelled, and never use these numbers to tune the final model.

TEST captures (final_test / test) are never read: every capture path goes
through capture_path(), which refuses them.

Usage (from the EdgeGuard folder, .venv active):
    python -m defender.crossval ambient --max-false-alarm-rate 0.01 \\
        --data-dir ~/Downloads/road/dataset
    python -m defender.crossval attacks --max-false-alarm-rate 0.01 \\
        --data-dir ~/Downloads/road/dataset --split ~/Downloads/road/splits.json
"""

import argparse
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional

from defender.dev_check import overlaps
from defender.fusion import fuse
from defender.road_reader import first_timestamp, iter_frames, make_windows
from defender.run_training import (DEVELOPMENT_WATCH_IDS, PROVISIONAL_SPLIT,
                                   keep_every_for, neutral_ids)
from defender.stage1 import Stage1Model
from defender.stage2 import Stage2Model, normalize_can_id
from defender.threshold import choose_threshold

VERSIONS = ("v1", "v2")   # v1 = Stage 1 score, v2 = Stage 1 + Stage 2 fused


# ---------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class Split:
    source: str                              # "provisional" or the splits.json path
    ambient: Dict[str, List[str]]            # train, validation, development, final_test
    attack_folds: Optional[Dict[int, List[str]]]   # fold -> attack captures it holds out
    forbidden: FrozenSet[str]                # TEST captures: never read


def provisional_split() -> Split:
    return Split("provisional", {k: list(v) for k, v in PROVISIONAL_SPLIT.items()},
                 None, frozenset(PROVISIONAL_SPLIT["final_test"]))


def load_split(path) -> Split:
    """Read splits.json (schema_version 2): train / val / test and cv_folds."""
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    if record.get("schema_version") != 2:
        raise ValueError(f"{path}: expected schema_version 2, got {record.get('schema_version')}")
    test = record["test"]
    forbidden = frozenset(test.get("ambient", []) + test.get("attacks", []))
    ambient = {"train": list(record["train"]["ambient"]),
               "validation": list(record["val"]["ambient"]),
               "development": [],
               "final_test": list(test.get("ambient", []))}
    folds = None
    cv = record.get("cv_folds")
    if cv:
        folds = {1: list(cv["fold_1_holds_out"]), 2: list(cv["fold_2_holds_out"])}
        leaked = sorted(forbidden & set(folds[1] + folds[2]))
        if leaked:
            raise ValueError(f"{path}: cv_folds contain TEST captures {leaked}")
        if set(folds[1]) & set(folds[2]):
            raise ValueError(f"{path}: a capture is held out by both folds")
    return Split(str(path), ambient, folds, forbidden)


def capture_path(data_dir, split: Split, name: str, folder: str = "ambient") -> Path:
    """Path of one capture. Refuses TEST captures, so they can never be read."""
    if name in split.forbidden:
        raise ValueError(f"{name} is a TEST capture: cross-validation never reads test data")
    return Path(data_dir) / folder / f"{name}.log"


# ---------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------
def binomial_upper_95(k: int, n: int) -> float:
    """Exact one-sided 95 % upper bound (Clopper-Pearson) on a rate k / n.
    Windows of one capture are correlated, so treat it as optimistic."""
    if n <= 0 or k >= n:
        return 1.0

    def cdf(p):   # P(X <= k), X ~ Binomial(n, p), in log space
        log_p, log_q = math.log(p), math.log1p(-p)
        return sum(math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                            + i * log_p + (n - i) * log_q) for i in range(k + 1))

    lo, hi = k / n, 1.0 - 1e-12
    for _ in range(100):
        mid = (lo + hi) / 2
        if cdf(mid) > 0.05:
            lo = mid
        else:
            hi = mid
    return hi


def _summary(alarms: int, windows: int, target: float) -> dict:
    return {"alarms": alarms, "windows": windows,
            "false_alarm_rate": round(alarms / windows, 6) if windows else None,
            "false_alarm_rate_95_upper": round(binomial_upper_95(alarms, windows), 6),
            "target": target}


# ---------------------------------------------------------------------
# Data loading (each capture read once, reused by every fold)
# ---------------------------------------------------------------------
def load_ambient(names, data_dir, split, ids, window_s, stride_s, max_windows, stats_watch,
                 log=print):
    """Sampled windows and Stage 2 full-capture range stats per capture."""
    probe = Stage2Model(watch_ids=stats_watch)
    windows, stats = {}, {}
    for name in names:
        path = capture_path(data_dir, split, name)
        step = keep_every_for(path, window_s, stride_s, max_windows)
        windows[name] = list(make_windows(path, ids[name], window_s, stride_s, keep_every=step))
        stats[name] = probe.capture_range_stats(iter_frames(path))
        log(f"  {ids[name]}: {len(windows[name])} windows (every {step}th)")
    return windows, stats


def _only_watched(stats, watch):
    """Restrict range stats to a watch-list (keys are 'ID|field')."""
    if watch is None:
        return stats
    keep = set(watch)
    return tuple({k: v for k, v in part.items() if k.split("|", 1)[0] in keep}
                 for part in stats)


def fit_models(names, windows, stats, watch, frozen_mode):
    """Stage 1 and Stage 2 fitted on the named captures only."""
    train = [w for n in names for w in windows[n]]
    stage1 = Stage1Model().fit(train)
    stage2 = Stage2Model(watch_ids=watch, frozen_mode=frozen_mode).fit(
        train, range_stats=[_only_watched(stats[n], watch) for n in names])
    return stage1, stage2


def score_both(stage1, stage2, windows) -> Dict[str, List[float]]:
    """v1 (Stage 1) and v2 (fused) scores for each window."""
    scores = {"v1": [], "v2": []}
    for window in windows:
        first = stage1.score(window)
        scores["v1"].append(first.score)
        scores["v2"].append(fuse(first, stage2.score(window)).score)
    return scores


# ---------------------------------------------------------------------
# Protocol 1: leave-one-capture-out over ambient
# ---------------------------------------------------------------------
def ambient_loco(names, windows, stats, max_false_alarm_rate, watch, frozen_mode="width",
                 log=print) -> dict:
    """Nested LOCO: out-of-fold threshold on the rest, false alarms on the held-out one."""
    if len(names) < 3:
        raise ValueError(f"leave-one-out needs at least 3 captures, got {len(names)}")
    rows = []
    for held_out in names:
        rest = [n for n in names if n != held_out]
        oof = {v: [] for v in VERSIONS}
        for inner_out in rest:
            models = fit_models([n for n in rest if n != inner_out], windows, stats,
                                watch, frozen_mode)
            for v, s in score_both(*models, windows[inner_out]).items():
                oof[v].extend(s)
        thresholds = {v: choose_threshold(oof[v], max_false_alarm_rate) for v in VERSIONS}
        scores = score_both(*fit_models(rest, windows, stats, watch, frozen_mode),
                            windows[held_out])
        row = {"capture_id": windows[held_out][0].capture_id if windows[held_out] else None,
               "windows": len(windows[held_out])}
        for v in VERSIONS:
            row[f"{v}_threshold"] = thresholds[v]
            row[f"{v}_alarms"] = sum(1 for s in scores[v] if s >= thresholds[v])
        rows.append(row)
        log(f"  held out {row['capture_id']}: v1 {row['v1_alarms']}/{row['windows']}, "
            f"v2 {row['v2_alarms']}/{row['windows']} false alarms")

    total = sum(r["windows"] for r in rows)
    summary = {}
    for v in VERSIONS:
        alarms = sum(r[f"{v}_alarms"] for r in rows)
        summary[v] = {**_summary(alarms, total, max_false_alarm_rate),
                      "captures_over_target": sum(
                          1 for r in rows
                          if r["windows"] and r[f"{v}_alarms"] / r["windows"] > max_false_alarm_rate)}
    return {"protocol": "ambient leave-one-capture-out, out-of-fold threshold",
            "captures": len(rows), "per_capture": rows, "summary": summary}


# ---------------------------------------------------------------------
# Protocol 2: 2-fold index-out CV over attack recordings
# ---------------------------------------------------------------------
def attack_type(name: str) -> str:
    """'max_speedometer_attack_1_masquerade' -> 'max_speedometer_attack'."""
    return re.sub(r"_\d+(_masquerade)?$", "", name)


def fold_watch_ids(train_attacks, metadata) -> List[str]:
    """Stage 2 watch-list: target IDs of the TRAINING fold's attacks only."""
    ids = set()
    for name in train_attacks:
        target = metadata[name].get("injection_id")
        if target and str(target).upper() != "XXX":
            ids.add(normalize_can_id(target))
    if not ids:
        raise ValueError("training fold has no targeted attacks: cannot build a watch-list")
    return sorted(ids)


def attack_cv(split, data_dir, metadata, max_false_alarm_rate, window_s, stride_s,
              max_windows, frozen_mode="width", log=print) -> dict:
    if not split.attack_folds:
        raise ValueError(
            "this split has no cv_folds. The provisional split puts the _2/_3 attack "
            "captures in final_test, so attack CV would read test data. Pass --split "
            "with a splits.json that defines cv_folds.")
    folds = split.attack_folds
    watches = {k: fold_watch_ids([n for f, c in folds.items() if f != k for n in c], metadata)
               for k in folds}
    union = sorted({i for w in watches.values() for i in w})

    ids = neutral_ids(split.ambient)
    train_names, val_names = split.ambient["train"], split.ambient["validation"]
    log("Reading train + validation ambient captures:")
    windows, stats = load_ambient(train_names + val_names, data_dir, split, ids, window_s,
                                  stride_s, max_windows, union, log)
    validation = [w for n in val_names for w in windows[n]]

    attack_names = sorted(n for c in folds.values() for n in c)
    attack_ids = {n: f"cap{len(ids) + i:02d}" for i, n in enumerate(attack_names, start=1)}

    fold_rows, capture_rows = [], []
    for k, held_out in folds.items():
        stage1, stage2 = fit_models(train_names, windows, stats, watches[k], frozen_mode)
        val_scores = score_both(stage1, stage2, validation)
        thresholds = {v: choose_threshold(val_scores[v], max_false_alarm_rate) for v in VERSIONS}
        fold_rows.append({"fold": k, "watch_ids": watches[k], "held_out": len(held_out),
                          **{f"{v}_threshold": thresholds[v] for v in VERSIONS}})
        log(f"Fold {k}: watch-list {watches[k]} (from the other fold), "
            f"holding out {len(held_out)} captures")
        for name in held_out:
            path = capture_path(data_dir, split, name, "attacks")
            interval = metadata[name].get("injection_interval")
            masquerade = name.endswith("_masquerade")
            t0 = first_timestamp(path)
            row = {"capture_id": attack_ids[name], "fold": k, "type": attack_type(name),
                   "condition": "masquerade" if masquerade else "fabrication",
                   "attacked": 0, "normal": 0,
                   **{f"{v}_{c}": 0 for v in VERSIONS for c in ("detected", "false_alarms")}}
            for window in make_windows(path, attack_ids[name], window_s, stride_s):
                attacked = interval is not None and overlaps(window, t0, interval)
                if masquerade and not attacked:
                    continue      # byte-identical to the fabrication twin: count once
                scores = score_both(stage1, stage2, [window])
                row["attacked" if attacked else "normal"] += 1
                for v in VERSIONS:
                    if scores[v][0] >= thresholds[v]:
                        row[f"{v}_detected" if attacked else f"{v}_false_alarms"] += 1
            capture_rows.append(row)
            log(f"  {name}: v1 {row['v1_detected']}/{row['attacked']}, "
                f"v2 {row['v2_detected']}/{row['attacked']} attacked windows detected")

    return {"protocol": "attacks 2-fold index-out CV, grouped by recording",
            "folds": fold_rows, "per_capture": capture_rows,
            "summary": _attack_summary(capture_rows, max_false_alarm_rate)}


def _attack_summary(rows, target) -> dict:
    """Per-type recall, macro-averaged over types (never pooled: one type
    would dominate a pooled number), plus false alarms on normal windows."""
    out = {}
    for v in VERSIONS:
        per_type = {}
        for condition in ("fabrication", "masquerade", "all"):
            recalls = {}
            for t in sorted({r["type"] for r in rows}):
                chosen = [r for r in rows if r["type"] == t
                          and (condition == "all" or r["condition"] == condition)]
                attacked = sum(r["attacked"] for r in chosen)
                if attacked:
                    recalls[t] = round(sum(r[f"{v}_detected"] for r in chosen) / attacked, 4)
            per_type[condition] = {
                "per_type_recall": recalls,
                "macro_recall": round(sum(recalls.values()) / len(recalls), 4) if recalls else None}
        normal = sum(r["normal"] for r in rows)
        alarms = sum(r[f"{v}_false_alarms"] for r in rows)
        out[v] = {**per_type,
                  "normal_windows_in_attack_captures": _summary(alarms, normal, target)}
    return out


# ---------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Defender cross-validation (never reads test).")
    parser.add_argument("protocol", choices=("ambient", "attacks"))
    parser.add_argument("--max-false-alarm-rate", type=float, required=True,
                        help="team decision, e.g. 0.01 (no default)")
    parser.add_argument("--data-dir", default="data/road", help="ROAD folder with ambient/ attacks/")
    parser.add_argument("--split", default="provisional",
                        help='"provisional" (run_training.PROVISIONAL_SPLIT) or a splits.json path')
    parser.add_argument("--window-s", type=float, default=1.0)
    parser.add_argument("--stride-s", type=float, default=0.5)
    parser.add_argument("--max-windows-per-capture", type=int, default=100,
                        help="ambient windows per capture, same default as run_training")
    parser.add_argument("--stage2-watch", default=",".join(DEVELOPMENT_WATCH_IDS),
                        help='ambient protocol only: watch-list, e.g. "0D0,6E0", or "all"')
    parser.add_argument("--frozen-mode", default="width", choices=("width", "rate"))
    parser.add_argument("--include-development", action="store_true",
                        help="ambient protocol: add development ambient captures to the pool")
    parser.add_argument("--out", help="JSON report path (default results/crossval_<protocol>.json)")
    args = parser.parse_args(argv)
    if args.max_windows_per_capture < 1:
        parser.error("--max-windows-per-capture must be at least 1")

    split = provisional_split() if args.split == "provisional" else load_split(
        Path(args.split).expanduser())
    data_dir = Path(args.data_dir).expanduser()
    settings = {"split": split.source, "window_s": args.window_s, "stride_s": args.stride_s,
                "max_windows_per_capture": args.max_windows_per_capture,
                "max_false_alarm_rate": args.max_false_alarm_rate,
                "frozen_mode": args.frozen_mode}

    if args.protocol == "ambient":
        watch = None if args.stage2_watch.strip().lower() == "all" else \
            sorted({normalize_can_id(i) for i in args.stage2_watch.split(",") if i.strip()})
        names = split.ambient["train"] + split.ambient["validation"]
        if args.include_development:
            names += split.ambient["development"]
        ids = neutral_ids(split.ambient)
        print(f"Reading {len(names)} ambient captures:")
        windows, stats = load_ambient(names, data_dir, split, ids, args.window_s,
                                      args.stride_s, args.max_windows_per_capture, watch)
        print(f"Leave-one-capture-out ({len(names)} outer folds, "
              f"{len(names) * (len(names) - 1)} inner fits):")
        report = ambient_loco(names, windows, stats, args.max_false_alarm_rate, watch,
                              args.frozen_mode)
        settings["stage2_watch_ids"] = watch
    else:
        metadata = json.loads((data_dir / "attacks" / "capture_metadata.json")
                              .read_text(encoding="utf-8"))
        report = attack_cv(split, data_dir, metadata, args.max_false_alarm_rate,
                           args.window_s, args.stride_s, args.max_windows_per_capture,
                           args.frozen_mode)

    report = {"settings": settings, **report,
              "note": "Procedure-level estimate: each fold has its own models and threshold. "
                      "Report beside the frozen-model final-test number, never instead of it, "
                      "and never use it to tune."}
    out = Path(args.out) if args.out else Path("results") / f"crossval_{args.protocol}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n=== Cross-validation summary (NOT the evidence gate) ===")
    for v in VERSIONS:
        s = report["summary"][v]
        if args.protocol == "ambient":
            print(f"  {v}: false alarms {s['alarms']}/{s['windows']} = {s['false_alarm_rate']} "
                  f"(95% upper {s['false_alarm_rate_95_upper']}, target {s['target']}), "
                  f"{s['captures_over_target']}/{report['captures']} captures over target")
        else:
            fa = s["normal_windows_in_attack_captures"]
            print(f"  {v}: macro recall fabrication {s['fabrication']['macro_recall']}, "
                  f"masquerade {s['masquerade']['macro_recall']}; false alarms "
                  f"{fa['alarms']}/{fa['windows']}")
    print(f"Report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
