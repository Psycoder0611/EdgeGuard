"""
Train Defender v1 and v2 on REAL ROAD ambient captures (Part 2).

Usage (from the EdgeGuard folder, .venv active):
    python -m defender.run_training --max-false-alarm-rate 0.01

What it does:
  1. Uses the PROVISIONAL ambient split below (Part 1 owns the official
     split; replace PROVISIONAL_SPLIT when it exists).
  2. Gives every capture a neutral id (cap01, cap02, ...) and saves the
     name -> id mapping to data/capture_id_map.json (data/ is never
     uploaded to GitHub).
  3. Reads train and validation captures with defender.road_reader
     (Part 2 fallback for Part 1's make_windows), limited to at most
     --max-windows-per-capture evenly spaced windows per capture so
     memory stays reasonable (about 1 MB per real window).
  4. Trains v1 (Stage 1) and v2 (v1's Stage 1 + new Stage 2) and saves
     them in --model-dir, then prints a summary. Stage 2 learns field ranges
     from EVERY frame of the train captures (streamed, low memory), because
     sampled windows miss rare-but-normal changes (found on real data:
     183 of 184 normal validation windows were flagged without this).

It NEVER reads attack captures and NEVER reads development or final_test
captures. Only train and validation ambient captures are used.

--harden-v3 trains ONLY v3 (v1's Stage 1 + Stage 2 with the "rate" frozen
check), from the same captures and settings, and leaves v1 and v2 untouched.
It hardens the Defender against the development miss found by Part 3
(frozen rolling counter on 0D0).

Window settings default to the team-agreed 1.0 s window / 0.5 s stride.
The false-alarm rate has NO default: it is a team decision.
"""

import argparse
import json
import math
from pathlib import Path

from defender.road_reader import first_timestamp, iter_frames, last_timestamp, make_windows
from defender.train import train_defender, train_v2

# Stage 2 watch-list: CAN IDs targeted by the PROVISIONAL DEVELOPMENT attacks
# (max_speedometer_1, reverse_light_off_1, reverse_light_on_1 -> 0D0;
#  correlated_signal_1 -> 6E0). Chosen from development only, never final_test.
# 4E7 (coolant, final_test only) is deliberately NOT included: an honest test
# of an attack on an unwatched ID.
DEVELOPMENT_WATCH_IDS = ["0D0", "6E0"]

# PROVISIONAL split of the 12 ROAD ambient captures (file names without .log).
# Agreed provisionally with the team; Part 1's split_manifest replaces it.
PROVISIONAL_SPLIT = {
    "train": [
        "ambient_dyno_drive_basic_long",
        "ambient_dyno_drive_basic_short",
        "ambient_dyno_drive_extended_long",
        "ambient_dyno_drive_radio_infotainment",
        "ambient_dyno_idle_radio_infotainment",
        "ambient_highway_street_driving_long",
    ],
    "validation": [
        "ambient_dyno_drive_extended_short",
        "ambient_dyno_drive_winter",
    ],
    "development": [
        "ambient_dyno_reverse",
        "ambient_dyno_exercise_all_bits",
    ],
    "final_test": [
        "ambient_dyno_drive_benign_anomaly",
        "ambient_highway_street_driving_diagnostics",
    ],
}


def neutral_ids(split=PROVISIONAL_SPLIT):
    """Fixed name -> neutral id mapping (cap01, cap02, ...) in split order."""
    names = [name for group in ("train", "validation", "development", "final_test")
             for name in split[group]]
    if len(names) != len(set(names)):
        raise ValueError("A capture appears in more than one split")
    return {name: f"cap{i:02d}" for i, name in enumerate(names, start=1)}


def keep_every_for(path, window_s, stride_s, max_windows):
    """How often to keep a window so a capture yields at most max_windows."""
    duration = last_timestamp(path) - first_timestamp(path)
    estimated = max(0, math.floor((duration - window_s) / stride_s) + 1)
    return max(1, math.ceil(estimated / max_windows))


def load_windows(names, ambient_dir, ids, window_s, stride_s, max_windows):
    windows = []
    for name in names:
        path = Path(ambient_dir) / f"{name}.log"
        step = keep_every_for(path, window_s, stride_s, max_windows)
        got = list(make_windows(path, ids[name], window_s, stride_s, keep_every=step))
        windows.extend(got)
        print(f"  {ids[name]}: {len(got)} windows (every {step}th)")
    return windows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Train Defender v1 and v2 on real ROAD data.")
    parser.add_argument("--max-false-alarm-rate", type=float, required=True,
                        help="team decision, e.g. 0.01 (no default)")
    parser.add_argument("--data-dir", default="data/road", help="ROAD folder (default data/road)")
    parser.add_argument("--model-dir", default="models", help="where to save models")
    parser.add_argument("--map-file", default="data/capture_id_map.json",
                        help="where to save the private name -> id mapping")
    parser.add_argument("--window-s", type=float, default=1.0, help="team-agreed: 1.0")
    parser.add_argument("--stride-s", type=float, default=0.5, help="team-agreed: 0.5")
    parser.add_argument("--max-windows-per-capture", type=int, default=100,
                        help="memory limit, about 1 MB per window (default 100)")
    parser.add_argument("--stage2-watch", default=",".join(DEVELOPMENT_WATCH_IDS),
                        help='Stage 2 watch-list, e.g. "0D0,6E0" (quote it in PowerShell), '
                             'or "all" to watch every ID')
    parser.add_argument("--harden-v3", action="store_true",
                        help="train only v3 (rate frozen check); v1 must already exist")
    parser.add_argument("--overwrite", action="store_true",
                        help="replace existing v1/v2 files (only if never evaluated)")
    args = parser.parse_args(argv)

    if args.max_windows_per_capture < 1:
        parser.error("--max-windows-per-capture must be at least 1")

    watch = None if args.stage2_watch.strip().lower() == "all" else \
        [i for i in args.stage2_watch.split(",") if i.strip()]

    ambient_dir = Path(args.data_dir) / "ambient"
    needed = PROVISIONAL_SPLIT["train"] + PROVISIONAL_SPLIT["validation"]
    missing = [n for n in needed if not (ambient_dir / f"{n}.log").exists()]
    if missing:
        parser.error(f"missing ambient captures in {ambient_dir}: {missing}")

    ids = neutral_ids()
    map_file = Path(args.map_file)
    map_file.parent.mkdir(parents=True, exist_ok=True)
    map_file.write_text(json.dumps({"note": "PRIVATE: never upload. PROVISIONAL split.",
                                    "ids": ids, "split": PROVISIONAL_SPLIT}, indent=2),
                        encoding="utf-8")

    print("Reading TRAIN captures:")
    train = load_windows(PROVISIONAL_SPLIT["train"], ambient_dir, ids,
                         args.window_s, args.stride_s, args.max_windows_per_capture)
    print("Reading VALIDATION captures:")
    validation = load_windows(PROVISIONAL_SPLIT["validation"], ambient_dir, ids,
                              args.window_s, args.stride_s, args.max_windows_per_capture)

    full_train_frames = [iter_frames(ambient_dir / f"{name}.log")
                         for name in PROVISIONAL_SPLIT["train"]]
    if args.harden_v3:
        print("Training v3 (v1 Stage 1 + Stage 2 with 'rate' frozen check;"
              " this can take several minutes)...")
        v3 = train_v2(args.model_dir, "v1", train, validation, "v3", args.model_dir,
                      args.window_s, args.stride_s, overwrite=args.overwrite,
                      stage2_range_captures=full_train_frames, stage2_watch_ids=watch,
                      stage2_frozen_mode="rate")
        reports = (v3,)
    else:
        print("Training v1 (Stage 1)...")
        v1 = train_defender(train, validation, args.max_false_alarm_rate, "v1", args.model_dir,
                            args.window_s, args.stride_s, overwrite=args.overwrite)
        print("Training v2 (v1 Stage 1 + new Stage 2, ranges from all train frames;"
              " this can take several minutes)...")
        v2 = train_v2(args.model_dir, "v1", train, validation, "v2", args.model_dir,
                      args.window_s, args.stride_s, overwrite=args.overwrite,
                      stage2_range_captures=full_train_frames, stage2_watch_ids=watch)
        reports = (v1, v2)

    print("\n=== Training summary (PROVISIONAL split) ===")
    for report in reports:
        print(f"{report.model_version}: {report.train_windows} train windows, "
              f"{report.validation_windows} validation windows, "
              f"threshold {report.threshold:.6f}, "
              f"validation false-alarm rate {report.validation_false_alarm_rate:.4f} "
              f"(target {report.max_false_alarm_rate})")
    print(f"Stage 2 watch-list: {reports[-1].stage2_watch_ids or 'all IDs'}"
          f"  |  frozen check: {reports[-1].stage2_frozen_mode}")
    print(f"Models saved in {args.model_dir}/  |  private id map: {map_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())