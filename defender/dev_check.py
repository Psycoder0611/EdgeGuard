"""
DEVELOPMENT sanity check: v1 vs v2 on the PROVISIONAL development split.

NOT the evidence gate. Final-test captures are never read here. Part 3's
evaluator and evidence gate produce the official results.

For each development attack capture, every window is labelled as
"attacked" if it overlaps the ROAD injection_interval. The interval is in
ELAPSED seconds from the capture's first timestamp, so windows are
converted with: elapsed = timestamp - first_timestamp(capture).
Development ambient captures are all-normal (false-alarm check).

Usage (from the EdgeGuard folder):
    python -m defender.dev_check
"""

import argparse
import json
from pathlib import Path

from defender.defender import Defender
from defender.road_reader import first_timestamp, make_windows
from defender.run_training import PROVISIONAL_SPLIT

# PROVISIONAL development attack captures (each with its masquerade twin).
DEVELOPMENT_ATTACKS = [
    "max_speedometer_attack_1",
    "max_speedometer_attack_1_masquerade",
    "reverse_light_off_attack_1",
    "reverse_light_off_attack_1_masquerade",
    "reverse_light_on_attack_1",
    "reverse_light_on_attack_1_masquerade",
    "correlated_signal_attack_1",
    "correlated_signal_attack_1_masquerade",
    "fuzzing_attack_1",
]


def overlaps(window, t0, interval):
    """Does this window overlap [start, end] (elapsed seconds)?"""
    start = window.window_start - t0
    end = window.window_end - t0
    return start < interval[1] and end > interval[0]


def check_capture(path, capture_id, interval, defenders, window_s, stride_s):
    """Counts per defender: attacked windows detected, normal windows flagged."""
    t0 = first_timestamp(path)
    counts = {name: {"attacked": 0, "detected": 0, "normal": 0, "false_alarms": 0}
              for name in defenders}
    for window in make_windows(path, capture_id, window_s, stride_s):
        attacked = interval is not None and overlaps(window, t0, interval)
        for name, defender in defenders.items():
            flagged = defender.score_window(window).decision == "ATTACK"
            c = counts[name]
            if attacked:
                c["attacked"] += 1
                c["detected"] += flagged
            else:
                c["normal"] += 1
                c["false_alarms"] += flagged
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DEVELOPMENT sanity check: v1 vs v2.")
    parser.add_argument("--data-dir", default="data/road")
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--window-s", type=float, default=1.0)
    parser.add_argument("--stride-s", type=float, default=0.5)
    args = parser.parse_args(argv)

    defenders = {v: Defender.load(args.model_dir, v) for v in ("v1", "v2")}
    metadata = json.loads((Path(args.data_dir) / "attacks" / "capture_metadata.json")
                          .read_text(encoding="utf-8"))

    rows = []
    # Neutral ids for development attack captures, continuing after the 12 ambient ids.
    for n, name in enumerate(DEVELOPMENT_ATTACKS, start=13):
        path = Path(args.data_dir) / "attacks" / f"{name}.log"
        interval = metadata[name].get("injection_interval")
        rows.append((name, check_capture(path, f"cap{n:02d}", interval, defenders,
                                         args.window_s, args.stride_s)))
    for n, name in enumerate(PROVISIONAL_SPLIT["development"], start=40):
        path = Path(args.data_dir) / "ambient" / f"{name}.log"
        rows.append((name, check_capture(path, f"cap{n:02d}", None, defenders,
                                         args.window_s, args.stride_s)))

    print("=== DEVELOPMENT sanity check (NOT the evidence gate) ===")
    print(f"{'capture':42s} {'attacked':>8s} {'v1 det':>7s} {'v2 det':>7s} "
          f"{'normal':>7s} {'v1 FA':>6s} {'v2 FA':>6s}")
    for name, c in rows:
        v1, v2 = c["v1"], c["v2"]
        print(f"{name:42s} {v1['attacked']:8d} {v1['detected']:7d} {v2['detected']:7d} "
              f"{v1['normal']:7d} {v1['false_alarms']:6d} {v2['false_alarms']:6d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())