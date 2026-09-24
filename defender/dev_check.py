"""
DEVELOPMENT sanity check: v1 vs v2 (vs v3, if trained) on the PROVISIONAL
development split.

NOT the evidence gate. Final-test captures are never read here. Part 3's
evaluator and evidence gate produce the official results.

For each development attack capture, every window is labelled as
"attacked" if it overlaps the ROAD injection_interval. The interval is in
ELAPSED seconds from the capture's first timestamp, so windows are
converted with: elapsed = timestamp - first_timestamp(capture).
Development ambient captures are all-normal (false-alarm check).

It also re-creates Part 3's confirmed development miss (all 0D0 frames of
the first ambient_dyno_reverse window frozen at 3A710460F5000000) as a
regression check.

Usage (from the EdgeGuard folder):
    python -m defender.dev_check
"""

import argparse
import json
from pathlib import Path

from defender.defender import Defender, stage1_path
from defender.road_reader import first_timestamp, make_windows
from defender.run_training import PROVISIONAL_SPLIT, keep_every_for
from shared.schemas import TrafficWindow

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

# Part 3's confirmed development miss: 0D0 frozen (counter + checksum).
PART3_FREEZE_PAYLOAD = "3A710460F5000000"


def overlaps(window, t0, interval):
    """Does this window overlap [start, end] (elapsed seconds)?"""
    start = window.window_start - t0
    end = window.window_end - t0
    return start < interval[1] and end > interval[0]


def freeze_id(window: TrafficWindow, can_id: str, payload: str) -> TrafficWindow:
    """COPY of the window with every frame of can_id set to one payload."""
    data = window.model_dump()
    data["window_id"] = window.window_id + "_v01"
    for frame in data["frames"]:
        if frame["can_id"].upper() == can_id:
            frame["payload"] = payload
    return TrafficWindow(**data)


def check_capture(path, capture_id, interval, defenders, window_s, stride_s, keep_every=1):
    """Counts per defender: attacked windows detected, normal windows flagged."""
    t0 = first_timestamp(path)
    counts = {name: {"attacked": 0, "detected": 0, "normal": 0, "false_alarms": 0}
              for name in defenders}
    for window in make_windows(path, capture_id, window_s, stride_s, keep_every=keep_every):
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
    parser = argparse.ArgumentParser(description="DEVELOPMENT sanity check: v1 vs v2 (vs v3).")
    parser.add_argument("--data-dir", default="data/road")
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--window-s", type=float, default=1.0)
    parser.add_argument("--stride-s", type=float, default=0.5)
    parser.add_argument("--max-ambient-windows", type=int, default=300,
                        help="sample long ambient captures (attack captures are always full)")
    args = parser.parse_args(argv)

    versions = [v for v in ("v1", "v2", "v3") if stage1_path(args.model_dir, v).exists()]
    print(f"Loading {', '.join(versions)} ...", flush=True)
    defenders = {v: Defender.load(args.model_dir, v) for v in versions}
    metadata = json.loads((Path(args.data_dir) / "attacks" / "capture_metadata.json")
                          .read_text(encoding="utf-8"))

    rows = []
    # Neutral ids for development attack captures, continuing after the 12 ambient ids.
    for n, name in enumerate(DEVELOPMENT_ATTACKS, start=13):
        path = Path(args.data_dir) / "attacks" / f"{name}.log"
        interval = metadata[name].get("injection_interval")
        print(f"  checking {name} ...", flush=True)
        rows.append((name, check_capture(path, f"cap{n:02d}", interval, defenders,
                                         args.window_s, args.stride_s)))
    for n, name in enumerate(PROVISIONAL_SPLIT["development"], start=40):
        path = Path(args.data_dir) / "ambient" / f"{name}.log"
        step = keep_every_for(path, args.window_s, args.stride_s, args.max_ambient_windows)
        print(f"  checking {name} (every {step}th window) ...", flush=True)
        rows.append((name, check_capture(path, f"cap{n:02d}", None, defenders,
                                         args.window_s, args.stride_s, keep_every=step)))

    print("\n=== DEVELOPMENT sanity check (NOT the evidence gate) ===")
    header = f"{'capture':42s} {'attacked':>8s}"
    for v in versions:
        header += f" {v + ' det':>7s}"
    header += f" {'normal':>7s}"
    for v in versions:
        header += f" {v + ' FA':>6s}"
    print(header)
    totals = {v: [0, 0, 0, 0] for v in versions}
    for name, c in rows:
        first = c[versions[0]]
        line = f"{name:42s} {first['attacked']:8d}"
        for v in versions:
            line += f" {c[v]['detected']:7d}"
        line += f" {first['normal']:7d}"
        for v in versions:
            line += f" {c[v]['false_alarms']:6d}"
        print(line)
        for v in versions:
            t = totals[v]
            t[0] += c[v]["detected"]; t[1] += c[v]["attacked"]
            t[2] += c[v]["false_alarms"]; t[3] += c[v]["normal"]
    print("Totals:")
    for v in versions:
        d, a, f, n = totals[v]
        print(f"  {v}: detected {d}/{a} attacked windows, false alarms {f}/{n} normal windows")

    # Regression check: Part 3's confirmed development miss.
    reverse = Path(args.data_dir) / "ambient" / f"{PROVISIONAL_SPLIT['development'][0]}.log"
    original = next(make_windows(reverse, "cap40", args.window_s, args.stride_s))
    frozen = freeze_id(original, "0D0", PART3_FREEZE_PAYLOAD)
    print("\n=== Part 3 freeze repro (0D0 frozen at 3A710460F5000000, dev only) ===")
    for v, defender in defenders.items():
        a = defender.score_window(original)
        b = defender.score_window(frozen)
        print(f"  {v}: original {a.decision} ({a.attack_score:.6f})  "
              f"frozen {b.decision} ({b.attack_score:.6f})  {b.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())