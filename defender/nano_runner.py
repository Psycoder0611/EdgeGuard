"""
Run the EdgeGuard Defender locally and measure inference latency (Part 2).

Purpose (HP requirement): show that primary detection runs ON THE NANO,
with no cloud connection, and report how fast it is.

What it records for every window:
    window_id, decision, attack_score, latency_ms
And a summary:
    number of windows, mean / median / p95 / max latency_ms,
    windows per second (inference only), number of ATTACK decisions,
    machine name and CPU architecture, model_version, and whether the
    traffic was MOCK.

latency_ms is Defender inference only (see defender.py). Window
collection time is NOT included and must be measured separately.

Usage today (Part 1's real windows are not ready yet):
    python -m defender.nano_runner --mock --output results/nano_benchmark_MOCK.json

--mock trains a small MOCK model in memory on MOCK traffic. Its numbers
show that the pipeline runs and how fast it is on this machine; they
say NOTHING about detection quality on ROAD.

Real mode (after Part 1's make_windows and a trained model exist) will
call run_benchmark() with a Defender.load(model_dir, version) and real
windows. It is intentionally not implemented until that interface exists.
"""

import argparse
import json
import platform
import statistics
import time
from pathlib import Path
from typing import Iterable, List, Optional

from pydantic import BaseModel, ConfigDict

from defender.defender import Defender
from defender.simulated_consumer import SimulatedConsumer
from defender.stage1 import Stage1Model
from defender.threshold import choose_threshold
from shared.schemas import TrafficWindow


class WindowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_id: str
    decision: str
    attack_score: float
    latency_ms: float


class BenchmarkSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mock_traffic: bool
    model_version: str
    machine: str
    architecture: str
    python_version: str
    windows: int
    attack_decisions: int
    latency_ms_mean: float
    latency_ms_median: float
    latency_ms_p95: float
    latency_ms_max: float
    windows_per_second: float
    wall_clock_seconds: float
    note: str


def _p95(values: List[float]) -> float:
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=20, method="inclusive")[18]


def run_benchmark(defender: Defender, windows: Iterable[TrafficWindow],
                  mock_traffic: bool,
                  consumer: Optional[SimulatedConsumer] = None):
    """Score every window locally. Returns (records, summary)."""
    if not isinstance(defender, Defender):
        raise TypeError("run_benchmark() needs a Defender")
    consumer = consumer or SimulatedConsumer()

    records: List[WindowRecord] = []
    started = time.perf_counter()
    for window in windows:
        output = defender.score_window(window)
        consumer.handle(output)
        records.append(WindowRecord(window_id=output.window_id, decision=output.decision,
                                    attack_score=output.attack_score,
                                    latency_ms=output.latency_ms))
    wall_clock = time.perf_counter() - started
    if not records:
        raise ValueError("No windows were given, nothing to benchmark")

    latencies = [r.latency_ms for r in records]
    total_inference_s = sum(latencies) / 1000.0
    summary = BenchmarkSummary(
        mock_traffic=mock_traffic,
        model_version=defender.model_version,
        machine=platform.node(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
        windows=len(records),
        attack_decisions=sum(1 for r in records if r.decision == "ATTACK"),
        latency_ms_mean=statistics.fmean(latencies),
        latency_ms_median=statistics.median(latencies),
        latency_ms_p95=_p95(latencies),
        latency_ms_max=max(latencies),
        windows_per_second=len(records) / total_inference_s if total_inference_s > 0 else 0.0,
        wall_clock_seconds=wall_clock,
        note=(
            "MOCK traffic: shows the pipeline runs locally and its speed; "
            "NOT a detection result on ROAD." if mock_traffic else
            "Real windows. Inference latency only; window collection time excluded."
        ),
    )
    return records, summary


def save_results(path, records, summary) -> None:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"summary": summary.model_dump(),
                                "windows": [r.model_dump() for r in records]}, indent=2),
                    encoding="utf-8")


def build_mock_defender() -> Defender:
    """MOCK model: trained in memory on MOCK traffic only."""
    from defender.mock_traffic import make_mock_normal_window
    stage1 = Stage1Model().fit([make_mock_normal_window(i, "cap90") for i in range(40)])
    validation = [stage1.score(make_mock_normal_window(i, "cap92")).score
                  for i in range(100, 130)]
    threshold = choose_threshold(validation, 0.0)
    return Defender(stage1, threshold, "MOCK_v1")


def mock_windows(count: int) -> List[TrafficWindow]:
    """MOCK mix: every 10th window is a MOCK fuzzing attack."""
    from defender.mock_traffic import make_mock_fuzzing_window, make_mock_normal_window
    return [make_mock_fuzzing_window(i) if i % 10 == 9 else make_mock_normal_window(i, "cap93")
            for i in range(count)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the Defender locally and measure latency.")
    parser.add_argument("--mock", action="store_true",
                        help="use MOCK model and MOCK traffic (the only mode available now)")
    parser.add_argument("--windows", type=int, default=200,
                        help="number of MOCK windows to score (default 200)")
    parser.add_argument("--output", required=True, help="where to save the JSON results")
    args = parser.parse_args(argv)

    if not args.mock:
        parser.error("Real mode needs Part 1's make_windows and a trained model. "
                     "Use --mock for now.")
    if args.windows < 1:
        parser.error("--windows must be at least 1")

    records, summary = run_benchmark(build_mock_defender(), mock_windows(args.windows),
                                     mock_traffic=True)
    save_results(args.output, records, summary)

    print("=== EdgeGuard Defender local run (MOCK traffic) ===")
    print(f"Machine:        {summary.machine} ({summary.architecture})")
    print(f"Model version:  {summary.model_version}")
    print(f"Windows scored: {summary.windows}  (ATTACK decisions: {summary.attack_decisions})")
    print(f"Latency ms:     mean {summary.latency_ms_mean:.3f} | median "
          f"{summary.latency_ms_median:.3f} | p95 {summary.latency_ms_p95:.3f} | "
          f"max {summary.latency_ms_max:.3f}")
    print(f"Throughput:     {summary.windows_per_second:.0f} windows/second (inference only)")
    print(f"Saved to:       {args.output}")
    print(summary.note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())