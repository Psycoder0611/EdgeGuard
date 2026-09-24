"""
Diagnostic (read-only): which Stage 2 check fires on NORMAL validation windows?
Usage: python -m defender.diagnose
"""
from collections import Counter

from defender.defender import Defender
from defender.road_reader import make_windows
from defender.run_training import PROVISIONAL_SPLIT, keep_every_for, neutral_ids


def main():
    defender = Defender.load("models", "v2")
    ids = neutral_ids()
    n = defender.stage2.training_windows
    normal_top = n / (n + 1)
    top_checks, flagged = Counter(), []
    total = 0
    for name in PROVISIONAL_SPLIT["validation"]:
        path = f"data/road/ambient/{name}.log"
        step = keep_every_for(path, 1.0, 0.5, 100)
        for window in make_windows(path, ids[name], 1.0, 0.5, keep_every=step):
            total += 1
            result = defender.stage2.score(window)
            if result.score > normal_top:
                top = max(result.sub_scores, key=result.sub_scores.get)
                top_checks[top] += 1
                flagged.append((result.score, result.evidence))
    print(f"Validation windows: {total}")
    print(f"Stage 2 above normal training range: {len(flagged)}")
    print(f"Which check caused it: {dict(top_checks)}")
    print("Top 5 examples:")
    for score, evidence in sorted(flagged, reverse=True)[:5]:
        print(f"  {score:.6f}  {evidence}")


if __name__ == "__main__":
    main()