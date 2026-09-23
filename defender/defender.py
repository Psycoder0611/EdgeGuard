"""
Main Defender interface for EdgeGuard (Part 2).

This is the ONE function other parts call:

    score_window(window) -> DefenderOutput

Input:  a TrafficWindow (shared/schemas.py), already preprocessed by Part 1.
        A plain dict is also accepted; it is validated as a TrafficWindow
        first, so any label field (is_attack, family, ...) is rejected.
Output: DefenderOutput with window_id, attack_score, threshold, decision,
        evidence, model_version and latency_ms.

Current version (v1): attack_score = Stage 1 timing score.
Stage 2 and fusion.py will be added later without changing this interface.

THRESHOLD WIRING (important):
DefenderOutput checks that decision matches score >= threshold. The
threshold used here MUST be the one chosen by threshold.py for THIS
model version and loaded with load_threshold(path, model_version).
Never type a threshold by hand here. Defender.load() does this for you,
and refuses files saved for a different model version.

latency_ms measures Defender inference only (scoring one window). Window
collection time is NOT included; measure it separately.
"""

import time
from pathlib import Path
from typing import Optional, Union

from defender.stage1 import Stage1Model
from defender.threshold import load_threshold, make_decision
from shared.schemas import DefenderOutput, TrafficWindow


def stage1_path(model_dir, model_version: str) -> Path:
    return Path(model_dir) / f"stage1_{model_version}.json"


def threshold_path(model_dir, model_version: str) -> Path:
    return Path(model_dir) / f"threshold_{model_version}.json"


class Defender:
    def __init__(self, stage1: Stage1Model, threshold: float, model_version: str):
        if not isinstance(stage1, Stage1Model) or not stage1.fitted:
            raise ValueError("Defender needs a trained Stage1Model")
        make_decision(0.0, threshold)          # validates threshold is in [0, 1]
        if not isinstance(model_version, str) or not model_version:
            raise ValueError("model_version must be a non-empty string, e.g. 'v1'")
        self.stage1 = stage1
        self.threshold = threshold
        self.model_version = model_version

    @classmethod
    def load(cls, model_dir, model_version: str) -> "Defender":
        """Load Stage 1 and its threshold, both for the same model version."""
        stage1 = Stage1Model.load(stage1_path(model_dir, model_version), model_version)
        threshold = load_threshold(threshold_path(model_dir, model_version), model_version)
        return cls(stage1, threshold, model_version)

    def score_window(self, window: Union[TrafficWindow, dict]) -> DefenderOutput:
        """Score one window. Never modifies the window."""
        if isinstance(window, dict):
            window = TrafficWindow.model_validate(window)   # rejects label fields
        elif not isinstance(window, TrafficWindow):
            raise TypeError(
                f"score_window() needs a TrafficWindow or dict, got {type(window).__name__}"
            )

        started = time.perf_counter()
        stage1_result = self.stage1.score(window)
        attack_score = stage1_result.score                 # v1: Stage 1 only
        decision = make_decision(attack_score, self.threshold)
        latency_ms = (time.perf_counter() - started) * 1000.0

        return DefenderOutput(
            window_id=window.window_id,
            attack_score=attack_score,
            threshold=self.threshold,
            decision=decision,
            evidence=stage1_result.evidence,
            model_version=self.model_version,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------
# Module-level interface promised to Part 3:  score_window(window)
# ---------------------------------------------------------------------
_active_defender: Optional[Defender] = None


def set_active_defender(defender: Defender) -> None:
    """Choose which trained Defender score_window() uses."""
    global _active_defender
    if not isinstance(defender, Defender):
        raise TypeError("set_active_defender() needs a Defender")
    _active_defender = defender


def score_window(window: Union[TrafficWindow, dict]) -> DefenderOutput:
    if _active_defender is None:
        raise RuntimeError(
            "No Defender loaded. Call set_active_defender(Defender.load(model_dir, "
            "model_version)) first."
        )
    return _active_defender.score_window(window)