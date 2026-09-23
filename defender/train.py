"""
Training for the EdgeGuard Defender (Part 2).

v1 training does two things, on two SEPARATE groups of NORMAL captures:
  1. TRAIN split       -> fit Stage 1 (learn normal timing)
  2. VALIDATION split  -> score those windows, choose the threshold with
                          choose_threshold(scores, max_false_alarm_rate)
Then it saves, for one model version:
  models/stage1_<version>.json
  models/threshold_<version>.json
  models/train_info_<version>.json   (what was used, for reproducibility)

Rules enforced here:
  - The false-alarm rate has NO default: the caller must supply it.
  - A capture may not appear in both train and validation (data leak).
  - Existing model files are never overwritten unless overwrite=True,
    so a model already judged by the evidence gate cannot change silently.

Rules the CALLER must follow (cannot be checked here, labels are hidden):
  - Train and validation captures must be NORMAL (ambient) captures.
  - Never pass development or final-test captures.

Part 1 interface this file is written against (agreed signature):
  make_windows(capture_path, capture_id, window_s, stride_s)
      -> Iterator[TrafficWindow]   (frames filled, features empty)
"""

import json
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from defender.defender import stage1_path, threshold_path
from defender.stage1 import Stage1Model
from defender.threshold import ATTACK, choose_threshold, make_decision, save_threshold
from shared.schemas import TrafficWindow

MakeWindows = Callable[[str, str, float, float], Iterator[TrafficWindow]]


def train_info_path(model_dir, model_version: str) -> Path:
    return Path(model_dir) / f"train_info_{model_version}.json"


class TrainingReport(BaseModel):
    """Summary of one training run, saved as train_info_<version>.json."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_version: str
    window_s: float
    stride_s: float
    train_capture_ids: List[str]
    validation_capture_ids: List[str]
    train_windows: int
    validation_windows: int
    max_false_alarm_rate: float
    threshold: float = Field(ge=0.0, le=1.0)
    validation_false_alarm_rate: float = Field(ge=0.0, le=1.0)


def _to_list(windows: Iterable[TrafficWindow], name: str) -> List[TrafficWindow]:
    result = list(windows)
    for i, window in enumerate(result):
        if not isinstance(window, TrafficWindow):
            raise TypeError(f"{name}[{i}] is {type(window).__name__}, expected TrafficWindow")
    return result


def train_defender(
    train_windows: Iterable[TrafficWindow],
    validation_windows: Iterable[TrafficWindow],
    max_false_alarm_rate: float,
    model_version: str,
    model_dir,
    window_s: float,
    stride_s: float,
    overwrite: bool = False,
) -> TrainingReport:
    """Fit Stage 1 on train windows, choose the threshold on validation windows,
    save everything for model_version. Returns a TrainingReport."""
    if not isinstance(model_version, str) or not model_version:
        raise ValueError("model_version must be a non-empty string, e.g. 'v1'")
    if window_s <= 0 or stride_s <= 0:
        raise ValueError(f"window_s and stride_s must be positive, got {window_s}, {stride_s}")

    train = _to_list(train_windows, "train_windows")
    validation = _to_list(validation_windows, "validation_windows")
    if len(train) < 2:
        raise ValueError(f"need at least 2 train windows, got {len(train)}")
    if len(validation) == 0:
        raise ValueError("validation_windows is empty: the threshold needs validation data")

    train_ids = sorted({w.capture_id for w in train})
    validation_ids = sorted({w.capture_id for w in validation})
    shared_ids = set(train_ids) & set(validation_ids)
    if shared_ids:
        raise ValueError(
            f"Data leak: capture(s) {sorted(shared_ids)} appear in BOTH train and "
            f"validation. Each capture must belong to exactly one split."
        )

    outputs = [
        stage1_path(model_dir, model_version),
        threshold_path(model_dir, model_version),
        train_info_path(model_dir, model_version),
    ]
    existing = [str(p) for p in outputs if p.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            f"Model {model_version!r} already exists ({existing}). Use a new version "
            f"name, or overwrite=True if you are sure it was never evaluated."
        )

    # 1. Learn normal timing from TRAIN only.
    stage1 = Stage1Model().fit(train)

    # 2. Choose the threshold from VALIDATION only.
    validation_scores = [stage1.score(w).score for w in validation]
    threshold = choose_threshold(validation_scores, max_false_alarm_rate)
    alarms = sum(1 for s in validation_scores if make_decision(s, threshold) == ATTACK)

    report = TrainingReport(
        model_version=model_version,
        window_s=window_s,
        stride_s=stride_s,
        train_capture_ids=train_ids,
        validation_capture_ids=validation_ids,
        train_windows=len(train),
        validation_windows=len(validation),
        max_false_alarm_rate=max_false_alarm_rate,
        threshold=threshold,
        validation_false_alarm_rate=alarms / len(validation),
    )

    # 3. Save all three files for this model version.
    stage1.save(outputs[0], model_version)
    save_threshold(threshold, model_version, outputs[1])
    outputs[2].write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
    return report


def train_from_captures(
    train_captures: Sequence[Tuple[str, str]],
    validation_captures: Sequence[Tuple[str, str]],
    make_windows: MakeWindows,
    window_s: float,
    stride_s: float,
    max_false_alarm_rate: float,
    model_version: str,
    model_dir,
    overwrite: bool = False,
) -> TrainingReport:
    """Same as train_defender, but builds windows with Part 1's make_windows().

    train_captures / validation_captures: lists of (capture_path, capture_id),
    e.g. [("data/road/ambient/<file>.log", "cap01"), ...] from the split manifest.
    """
    def collect(captures):
        windows = []
        for path, capture_id in captures:
            windows.extend(make_windows(path, capture_id, window_s, stride_s))
        return windows

    return train_defender(
        train_windows=collect(train_captures),
        validation_windows=collect(validation_captures),
        max_false_alarm_rate=max_false_alarm_rate,
        model_version=model_version,
        model_dir=model_dir,
        window_s=window_s,
        stride_s=stride_s,
        overwrite=overwrite,
    )