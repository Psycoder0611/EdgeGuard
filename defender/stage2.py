"""
Stage 2 payload detector for the EdgeGuard Defender (Part 2).

Stage 2 looks at PAYLOAD CONTENT, never timing (that is Stage 1's job).
It is meant to catch masquerade and other attacks that keep normal
message timing but change what a message says.

It learns "normal" from NORMAL TRAINING windows only, per CAN ID and per
"field" inside that ID's payload:
    byte fields   each payload byte position (byte0, byte1, ...)
    pair fields   each pair of consecutive bytes, as a 16-bit number,
                  in BOTH byte orders (pair0_be, pair0_le, pair1_be, ...)
                  This catches 2-byte signals regardless of byte order,
                  without needing Part 1's decoded signals.

For a new window it checks three signs, per field:
    out_of_range   a value outside the range ever seen in normal training
                   (typical of "max_speedometer", "max_engine_coolant_temp")
    frozen_break   a field that normally varies is held at one exact value
                   for the whole window (typical of "reverse_light_on/off",
                   and of masquerade attacks that hold a forced value)
    large_jump     two consecutive frames of the same field differ by more
                   than any jump ever seen in normal training

Raw values become 0..1 scores the same way as Stage 1 (see
defender.stage1._unusualness): compared against the same checks run on
every normal training window. The Stage 2 score is the highest sub-score
found on any field.

KNOWN LIMITS (expected, not bugs):
  - "accelerator" ROAD attacks inject no frames at all -> Stage 2 has
    nothing to see; it will not catch them (neither does Stage 1).
  - "correlated_signal_attack" changes a RELATIONSHIP between two CAN IDs,
    not one field's own range. This detector checks fields independently
    and is NOT expected to reliably catch it. That needs a separate
    cross-ID check (a later addition), or Part 1's decoded_signals.
  - A field that is a rolling counter or checksum in training will show
    a wide "normal" range, so out_of_range contributes little for it.
    This is fine: the window score is the MAX across all fields, so a
    noisy field does not hide a real anomaly elsewhere.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from pydantic import BaseModel, ConfigDict, Field

from defender.stage1 import _unusualness
from shared.schemas import TrafficWindow

CHECKS = ("out_of_range", "frozen_break", "large_jump")


class Stage2Result(BaseModel):
    """Stage 2 output for one window (internal to the Defender)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: float = Field(ge=0.0, le=1.0)
    sub_scores: Dict[str, float]
    evidence: str


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def _payload_bytes(payload: str) -> List[int]:
    return [int(payload[i:i + 2], 16) for i in range(0, len(payload), 2)]


def _field_values(window: TrafficWindow) -> Dict[Tuple[str, str], List[int]]:
    """(can_id, field_name) -> values, in timestamp order, for this window."""
    by_id: Dict[str, List[Tuple[float, List[int]]]] = defaultdict(list)
    for frame in window.frames:
        by_id[frame.can_id.upper()].append((frame.timestamp, _payload_bytes(frame.payload)))

    fields: Dict[Tuple[str, str], List[int]] = defaultdict(list)
    for can_id, entries in by_id.items():
        entries.sort(key=lambda e: e[0])
        for _, data in entries:
            for i, byte in enumerate(data):
                fields[(can_id, f"byte{i}")].append(byte)
            for i in range(len(data) - 1):
                fields[(can_id, f"pair{i}_be")].append((data[i] << 8) | data[i + 1])
                fields[(can_id, f"pair{i}_le")].append((data[i + 1] << 8) | data[i])
    return fields


# ---------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------
class Stage2Model:
    def __init__(self):
        self.fitted = False
        self.field_range: Dict[str, Tuple[int, int]] = {}    # "ID|field" -> (min, max)
        self.field_max_jump: Dict[str, int] = {}
        self.reference: Dict[str, List[float]] = {}          # sorted raw values per check
        self.training_windows = 0

    @staticmethod
    def _key(can_id: str, field_name: str) -> str:
        return f"{can_id}|{field_name}"

    # ---------- training ----------------------------------------------
    def fit(self, normal_windows: List[TrafficWindow]) -> "Stage2Model":
        """Learn normal payload content from NORMAL TRAINING windows only."""
        if not isinstance(normal_windows, (list, tuple)) or len(normal_windows) < 2:
            raise ValueError("fit() needs a list of at least 2 normal training windows")
        for i, window in enumerate(normal_windows):
            if not isinstance(window, TrafficWindow):
                raise TypeError(
                    f"normal_windows[{i}] is {type(window).__name__}, expected TrafficWindow"
                )

        all_values: Dict[str, List[int]] = defaultdict(list)
        max_jump: Dict[str, int] = defaultdict(int)
        for window in normal_windows:
            for (can_id, field_name), values in _field_values(window).items():
                key = self._key(can_id, field_name)
                all_values[key].extend(values)
                for a, b in zip(values, values[1:]):
                    max_jump[key] = max(max_jump[key], abs(b - a))

        self.field_range = {k: (min(v), max(v)) for k, v in all_values.items()}
        self.field_max_jump = dict(max_jump)
        self.fitted = True   # needed so _raw_values can run

        raw_lists: Dict[str, List[float]] = {check: [] for check in CHECKS}
        for window in normal_windows:
            raw, _ = self._raw_values(window)
            for check in CHECKS:
                raw_lists[check].append(raw[check])
        self.reference = {check: sorted(values) for check, values in raw_lists.items()}
        self.training_windows = len(normal_windows)
        return self

    # ---------- raw checks --------------------------------------------
    def _raw_values(self, window: TrafficWindow) -> Tuple[Dict[str, float], Dict[str, str]]:
        raw = {check: 0.0 for check in CHECKS}
        evidence: Dict[str, str] = {}

        for (can_id, field_name), values in _field_values(window).items():
            key = self._key(can_id, field_name)
            if key not in self.field_range:
                continue    # unseen field: covered by Stage 1's unknown_ids, not here
            low, high = self.field_range[key]
            width = high - low

            # 1. out_of_range
            overage = max((low - v if v < low else v - high if v > high else 0) for v in values)
            if overage > 0:
                ratio = overage / (width if width > 0 else 1)
                if ratio > raw["out_of_range"]:
                    raw["out_of_range"] = ratio
                    evidence["out_of_range"] = (
                        f"ID {can_id} {field_name}: value out of normal range "
                        f"[{low}, {high}] by {overage}"
                    )

            # 2. frozen_break: normally varies, but held constant all window
            if width > 0 and len(values) >= 2 and min(values) == max(values):
                if width > raw["frozen_break"]:
                    raw["frozen_break"] = float(width)
                    evidence["frozen_break"] = (
                        f"ID {can_id} {field_name}: frozen at {values[0]} for the whole "
                        f"window (normally varies {low}-{high})"
                    )

            # 3. large_jump
            if len(values) >= 2:
                jump = max(abs(b - a) for a, b in zip(values, values[1:]))
                normal_jump = self.field_max_jump.get(key, 0)
                ratio = jump / normal_jump if normal_jump > 0 else float(jump)
                if jump > normal_jump and ratio > raw["large_jump"]:
                    raw["large_jump"] = ratio
                    evidence["large_jump"] = (
                        f"ID {can_id} {field_name}: jump of {jump} between consecutive "
                        f"frames, normal max jump {normal_jump}"
                    )
        return raw, evidence

    # ---------- scoring -----------------------------------------------
    def score(self, window: TrafficWindow) -> Stage2Result:
        """Score one window. Does not modify the window."""
        if not self.fitted:
            raise RuntimeError("Stage 2 is not trained. Call fit() or load() first.")
        if not isinstance(window, TrafficWindow):
            raise TypeError(f"score() needs a TrafficWindow, got {type(window).__name__}")

        raw, evidence = self._raw_values(window)
        sub_scores = {c: _unusualness(raw[c], self.reference[c]) for c in CHECKS}
        top_check = max(CHECKS, key=lambda c: sub_scores[c])
        top_score = sub_scores[top_check]
        normal_top = self.training_windows / (self.training_windows + 1)
        if top_score > normal_top and top_check in evidence:
            text = f"Payload anomaly ({top_check}): {evidence[top_check]}"
        else:
            text = "No payload anomaly beyond normal training range"
        return Stage2Result(score=top_score, sub_scores=sub_scores, evidence=text)

    # ---------- save / load -------------------------------------------
    def save(self, path, model_version: str) -> None:
        if not self.fitted:
            raise RuntimeError("Cannot save an untrained Stage 2 model")
        if not isinstance(model_version, str) or not model_version:
            raise ValueError("model_version must be a non-empty string, e.g. 'v2'")
        record = {
            "model_version": model_version,
            "field_range": self.field_range,
            "field_max_jump": self.field_max_jump,
            "reference": self.reference,
            "training_windows": self.training_windows,
        }
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(record, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path, expected_model_version: str) -> "Stage2Model":
        file = Path(path)
        if not file.exists():
            raise FileNotFoundError(f"No Stage 2 model at {file}. Train and save it first.")
        record = json.loads(file.read_text(encoding="utf-8"))
        if record.get("model_version") != expected_model_version:
            raise ValueError(
                f"Model version mismatch: Stage 2 file is {record.get('model_version')!r}, "
                f"expected {expected_model_version!r}"
            )
        model = cls()
        model.field_range = {k: tuple(v) for k, v in record["field_range"].items()}
        model.field_max_jump = record["field_max_jump"]
        model.reference = record["reference"]
        model.training_windows = record["training_windows"]
        model.fitted = True
        return model