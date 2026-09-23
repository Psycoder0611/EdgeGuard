"""Tests for part3/attack_injector.py; all frames here are mock data.

Run from EdgeGuard: python -m pytest tests/test_attack_injector.py -v
"""

import pytest

from part3.attack_injector import inject_freeze
from part3.attack_spec import AttackSpec
from shared.schemas import TrafficWindow


def sample_window():
    return TrafficWindow(
        window_id="cap07_w0153",
        capture_id="cap07",
        window_start=100.0,
        window_end=101.0,
        frames=[
            {"timestamp": 100.100, "can_id": "0F4", "payload": "01"},
            {"timestamp": 100.150, "can_id": "1A0", "payload": "99"},
            {"timestamp": 100.200, "can_id": "0f4", "payload": "02"},
            {"timestamp": 100.300, "can_id": "0F4", "payload": "03"},
            {"timestamp": 100.800, "can_id": "0F4", "payload": "04"},
        ],
    )


def freeze_spec(**changes):
    values = dict(
        attack_id="atk_001",
        family="freeze",
        target_can_id="0F4",
        start_offset_ms=0,
        duration_ms=500,
    )
    values.update(changes)
    return AttackSpec(**values)


def test_freeze_changes_only_matching_frames_and_preserves_source():
    source = sample_window()
    attacked = inject_freeze(source, freeze_spec())

    assert attacked.window_id == "cap07_w0153_v01"
    assert attacked.capture_id == source.capture_id
    assert [f.payload for f in attacked.frames] == ["01", "99", "01", "01", "04"]
    assert [f.payload for f in source.frames] == ["01", "99", "02", "03", "04"]
    assert [f.timestamp for f in attacked.frames] == [f.timestamp for f in source.frames]
    assert attacked.features == {} and attacked.decoded_signals == {}


def test_second_variant_gets_a_distinct_neutral_id():
    attacked = inject_freeze(sample_window(), freeze_spec(), variant_index=2)
    assert attacked.window_id == "cap07_w0153_v02"


def test_interval_uses_window_start_in_milliseconds():
    attacked = inject_freeze(
        sample_window(), freeze_spec(start_offset_ms=150, duration_ms=200)
    )
    # The frame at 100.100 is outside; 100.200 and 100.300 are inside.
    assert [f.payload for f in attacked.frames] == ["01", "99", "02", "02", "04"]


@pytest.mark.parametrize(
    "changes",
    [
        {"target_can_id": "ABC"},
        {"start_offset_ms": 900, "duration_ms": 100},
        {"start_offset_ms": 0, "duration_ms": 150},
    ],
)
def test_rejects_attack_that_changes_no_frames(changes):
    with pytest.raises(ValueError):
        inject_freeze(sample_window(), freeze_spec(**changes))


def test_rejects_preprocessed_input():
    source = sample_window()
    source.features = {"frame_count": 5.0}
    with pytest.raises(ValueError, match="raw window"):
        inject_freeze(source, freeze_spec())


def test_rejects_invalid_variant_index():
    with pytest.raises(ValueError, match="positive integer"):
        inject_freeze(sample_window(), freeze_spec(), variant_index=0)
