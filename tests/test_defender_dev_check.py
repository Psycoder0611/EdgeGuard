"""
Tests for defender/dev_check.py (window labelling logic only).

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_dev_check.py -v
"""

from defender.dev_check import DEVELOPMENT_ATTACKS, overlaps
from shared.schemas import TrafficWindow

T0 = 1080000000.0


def window(start_elapsed, length=1.0):
    return TrafficWindow(window_id="cap13_w00000", capture_id="cap13",
                         window_start=T0 + start_elapsed,
                         window_end=T0 + start_elapsed + length, frames=[])


def test_window_inside_interval_is_attacked():
    assert overlaps(window(10.0), T0, [9.0, 30.0])


def test_window_partly_overlapping_is_attacked():
    assert overlaps(window(8.5), T0, [9.0, 30.0])


def test_window_before_interval_is_normal():
    assert not overlaps(window(7.0), T0, [9.0, 30.0])


def test_window_after_interval_is_normal():
    assert not overlaps(window(31.0), T0, [9.0, 30.0])


def test_uses_elapsed_time_not_raw_timestamp():
    """Raw timestamps (~1080000000) must never be compared with the interval."""
    assert not overlaps(window(100.0), T0, [9.0, 30.0])
    assert overlaps(window(10.0), T0, [9.0, 30.0])


def test_development_list_has_no_final_test_or_accelerator_captures():
    for name in DEVELOPMENT_ATTACKS:
        assert "_2" not in name and "_3" not in name
        assert "coolant" not in name and "accelerator" not in name