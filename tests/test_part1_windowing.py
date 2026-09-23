"""
Tests for part1/windowing.py.

Run from the EdgeGuard folder:
    python -m pytest tests/test_part1_windowing.py -v

Covers the LOCKED team decisions: 1.0 s windows, 1.0 s stride, no overlap,
empty windows kept, final partial window dropped.
"""

import pytest

from part1.windowing import (
    STRIDE_S,
    WINDOW_S,
    make_windows,
    window_id_for,
    windows_from_frames,
)
from shared.schemas import Frame, TrafficWindow


def frame(t, can_id="0F4"):
    return Frame(timestamp=t, can_id=can_id, payload="00")


# ---------- locked decisions ------------------------------------------
def test_locked_window_and_stride():
    assert WINDOW_S == 1.0
    assert STRIDE_S == 1.0


def test_window_id_format():
    assert window_id_for("cap07", 153) == "cap07_w0153"
    assert window_id_for("cap07", 0) == "cap07_w0000"


# ---------- grouping --------------------------------------------------
def test_frames_grouped_into_one_second_windows():
    wins = list(windows_from_frames([frame(0.1), frame(0.9), frame(1.2), frame(2.5)],
                                    "cap07"))
    assert [len(w.frames) for w in wins] == [2, 1]
    assert (wins[0].window_start, wins[0].window_end) == (0.0, 1.0)
    assert (wins[1].window_start, wins[1].window_end) == (1.0, 2.0)


def test_boundary_frame_goes_to_the_later_window():
    """Half-open [start, end): a frame at exactly 1.0 is counted once."""
    wins = list(windows_from_frames([frame(0.5), frame(1.0), frame(2.5)], "cap07"))
    assert [f.timestamp for f in wins[0].frames] == [0.5]
    assert [f.timestamp for f in wins[1].frames] == [1.0]


def test_no_frame_appears_in_two_windows():
    stream = [frame(i * 0.1) for i in range(55)]
    seen = [f.timestamp for w in windows_from_frames(stream, "cap07") for f in w.frames]
    assert len(seen) == len(set(seen))


def test_gap_produces_empty_windows():
    wins = list(windows_from_frames([frame(0.5), frame(3.5), frame(4.5)], "cap07"))
    assert [w.window_id for w in wins] == [
        "cap07_w0000", "cap07_w0001", "cap07_w0002", "cap07_w0003"]
    assert wins[1].frames == [] and wins[2].frames == []


def test_final_partial_window_is_dropped():
    wins = list(windows_from_frames([frame(0.5), frame(1.5), frame(2.3)], "cap07"))
    assert all(f.timestamp != 2.3 for w in wins for f in w.frames)
    assert wins[-1].window_id == "cap07_w0001"


def test_single_window_capture_yields_nothing():
    """Everything is in the final partial window, which is dropped."""
    assert list(windows_from_frames([frame(0.1), frame(0.5)], "cap07")) == []


def test_empty_stream_yields_nothing():
    assert list(windows_from_frames([], "cap07")) == []


# ---------- output contract -------------------------------------------
def test_windows_are_valid_traffic_windows():
    for w in windows_from_frames([frame(0.1), frame(1.1), frame(2.1)], "cap07"):
        assert isinstance(w, TrafficWindow)


def test_features_and_signals_start_empty():
    """preprocess() fills these later, AFTER any injection."""
    for w in windows_from_frames([frame(0.1), frame(1.1), frame(2.1)], "cap07"):
        assert w.features == {} and w.decoded_signals == {}


def test_window_ids_carry_the_capture_id():
    for w in windows_from_frames([frame(0.1), frame(1.1), frame(2.1)], "cap12"):
        assert w.window_id.startswith("cap12_w")
        assert w.capture_id == "cap12"


# ---------- guards ----------------------------------------------------
def test_rejects_overlapping_stride():
    with pytest.raises(NotImplementedError, match="Overlapping"):
        list(windows_from_frames([frame(0.1)], "cap07", window_s=1.0, stride_s=0.5))


def test_rejects_non_positive_window():
    with pytest.raises(ValueError):
        list(windows_from_frames([frame(0.1)], "cap07", window_s=0, stride_s=0))


def test_rejects_out_of_order_frames():
    with pytest.raises(ValueError, match="out of order"):
        list(windows_from_frames([frame(1.5), frame(0.5), frame(2.5)], "cap07"))


# ---------- from a real file ------------------------------------------
def test_make_windows_reads_a_road_log(tmp_path):
    log = tmp_path / "cap.log"
    # 30 frames, 0.1 s apart -> spans 0.0 .. 2.9 s
    log.write_text("\n".join(
        f"({1110000000 + i // 10}.{(i % 10) * 100000:06d}) can0 0F4#960C010204B10240"
        for i in range(30)
    ) + "\n")
    wins = list(make_windows(str(log), "cap01"))
    assert [w.window_id for w in wins] == ["cap01_w0000", "cap01_w0001"]
    assert wins[0].window_start == 0.0
