"""
Tests for defender/road_reader.py.

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_road_reader.py -v

Uses small FAKE log files written to a temporary folder, never the real
dataset. Their lines copy the real ROAD format.
"""

import hashlib

import pytest
from pydantic import ValidationError

from defender.road_reader import first_timestamp, last_timestamp, make_windows, parse_line

T0 = 1080000000.0


def write_log(tmp_path, times_ids, name="cap01.log"):
    """FAKE log: one line per (elapsed_seconds, can_id)."""
    lines = [f"({T0 + t:.6f}) can0 {cid}#0011223344556677" for t, cid in times_ids]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def regular_log(tmp_path, seconds=5.0, period=0.1):
    """FAKE log: ID 0D0 every `period` seconds for `seconds` seconds."""
    count = int(round(seconds / period))
    return write_log(tmp_path, [(k * period, "0D0") for k in range(count)])


# ---------- Line parsing ----------------------------------------------
def test_parses_real_road_line_format():
    assert parse_line("(1080000000.001017) can0 0D7#0000020080000000", 1) == \
        (1080000000.001017, "0D7", "0000020080000000")


def test_lowercase_hex_is_uppercased():
    assert parse_line("(1.5) can0 0d7#00ff", 1) == (1.5, "0D7", "00FF")


def test_empty_payload_is_allowed():
    assert parse_line("(1.5) can0 0D7#", 1) == (1.5, "0D7", "")


def test_malformed_line_names_line_number():
    with pytest.raises(ValueError, match="line 7"):
        parse_line("garbage here", 7)


# ---------- Windowing --------------------------------------------------
def test_non_overlapping_windows_count_every_frame_once(tmp_path):
    path = regular_log(tmp_path, seconds=5.0, period=0.1)     # 50 frames, 0.0 .. 4.9
    windows = list(make_windows(path, "cap01", 1.0, 1.0))
    assert len(windows) == 4                                   # 5th window only partly covered
    assert [len(w.frames) for w in windows] == [10, 10, 10, 10]


def test_window_ids_and_bounds(tmp_path):
    path = regular_log(tmp_path)
    windows = list(make_windows(path, "cap07", 1.0, 1.0))
    assert windows[0].window_id == "cap07_w00000"
    assert windows[1].window_id == "cap07_w00001"
    assert windows[0].window_start == T0 and windows[0].window_end == T0 + 1.0
    assert windows[1].window_start == T0 + 1.0


def test_features_are_empty(tmp_path):
    w = next(make_windows(regular_log(tmp_path), "cap01", 1.0, 1.0))
    assert w.features == {} and w.decoded_signals == {}


def test_overlapping_windows(tmp_path):
    path = regular_log(tmp_path, seconds=5.0, period=0.1)
    windows = list(make_windows(path, "cap01", 1.0, 0.5))
    assert windows[1].window_start == T0 + 0.5
    assert all(len(w.frames) == 10 for w in windows)
    assert len(windows) == 8


def test_gap_in_data_gives_empty_window(tmp_path):
    path = write_log(tmp_path, [(0.1, "0D0"), (0.5, "0D0"), (2.2, "0D0"), (3.5, "0D0")])
    windows = list(make_windows(path, "cap01", 1.0, 1.0))
    assert [len(w.frames) for w in windows] == [2, 0, 1]


def test_frames_stay_in_time_order(tmp_path):
    path = write_log(tmp_path, [(0.1, "0D0"), (0.2, "1A0"), (0.3, "0F4"), (1.5, "0D0")])
    w = next(make_windows(path, "cap01", 1.0, 1.0))
    assert [f.can_id for f in w.frames] == ["0D0", "1A0", "0F4"]


def test_is_lazy_generator(tmp_path):
    """Windows are produced one at a time, so huge files are not loaded at once."""
    gen = make_windows(regular_log(tmp_path), "cap01", 1.0, 1.0)
    assert next(gen).window_id == "cap01_w00000"


# ---------- Safety -----------------------------------------------------
def test_capture_file_is_not_modified(tmp_path):
    path = regular_log(tmp_path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    list(make_windows(path, "cap01", 1.0, 1.0))
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_rejects_revealing_capture_id(tmp_path):
    with pytest.raises(ValidationError, match="neutral"):
        list(make_windows(regular_log(tmp_path), "fuzzing_attack_1", 1.0, 1.0))


def test_malformed_file_stops_with_line_number(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("(1.0) can0 0D0#00\nthis is not a can frame\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        list(make_windows(path, "cap01", 1.0, 1.0))


@pytest.mark.parametrize("window_s, stride_s", [(0.0, 1.0), (1.0, 0.0)])
def test_rejects_non_positive_settings(tmp_path, window_s, stride_s):
    with pytest.raises(ValueError, match="positive"):
        list(make_windows(regular_log(tmp_path), "cap01", window_s, stride_s))


# ---------- first_timestamp for the evaluator --------------------------
def test_first_timestamp(tmp_path):
    assert first_timestamp(regular_log(tmp_path)) == T0


def test_first_timestamp_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="no CAN frames"):
        first_timestamp(path)




# ---------- last_timestamp and keep_every ------------------------------
def test_last_timestamp(tmp_path):
    path = regular_log(tmp_path, seconds=5.0, period=0.1)
    assert abs(last_timestamp(path) - (T0 + 4.9)) < 1e-6


def test_last_timestamp_single_line(tmp_path):
    path = write_log(tmp_path, [(0.25, "0D0")])
    assert abs(last_timestamp(path) - (T0 + 0.25)) < 1e-6


def test_keep_every_skips_windows_but_keeps_ids(tmp_path):
    path = regular_log(tmp_path, seconds=10.0, period=0.1)
    all_windows = list(make_windows(path, "cap01", 1.0, 1.0))
    kept = list(make_windows(path, "cap01", 1.0, 1.0, keep_every=3))
    assert [w.window_id for w in kept] == [w.window_id for w in all_windows[::3]]
    assert kept[1].model_dump() == all_windows[3].model_dump()


def test_keep_every_rejects_zero(tmp_path):
    with pytest.raises(ValueError, match="keep_every"):
        list(make_windows(regular_log(tmp_path), "cap01", 1.0, 1.0, keep_every=0))



def test_iter_frames_streams_every_frame(tmp_path):
    from defender.road_reader import iter_frames
    frames = list(iter_frames(regular_log(tmp_path, seconds=1.0, period=0.1)))
    assert len(frames) == 10 and frames[0] == (T0, "0D0", "0011223344556677")