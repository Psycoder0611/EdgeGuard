"""
Tests for defender/run_training.py.

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_run_training.py -v

Uses a FAKE ROAD folder in a temporary directory, with small fake logs
named like the real ambient files. Never touches the real dataset.
"""

import json

import pytest

from defender.defender import Defender
from defender.run_training import PROVISIONAL_SPLIT, keep_every_for, main, neutral_ids

T0 = 1080000000.0


def write_fake_capture(folder, name, seconds=20.0, seed=0):
    """FAKE ROAD log: 0D0 every 20 ms with a varying byte, 0F4 every 50 ms."""
    lines = []
    for k in range(int(seconds / 0.02)):
        jitter = (((seed * 7 + k * 3) % 5) - 2) * 0.0002
        lines.append((k * 0.02 + jitter, f"0D0#{k % 200:02X}00000000000000"))
    for k in range(int(seconds / 0.05)):
        lines.append((k * 0.05 + 0.003, "0F4#0102030405060708"))
    lines.sort()
    text = "\n".join(f"({T0 + t:.6f}) can0 {rest}" for t, rest in lines) + "\n"
    (folder / f"{name}.log").write_text(text, encoding="utf-8")


@pytest.fixture
def fake_road(tmp_path):
    ambient = tmp_path / "road" / "ambient"
    ambient.mkdir(parents=True)
    for i, name in enumerate(PROVISIONAL_SPLIT["train"] + PROVISIONAL_SPLIT["validation"]):
        write_fake_capture(ambient, name, seed=i)
    return tmp_path


def run(fake_road, *extra):
    return main(["--max-false-alarm-rate", "0.0",
                 "--data-dir", str(fake_road / "road"),
                 "--model-dir", str(fake_road / "models"),
                 "--map-file", str(fake_road / "private" / "map.json"),
                 "--max-windows-per-capture", "10", *extra])


# ---------- Split and ids ---------------------------------------------
def test_split_has_all_12_ambient_captures_once():
    names = [n for group in PROVISIONAL_SPLIT.values() for n in group]
    assert len(names) == 12 and len(set(names)) == 12


def test_reverse_is_not_in_training():
    assert "ambient_dyno_reverse" not in PROVISIONAL_SPLIT["train"]


def test_neutral_ids_are_neutral():
    for cid in neutral_ids().values():
        assert "ambient" not in cid and "attack" not in cid and cid.startswith("cap")


# ---------- Full run on FAKE data -------------------------------------
def test_trains_loadable_v1_and_v2(fake_road):
    assert run(fake_road) == 0
    v1 = Defender.load(fake_road / "models", "v1")
    v2 = Defender.load(fake_road / "models", "v2")
    assert v1.stage2 is None and v2.stage2 is not None


def test_records_team_window_settings(fake_road):
    run(fake_road)
    info = json.loads((fake_road / "models" / "train_info_v1.json").read_text(encoding="utf-8"))
    assert info["window_s"] == 1.0 and info["stride_s"] == 0.5


def test_window_cap_is_respected(fake_road):
    run(fake_road)
    info = json.loads((fake_road / "models" / "train_info_v1.json").read_text(encoding="utf-8"))
    assert info["train_windows"] <= 6 * 10
    assert info["validation_windows"] <= 2 * 10


def test_private_map_written_outside_models(fake_road):
    run(fake_road)
    saved = json.loads((fake_road / "private" / "map.json").read_text(encoding="utf-8"))
    assert saved["ids"] == neutral_ids()
    model_files = " ".join(p.read_text(encoding="utf-8")
                           for p in (fake_road / "models").glob("*.json"))
    assert "ambient" not in model_files        # real names never enter model files


def test_rerun_refuses_to_overwrite(fake_road):
    run(fake_road)
    with pytest.raises(FileExistsError):
        run(fake_road)


def test_overwrite_flag_allows_rerun(fake_road):
    run(fake_road)
    assert run(fake_road, "--overwrite") == 0


# ---------- Required inputs -------------------------------------------
def test_false_alarm_rate_is_required(fake_road):
    with pytest.raises(SystemExit):
        main(["--data-dir", str(fake_road / "road")])


def test_missing_capture_gives_clear_error(fake_road):
    (fake_road / "road" / "ambient" / "ambient_dyno_drive_winter.log").unlink()
    with pytest.raises(SystemExit):
        run(fake_road)


def test_keep_every_for_limits_windows(fake_road):
    path = fake_road / "road" / "ambient" / "ambient_dyno_drive_winter.log"
    # 20 s capture, 1 s window, 0.5 s stride -> about 39 windows; cap 10 -> every 4th
    assert keep_every_for(path, 1.0, 0.5, 10) == 4


def test_default_watch_list_is_recorded(fake_road):
    run(fake_road)
    info = json.loads((fake_road / "models" / "train_info_v2.json").read_text(encoding="utf-8"))
    assert info["stage2_watch_ids"] == ["0D0", "6E0"]


def test_watch_all_option(fake_road):
    run(fake_road, "--stage2-watch", "all")
    info = json.loads((fake_road / "models" / "train_info_v2.json").read_text(encoding="utf-8"))
    assert info["stage2_watch_ids"] is None