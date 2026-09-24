"""
Tests for defender/crossval.py.

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_crossval.py -v

Uses a FAKE ROAD folder and a FAKE splits.json in a temporary directory.
Never touches the real dataset.
"""

import json

import pytest

from defender import crossval
from defender.crossval import (ambient_loco, attack_type, binomial_upper_95,
                               capture_path, fold_watch_ids, load_ambient, load_split, main,
                               provisional_split)
from defender.road_reader import iter_frames
from defender.stage2 import Stage2Model

T0 = 1080000000.0
AMBIENT = ["amb_a", "amb_b", "amb_c", "amb_d", "amb_e"]
TEST_AMBIENT = ["amb_test"]
FOLD1 = ["speed_attack_1", "speed_attack_1_masquerade"]
FOLD2 = ["speed_attack_2", "speed_attack_2_masquerade"]
TEST_ATTACKS = ["speed_attack_3"]


def write_capture(path, seconds=20.0, seed=0, inject=None):
    """FAKE ROAD log: 0D0 every 20 ms with a varying byte, 0F4 every 50 ms.
    inject=(start, end): 0D0 byte 0 forced to FF inside that elapsed interval."""
    lines = []
    for k in range(int(seconds / 0.02)):
        t = k * 0.02 + (((seed * 7 + k * 3) % 5) - 2) * 0.0002
        byte0 = "FF" if inject and inject[0] <= t <= inject[1] else f"{k % 200:02X}"
        lines.append((t, f"0D0#{byte0}00000000000000"))
    for k in range(int(seconds / 0.05)):
        lines.append((k * 0.05 + 0.003, "0F4#0102030405060708"))
    lines.sort()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"({T0 + t:.6f}) can0 {rest}" for t, rest in lines) + "\n",
                    encoding="utf-8")


@pytest.fixture
def fake_road(tmp_path):
    road = tmp_path / "road"
    for i, name in enumerate(AMBIENT):
        write_capture(road / "ambient" / f"{name}.log", seed=i)
    metadata = {}
    for name in FOLD1 + FOLD2:
        write_capture(road / "attacks" / f"{name}.log", inject=(8.0, 12.0))
        metadata[name] = {"injection_id": "0xd0", "injection_interval": [8.0, 12.0]}
    # TEST captures are deliberately NOT written: reading one would crash the test.
    for name in TEST_ATTACKS:
        metadata[name] = {"injection_id": "0xd0", "injection_interval": [8.0, 12.0]}
    (road / "attacks" / "capture_metadata.json").write_text(json.dumps(metadata))
    splits = {"schema_version": 2,
              "train": {"ambient": AMBIENT[:3], "attacks": FOLD1 + FOLD2},
              "val": {"ambient": AMBIENT[3:], "attacks": []},
              "test": {"ambient": TEST_AMBIENT, "attacks": TEST_ATTACKS},
              "cv_folds": {"fold_1_holds_out": FOLD1, "fold_2_holds_out": FOLD2}}
    (tmp_path / "splits.json").write_text(json.dumps(splits))
    return tmp_path


def quiet(*_):
    pass


# ---------- Statistics ------------------------------------------------
def test_binomial_upper_zero_alarms_matches_closed_form():
    # k = 0: upper bound is 1 - 0.05 ** (1 / n)
    assert binomial_upper_95(0, 100) == pytest.approx(1 - 0.05 ** (1 / 100), rel=1e-6)


def test_binomial_upper_is_above_observed_rate():
    assert 5 / 200 < binomial_upper_95(5, 200) < 0.06
    assert binomial_upper_95(3, 3) == 1.0 and binomial_upper_95(0, 0) == 1.0


# ---------- Split -----------------------------------------------------
def test_load_split_reads_folds_and_forbids_test(fake_road):
    split = load_split(fake_road / "splits.json")
    assert split.ambient["train"] == AMBIENT[:3]
    assert split.ambient["validation"] == AMBIENT[3:]
    assert split.attack_folds == {1: FOLD1, 2: FOLD2}
    assert split.forbidden == frozenset(TEST_AMBIENT + TEST_ATTACKS)


def test_capture_path_refuses_test_captures(fake_road):
    split = load_split(fake_road / "splits.json")
    with pytest.raises(ValueError, match="TEST capture"):
        capture_path(fake_road / "road", split, "speed_attack_3", "attacks")
    with pytest.raises(ValueError, match="TEST capture"):
        capture_path(fake_road / "road", split, "amb_test")


def test_provisional_split_forbids_final_test():
    split = provisional_split()
    assert split.attack_folds is None
    for name in split.ambient["final_test"]:
        with pytest.raises(ValueError, match="TEST capture"):
            capture_path("data/road", split, name)


def test_load_split_rejects_test_capture_in_a_fold(fake_road):
    record = json.loads((fake_road / "splits.json").read_text())
    record["cv_folds"]["fold_1_holds_out"].append("speed_attack_3")
    bad = fake_road / "bad.json"
    bad.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="TEST captures"):
        load_split(bad)


# ---------- Stage 2 precomputed range stats ---------------------------
def test_range_stats_give_the_same_stage2_model(fake_road):
    split = load_split(fake_road / "splits.json")
    ids = {n: f"cap{i:02d}" for i, n in enumerate(AMBIENT, start=1)}
    windows, stats = load_ambient(AMBIENT[:2], fake_road / "road", split, ids, 1.0, 0.5, 10,
                                  ["0D0"], quiet)
    train = windows[AMBIENT[0]] + windows[AMBIENT[1]]
    paths = [fake_road / "road" / "ambient" / f"{n}.log" for n in AMBIENT[:2]]
    a = Stage2Model(watch_ids=["0D0"]).fit(train, range_captures=[iter_frames(p) for p in paths])
    b = Stage2Model(watch_ids=["0D0"]).fit(train, range_stats=[stats[n] for n in AMBIENT[:2]])
    assert a.field_range == b.field_range
    assert a.field_max_jump == b.field_max_jump
    assert a.reference == b.reference


# ---------- Protocol 1: ambient LOCO -----------------------------------
def test_loco_never_fits_on_the_held_out_capture(fake_road, monkeypatch):
    split = load_split(fake_road / "splits.json")
    ids = {n: f"cap{i:02d}" for i, n in enumerate(AMBIENT, start=1)}
    names = AMBIENT[:4]
    windows, stats = load_ambient(names, fake_road / "road", split, ids, 1.0, 0.5, 10,
                                  ["0D0"], quiet)
    fits = []
    real_fit = crossval.fit_models

    def spy(fit_names, *args):
        fits.append(list(fit_names))
        return real_fit(fit_names, *args)

    monkeypatch.setattr(crossval, "fit_models", spy)
    report = ambient_loco(names, windows, stats, 0.1, ["0D0"], log=quiet)

    per_outer = len(names)            # (len - 1) inner fits + 1 outer fit per held-out capture
    assert len(fits) == len(names) * per_outer
    for i, held_out in enumerate(names):
        for fit_names in fits[i * per_outer:(i + 1) * per_outer]:
            assert held_out not in fit_names
    assert [r["capture_id"] for r in report["per_capture"]] == [ids[n] for n in names]
    for v in ("v1", "v2"):
        s = report["summary"][v]
        assert s["windows"] == sum(len(windows[n]) for n in names)
        assert 0 <= s["alarms"] <= s["windows"]


def test_loco_needs_three_captures(fake_road):
    with pytest.raises(ValueError, match="at least 3"):
        ambient_loco(["a", "b"], {}, {}, 0.01, None, log=quiet)


# ---------- Protocol 2: attack 2-fold CV --------------------------------
def test_attack_type_strips_index_and_masquerade():
    assert attack_type("max_speedometer_attack_1_masquerade") == "max_speedometer_attack"
    assert attack_type("correlated_signal_attack_2") == "correlated_signal_attack"


def test_fold_watch_ids_ignore_fuzzing_and_accelerator():
    metadata = {"a": {"injection_id": "0xd0"}, "b": {"injection_id": "0x6e0"},
                "fuzz": {"injection_id": "XXX"}, "accel": {"injection_id": None}}
    assert fold_watch_ids(["a", "b", "fuzz", "accel"], metadata) == ["0D0", "6E0"]
    with pytest.raises(ValueError, match="no targeted attacks"):
        fold_watch_ids(["fuzz", "accel"], metadata)


def test_attack_cv_refuses_split_without_folds():
    with pytest.raises(ValueError, match="no cv_folds"):
        crossval.attack_cv(provisional_split(), "data/road", {}, 0.01, 1.0, 0.5, 10, log=quiet)


def test_attack_cv_runs_and_counts_masquerade_normal_windows_once(fake_road):
    split = load_split(fake_road / "splits.json")
    metadata = json.loads((fake_road / "road" / "attacks" / "capture_metadata.json").read_text())
    report = crossval.attack_cv(split, fake_road / "road", metadata, 0.1, 1.0, 0.5, 10,
                                log=quiet)
    assert [f["watch_ids"] for f in report["folds"]] == [["0D0"], ["0D0"]]
    rows = {r["capture_id"]: r for r in report["per_capture"]}
    assert len(rows) == 4
    for r in rows.values():
        assert r["attacked"] > 0
        if r["condition"] == "masquerade":
            assert r["normal"] == 0          # its normal windows are the twin's
        else:
            assert r["normal"] > 0
    # byte0 = FF is outside the normal 0..199 range, so v2 must catch it
    assert report["summary"]["v2"]["all"]["macro_recall"] > 0.5


# ---------- Command line ----------------------------------------------
def test_main_ambient_writes_report(fake_road):
    out = fake_road / "out" / "loco.json"
    assert main(["ambient", "--max-false-alarm-rate", "0.1",
                 "--data-dir", str(fake_road / "road"),
                 "--split", str(fake_road / "splits.json"),
                 "--max-windows-per-capture", "10", "--stage2-watch", "0D0",
                 "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["captures"] == 5            # 3 train + 2 validation, never test
    assert report["settings"]["stage2_watch_ids"] == ["0D0"]


def test_main_attacks_writes_report(fake_road):
    out = fake_road / "out" / "attacks.json"
    assert main(["attacks", "--max-false-alarm-rate", "0.1",
                 "--data-dir", str(fake_road / "road"),
                 "--split", str(fake_road / "splits.json"),
                 "--max-windows-per-capture", "10", "--out", str(out)]) == 0
    assert len(json.loads(out.read_text())["per_capture"]) == 4
