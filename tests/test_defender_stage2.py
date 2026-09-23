"""
Tests for defender/stage2.py.

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_stage2.py -v

ALL windows here are MOCK traffic made up for testing. They imitate the
shape of the ROAD masquerade families (a forced/frozen byte or an
out-of-range value) but are not real data, so these tests prove the
logic works, not how well it does on ROAD.
"""

import pytest

from defender.stage1 import Stage1Model
from defender.stage2 import Stage2Model
from defender.threshold import ATTACK, ACCEPT, choose_threshold, make_decision
from shared.schemas import TrafficWindow

# MOCK normal traffic: ID -> period in seconds, and a payload generator
MOCK_PERIODS = {"0D0": 0.010, "0F4": 0.020}


def mock_payload(can_id: str, k: int) -> str:
    """Deterministic, varying MOCK payload (0D0 byte0 cycles, 0F4 pair0 cycles)."""
    if can_id == "0D0":
        b0 = k % 200          # varies a lot, like a real signal or counter
        return f"{b0:02X}00000000000000"
    pair = (1000 + k * 7) % 4000     # varies, e.g. a 2-byte speed-like value
    b0, b1 = pair >> 8, pair & 0xFF
    return f"{b0:02X}{b1:02X}0000000000000"[:16]


def make_normal_window(index: int) -> TrafficWindow:
    """MOCK 1-second window with varying payloads, normal timing."""
    start = 1000.0 + index
    frames = []
    for can_id, period in MOCK_PERIODS.items():
        count = int(round(1.0 / period))
        for k in range(count):
            t = round(start + 0.001 + k * period, 6)
            frames.append({"timestamp": t, "can_id": can_id,
                           "payload": mock_payload(can_id, index * 100 + k)})
    frames.sort(key=lambda f: f["timestamp"])
    return TrafficWindow(window_id=f"cap01_w{index:04d}", capture_id="cap01",
                         window_start=start, window_end=start + 1.0, frames=frames)


def with_payload_override(window: TrafficWindow, can_id: str, payload: str) -> TrafficWindow:
    """MOCK masquerade: return a COPY where every frame of can_id has this payload."""
    data = window.model_dump()
    for frame in data["frames"]:
        if frame["can_id"] == can_id:
            frame["payload"] = payload
    return TrafficWindow(**data)


@pytest.fixture(scope="module")
def model():
    return Stage2Model().fit([make_normal_window(i) for i in range(40)])


@pytest.fixture(scope="module")
def normal_validation_scores(model):
    return [model.score(make_normal_window(i)).score for i in range(100, 130)]


# ---------- MOCK attacks (masquerade-style) ----------------------------
def frozen_byte_window():
    """0D0 byte0 held at a value it never reaches in training -> out_of_range AND frozen."""
    w = make_normal_window(200)
    return with_payload_override(w, "0D0", "FF00000000000000")


def frozen_but_in_range_window():
    """0D0 byte0 held constant at a value seen in training -> frozen_break only."""
    w = make_normal_window(201)
    return with_payload_override(w, "0D0", "0500000000000000")


def large_jump_window():
    """One 0D0 frame jumps far beyond any training jump, then returns."""
    w = make_normal_window(202)
    data = w.model_dump()
    d0_frames = [f for f in data["frames"] if f["can_id"] == "0D0"]
    d0_frames[len(d0_frames) // 2]["payload"] = "C800000000000000"   # 200, far from neighbours
    return TrafficWindow(**data)


def timing_only_attack_window():
    """Extra unknown-ID frames: Stage 1's job, NOT Stage 2's. Payload content is untouched."""
    data = make_normal_window(203).model_dump()
    data["frames"].append({"timestamp": data["window_start"] + 0.5, "can_id": "7FF",
                           "payload": "FFFFFFFFFFFFFFFF"})
    return TrafficWindow(**data)


# ---------- Normal behaviour ------------------------------------------
def test_scores_are_between_zero_and_one(model):
    for w in [make_normal_window(300), frozen_byte_window(), large_jump_window()]:
        result = model.score(w)
        assert 0.0 <= result.score < 1.0
        assert set(result.sub_scores) == {"out_of_range", "frozen_break", "large_jump"}


def test_normal_window_has_no_payload_evidence(model):
    result = model.score(make_normal_window(5))       # a training window
    assert "No payload anomaly" in result.evidence


def test_scoring_is_deterministic(model):
    w = frozen_byte_window()
    assert model.score(w).score == model.score(w).score


# ---------- Attacks score above all normal windows ----------------------
def test_out_of_range_value_detected(model, normal_validation_scores):
    """Forcing 0D0 byte0 out of range also forces its byte-pair fields out of
    range; either evidence is correct, since the score is the max over all
    fields. This test only checks the attack is caught and attributed to 0D0."""
    result = model.score(frozen_byte_window())
    assert result.score > max(normal_validation_scores)
    assert "0D0" in result.evidence


def test_frozen_in_range_value_detected(model, normal_validation_scores):
    result = model.score(frozen_but_in_range_window())
    assert result.score > max(normal_validation_scores)
    assert "frozen_break" in result.evidence


def test_large_jump_detected(model, normal_validation_scores):
    result = model.score(large_jump_window())
    assert result.score > max(normal_validation_scores)
    assert "large_jump" in result.evidence


def test_timing_only_attack_is_a_known_limit(model):
    """An attack that only adds an unknown ID (no payload change) is Stage 1's job."""
    original = make_normal_window(203)
    assert model.score(timing_only_attack_window()).score == model.score(original).score


# ---------- Byte-pair (2-byte / 16-bit) detection -----------------------
def test_two_byte_value_out_of_range_detected(model, normal_validation_scores):
    """0F4's first pair (bytes 0-1) held far outside its trained 1000-5000 range."""
    w = with_payload_override(make_normal_window(204), "0F4", "FFFF000000000000")
    result = model.score(w)
    assert result.score > max(normal_validation_scores)
    assert "pair0" in result.evidence


# ---------- Works with threshold.py and alongside Stage 1 ----------------
def test_end_to_end_with_threshold(model, normal_validation_scores):
    threshold = choose_threshold(normal_validation_scores, 0.0)
    for s in normal_validation_scores:
        assert make_decision(s, threshold) == ACCEPT
    for w in [frozen_byte_window(), frozen_but_in_range_window(), large_jump_window()]:
        assert make_decision(model.score(w).score, threshold) == ATTACK


def test_stage1_and_stage2_are_complementary(model):
    """Stage 1 catches timing-only attacks that Stage 2 does not, and vice versa."""
    stage1 = Stage1Model().fit([make_normal_window(i) for i in range(40)])
    timing_attack = timing_only_attack_window()
    payload_attack = frozen_byte_window()

    assert stage1.score(timing_attack).score > stage1.score(make_normal_window(0)).score
    assert model.score(timing_attack).score == model.score(make_normal_window(203)).score

    assert model.score(payload_attack).score > model.score(make_normal_window(0)).score


# ---------- Safety -------------------------------------------------------
def test_scoring_does_not_modify_window(model):
    w = frozen_byte_window()
    before = w.model_dump()
    model.score(w)
    assert w.model_dump() == before


def test_lowercase_ids_match_uppercase(model):
    w = make_normal_window(301)
    data = w.model_dump()
    for frame in data["frames"]:
        frame["can_id"] = frame["can_id"].lower()
    lower = TrafficWindow(**data)
    assert model.score(lower).score == model.score(w).score


# ---------- Invalid use ----------------------------------------------------
def test_score_before_fit_gives_clear_error():
    with pytest.raises(RuntimeError, match="not trained"):
        Stage2Model().score(make_normal_window(0))


def test_fit_rejects_empty_list():
    with pytest.raises(ValueError, match="at least 2"):
        Stage2Model().fit([])


def test_fit_rejects_non_window():
    with pytest.raises(TypeError, match="expected TrafficWindow"):
        Stage2Model().fit([make_normal_window(0), {"frames": []}])


def test_score_rejects_dictionary(model):
    with pytest.raises(TypeError, match="needs a TrafficWindow"):
        model.score({"frames": []})


def test_unseen_can_id_does_not_crash(model):
    """A CAN ID never seen in training: Stage 2 skips it (Stage 1's job)."""
    data = make_normal_window(302).model_dump()
    data["frames"].append({"timestamp": data["window_start"] + 0.5, "can_id": "7FF",
                           "payload": "0000000000000000"})
    result = model.score(TrafficWindow(**data))
    assert 0.0 <= result.score <= 1.0


# ---------- Save / load ------------------------------------------------
def test_save_and_load_give_identical_scores(model, tmp_path):
    path = tmp_path / "stage2_v2.json"
    model.save(path, "v2")
    loaded = Stage2Model.load(path, "v2")
    for w in [make_normal_window(400), frozen_byte_window(), large_jump_window()]:
        assert loaded.score(w).score == model.score(w).score


def test_load_refuses_other_model_version(model, tmp_path):
    path = tmp_path / "stage2_v2.json"
    model.save(path, "v2")
    with pytest.raises(ValueError, match="Model version mismatch"):
        Stage2Model.load(path, "v3")


def test_cannot_save_untrained_model(tmp_path):
    with pytest.raises(RuntimeError, match="untrained"):
        Stage2Model().save(tmp_path / "x.json", "v2")