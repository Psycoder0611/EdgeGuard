"""Tests for rule-based Red Team proposals using made-up traffic.

Run from EdgeGuard: python -m pytest tests/test_red_team_agent.py -v
"""

import pytest

from part3.attack_injector import inject_freeze
from part3.red_team_agent import propose_freeze
from shared.schemas import TrafficWindow


def sample_window():
    return TrafficWindow(
        window_id="cap07_w0001",
        capture_id="cap07",
        window_start=100.0,
        window_end=101.0,
        frames=[
            {"timestamp": 100.1, "can_id": "0F4", "payload": "01"},
            {"timestamp": 100.2, "can_id": "1A0", "payload": "AA"},
            {"timestamp": 100.3, "can_id": "0f4", "payload": "02"},
            {"timestamp": 100.4, "can_id": "0F4", "payload": "03"},
            {"timestamp": 100.5, "can_id": "1A0", "payload": "AA"},
        ],
    )


def test_proposes_attack_that_injector_can_apply_without_changing_source():
    source = sample_window()
    proposal = propose_freeze(source, attack_id="atk_demo")
    assert proposal.attack_id == "atk_demo"
    assert proposal.family == "freeze"
    assert proposal.target_can_id == "0F4"
    assert proposal.duration_ms == pytest.approx(1000.0)

    attacked = inject_freeze(source, proposal)
    assert [frame.payload for frame in source.frames] == ["01", "AA", "02", "03", "AA"]
    assert [frame.payload for frame in attacked.frames] == ["01", "AA", "01", "01", "AA"]


def test_rejects_constant_payloads():
    source = sample_window()
    for frame in source.frames:
        if frame.can_id.upper() == "0F4":
            frame.payload = "01"
    with pytest.raises(ValueError, match="no CAN ID has changing payloads"):
        propose_freeze(source)


def test_rejects_preprocessed_window():
    source = sample_window()
    source.features = {"frame_count": 5.0}
    with pytest.raises(ValueError, match="raw window"):
        propose_freeze(source)


def test_rejects_zero_duration_window():
    source = TrafficWindow(
        window_id="cap07_w0002",
        capture_id="cap07",
        window_start=100.0,
        window_end=100.0,
        frames=[],
    )
    with pytest.raises(ValueError, match="positive duration"):
        propose_freeze(source)
