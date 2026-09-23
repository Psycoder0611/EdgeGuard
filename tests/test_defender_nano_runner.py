"""
Tests for defender/nano_runner.py.

Run from the EdgeGuard folder with:
    python -m pytest tests/test_defender_nano_runner.py -v

ALL traffic here is MOCK.
"""

import json
import socket

import pytest

from defender.nano_runner import build_mock_defender, main, mock_windows, run_benchmark


@pytest.fixture(scope="module")
def mock_defender():
    return build_mock_defender()


def test_one_record_per_window(mock_defender):
    records, summary = run_benchmark(mock_defender, mock_windows(20), mock_traffic=True)
    assert len(records) == 20 and summary.windows == 20


def test_latency_values_are_valid(mock_defender):
    records, summary = run_benchmark(mock_defender, mock_windows(20), mock_traffic=True)
    assert all(r.latency_ms >= 0 for r in records)
    assert summary.latency_ms_median <= summary.latency_ms_p95 <= summary.latency_ms_max
    assert summary.windows_per_second > 0


def test_mock_attacks_are_counted(mock_defender):
    _, summary = run_benchmark(mock_defender, mock_windows(20), mock_traffic=True)
    assert summary.attack_decisions == 2          # windows 9 and 19 are MOCK fuzzing


def test_mock_results_are_labelled(mock_defender):
    _, summary = run_benchmark(mock_defender, mock_windows(5), mock_traffic=True)
    assert summary.mock_traffic is True
    assert "MOCK" in summary.note and "NOT a detection result" in summary.note


def test_single_window_works(mock_defender):
    _, summary = run_benchmark(mock_defender, mock_windows(1), mock_traffic=True)
    assert summary.latency_ms_p95 == summary.latency_ms_max


def test_runs_with_network_blocked(mock_defender, monkeypatch):
    """Primary detection must not need any network connection."""
    def no_network(*args, **kwargs):
        raise AssertionError("Defender tried to open a network connection")
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    records, _ = run_benchmark(mock_defender, mock_windows(10), mock_traffic=True)
    assert len(records) == 10


def test_rejects_empty_window_list(mock_defender):
    with pytest.raises(ValueError, match="No windows"):
        run_benchmark(mock_defender, [], mock_traffic=True)


def test_rejects_non_defender():
    with pytest.raises(TypeError, match="needs a Defender"):
        run_benchmark("not a defender", mock_windows(1), mock_traffic=True)


def test_command_line_mock_run_saves_results(tmp_path, capsys):
    out = tmp_path / "bench.json"
    assert main(["--mock", "--windows", "15", "--output", str(out)]) == 0
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["summary"]["windows"] == 15
    assert saved["summary"]["mock_traffic"] is True
    assert len(saved["windows"]) == 15
    assert "MOCK traffic" in capsys.readouterr().out


def test_command_line_refuses_real_mode_for_now(tmp_path):
    with pytest.raises(SystemExit):
        main(["--output", str(tmp_path / "x.json")])