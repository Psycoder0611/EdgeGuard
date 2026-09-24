# EdgeGuard Defender (Part 2: Blue Team)

The Defender looks at one window of CAN traffic and returns **one attack score**, a threshold, a decision (`ATTACK` / `ACCEPT`) and a short evidence text. It runs fully locally, with no cloud connection needed for detection.

> **Status:** v1 and v2 are trained on real ROAD data using a **provisional** split. All results below are from the **development** split only. Official results come from Part 3's evidence gate on the final test set.

---

## How it fits in the system

```
ROAD raw frames
      ↓
Part 1: raw TrafficWindow  (defender/road_reader.py is a fallback until Part 1's make_windows exists)
      ↓
Part 3 (testing only): inject attack into a COPY
      ↓
Part 1: same preprocessing
      ↓
Part 2: score_window(window) -> DefenderOutput      <- this part
      ↓
Simulated consumer (alert / isolate / forward)  and  Part 3 evaluator (joins by window_id)
```

The Defender never receives labels, attack family, injection interval or the attack specification. The shared schema (`shared/schemas.py`) rejects any such field.

---

## What the Defender contains

| Version | Components | Purpose |
|---|---|---|
| **v1** | Stage 1 (timing) | Baseline |
| **v2** | v1's **unchanged** Stage 1 + new Stage 2 (payload), max fusion | Improved candidate |

**Stage 1: timing** (`defender/stage1.py`) learns from normal traffic, per CAN ID: which IDs exist, normal message rate and normal gap between frames. It flags unknown IDs, too many frames and gaps that are too short.

**Stage 2: payload** (`defender/stage2.py`) learns, per watched CAN ID and per field (each byte, and each byte pair as a 16-bit value in both byte orders), the normal value range and the largest normal jump. It flags out-of-range values, a normally-varying field frozen for a whole window, and abnormally large jumps.

**Fusion** (`defender/fusion.py`) takes the **higher** of the two scores. Evidence is labelled `[Stage 1]` or `[Stage 2]`.

**Scores** mean "how unusual compared with normal training windows" (0 to 1). They are **scores, not calibrated probabilities**.

---

## Key design decisions

1. **v2 reuses v1's Stage 1 unchanged.** `train_v2` loads v1's Stage 1, requires the same train and validation captures, and refuses otherwise. The only difference between v1 and v2 is Stage 2, so any improvement can be attributed exactly.
2. **Same false-alarm budget.** v2 uses v1's target false-alarm rate by default.
3. **Threshold chosen on validation only.** `choose_threshold()` picks the lowest threshold keeping `false alarms / normal validation windows <= target`. It is saved together with its model version and refused for any other version.
4. **Stage 2 watch-list: `0D0`, `6E0`.** These are the CAN IDs targeted by the **development** attacks only. On real data, watching all ~100 IDs flagged **170 of 184** normal validation windows (every new drive has some field doing something new). Watching only `0D0, 6E0` flagged **0 of 184**.
5. **Stage 2 learns ranges from every training frame**, not only sampled windows, streamed line by line so memory stays low.
6. **Models are never overwritten silently.** Retraining an existing version needs `--overwrite`.

---

## Setup

```bash
python -m venv .venv
# Windows:      .venv\Scripts\Activate.ps1
# Linux / Nano: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests -q
```

### ROAD data (not in this repository)

Download the ROAD dataset (Verma et al., ORNL) and place it so that these exist:

```
data/road/ambient/*.log
data/road/attacks/*.log
data/road/attacks/capture_metadata.json
```

`data/` is in `.gitignore` and is never uploaded.

---

## Commands

| Task | Command |
|---|---|
| Run all tests | `python -m pytest tests -q` |
| Train v1 and v2 on real data | `python -m defender.run_training --max-false-alarm-rate 0.01` |
| Development check (v1 vs v2) | `python -m defender.dev_check` |
| Local run + latency benchmark (MOCK traffic) | `python -m defender.nano_runner --mock --output results/nano_benchmark_MOCK.json` |
| Diagnostic: Stage 2 on normal validation | `python -m defender.diagnose` |
| Diagnostic: test a watch-list | `python -m defender.diagnose_watch --watch "0D0,6E0"` |

In PowerShell, **quote** CAN ID lists (`"0D0,6E0"`). Otherwise `6E0` is read as the number 6.

Training settings (team-agreed): 1.0 s windows, 0.5 s stride, at most 100 evenly spaced windows per training capture (about 1 MB of memory per real window). Training takes a few minutes on a laptop.

---

## Using the Defender from other parts

```python
from defender.defender import Defender, set_active_defender, score_window

set_active_defender(Defender.load("models", "v2"))   # or "v1"
output = score_window(window)   # TrafficWindow or dict; label fields are rejected
```

`DefenderOutput` fields: `window_id`, `attack_score`, `threshold`, `decision`, `evidence`, `model_version`, `latency_ms`.

`latency_ms` is Defender inference time only. Window collection time is not included.

**Helpers for Part 1 and Part 3** (`defender/road_reader.py`):
- `make_windows(capture_path, capture_id, window_s, stride_s)` has exactly the agreed Part 1 signature.
- `first_timestamp(capture_path)`: ROAD `injection_interval` is in **elapsed seconds from the capture start**, so `elapsed = timestamp - first_timestamp(capture)`.

**ID format:** ROAD metadata writes `0xd0`, while the logs and schema use `0D0`. Use `defender.stage2.normalize_can_id()` to convert.

---

## Provisional split

| Split | Ambient | Attacks (each with its `_masquerade` twin) |
|---|---|---|
| train | drive_basic_long, drive_basic_short, drive_extended_long, drive_radio_infotainment, idle_radio_infotainment, highway_street_driving_long | none |
| validation | drive_extended_short, drive_winter | none |
| development | dyno_reverse, dyno_exercise_all_bits | max_speedometer_1, reverse_light_off_1, reverse_light_on_1, correlated_signal_1, fuzzing_1 |
| final_test | drive_benign_anomaly, highway_street_driving_diagnostics | max_speedometer_2/3, reverse_light_off_2/3, reverse_light_on_2/3, correlated_signal_2/3, fuzzing_2/3, max_engine_coolant_temp |
| separate challenge | none | 4 accelerator captures (no injection interval in our metadata) |

`dyno_reverse` is kept out of training so reverse-light behaviour is not learned as normal. The coolant attack (the only pair, target `4E7`) is in final_test as an honest test of an **unwatched** target ID. Part 1 owns the official split.

---

## Results: DEVELOPMENT split only

Window-level counts (1 s windows, 0.5 s stride, so windows overlap). A window counts as attacked if it overlaps the injection interval.

| Attack family (normal + masquerade) | v1 detected | v2 detected |
|---|---|---|
| max_speedometer | 0 / 100 | **100 / 100** |
| correlated_signal | 4 / 88 | **88 / 88** |
| fuzzing | 8 / 8 | 8 / 8 |
| reverse_light_off / on | 0 / 114 | 0 / 114 |
| **All development attacks** | **12 / 310 (4%)** | **196 / 310 (63%)** |

| Normal traffic | v1 false alarms | v2 false alarms |
|---|---|---|
| Normal windows in attack captures + dyno_reverse | 15 / 636 | 15 / 636 |
| dyno_exercise_all_bits (deliberately unusual) | 15 / 4344 (0.3%) | 333 / 4344 (7.7%) |

Validation (threshold selection, target 1%): v1 and v2 both have threshold 0.964225 and 0 / 184 false alarms.

---

## Known limitations

- **Reverse-light attacks are not detected** by v1 or v2. They set a flag to a value inside the normal range learned by Stage 2.
- **Stage 1 alone catches fuzzing only** on real data. ROAD fabrication attacks do not disturb timing enough to stand out.
- **Attacks on unwatched CAN IDs are invisible to Stage 2** (for example the coolant masquerade on `4E7`). Stage 1 may still see extra frames.
- **Accelerator captures** contain no injected frames and are outside the main results.
- **More false alarms on extreme-but-benign traffic** with v2 (7.7% on `exercise_all_bits`).
- **Provisional split and development-only results.** Final numbers come from Part 3's evidence gate on the final test.
- Stage 1 and Stage 2 are statistical detectors running on the CPU. On the Nano they run locally without a GPU.

---

## Pending

- Nano benchmark with **real** windows (currently mock mode only).
- Official split from Part 1, then retrain with `--overwrite` if it differs.
- Evidence gate (Part 3): compare v1 and v2 on the final test set.

## Data citation

Verma, M. E., et al. *ROAD: The Real ORNL Automotive Dynamometer Controller Area Network Intrusion Detection Dataset.* arXiv:2012.14600, 2020.