# CLAUDE.md

Guidance for Claude Code and teammates working in this repo: what exists, what is still open, and the rules that keep the results honest.

## What this is

EdgeGuard is an on-vehicle CAN bus intrusion detector, built on the ROAD dataset (real CAN recordings from one car, with injected attacks). The team splits the work into parts:

| Part | Owner area | Folder |
|---|---|---|
| Part 1 | Reading captures, windowing, preprocessing, official split | `part1/` |
| Part 2 | The Defender: detection models, training, threshold, cross-validation | `defender/` |
| Part 3 | Red team, injector, evaluator, evidence gate | not in this repo yet |
| Member 4 | Dashboard and demo UI | `dashboard/` |
| Shared | Data contracts between parts | `shared/schemas.py` |

**Deadline:** submission Fri 25 Sep 2026, 8pm (from `~/Downloads/road/CLAUDE.md`).

## Where the data is

The ROAD dataset is **not** in this repo and must never be committed. `.gitignore` blocks `data/`, `*.log` and `*.csv`.

- On this machine: `~/Downloads/road/dataset/` (`ambient/`, `attacks/`, `attacks/capture_metadata.json`).
- The code defaults to `data/road/`, which does not exist. Either pass `--data-dir ~/Downloads/road/dataset`, or link it once: `mkdir -p data && ln -s ~/Downloads/road/dataset data/road`.

`~/Downloads/road/` is also a **separate, more complete preprocessing project** (`edgeguard/` package, `splits.json`, `docs/00–06`). It is not a git repo. See "What to do next".

## Commands

Run from the repo root. The environment is a local `.venv` (gitignored): `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`.

| Task | Command |
|---|---|
| All tests (309, about 20 s) | `.venv/bin/python -m pytest -q` |
| Train v1 + v2 | `python -m defender.run_training --max-false-alarm-rate 0.01 --data-dir <road>` |
| Development check | `python -m defender.dev_check --data-dir <road>` |
| Leave-one-out false alarms | `python -m defender.crossval ambient --max-false-alarm-rate 0.01 --data-dir <road> [--split <splits.json>]` |
| 2-fold attack CV | `python -m defender.crossval attacks --max-false-alarm-rate 0.01 --data-dir <road> --split ~/Downloads/road/splits.json` |
| Latency benchmark (mock traffic) | `python -m defender.nano_runner --mock --output results/nano_benchmark_MOCK.json` |
| Dashboard | `cd dashboard && npm install && npm run dev` |

The false-alarm rate has no default on purpose: it is a team decision (0.01 has been used so far).

## What is implemented

### Part 1 (`part1/`): partial
- `fleet_simulator.py`: reads ROAD logs, exact integer-nanosecond timestamps converted to elapsed seconds, neutral capture IDs via `discover_captures()` (alphabetical, ambient first).
- `windowing.py`: 1.0 s windows, **1.0 s stride (locked)**, empty windows kept, trailing partial window dropped.
- **Not done:** feature filling (`preprocess()`), the official split manifest, cleaning (duplicates, the `0xFFF` filler frame).

### Part 2 (`defender/`): working on real data
- `road_reader.py`: Part 2's own window reader (raw float timestamps, **0.5 s stride**), used because Part 1's windowing wasn't ready.
- `stage1.py`: timing detector (unknown IDs, rate excess, short gaps).
- `stage2.py`: payload detector on a watch-list (`0D0`, `6E0`), checking out-of-range values, frozen fields and large jumps. Full-capture range stats can be precomputed per capture (`capture_range_stats`, `merge_range_stats`) and give an identical model.
- `fusion.py`: v2 score = max(Stage 1, Stage 2).
- `threshold.py`: lowest threshold that meets the false-alarm target on normal validation windows.
- `train.py` / `run_training.py`: v1 = Stage 1; v2 = v1's unchanged Stage 1 + Stage 2. Models saved in `models/` (`*_v1.json`, `*_v2.json`). Uses `PROVISIONAL_SPLIT` (hard-coded in `run_training.py`).
- `dev_check.py`: development-only sanity check.
- `crossval.py` (new):
  - `ambient`: nested leave-one-capture-out over train + validation ambient. The threshold comes from out-of-fold scores, and false alarms are counted on the held-out capture, for v1 and v2.
  - `attacks`: 2-fold index-out CV using `splits.json` `cv_folds`. The watch-list comes from the other fold's attack targets, and recall is macro-averaged per attack type. A masquerade capture only contributes its attacked windows.
  - Test captures are refused by `capture_path()`. Reports are written to `results/crossval_*.json` using neutral IDs only.
- `nano_runner.py`: latency benchmark, **mock traffic only**.

### Dashboard (`dashboard/`): mock data only
React + Vite, KPI tab, live architecture diagram, fleet view. Reads mock `DefenderOutput` records; it isn't connected to the real Defender yet.

### Results so far
Development split (from `defender/README.md`):
- v2 detects 196 / 310 attacked windows; v1 detects 12 / 310.
- Reverse-light attacks and a frozen `0D0` signal are missed.

2-fold attack CV with `splits.json` (`results/crossval_attacks_splitsjson.json`):

| | v1 | v2 |
|---|---|---|
| Macro recall, fabrication | 1 % | 67 % |
| Macro recall, masquerade | 1 % | 50 % |
| False alarms on normal windows in attack captures | 11 / 416 | 1 / 416 |

- v2 catches correlated_signal and max_speedometer 100 %.
- reverse_light_on: 64 % fabricated, 0 % masquerade. reverse_light_off: about 0 %.

Leave-one-out false alarms: `results/crossval_ambient_provisional.json` and `results/crossval_ambient_splitsjson.json`.

## Known problems (fix before trusting final numbers)

1. **Two splits exist and disagree.**
   - `PROVISIONAL_SPLIT` (this repo) and `~/Downloads/road/splits.json` put different captures in test.
   - The current v1/v2 models were trained on `basic_short` and `highway_long`, which are **test** in `splits.json`.
   - If `splits.json` is adopted, retrain before any final-test evaluation.
2. **Validation is too small.** The threshold is chosen on 2 captures (184 windows). It showed 0 false alarms there, but 2–4 % on development.
3. **Three capture-ID schemes.**
   - `neutral_ids()` numbers captures in split order.
   - `discover_captures()` numbers them alphabetically.
   - `dev_check` uses cap13+ and cap40+.
   - `cap07` means different files in different places.
4. **Part 1 and Part 2 windowing differ** in stride (1.0 vs 0.5 s), timestamps (elapsed vs raw float) and window_id format (`w0000` vs `w00000`). Part 1's `make_windows` raises on stride 0.5, so it can't simply replace `road_reader`.
5. **The final test mostly repeats known attacks.** The watch-list was picked from development attacks that target the same IDs as the final-test attacks. Only coolant (`4E7`) tests an unseen target. Report the two separately.

## What to do next (in order)

1. **Save the other project in git.** Copy `~/Downloads/road/{edgeguard/, splits.json, docs/, tests/}` into this repo (not `dataset/` or `build/`) and commit. It currently exists only on one laptop.
2. **Pick one split: `splits.json`.** Replace `PROVISIONAL_SPLIT` in `run_training.py` with a loader for it (`defender.crossval.load_split` already reads it).
3. **Pick one capture-ID scheme and one stride**, then keep `road_reader` or switch to Part 1's windowing.
4. **Retrain v1/v2** with `--overwrite` on the chosen split. The old models are only valid for the provisional split.
5. **Report false alarms from leave-one-out** (`crossval ambient`) beside validation, and the attack CV per type.
6. **Final-test evaluation** (Part 3 evidence gate): run once, on the frozen models.
7. Later / future work: use the other project's features (`edgeguard/features.py`), cross-signal checks for reverse-light and freeze attacks, real-traffic Nano benchmark, connect the dashboard to real Defender output.

## Rules for any code touching data

- **Split by capture, never by window.** Windows overlap.
- **Never read test / final_test captures** during development, tuning or CV. Use `crossval.capture_path()`-style guards.
- A fabrication capture and its `_masquerade` twin are one recording and always share a split.
- Models, ranges and thresholds are fitted on **normal train/validation data only**. The threshold is never chosen from attack data or from in-sample scores.
- The Defender only sees neutral IDs (`cap07`). File names contain the answer (`..._attack_1`), and `shared/schemas.py` rejects them.
- Never overwrite a model that has been evaluated. Use a new version name (`--overwrite` only for never-evaluated models).
- Cross-validation numbers estimate the training *procedure*. Report them beside the final-test number, never instead of it, and never tune on them.
- Detection results must be measured on real ROAD captures. Mock or synthetic numbers are labelled as such.

## Code style

Plain Python, pydantic models for contracts, small modules with a long docstring explaining the "why". Each module has a matching `tests/test_*.py` that uses fake logs in `tmp_path` and never the real dataset. Match that when adding code.
