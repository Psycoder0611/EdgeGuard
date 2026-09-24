# CLAUDE.md

Guidance for Claude Code and teammates working in this repo: what exists, what is still open, and the rules that keep the results honest.

## What this is

EdgeGuard is an on-vehicle CAN bus intrusion detector, built on the ROAD dataset (real CAN recordings from one car, with injected attacks). The team splits the work into parts:

| Part | Owner area | Folder |
|---|---|---|
| Part 1 | Reading captures, cleaning, windowing, labels, decoded signals, the split | `part1/` |
| Part 2 | The Defender: detection models, training, threshold, cross-validation | `defender/` |
| Part 3 | Red team, injector, evaluator, evidence gate | not in this repo yet |
| Member 4 | Dashboard and demo UI | `dashboard/` |
| Shared | Data contracts between parts | `shared/schemas.py` |

**Deadline:** originally Fri 25 Sep 2026, 8pm; **extended** (new date to be confirmed).

**Current branch:** `part1-data-pipeline`. It holds all the Part 1 work below and is **not committed or pushed yet**.

## Source of truth: the revised build plan

`EdgeGuard_Combined_Build_Plan_revised.pdf` (23 Sep 2026) is the team's plan. Where this file or the code disagrees with it, the plan wins. The parts that constrain the code:

- **Windows:** fixed, **non-overlapping 1-second** windows as the first implementation. Preserve message order and timestamps. Each window has `vehicle_id`, `capture_id`, `window_start`, and frames (`timestamp`, `can_id`, raw payload).
- **Labels are private:** labels, attack details and source capture names live in a separate evaluator record, never in the Defender request.
- **Split:** freeze train, validation and final test *before* tuning, and keep related source and derived captures together.
  - Train v1 on train.
  - Develop attacks and v2 candidates on **development**.
  - Compare v1 and v2 **once** on untouched test captures.
- **Threshold:** chosen on validation captures, never on the final test. Section 3 says "validation" while section 6 says "tune thresholds using development data". We read it as: threshold from normal validation drives, development for attacks and v2 misses. **The team still needs to confirm this.**
- **Defender:** Layer 0 rules (frequency, out-of-range decoded values, flatlines, abrupt changes) plus one lightweight anomaly model, combined by a fixed, documented rule. Measure what each contributes. **Every evaluation window is scored.** Decoded signals are optional features, and a missing signal is handled explicitly, never guessed.
- **Deferred:** timing CNN and cross-signal models (unless supported by data and an ablation), large LLM analyst, five attack families, OTA/registry, full fleet dashboard.
- **Metrics:** recall by attack family and overall; **false alarms per hour** of normal traffic; **detection delay** (time to first alert); edge latency (median and p95); end-to-end delay, with window collection separate from processing; v1 vs v2 on the same untouched test groups, including regressions.
- **Part 1 = Block 1 "Data":** load ROAD with the source preserved, create the split manifest, build 1-second windows. Completion check: **normal windows and private labels are reproducible.**

## Where the data is

The ROAD dataset is **not** in this repo and must never be committed. `.gitignore` blocks `data/`, `*.log` and `*.csv`.

- On this machine: `~/Downloads/road/dataset/` (`ambient/`, `attacks/`, both `capture_metadata.json` files, `signal_extractions/DBC/anonymized.dbc`).
- The code defaults to `data/road/`, which does not exist. Either pass `--data-dir ~/Downloads/road/dataset`, or link it once: `mkdir -p data && ln -s ~/Downloads/road/dataset data/road`.

`~/Downloads/road/` is also a **separate preprocessing project** (`edgeguard/` package, `splits.json`, `docs/00–06`). Part 1 here reuses its measured findings, labelling rules and decoder layout rules. It is **not a git repo** and exists only on this laptop.

## Commands

Run from the repo root. The environment is a local `.venv` (gitignored): `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`. Below, `<road>` = `~/Downloads/road/dataset`.

| Task | Command |
|---|---|
| All tests (335, about 20 s) | `.venv/bin/python -m pytest -q` |
| Show the split | `python -m part1.split_manifest show` |
| Rebuild the split (only if the team changes it) | `python -m part1.split_manifest build --splits ~/Downloads/road/splits.json --data-dir <road>` |
| Reproducibility check | `python -m part1.reproduce --data-dir <road> --check results/part1_fingerprint.json` |
| Train v1 + v2 | `python -m defender.run_training --max-false-alarm-rate 0.01 --data-dir <road>` |
| Development check | `python -m defender.dev_check --data-dir <road>` |
| Leave-one-out false alarms (normal drives) | `python -m defender.crossval ambient --max-false-alarm-rate 0.01 --data-dir <road>` |
| 2-fold attack CV (development) | `python -m defender.crossval attacks --max-false-alarm-rate 0.01 --data-dir <road>` |
| Latency benchmark (mock traffic) | `python -m defender.nano_runner --mock --output results/nano_benchmark_MOCK.json` |
| Dashboard | `cd dashboard && npm install && npm run dev` |

The false-alarm rate has no default on purpose: it is a team decision (0.01 has been used so far).

## How data flows (Part 1)

```
ROAD .log  ->  fleet_simulator.iter_raw   (elapsed integer microseconds, malformed lines counted)
           ->  cleaning.clean             (exact duplicates dropped, 0xFFF filler counted, 0.1 % gate)
           ->  windowing.raw_windows      (1 s, non-overlapping, empty windows kept, partial last dropped)
           ->  TrafficWindow              (neutral capture_id + vehicle_id; goes to the Defender)
           +   labels.window_label        (GroundTruthLabel; evaluator only, never to the Defender)
preprocess(window, decoder)               (fills decoded_signals AFTER any injection, on a copy)
```

Everyone gets data through **`part1.pipeline.RoadData`**: `windows()`, `labelled_windows()`, `frames()`, `metadata()`, `keep_every()`. It reads the split from `part1/split_manifest.json` and **refuses final_test / separate captures** unless created with `final_evaluation=True`.

## What is done

### Part 1: Block 1 steps 1–6, all done (branch `part1-data-pipeline`)

| Step | What was built | File(s) | Checked by |
|---|---|---|---|
| 1. Frozen split manifest | 45 captures, 5 groups, one neutral-ID scheme (same as `discover_captures`). Twins share a group; development attacks carry a fold (`_1`/`_2`). Checked on load. | `part1/split_manifest.py`, `part1/split_manifest.json` | `tests/test_part1_split_manifest.py` (including the committed file) |
| 2. One windowing function | 1 s non-overlapping, integer-µs boundaries, `vehicle_id`, `keep_every` sampling for training only, cleaning built in. `defender/road_reader.py` **deleted**. | `part1/windowing.py`, `part1/fleet_simulator.py` | `tests/test_part1_windowing.py` |
| 3. Metadata and private labels | Frame rules: masquerade, fabrication (with payload mask), fuzzing (whole capture), accelerator (none). Closed interval compared in integer µs. A window is an attack if it holds ≥ 1 injected frame; labels store `injected_frames` and `interval_overlap_s`. | `part1/labels.py`, `part1/pipeline.py` (`CaptureMetadata`) | `tests/test_part1_labels.py`, `tests/test_part1_pipeline.py` |
| 4. Cleaning | Exact duplicates dropped, `0xFFF` filler counted not removed, malformed lines counted, out-of-order frames raise. A capture fails if more than 0.1 % would be removed. | `part1/cleaning.py` | `tests/test_part1_cleaning.py` |
| 5. Decoded signals | Pure-Python DBC decoder (Intel and Motorola, signed, NaN for short payloads, error for watched IDs missing from the DBC). `preprocess()` fills `decoded_signals` as `"0D0:Unknown_4" -> values`. | `part1/decode.py`, `part1/pipeline.py` | `tests/test_part1_decode.py` |
| 6. Reproducibility check | Hashes every window and label per capture. Neutral IDs only, safe to commit. | `part1/reproduce.py`, `results/part1_fingerprint.json` | `tests/test_part1_pipeline.py` |

**Checked on the real dataset:**
- **Decoder:** bit-exact against ROAD's signal CSVs. 0 mismatches over 115,287 frames of `ambient_dyno_reverse` and 197,664 frames of `max_speedometer_attack_1_masquerade`, across all 664 signals.
- **Labels:** each of the 8 development fabrication captures has exactly as many injected frames as its masquerade twin (e.g. 2,445 for `max_speedometer_attack_1`, matching the other project's figure).
- **Reproducibility:** 27 captures (train, validation, development) run twice with identical windows and labels.

**Shared schema changes** (`shared/schemas.py`, all optional fields, so older code still works):
- `TrafficWindow.vehicle_id`, checked to be neutral.
- `GroundTruthLabel.injected_frames` and `interval_overlap_s`. A normal label may not have them.

### Part 2 (`defender/`): switched over to Part 1
- `run_training`, `dev_check`, `crossval`, `diagnose`, `diagnose_watch` now read the manifest and get windows and labels from `RoadData`. `PROVISIONAL_SPLIT`, `neutral_ids()` and the time-overlap labelling are gone.
- `Defender.load()` reads the window length from `train_info_<version>.json`, and `score_window()` **refuses windows of any other length**.
- `stage2.py`: full-capture range stats are computed once per capture and reused across folds (`capture_range_stats`, `merge_range_stats`), giving an identical model.
- **v1 and v2 were retrained** on the manifest (`models/*_v1.json`, `*_v2.json` overwritten; they had never been final-evaluated).
- `nano_runner.py`: latency benchmark, **mock traffic only** (unchanged).

### Dashboard (`dashboard/`): mock data only
React + Vite, KPI tab, live architecture diagram, fleet view. Reads mock `DefenderOutput` records; it isn't connected to the real Defender yet.

## Results (frozen manifest, Part 1 windows and labels)

All from train, validation and development captures. **None of this is the final test.**

**Training:**

| | v1 | v2 |
|---|---|---|
| Threshold | 0.958763 | 0.998808 |
| Validation false alarms (target 1 %) | 1 / 182 = 0.55 % | 1 / 182 = 0.55 % |

Training used 581 windows from 7 drives; validation used 182 windows from 2 drives.

**Development check** (`dev_check`, every window of the 18 development attack captures):

| | v1 | v2 |
|---|---|---|
| Attacked windows detected | 10 / 390 | **247 / 390** |
| False alarms on normal windows | 6 / 237 | 1 / 237 |

- **v2 catches:** correlated_signal and max_speedometer (100 %), fuzzing (100 %), and fabricated reverse_light_on_2 (38 / 38).
- **v2 misses:** reverse_light_off, reverse_light_on_1, all reverse-light masquerades, and Part 3's frozen-`0D0` window.

**2-fold attack CV** (`results/crossval_attacks.json`), average recall over attack types:

| | v1 | v2 |
|---|---|---|
| Fabrication | 1 % | 67 % |
| Masquerade | 1 % | 50 % |
| Fuzzing | 100 % | 100 % |
| False alarms on normal windows | 6 / 237 | 1 / 237 |

**Leave-one-out false alarms on normal drives** (`results/crossval_ambient.json`; 9 drives, each held out in turn, out-of-fold threshold, target 1 %):

| | v1 | v2 |
|---|---|---|
| False alarms | 5 / 763 = 0.66 % (95 % upper 1.4 %) | **30 / 763 = 3.9 %** (95 % upper 5.3 %) |
| Per hour of normal driving | 24 / h | 142 / h |
| Drives over the 1 % target | 5 / 9 (0 or 1 alarm each, on ~50–100 windows) | 2 / 9 |

- 29 of v2's 30 false alarms come from **one drive, `extended_short`** (29 / 90 windows).
- Every other drive has 0 or 1 false alarm.
- The per-hour figures use sampled windows (at most 100 per drive), so treat them as rough.
- Validation alone (0.55 %) hides this: it is the same coverage problem seen before the manifest.

Results from before the manifest (provisional split, 0.5 s overlapping windows) are superseded, and are kept only in `defender/README.md` for the record.

## Decisions the team must confirm (before merging)

1. **Shared schema change:** `vehicle_id`, `injected_frames`, `interval_overlap_s`. `schemas.py` says fields change only with team agreement, and Part 3 must know about them.
2. **Part 1's code was rewritten** by Part 2. The Part 1 owner should review `part1/`.
3. **Fuzzing `_1`/`_2` are in development.** `splits.json` puts all fuzzing in test, because that project trains Stage 1 on synthetic fuzzing. This one doesn't.
4. **No highway driving in training.** Both highway drives are final test (as in `splits.json`), so expect more false alarms on them at the final test. Accept this consciously, or move one highway drive to train and rebuild the manifest.
5. **Threshold on validation vs development** (the build plan contradiction above).

## Known problems and limits

1. **Stage 2 false alarms depend on which drives are in training.** In leave-one-out, `extended_short` alone produces most of v2's false alarms (29 / 90) when it's held out. Its value ranges aren't covered by the other drives.
2. **Validation is small:** 2 drives, 182 windows. Use the leave-one-out number beside it.
3. **Decoded signals exist, but the Defender doesn't use them yet.** The reverse-light misses (one bit inside a byte) need Stage 2 to check decoded signals. Until then that recall gain is a hypothesis.
4. **The frozen-`0D0` repro is weaker.** Its drive (`ambient_dyno_reverse`) is now in train, so the repro window may be in-sample.
5. **The final test mostly repeats known attacks.** The watch-list (`0D0`, `6E0`) comes from development attacks that target the same IDs as the final-test `_3` attacks. Only coolant (`4E7`) tests an unseen target. Report the two separately.
6. **Short attacks with 1 s windows.** The shortest attack (fuzzing_3, 0.65 s) often falls across a window boundary. Use `interval_overlap_s` to report partly covered windows separately.

## What to do next (in order)

1. **Finish the branch.**
   - Delete the superseded `results/crossval_ambient_provisional.json`, `crossval_ambient_splitsjson.json` and `crossval_attacks_splitsjson.json`.
   - Run the tests.
   - Review `git diff`, with extra care on `shared/schemas.py` and `part1/`.
2. **Get agreement** on the five decisions above (Part 1 owner, Part 3 owner).
3. **Commit, push the branch, open a PR.** Mention in the commit message that the models were retrained.
4. **Save the other project in git.** Copy `~/Downloads/road/{edgeguard/, splits.json, docs/, tests/}` (not `dataset/` or `build/`) into this repo or its own repo.
5. **Stage 2 on decoded signals** (Part 2).
   - Out-of-range and flatline checks per decoded signal of the watch-list IDs, using `preprocess(window, Decoder)` at training and scoring time.
   - Percentile bounds instead of min/max, chosen by cross-validation (the other project found min/max bounds too loose).
   - Measure with `crossval attacks` and `crossval ambient`; keep only if recall rises without more false alarms.
6. **Reduce false-alarm sensitivity to training coverage.** Target `extended_short`'s 29 / 90, e.g. with percentile bounds or more regime coverage in train (a manifest change is a team decision).
7. **Report the plan's metrics:** false alarms per hour (already in the cross-validation reports), detection delay per attack (time to first alert after the interval starts), recall for fully vs partly covered windows (`interval_overlap_s`).
8. **Part 3 integration:** the injector works on a COPY of `RoadData` windows, re-windows with `windowing.windows_from_frames`, calls `preprocess()`, and the evaluator joins `DefenderOutput` with `GroundTruthLabel` by `window_id`.
9. **Final evaluation, once:** freeze models, then score final_test with `RoadData(..., final_evaluation=True)` (v1 vs v2, including regressions).
10. **Later:** real-traffic Nano benchmark (`nano_runner` real mode), connect the dashboard to real Defender output, the second-opinion escalation service (build plan section 7).

## Rules for any code touching data

- **Split by capture, never by window.** Neighbouring windows of one drive are near-copies, so a window-level split leaks.
- **Get captures only through `RoadData` / `Manifest.capture_path()`**, which refuse final_test and separate captures. Only the final evaluation passes `final_evaluation=True`.
- **Never build a split from a glob, a seed or a hard-coded list.** The manifest is the split.
- A fabrication capture and its `_masquerade` twin are one recording and always share a split. Count normal windows from the fabrication capture only.
- Models, ranges and thresholds are fitted on **normal train/validation data only**. The threshold is never chosen from attack data or from in-sample scores.
- The Defender only sees neutral IDs (`cap07`, `veh01`) and never a `GroundTruthLabel`. File names contain the answer (`..._attack_1`), and `shared/schemas.py` rejects them.
- **Evaluation scores every window.** `keep_every > 1` is for training memory only.
- Cleaning removes only capture artifacts, never unusual content: unusual content is what attacks look like.
- Never overwrite a model that has been evaluated. Use a new version name (`--overwrite` only for never-evaluated models).
- Cross-validation numbers estimate the training *procedure*. Use them to choose settings (train/validation/development only), and report them beside the final-test number, never instead of it. Never tune on the final test.
- Detection results must be measured on real ROAD captures. Mock or synthetic numbers are labelled as such.

## Code style

Plain Python, pydantic models for contracts, small modules with a long docstring explaining the "why". Each module has a matching `tests/test_*.py` that uses fake data and never the real dataset. `tests/conftest.py` provides a shared fake ROAD folder (every capture kind, a fake DBC, metadata and a manifest). Match that when adding code.
