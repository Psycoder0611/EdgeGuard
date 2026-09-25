# EdgeGuard

On-vehicle CAN-bus intrusion detection that runs at the edge, escalates to the cloud only when it is genuinely unsure, and never sends raw vehicle data off the device.

Built for the HP Edge AI SJSUHack 2026 (Secure AI track).

## Who this is for

**Target user:** a security analyst monitoring a vehicle fleet for cyberattacks — an automotive OEM's SOC, or a fleet operator's security team.

**The problem:** CAN-bus intrusions (a spoofed sensor reading, a safety-critical signal frozen mid-attack) have to be caught in real time, inside the vehicle. A car is not always connected, cannot wait on a cloud round trip to flag an attack on its brakes or speedometer, and its raw internal bus traffic is proprietary telemetry that should not leave the vehicle by default.

**Why not cloud-only:**
- **Hard latency budget** — detection has to happen in milliseconds, not after a network round trip.
- **Intermittent connectivity** — a car loses signal; cloud-only means blind spots exactly when an attack might occur.
- **Data residency** — raw CAN frames should stay on-device. EdgeGuard's sanitizer (`part1/sanitizer.py`) enforces this as an allow-list: only a derived score, threshold, decision and evidence string may ever leave the vehicle, never a raw frame.

EdgeGuard's answer: run detection locally, on the edge device, always. Escalate to a cloud second opinion only for the subset of cases the local model is genuinely uncertain about, and never block the local decision on that call succeeding.

## Architecture

Two modes, both scoring the same real-time signal from CAN traffic (see `CLAUDE.md` for the full design discussion):

- **Ordinary detection** — replay CAN traffic -> Defender (Stage 1 timing + Stage 2 payload checks, fused) -> local decision (ALERT / ISOLATE / FORWARD), with uncertain cases optionally escalated to a cloud second opinion.
- **Adversarial testing and hardening** — a Red Team proposes synthetic attacks against real driving captures, a constrained injector applies them, the Defender scores both, and confirmed misses feed a hardening loop that produces (and evaluates) candidate model updates against real, held-out data.

```
Fleet replay -> preprocess -> Defender (Stage 1 + Stage 2) -> local decision
                                    |
                         uncertain? (escalation_policy)
                                    v
                  sanitize -> simulated cloud second opinion
                       (never blocks the local decision)
```

Components:

| Part | What it does |
|---|---|
| `part1/` | Real ROAD data pipeline, windowing, decoding, the cloud-escalation path (`escalation_policy.py`, `sanitizer.py`, `mock_cloud_endpoint.py`, `egress_metrics.py`) |
| `defender/` | The detector itself: Stage 1 (timing), Stage 2 (payload range/frozen/jump checks), fusion, training, cross-validation |
| `part3/` | Red Team attack proposal + injection, evasion logging, hardening-set construction |
| `integration/` | `run_demo.py` (one command, both modes) and `run_final_evaluation.py` (the one-time held-out evidence gate) |
| `dashboard/` | Live view of real Defender output (React + Vite) |

## Quick start

```bash
git clone https://github.com/Psycoder0611/EdgeGuard.git
cd EdgeGuard
bash setup.sh                    # creates a venv, installs dependencies
source .venv/bin/activate
```

Train the models (real ROAD normal-driving data only; see `CLAUDE.md` for where to get it):

```bash
python -m defender.run_training --max-false-alarm-rate 0.01 --data-dir <path-to-road>
```

Run the demo — ordinary detection, Red Team attack testing, and (optionally) live cloud escalation, all in one command:

```bash
# terminal 1: the simulated cloud second opinion
python -m uvicorn part1.mock_cloud_endpoint:app --host 127.0.0.1 --port 9000

# terminal 2: the demo itself
python -m integration.run_demo --model-version v2 --data-dir <path-to-road> \
    --escalate --max-escalation-rate 0.3
```

Run the dashboard:

```bash
cd dashboard && npm install && npm run dev
```

## Real results (real ROAD data, never synthetic numbers presented as real)

One-time held-out evaluation (`final_test`, never touched during development — see `CLAUDE.md`'s Final evaluation section):

| | v1 (Stage 1 only) | v2 (Stage 1 + Stage 2) |
|---|---|---|
| Recall | 0.39% | **64.9%** |
| False alarms | 0.41% | 9.07% |
| Precision | 4.8% | 27.4% |
| F1 | 0.7% | 38.5% |
| Mean inference | 0.31 ms | 1.80 ms |

v2's Stage 2 payload check is what catches anything beyond fuzzing attacks — the whole reason this project exists. It is also honestly not finished: false alarms on final_test (9.07%) are well above the 1% target, and two attack types are still missed entirely.

## What EdgeGuard does not yet catch, and why

- **`max_engine_coolant_temp` (0% recall, both models).** The one final-test attack target Stage 2 never watches. It confirms the watch-list does not generalize to an unseen CAN ID — a real, disclosed limitation, not a hidden one.
- **`reverse_light_off` (0% recall).** A one-bit signal flip inside a byte. Stage 2's payload checks work at the byte level; catching this needs decoded-signal checking (`part1/decode.py` exists and is tested, but nothing wires it into Stage 2 scoring yet).
- **A real hardening attempt (`v5`) failed its evidence-gate test.** We built a candidate from confirmed Red Team misses, validated it looked great against Red Team's own synthetic attacks, then ran it against the real held-out attacks: identical recall, nearly triple the false alarms. Full story, including why, in `CLAUDE.md`'s Hardening loop section — we're documenting this because a negative result honestly reported is worth more than a cherry-picked positive one.
- **The cloud-escalation path is wired and real** (calibrated on validation data, sanitizes before sending, degrades gracefully if the cloud is unreachable — verified by actually killing the process mid-run), but the simulated cloud's stand-in threshold is not yet calibrated relative to each model's real operating point, so its "correction rate" number isn't meaningful yet. The mechanism is real; that one number isn't, and we're not presenting it as if it were.

## Full engineering log

`CLAUDE.md` is the living build log: every real result, every negative finding, every open decision the team still needs to make, with real numbers and honest caveats throughout. Start there for anything this README doesn't cover.
