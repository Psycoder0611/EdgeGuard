# EdgeGuard dashboard (Member 4: dashboard and demo UI)

React + Vite dashboard for the EdgeGuard demo. Currently runs entirely on
mock `DefenderOutput` records shaped exactly like `shared/schemas.py` in the
main EdgeGuard repo, so swapping in real output is a one-line change (see
"Connecting the real feed" below) with no component changes needed.

## Layout

- **System architecture (live)** — always visible at the top. Animates your
  team's own architecture doc: the ordinary-detection lane (Fleet replay →
  Blue Team → Simulated consumer) pulses live, in sync with each replayed
  window, since that's the lane that actually runs per window. The
  adversarial testing/hardening lane (Red Team → injector → ground truth →
  evidence gate) is shown as a static, dimmed strip underneath, labeled
  "offline" — that lane runs once, comparing two frozen model versions, not
  per window, so animating it live would misrepresent how the pipeline
  actually works. See `src/components/ArchitectureDiagram.jsx`.
- **KPIs tab** — the original metrics dashboard (below).
- **Fleet view tab** — a glowing wireframe car on a route (`CarsView.jsx`),
  cyan while normal, red mid-attack, with a checkpoint gate (the Blue Team
  detector) and incoming Red Team arrows. Dark by design — the neon glow
  effect needs a dark surface to read.

## Sections (matches the task card)

- **Replay status** — capture id, window index/progress, play/pause/reset, speed.
- **Attack score** — current `attack_score` vs. `threshold`, labeled as a score
  (not a probability) per the team's own schema comment.
- **Affected CAN ID** — best-effort, parsed out of the free-text `evidence`
  field (see `src/utils/parseEvidence.js`). There's no dedicated CAN-ID field
  in `DefenderOutput` yet, so this can silently return nothing for evidence
  strings that don't say "ID <hex>" (e.g. Stage 1's `unknown_ids` check).
  Worth raising with whoever owns `defender/stage1.py`/`stage2.py`/`fusion.py`
  if the team wants this to be reliable rather than best-effort.
- **Simulated response** — mirrors `defender/simulated_consumer.py`'s three
  actions (`SIMULATED_ALERT` / `SIMULATED_ISOLATION` / `SIMULATED_FORWARD`).
  The Alert/Isolate toggle mirrors that module's `attack_action` constructor
  argument, which the team said was a "team setting."
- **Local / cloud routing** — presentational only. There is no cloud
  escalation path anywhere in the current codebase (confirmed by reading
  `defender/`), and the team's own architecture doc scopes that out as an
  open decision. Shown here as a placeholder so the layout doesn't need
  reworking once that decision is made.
- **Alert timeline** — a scrolling strip of every window played so far,
  color-coded, hover/focus for per-window detail (window id, score, evidence).

## Running it

```bash
npm install
npm run dev       # local dev server
npm run build     # production build -> dist/
```

## Mock data

`src/data/mockRun.js` generates one deterministic 240-window replay (same
sequence every reload — useful for rehearsing before the real recording) with
three multi-window attack bursts, since a real injected attack spans several
consecutive 1-second windows, not one isolated blip. The threshold value
(`0.9642248722316866`) matches the mock example already shared.

## Connecting the real feed

1. Implement `connectLiveFeed()` in `src/data/liveFeed.js` to pull real
   `DefenderOutput` records from wherever Part 2's inference ends up exposed
   (once Member 5's Nano runtime work and the "real mode" of
   `defender/nano_runner.py` exist).
2. In `src/App.jsx`, flip `DATA_SOURCE` from `"mock"` to `"live"` and swap the
   `buildMockRun(...)` call for the live feed.

No component under `App.jsx` needs to change — they only ever consume
`DefenderOutput`-shaped objects.

## Known gaps / open questions (worth raising at the team discussion)

- CAN ID parsing is best-effort text parsing, not a real field — see above.
- Local/cloud routing has no backend; it's UI-only until the team decides
  the HP edge/cloud requirement.
- `part1/windowing.py` locks window/stride to 1.0s/1.0s ("no overlap"), but
  `defender/README.md`'s results table describes 0.5s stride ("windows
  overlap"). Not this dashboard's bug, but worth flagging to whoever owns
  those two files since it'll affect real replay speed/pacing once wired up.
