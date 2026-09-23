## Part 3: Red Team and Evaluation

Part 3 creates test attacks and measures how well the Defender detects them. It does not train or run the Defender itself.

### How it works

1. Receive a raw `TrafficWindow` from Part 1.
2. Propose a freeze attack against a CAN ID whose payload changes in that window.
3. Validate the proposal, then inject it into a **copy** of the raw window.
4. Pass the modified window through Part 1's preprocessing before sending it to the Defender.
5. Compare the Defender's output with hidden labels to calculate detection metrics.
6. Record confirmed misses from the development split for later Defender retraining.
7. Compare baseline and updated Defender results on the held-out final test split.

The current attack implementation supports **freeze attacks**. Other attack families and an adaptive or LLM-based attacker are future work.

### Files

| File | Purpose |
| --- | --- |
| `attack_spec.py` | Defines a freeze attack proposal. |
| `red_team_agent.py` | Proposes a freeze attack from a raw window. |
| `attack_validator.py` | Checks whether the proposal can modify the window. |
| `attack_injector.py` | Applies the attack to a copy of the window. |
| `evaluator.py` | Joins Defender outputs with hidden labels by window ID. |
| `metrics.py` | Calculates detection counts and rates. |
| `evasion_log.py` | Records confirmed development-set misses. |
| `hardening_set.py` | Prepares a list of misses for retraining. |
| `evidence_gate.py` | Compares Defender versions on held-out test results. |

### Tests and current status

From the repository root, run:

```bash
python -m pytest tests/test_{attack_injector,attack_validator,evaluator,evasion_log,evidence_gate,hardening_set,metrics,red_team_agent}.py -q
```

All **50 Part 3 tests passed**. A separate smoke check loaded a one-second ROAD sample with 2,392 CAN frames; the freeze injector changed 93 frames, matching the validator's prediction. This confirms the injection path works on that sample. End-to-end Defender performance has not been measured yet.
