"""Part 3 Red Team: propose attack specifications, never edit traffic.

This first version is deterministic and uses development windows only.
It does not query the Defender or read hidden ground-truth labels. Later,
feedback-based proposals must use development-set scores, never final-test
results or private Defender evidence.
"""

from collections import defaultdict

from part3.attack_spec import AttackSpec
from shared.schemas import TrafficWindow


def propose_freeze(window: TrafficWindow, *, attack_id: str = "atk_001") -> AttackSpec:
    """Pick a CAN ID that varies in this window, then propose a full-window freeze.

    The first matching payload becomes the frozen value; later distinct
    payloads are the ones the injector can change. Choose the ID with the
    most changes; resolve ties by hexadecimal ID for reproducibility.
    """
    if window.features or window.decoded_signals:
        raise ValueError("propose an attack from a raw window before preprocessing")
    duration_ms = (window.window_end - window.window_start) * 1000.0
    if duration_ms <= 0:
        raise ValueError("window must have positive duration")

    payloads_by_id: dict[str, list[str]] = defaultdict(list)
    for frame in window.frames:
        payloads_by_id[frame.can_id.upper()].append(frame.payload)

    candidates = [
        (sum(payload != values[0] for payload in values[1:]), can_id)
        for can_id, values in payloads_by_id.items()
        if len(values) >= 2
    ]
    candidates = [(changes, can_id) for changes, can_id in candidates if changes > 0]
    if not candidates:
        raise ValueError("no CAN ID has changing payloads in this window")

    _, target_id = min(candidates, key=lambda pair: (-pair[0], int(pair[1], 16)))
    return AttackSpec(
        attack_id=attack_id,
        family="freeze",
        target_can_id=target_id,
        start_offset_ms=0.0,
        duration_ms=duration_ms,
        reasoning="Freeze a changing CAN payload to test payload-aware detection.",
    )
