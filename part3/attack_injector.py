"""Part 3: apply a freeze attack to a COPY of a raw traffic window.

Call Part 1's preprocess() on the returned window before Defender inference.
Ground-truth labels and attack specifications must remain outside that window.
"""

from shared.schemas import TrafficWindow
from part3.attack_spec import AttackSpec


def inject_freeze(
    window: TrafficWindow, spec: AttackSpec, *, variant_index: int = 1
) -> TrafficWindow:
    """Repeat the first matching payload for one CAN ID within a time interval.

    start_offset_ms is relative to this window's start, not the capture's
    start or the ROAD metadata injection_interval. Timestamps and ordering
    are preserved. Raise ValueError if the attack changes no frame.
    """
    if spec.family != "freeze":
        raise ValueError(f"unsupported attack family: {spec.family}")
    if isinstance(variant_index, bool) or not isinstance(variant_index, int) or variant_index < 1:
        raise ValueError("variant_index must be a positive integer")
    if window.features or window.decoded_signals:
        raise ValueError("inject into a raw window before preprocessing")

    start = window.window_start + spec.start_offset_ms / 1000.0
    end = start + spec.duration_ms / 1000.0
    if start >= window.window_end or end <= window.window_start:
        raise ValueError("injection interval does not overlap the window")

    attacked = window.model_copy(deep=True)
    frozen_payload = None
    changed = 0
    for frame in attacked.frames:
        if start <= frame.timestamp < end and frame.can_id.upper() == spec.target_can_id.upper():
            if frozen_payload is None:
                frozen_payload = frame.payload
            elif frame.payload != frozen_payload:
                frame.payload = frozen_payload
                changed += 1

    if changed == 0:
        raise ValueError("freeze changed no frames; choose another window, ID, or interval")

    attacked.window_id = f"{window.window_id}_v{variant_index:02d}"
    return attacked
