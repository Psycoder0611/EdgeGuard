"""
Part 1 -- windowing.

Groups the frame stream from fleet_simulator into TrafficWindow objects.
This is the function the Defender (Part 2) and the injector (Part 3) consume.

LOCKED TEAM DECISIONS
    window size   1.0 s
    stride        1.0 s   (stride == window -> no overlap)
    window_id     "{capture_id}_w{index:04d}", index from 0 within a capture
    empty windows EMITTED  (a quiet second is real traffic; dropping it would
                  silently shrink the normal-traffic denominator)
    final window  DROPPED  (it only covers part of a second, so its timing
                  statistics are not comparable to a full window)

Frame assignment is half-open: a frame belongs to window k when
    k * window_s  <=  timestamp  <  (k + 1) * window_s
so a frame landing exactly on a boundary is counted once, in the later window.

Output windows have frames filled and features / decoded_signals EMPTY.
preprocess() fills those afterwards -- after any red-team injection -- so
normal and attacked traffic go through identical preprocessing.
"""

from __future__ import annotations

import math
from typing import Iterable, Iterator, List

from shared.schemas import Frame, TrafficWindow

from part1.fleet_simulator import read_frames

WINDOW_S = 1.0     # locked
STRIDE_S = 1.0     # locked -- equal to WINDOW_S, so windows never overlap


def window_id_for(capture_id: str, index: int) -> str:
    """cap07, 153 -> cap07_w0153. Deterministic, so Part 3 can look it up."""
    return f"{capture_id}_w{index:04d}"


def windows_from_frames(
    frames: Iterable[Frame],
    capture_id: str,
    window_s: float = WINDOW_S,
    stride_s: float = STRIDE_S,
) -> Iterator[TrafficWindow]:
    """Group an elapsed-time frame stream into TrafficWindows.

    Split out from make_windows() so it can be tested with made-up frames and
    so Part 3 can re-window an injected frame list without touching files.
    Frames must arrive in timestamp order, starting near 0.0.
    """
    if window_s <= 0:
        raise ValueError(f"window_s must be positive, got {window_s}")
    if not math.isclose(stride_s, window_s):
        raise NotImplementedError(
            f"stride_s={stride_s} != window_s={window_s}. Overlapping windows "
            f"are not supported: the team locked stride == window so each frame "
            f"lands in exactly one window. Change the decision before the code."
        )

    current_index = 0
    bucket: List[Frame] = []
    last_ts = None

    for frame in frames:
        if last_ts is not None and frame.timestamp < last_ts:
            raise ValueError(
                f"{capture_id}: frames out of order ({frame.timestamp} after "
                f"{last_ts}); windowing assumes a time-ordered stream"
            )
        last_ts = frame.timestamp

        index = int(frame.timestamp // window_s)

        # Close every window that ends before this frame, including any empty
        # ones in a gap, before placing the frame.
        while current_index < index:
            yield _build(capture_id, current_index, window_s, bucket)
            bucket = []
            current_index += 1

        bucket.append(frame)

    # The loop never emits the window holding the final frame: that window is
    # only partially covered by the recording, so it is dropped on purpose.


def make_windows(
    capture_path: str,
    capture_id: str,
    window_s: float = WINDOW_S,
    stride_s: float = STRIDE_S,
) -> Iterator[TrafficWindow]:
    """Agreed entry point for Parts 2 and 3.

    Streams one ROAD capture file and yields TrafficWindow objects with
    frames filled and features / decoded_signals empty.

        for window in make_windows(path, "cap07"):
            ...

    capture_id must be the neutral id from fleet_simulator.discover_captures,
    never the original file name.
    """
    yield from windows_from_frames(
        read_frames(capture_path), capture_id, window_s, stride_s
    )


def _build(capture_id: str, index: int, window_s: float,
           frames: List[Frame]) -> TrafficWindow:
    start = index * window_s
    return TrafficWindow(
        window_id=window_id_for(capture_id, index),
        capture_id=capture_id,
        window_start=start,
        window_end=start + window_s,
        frames=frames,
    )


if __name__ == "__main__":
    import os
    import sys
    import time

    from part1.fleet_simulator import discover_captures

    road = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/Downloads/road")
    caps = discover_captures(road)
    if not caps:
        sys.exit(f"no captures found under {road}")

    cap = caps[0]
    print(f"windowing {cap.capture_id} ...")
    t0 = time.perf_counter()
    count = frames = empty = 0
    first = None
    for w in make_windows(cap.path, cap.capture_id):
        if first is None:
            first = w
        count += 1
        frames += len(w.frames)
        empty += not w.frames
    elapsed = time.perf_counter() - t0

    print(f"  windows        {count}")
    print(f"  frames         {frames}")
    print(f"  empty windows  {empty}")
    print(f"  avg frames/win {frames / count:.0f}" if count else "")
    print(f"  took           {elapsed:.1f}s")
    if first:
        print(f"\nfirst window: {first.window_id}  "
              f"[{first.window_start}, {first.window_end})  "
              f"{len(first.frames)} frames")
