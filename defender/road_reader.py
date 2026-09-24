"""
ROAD log reader: turns a ROAD .log capture into TrafficWindows.

PART 2 FALLBACK. Window creation is Part 1's job. This reader exists so
the Defender can be trained and tested on real ROAD data before Part 1's
make_windows() is ready. It uses EXACTLY the agreed signature:

    make_windows(capture_path, capture_id, window_s, stride_s)
        -> Iterator[TrafficWindow]   (frames filled, features empty)

so Part 1's version can replace it with no other changes (Part 1 is
also welcome to reuse this one).

ROAD log line format (checked on the real files):
    (1080000000.001017) can0 0D7#0000020080000000
     timestamp          bus  ID  payload (hex)

Behaviour:
  - Reads the file LINE BY LINE (some captures are ~400 MB), never all at once.
  - Never modifies the capture file (opened read-only).
  - Window k covers [t0 + k*stride_s, t0 + k*stride_s + window_s), where
    t0 is the first timestamp in the file. A frame on a boundary belongs to
    the LATER window, so with stride_s == window_s no frame is counted twice.
  - Windows with no frames (a pause in the data) are still produced.
  - A trailing window that the capture does not fully cover is dropped,
    because a half-length window would make message rates look too low.
  - capture_id must be neutral (e.g. "cap07"); the shared schema rejects
    names containing "ambient" or "attack".
  - A malformed line stops reading with an error naming the line number.
"""

import os
import re
from collections import deque
from typing import Iterator, Tuple

from shared.schemas import TrafficWindow

_LINE = re.compile(r"^\((\d+(?:\.\d+)?)\)\s+\S+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)\s*$")


def parse_line(line: str, line_number: int) -> Tuple[float, str, str]:
    """Parse one ROAD log line into (timestamp, can_id, payload)."""
    match = _LINE.match(line.strip())
    if not match:
        raise ValueError(
            f"line {line_number}: not a ROAD log line: {line.strip()[:60]!r} "
            f"(expected e.g. '(1080000000.001017) can0 0D7#0000020080000000')"
        )
    return float(match.group(1)), match.group(2).upper(), match.group(3).upper()

def iter_frames(capture_path) -> Iterator[Tuple[float, str, str]]:
    """Every (timestamp, can_id, payload) of a capture, line by line."""
    return _frames(capture_path)
    
def _frames(capture_path) -> Iterator[Tuple[float, str, str]]:
    with open(capture_path, "r", encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            if line.strip():
                yield parse_line(line, number)


def first_timestamp(capture_path) -> float:
    """First timestamp of a capture. The evaluator needs this to convert
    raw timestamps to the elapsed seconds used by injection_interval."""
    for timestamp, _, _ in _frames(capture_path):
        return timestamp
    raise ValueError(f"{capture_path} contains no CAN frames")


def last_timestamp(capture_path) -> float:
    """Last timestamp of a capture, read from the END of the file (fast even
    for very large captures)."""
    with open(capture_path, "rb") as file:
        file.seek(0, os.SEEK_END)
        position = file.tell()
        tail = b""
        while position > 0:
            step = min(4096, position)
            position -= step
            file.seek(position)
            tail = file.read(step) + tail
            lines = [l for l in tail.decode("utf-8", errors="replace").splitlines() if l.strip()]
            if len(lines) >= 2 or (position == 0 and lines):
                return parse_line(lines[-1], -1)[0]
    raise ValueError(f"{capture_path} contains no CAN frames")


def make_windows(capture_path, capture_id: str, window_s: float,
                 stride_s: float, *, keep_every: int = 1) -> Iterator[TrafficWindow]:
    """Yield TrafficWindows from a ROAD .log file (frames filled, features empty).
    Optional keep_every=N yields only every Nth window (skipped ones are never
    built), to limit memory. The default 1 is the agreed Part 1 behaviour."""
    if window_s <= 0 or stride_s <= 0:
        raise ValueError(f"window_s and stride_s must be positive, got {window_s}, {stride_s}")
    if not isinstance(keep_every, int) or keep_every < 1:
        raise ValueError(f"keep_every must be a whole number >= 1, got {keep_every}")

    buffer = deque()          # frames that may still belong to a future window
    window_index = 0
    start = None

    def build(win_start):
        win_end = win_start + window_s
        frames = [{"timestamp": t, "can_id": i, "payload": p}
                  for (t, i, p) in buffer if win_start <= t < win_end]
        return TrafficWindow(window_id=f"{capture_id}_w{window_index:05d}",
                             capture_id=capture_id, window_start=win_start,
                             window_end=win_end, frames=frames)

    for frame in _frames(capture_path):
        timestamp = frame[0]
        if start is None:
            start = timestamp
        # Emit every window that ends at or before this frame's time.
        while timestamp >= start + window_s:
            if window_index % keep_every == 0:
                yield build(start)
            window_index += 1
            start += stride_s
            while buffer and buffer[0][0] < start:
                buffer.popleft()
        buffer.append(frame)
    # Remaining buffered frames only partly fill a window: dropped (see docstring).