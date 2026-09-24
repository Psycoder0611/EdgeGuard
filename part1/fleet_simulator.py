"""
Part 1 -- fleet simulator.

Reads ROAD .log captures and yields Frame objects. Nothing else in the
pipeline touches raw files or raw timestamps.

Responsibilities
    - parse the SocketCAN log line format
    - convert timestamps to ELAPSED seconds from the start of each capture
    - assign neutral capture ids (cap01, cap02, ...) so no file name reaches
      the Defender
    - never modify the original ROAD files

Log line format (confirmed against the real files):
    (1110000000.000000) can0 0F4#960C010204B10240
     └── timestamp ──┘  └bus┘ └ID┘ └── payload ──┘

Two ID formats exist and must be reconciled
    .log files            "0F4"    uppercase, 3 hex digits
    capture_metadata.json "0x6e0"  lowercase, 0x prefix, sometimes 2 digits
    signal_extraction CSV  244     decimal
    Canonical form is the .log form: uppercase, no prefix, zero padded to at
    least 3 digits. Use canonical_can_id() for every source.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from shared.schemas import Frame

# (timestamp) bus ID#PAYLOAD
_LOG_LINE = re.compile(
    r"^\((?P<ts>\d+(?:\.\d+)?)\)\s+"
    r"(?P<bus>\S+)\s+"
    r"(?P<can_id>[0-9A-Fa-f]+)#(?P<payload>[0-9A-Fa-f]*)\s*$"
)


def canonical_can_id(raw) -> str:
    """One CAN id form for every source.

        canonical_can_id("0F4")    -> "0F4"    (already canonical)
        canonical_can_id("0x6e0")  -> "6E0"    (metadata form)
        canonical_can_id("0xd0")   -> "0D0"    (metadata, 2 digits -> padded)
        canonical_can_id(244)      -> "0F4"    (decimal, from signal CSVs)

    Without padding, metadata "0xd0" becomes "D0" and never matches the log
    file's "0D0" -- the lookup silently returns nothing.
    """
    if isinstance(raw, int):
        return format(raw, "03X")
    text = str(raw).strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if text.upper() == "XXX":       # fuzzing: every id is injected
        return "XXX"
    return format(int(text, 16), "03X")


@dataclass(frozen=True)
class Capture:
    """One ROAD capture file, with its neutral id.

    original_name and path stay on this object and must never be copied into
    a TrafficWindow -- "max_speedometer_attack_1" would hand over the answer.
    """
    capture_id: str          # "cap07"
    original_name: str       # "max_speedometer_attack_1"
    path: str
    first_timestamp: Optional[float] = None   # raw, filled after first read


def discover_captures(road_dir: str) -> list[Capture]:
    """Assign cap01..capNN deterministically.

    Sorted by folder then file name, so every teammate running this on their
    own machine gets the SAME mapping. os.listdir alone is unordered -- the
    sort is what makes it reproducible.

    Ambient captures come first, then attack captures. The ordering rule is
    arbitrary but must be stable, or cap07 means different files for
    different people and every split becomes meaningless.
    """
    captures: list[Capture] = []
    for sub in ("ambient", "attacks"):
        folder = os.path.join(road_dir, sub)
        if not os.path.isdir(folder):
            continue
        names = sorted(f for f in os.listdir(folder) if f.endswith(".log"))
        for name in names:
            captures.append(
                Capture(
                    capture_id="",                       # filled below
                    original_name=name[: -len(".log")],
                    path=os.path.join(folder, name),
                )
            )
    return [
        Capture(f"cap{i:02d}", c.original_name, c.path)
        for i, c in enumerate(captures, start=1)
    ]


def _to_nanoseconds(ts_text: str) -> int:
    """'1110000000.001020' -> 1110000000001020000, exactly.

    Parsing to float first loses precision: at ~1.1e9 a float only resolves
    about 0.24 microseconds, so 0.1 s of elapsed time comes out as
    0.09999990463256836. That is enough to push a frame across a window
    boundary. Integer nanoseconds are exact.
    """
    seconds, _, fraction = ts_text.partition(".")
    return int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0")[:9])


def read_frames(capture_path: str) -> Iterator[Frame]:
    """Stream one capture as Frames with ELAPSED timestamps.

    Streams line by line: some ROAD logs are ~400 MB and must not be read
    into memory whole.

    The first timestamp in the file becomes 0.0 and everything counts up from
    there, so frames, window bounds and injection_interval all share one
    clock. Raw log timestamps (~1110000000) never leave this function.

    The subtraction is done in integer nanoseconds, then converted once to
    float. Elapsed values are small, so that final float is precise.
    """
    first_ns: Optional[int] = None
    with open(capture_path, "r") as fh:
        for line in fh:
            match = _LOG_LINE.match(line)
            if match is None:
                continue                      # blank, comment or malformed
            raw_ns = _to_nanoseconds(match["ts"])
            if first_ns is None:
                first_ns = raw_ns
            yield Frame(
                timestamp=(raw_ns - first_ns) / 1_000_000_000,
                can_id=match["can_id"].upper(),
                payload=match["payload"].upper(),
            )


def read_capture_stats(capture_path: str) -> dict:
    """One pass over a capture, for sanity checking before building windows.

    Reports skipped lines explicitly: silently dropping a chunk of a file is
    the kind of thing nobody notices until the numbers look strange.
    """
    parsed = skipped = 0
    first_ts = last_ts = None
    ids: set[str] = set()
    with open(capture_path, "r") as fh:
        for line in fh:
            if not line.strip():
                continue
            match = _LOG_LINE.match(line)
            if match is None:
                skipped += 1
                continue
            ts = float(match["ts"])
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            ids.add(match["can_id"].upper())
            parsed += 1
    duration = (last_ts - first_ts) if first_ts is not None else 0.0
    return {
        "frames": parsed,
        "skipped_lines": skipped,
        "duration_s": round(duration, 6),
        "unique_ids": len(ids),
        "first_raw_timestamp": first_ts,
        "msg_per_sec": round(parsed / duration, 1) if duration else 0.0,
    }


if __name__ == "__main__":
    import sys

    road = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/Downloads/road")
    caps = discover_captures(road)
    print(f"{len(caps)} captures found\n")
    for c in caps[:5]:
        print(f"  {c.capture_id}  <-  {c.original_name}")
    print("  ...")
    if caps:
        c = caps[0]
        print(f"\nstats for {c.capture_id}:")
        for key, value in read_capture_stats(c.path).items():
            print(f"  {key:22} {value}")
        print(f"\nfirst 3 frames of {c.capture_id} (elapsed seconds):")
        for i, frame in enumerate(read_frames(c.path)):
            print(f"  t={frame.timestamp:.6f}  id={frame.can_id}  "
                  f"dlc={len(frame.payload)//2}  payload={frame.payload}")
            if i >= 2:
                break
