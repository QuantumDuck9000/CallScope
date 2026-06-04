"""Discover and lightly index pcap/pcapng inputs.

Discovery expands a single file, a directory, or a glob into a sorted list of
paths. Indexing collects cheap metadata (size, a sampled first/last packet
time, a format hint) without reading entire large captures.
"""

from __future__ import annotations

import glob
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from .. import platform_utils
from ..errors import PcapInputError

_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# Classic pcap magic numbers (both endiannesses, us and ns).
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
# pcapng section header block type.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass
class PcapFileInfo:
    path: Path
    size_bytes: int
    first_packet_time: float | None = None
    last_packet_time: float | None = None
    packet_count_sampled: int | None = None
    format_hint: str | None = None
    readable: bool = True
    error: str | None = None


def discover_pcaps(pattern_or_path: str) -> list[Path]:
    """Expand a file, directory, or glob into a sorted list of capture paths."""
    norm = platform_utils.normalize_path(pattern_or_path)

    paths: list[Path] = []
    if norm.is_dir():
        for entry in norm.iterdir():
            if entry.is_file() and entry.suffix.lower() in _PCAP_EXTENSIONS:
                paths.append(entry)
    elif norm.is_file():
        paths.append(norm)
    else:
        # Treat as a glob against the original pattern (preserve wildcards).
        expanded = os.path.expandvars(os.path.expanduser(pattern_or_path))
        matches = glob.glob(expanded)
        paths = [Path(m) for m in matches if Path(m).is_file()]

    if not paths:
        raise PcapInputError(f"No pcap files found for input: {pattern_or_path!r}")

    return sorted(paths, key=lambda p: p.name)


def _detect_format(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head == _PCAPNG_MAGIC:
        return "pcapng"
    if head in _PCAP_MAGICS:
        return "pcap"
    return None


def _sample_classic_pcap_first_time(path: Path) -> float | None:
    """Read just the global header + first record header of a classic pcap."""
    try:
        with path.open("rb") as fh:
            magic = fh.read(4)
            if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            else:
                return None
            nanos = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
            fh.read(20)  # rest of 24-byte global header
            rec = fh.read(16)
            if len(rec) < 16:
                return None
            ts_sec, ts_frac = struct.unpack(f"{endian}II", rec[:8])
            frac = ts_frac / 1_000_000_000 if nanos else ts_frac / 1_000_000
            return ts_sec + frac
    except (OSError, struct.error):
        return None


def index_pcaps(paths: list[Path]) -> list[PcapFileInfo]:
    """Build lightweight :class:`PcapFileInfo` records for each path."""
    infos: list[PcapFileInfo] = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError as exc:
            infos.append(
                PcapFileInfo(
                    path=path, size_bytes=0, readable=False, error=str(exc)
                )
            )
            continue
        fmt = _detect_format(path)
        first_time = _sample_classic_pcap_first_time(path) if fmt == "pcap" else None
        infos.append(
            PcapFileInfo(
                path=path,
                size_bytes=size,
                format_hint=fmt,
                first_packet_time=first_time,
                readable=fmt is not None,
                error=None if fmt is not None else "Unrecognized capture format header.",
            )
        )
    return infos


__all__ = ["PcapFileInfo", "discover_pcaps", "index_pcaps"]
