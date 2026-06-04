"""Capture-quality preflight and chain-of-custody.

Computes a SHA-256 of each source capture (so the exact file is reproducible by
the other team) and, when ``capinfos`` is available, reports snaplen
truncation and drop counts. Certifying the capture up front pre-empts the
"your capture is bad" deflection. Anything requiring Wireshark degrades
gracefully when the tools are absent.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .. import platform_utils
from ..models import CaptureQuality, Owner, RecordingFinding, Severity

CODE_TRUNCATED = "CAP_TRUNCATED"
CODE_DROPS = "CAP_DROPS"


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_capinfos(text: str) -> dict:
    info: dict = {}
    for line in text.splitlines():
        low = line.lower()
        if "packet size limit" in low or "snaplen" in low:
            m = re.search(r"(\d+)", line)
            if m:
                info["snaplen"] = int(m.group(1))
            if "truncat" in low:
                info["truncated"] = True
        elif "number of dropped" in low or "drop count" in low:
            m = re.search(r"(\d+)", line)
            if m:
                info["drops"] = int(m.group(1))
    return info


def _run_capinfos(path: Path) -> dict:
    exe = platform_utils.find_executable("capinfos")
    if exe is None:
        return {}
    try:
        result = subprocess.run(  # noqa: S603 - fixed args, shell=False
            [exe, "-T", "-x", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}
    return _parse_capinfos(result.stdout)


def assess_capture_quality(paths: list[Path]) -> CaptureQuality:
    """Checksum each capture and gather any available capinfos stats."""
    quality = CaptureQuality()
    capinfos_available = platform_utils.find_executable("capinfos") is not None
    if not capinfos_available:
        quality.notes.append("capinfos not found — snaplen/drop stats unavailable.")

    total_drops = 0
    for path in paths:
        try:
            quality.file_checksums[str(path)] = sha256_file(path)
        except OSError as exc:
            quality.notes.append(f"Could not checksum {path}: {exc}")
        info = _run_capinfos(path)
        if info.get("truncated"):
            quality.truncated = True
        if "snaplen" in info:
            quality.snaplen = info["snaplen"]
        if "drops" in info:
            total_drops += info["drops"]
    if capinfos_available:
        quality.drop_count = total_drops
    return quality


def build_capture_findings(quality: CaptureQuality) -> list[RecordingFinding]:
    findings: list[RecordingFinding] = []
    if quality.truncated:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_TRUNCATED,
                title="Capture is snaplen-truncated",
                detail=(
                    f"Packets were captured with a snaplen of {quality.snaplen}; "
                    "payloads may be incomplete."
                ),
                recommendation="Re-capture with full frame length (snaplen 0/65535).",
                owner=Owner.CAPTURE,
            )
        )
    if quality.drop_count:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_DROPS,
                title="Capture reported dropped packets",
                detail=f"{quality.drop_count} packet(s) were dropped during capture — gaps may be capture artifacts, not network loss.",
                owner=Owner.CAPTURE,
            )
        )
    return findings


__all__ = [
    "assess_capture_quality",
    "build_capture_findings",
    "sha256_file",
    "CODE_TRUNCATED",
    "CODE_DROPS",
]
