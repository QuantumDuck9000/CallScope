"""Thin, safe wrappers around the Wireshark CLI tools (tshark, mergecap).

All subprocess invocations use ``shell=False`` with argument lists, so
user-provided values (Call-IDs, paths, filters) are never shell-interpreted.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .. import platform_utils
from ..errors import (
    MergecapNotAvailable,
    TsharkExecutionError,
    TsharkNotAvailable,
)

# How long a single tshark/mergecap invocation may run before we give up.
_DEFAULT_TIMEOUT = 600


def tshark_available() -> bool:
    return platform_utils.tool_available("tshark")


def mergecap_available() -> bool:
    return platform_utils.tool_available("mergecap")


def get_tshark_version() -> str | None:
    return platform_utils.get_tshark_version()


def _require_tshark() -> str:
    path = platform_utils.find_tshark()
    if path is None:
        raise TsharkNotAvailable()
    return path


def _require_mergecap() -> str:
    path = platform_utils.find_mergecap()
    if path is None:
        raise MergecapNotAvailable()
    return path


def _tls_args(tls_keylog: Path | None) -> list[str]:
    """Return the tshark preference args for a TLS key log file, if supplied."""
    if tls_keylog is None:
        return []
    return ["-o", f"tls.keylog_file:{tls_keylog}"]


def _reassembly_args() -> list[str]:
    """Preferences that reassemble SIP-over-TCP/TLS multipart bodies.

    SIPREC INVITEs carry a multipart/mixed body (SDP + rs-metadata+xml) that
    frequently spans several TCP segments. Without these, the metadata part is
    truncated or emitted as raw hex and never parses.
    """
    return [
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "sip.desegment_headers:TRUE",
        "-o", "sip.desegment_body:TRUE",
    ]


def _run(cmd: list[str], *, timeout: int = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run a command list with shell=False and surface failures uniformly."""
    if os.environ.get("CALLSCOPE_DEBUG"):
        print("[callscope] tshark:", " ".join(cmd), file=sys.stderr)
    try:
        result = subprocess.run(  # noqa: S603 - shell=False, args are a list
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing dependent
        raise TsharkExecutionError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc
    except OSError as exc:
        raise TsharkExecutionError(f"Failed to execute {cmd[0]!r}: {exc}") from exc
    if result.returncode != 0:
        raise TsharkExecutionError(
            f"{Path(cmd[0]).name} exited with code {result.returncode}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    if os.environ.get("CALLSCOPE_DEBUG"):
        nlines = len([ln for ln in result.stdout.splitlines() if ln.strip()])
        print(f"[callscope]   -> {nlines} output line(s)", file=sys.stderr)
    return result


def run_tshark_json(
    pcap: Path,
    display_filter: str | None = None,
    tls_keylog: Path | None = None,
) -> list[dict]:
    """Run tshark with ``-T json`` and return the parsed packet array."""
    tshark = _require_tshark()
    cmd = [tshark, "-r", str(pcap), "-T", "json"]
    cmd += _reassembly_args()
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += _tls_args(tls_keylog)
    result = _run(cmd)
    if not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise TsharkExecutionError(f"Could not parse tshark JSON output: {exc}") from exc
    if not isinstance(data, list):
        raise TsharkExecutionError("Unexpected tshark JSON output (expected a list).")
    return data


_INVALID_FIELD_RE = re.compile(r"^\s+([a-zA-Z0-9_.]+)\s*$")


def _parse_invalid_fields(message: str) -> list[str]:
    """Extract the field names tshark rejected from its error message."""
    if "aren't valid" not in message and "isn't a valid" not in message:
        return []
    bad: list[str] = []
    for line in message.splitlines():
        m = _INVALID_FIELD_RE.match(line)
        if m:
            bad.append(m.group(1))
    return bad


def run_tshark_fields(
    pcap: Path,
    fields: list[str],
    display_filter: str | None = None,
    tls_keylog: Path | None = None,
    decode_as: list[str] | None = None,
    occurrence: str = "f",
) -> list[dict[str, str]]:
    """Run tshark with ``-T fields`` and return a list of field dicts.

    Output is requested as tab-separated with a header row so we can map columns
    back to field names regardless of tshark version. ``decode_as`` entries
    (e.g. ``"udp.port==40000,rtcp"``) force a dissector on a port. ``occurrence``
    is the tshark ``-E occurrence`` mode (``"f"`` first, ``"a"`` all — use ``"a"``
    to get every value of a repeated field, e.g. RTCP report blocks, comma-joined).

    Field names drift between tshark versions; if tshark rejects one or more
    fields as invalid, the offending fields are dropped and the command is
    retried, so a single unknown field never blanks out the whole result.
    """
    if not fields:
        raise ValueError("At least one field is required for run_tshark_fields.")
    tshark = _require_tshark()
    active = list(fields)

    while True:
        cmd = [tshark, "-r", str(pcap), "-T", "fields"]
        cmd += _reassembly_args()
        for entry in decode_as or []:
            cmd += ["-d", entry]
        for fname in active:
            cmd += ["-e", fname]
        cmd += ["-E", "header=y", "-E", "separator=/t", "-E", f"occurrence={occurrence}"]
        if display_filter:
            cmd += ["-Y", display_filter]
        cmd += _tls_args(tls_keylog)
        try:
            result = _run(cmd)
            break
        except TsharkExecutionError as exc:
            bad = _parse_invalid_fields(str(exc))
            remaining = [f for f in active if f not in bad]
            if not bad or remaining == active or not remaining:
                raise
            if os.environ.get("CALLSCOPE_DEBUG"):
                print(f"[callscope]   dropping invalid field(s): {bad}", file=sys.stderr)
            active = remaining

    lines = result.stdout.splitlines()
    if not lines:
        return []
    header = lines[0].split("\t")
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split("\t")
        values += [""] * (len(header) - len(values))
        rows.append(dict(zip(header, values, strict=False)))
    return rows


def extract_packets(
    input_pcap: Path,
    output_pcap: Path,
    display_filter: str,
    tls_keylog: Path | None = None,
    output_format: str = "pcapng",
) -> None:
    """Extract packets matching ``display_filter`` from one capture file.

    Uses ``tshark -Y <filter> -w <out>`` which preserves full packet bytes
    (unlike a JSON/fields read).
    """
    tshark = _require_tshark()
    cmd = [
        tshark,
        "-r", str(input_pcap),
        "-Y", display_filter,
        "-w", str(output_pcap),
        "-F", output_format,
    ]
    cmd += _tls_args(tls_keylog)
    _run(cmd)


def merge_pcaps(inputs: list[Path], output: Path, output_format: str = "pcapng") -> None:
    """Merge multiple capture files into one using mergecap."""
    if not inputs:
        raise TsharkExecutionError("merge_pcaps called with no input files.")
    mergecap = _require_mergecap()
    cmd = [mergecap, "-F", output_format, "-w", str(output)]
    cmd += [str(p) for p in inputs]
    _run(cmd)


__all__ = [
    "tshark_available",
    "mergecap_available",
    "get_tshark_version",
    "run_tshark_json",
    "run_tshark_fields",
    "extract_packets",
    "merge_pcaps",
]
