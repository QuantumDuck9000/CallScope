"""Output writing: directories, JSON files, summary.txt, and pcap finalization."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from enum import Enum
from pathlib import Path

from .. import config
from ..models import RecordingAnalysis, Severity
from . import tshark


def ensure_output_dir(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def ensure_temp_dir(out_dir: Path) -> Path:
    temp = out_dir / config.TEMP_DIRNAME
    temp.mkdir(parents=True, exist_ok=True)
    return temp


def _json_default(obj: object) -> object:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def write_json(path: Path, data: object) -> None:
    """Write ``data`` as pretty JSON, tolerating dataclasses/enums/Paths."""
    if dataclasses.is_dataclass(data) and not isinstance(data, type):
        data = dataclasses.asdict(data)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=_json_default, ensure_ascii=False)
        fh.write("\n")


def _epoch_to_iso_z(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    moment = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "unknown"
    total_ms = int(round(seconds * 1000))
    hours, rem = divmod(total_ms, 3_600_000)
    minutes, rem = divmod(rem, 60_000)
    secs, ms = divmod(rem, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{ms:03d}"


def _endpoint_str(endpoint: object) -> str:
    if endpoint is None:
        return "unknown"
    ip = getattr(endpoint, "ip", "") or "unknown"
    port = getattr(endpoint, "port", None)
    return f"{ip}:{port}" if port is not None else ip


def _status(value: Severity | None) -> str:
    return value.value if value is not None else "UNKNOWN"


def write_summary_txt(path: Path, analysis: RecordingAnalysis) -> None:
    """Write the stable, grep-friendly summary.txt."""
    epochs = [m.timestamp_epoch for m in analysis.sip_messages if m.timestamp_epoch is not None]
    start_epoch = min(epochs) if epochs else None
    end_epoch = max(epochs) if epochs else None
    duration = (end_epoch - start_epoch) if (start_epoch and end_epoch) else None

    declared = sum(len(m.streams) for m in analysis.metadata)
    observed = len(analysis.rtp_streams)

    warnings = len(analysis.warnings())
    errors = len(analysis.errors())

    output_pcap = analysis.output_pcap.name if analysis.output_pcap else "(none)"
    report_html = analysis.report_html.name if analysis.report_html else "(none)"

    rtcp_note = ""
    if analysis.status_rtcp == Severity.WARN:
        missing = [
            s for s in analysis.rtp_streams if not s.rtcp_observed
        ]
        if missing:
            rtcp_note = f" missing for {len(missing)} stream(s)"

    gaps_total = sum(s.sequence_gaps for s in analysis.rtp_streams)
    gaps_note = f" {gaps_total} RTP sequence gaps" if gaps_total else ""

    lines = [
        f"CALL-ID:      {analysis.call_id}",
        "MODE:         SIPREC",
        f"START:        {_epoch_to_iso_z(start_epoch) or 'unknown'}",
        f"END:          {_epoch_to_iso_z(end_epoch) or 'unknown'}",
        f"DURATION:     {_format_duration(duration)}",
        f"SRC:          {_endpoint_str(analysis.src_endpoint)}",
        f"SRS:          {_endpoint_str(analysis.srs_endpoint)}",
        f"SIP:          {_status(analysis.status_sip)}",
        f"SDP:          {_status(analysis.status_sdp)}",
        f"METADATA:     {_status(analysis.status_metadata)}",
        f"STREAMS:      {declared} declared / {observed} observed",
        f"RTP:          {_status(analysis.status_rtp)}",
        f"RTCP:         {_status(analysis.status_rtcp)}{rtcp_note}",
        f"GAPS:         {_status(analysis.status_gaps)}{gaps_note}",
        f"FINDINGS:     {warnings} warnings, {errors} errors",
        f"OUTPUT-PCAP:  {output_pcap}",
        f"REPORT-HTML:  {report_html}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def finalize_output_pcap(partials: list[Path], output: Path, output_format: str) -> None:
    """Merge partial captures into the final output (or copy a single partial)."""
    existing = [p for p in partials if p.exists()]
    if not existing:
        return
    if len(existing) == 1:
        # Still run through mergecap to normalize the output format.
        tshark.merge_pcaps(existing, output, output_format=output_format)
    else:
        tshark.merge_pcaps(existing, output, output_format=output_format)


__all__ = [
    "ensure_output_dir",
    "ensure_temp_dir",
    "write_json",
    "write_summary_txt",
    "finalize_output_pcap",
]
