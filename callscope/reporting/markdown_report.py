"""Render a paste-ready markdown escalation report.

Designed to drop into a ticket: a one-glance header, the plain-English
narrative, findings grouped by owner (with severity, RFC clause and frame
numbers), the B2BUA fingerprint, the stream table, an explicit
"not provable from SIPREC alone" section, and a chain-of-custody block with
the source-capture SHA-256 hashes.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from ..models import Owner, RecordingAnalysis, Severity

_OWNER_ORDER = [Owner.SBC, Owner.GENESYS, Owner.NETWORK, Owner.CAPTURE, Owner.UNPROVABLE, Owner.UNKNOWN]
_OWNER_TITLE = {
    Owner.SBC: "SBC (provable from this capture)",
    Owner.GENESYS: "Genesys / recorder",
    Owner.NETWORK: "Network / recording path",
    Owner.CAPTURE: "Capture quality",
    Owner.UNPROVABLE: "Not provable from SIPREC alone",
    Owner.UNKNOWN: "Unclassified",
}


def _sev_tag(sev: Severity) -> str:
    return f"`{sev.value}`"


def _endpoint(ep) -> str:
    if ep is None:
        return "unknown"
    return f"{ep.ip}:{ep.port}" if getattr(ep, "port", None) else ep.ip


def render_markdown_escalation(analysis: RecordingAnalysis) -> str:
    lines: list[str] = []
    health = analysis.overall_health.value if analysis.overall_health else "UNKNOWN"
    lines.append(f"# SIPREC recording analysis — {analysis.call_id}")
    lines.append("")
    lines.append(f"- Overall health: **{health}**")
    lines.append(f"- SRC / SBC: `{_endpoint(analysis.src_endpoint)}`")
    lines.append(f"- SRS / recorder: `{_endpoint(analysis.srs_endpoint)}`")
    declared = sum(len(m.streams) for m in analysis.metadata)
    lines.append(f"- Streams: {declared} declared / {len(analysis.rtp_streams)} observed")
    lines.append(f"- Generated: {dt.datetime.now(tz=dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")

    if analysis.narrative:
        lines.append("## What happened")
        lines.append("")
        for step in analysis.narrative:
            frame = f" (frame {step.frame_number})" if step.frame_number else ""
            lines.append(f"{step.index}. {step.text}{frame}")
        lines.append("")

    grouped = analysis.findings_by_owner()
    if analysis.findings:
        lines.append("## Findings by owner")
        lines.append("")
        for owner in _OWNER_ORDER:
            items = grouped.get(owner.value, [])
            if not items:
                continue
            lines.append(f"### {_OWNER_TITLE[owner]}")
            lines.append("")
            for f in items:
                clause = f" [{f.clause}]" if f.clause else ""
                frames = f" — frames {', '.join(str(x) for x in f.evidence_frames)}" if f.evidence_frames else ""
                lines.append(f"- {_sev_tag(f.severity)} **{f.title}**{clause}: {f.detail}{frames}")
                if f.recommendation:
                    lines.append(f"  - Recommended: {f.recommendation}")
            lines.append("")

    if analysis.fingerprints:
        lines.append("## Endpoint fingerprint")
        lines.append("")
        lines.append("| Actor | IP | User-Agent / Server | Via sent-by | SDP origin |")
        lines.append("| --- | --- | --- | --- | --- |")
        for fp in analysis.fingerprints:
            banner = fp.user_agent or fp.server or "—"
            lines.append(
                f"| {fp.actor} | {fp.ip or '—'} | {banner} | {fp.via_sent_by or '—'} | {fp.sdp_origin_addr or '—'} |"
            )
        lines.append("")

    if analysis.rtp_streams:
        lines.append("## Observed media streams")
        lines.append("")
        lines.append("| SSRC | Dst | PT | Packets | Gaps | RTCP | Stream |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for s in analysis.rtp_streams:
            ssrc = f"0x{s.ssrc:08x}" if s.ssrc is not None else "—"
            dst = f"{s.dst.ip}:{s.dst.port}" if s.dst.port else s.dst.ip
            lines.append(
                f"| {ssrc} | {dst} | {s.payload_type if s.payload_type is not None else '—'} | "
                f"{s.packet_count} | {s.sequence_gaps} | {'yes' if s.rtcp_observed else 'no'} | "
                f"{s.matched_siprec_stream_id or s.matched_sdp_label or '—'} |"
            )
        lines.append("")

    unprovable = grouped.get(Owner.UNPROVABLE.value, [])
    if unprovable:
        lines.append("## Limits of this evidence")
        lines.append("")
        lines.append(
            "The following cannot be isolated from a SIPREC-only capture and need the "
            "original call leg, the SBC's on-box capture, or Genesys-side logs to close:"
        )
        for f in unprovable:
            lines.append(f"- {f.title}: {f.detail}")
        lines.append("")

    if analysis.capture_quality and analysis.capture_quality.file_checksums:
        lines.append("## Chain of custody")
        lines.append("")
        lines.append("Source capture SHA-256 (verify the analyzed files are unmodified):")
        lines.append("")
        for path, digest in analysis.capture_quality.file_checksums.items():
            lines.append(f"- `{digest}`  {Path(path).name}")
        for note in analysis.capture_quality.notes:
            lines.append(f"- note: {note}")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_markdown_report(analysis: RecordingAnalysis, out_dir: Path) -> Path:
    """Write escalation.md plus a timestamped copy; return the primary path."""
    text = render_markdown_escalation(analysis)
    primary = out_dir / "escalation.md"
    primary.write_text(text, encoding="utf-8")
    stamp = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    (out_dir / f"escalation-{stamp}.md").write_text(text, encoding="utf-8")
    return primary


__all__ = ["render_markdown_escalation", "write_markdown_report"]
