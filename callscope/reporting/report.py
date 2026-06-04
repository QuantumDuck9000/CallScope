"""Render the self-contained HTML report from a :class:`RecordingAnalysis`.

The Jinja2 template is loaded from installed package data via
``importlib.resources`` so rendering works from a built wheel, not just an
editable install. All report data is embedded as JSON inside the HTML, and the
template inlines its own CSS/JS so the result is fully offline-capable.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from enum import Enum
from importlib import resources
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .. import config
from ..errors import ReportGenerationError
from ..models import RecordingAnalysis, Severity
from .ladder import build_ladder_model


def _json_default(obj: object) -> object:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)


def _status_value(value: Severity | None) -> str:
    return value.value if isinstance(value, Severity) else "UNKNOWN"


def _duration_str(analysis: RecordingAnalysis) -> str:
    epochs = [m.timestamp_epoch for m in analysis.sip_messages if m.timestamp_epoch is not None]
    if len(epochs) < 2:
        return "unknown"
    seconds = max(epochs) - min(epochs)
    total_ms = int(round(seconds * 1000))
    hours, rem = divmod(total_ms, 3_600_000)
    minutes, rem = divmod(rem, 60_000)
    secs, ms = divmod(rem, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{ms:03d}"


def _endpoint_dict(endpoint: object) -> dict | None:
    if endpoint is None:
        return None
    return {
        "ip": getattr(endpoint, "ip", None),
        "port": getattr(endpoint, "port", None),
        "label": getattr(endpoint, "label", None),
    }


def _rtcp_card_detail(analysis: RecordingAnalysis) -> str:
    s = analysis.rtcp_packet_summary or {}
    if not s.get("total"):
        return "no RTCP observed"
    by = s.get("by_type", {})
    if s.get("report_blocks"):
        return f"{s['report_blocks']} reception reports"
    return f"{s['total']} pkts ({by.get('SR', 0)} SR, {by.get('RR', 0)} RR) — no reception reports, quality not scorable"


def build_report_context(analysis: RecordingAnalysis) -> dict:
    """Assemble the full context dict embedded into the report."""
    ladder = build_ladder_model(analysis.sip_messages)

    from ..siprec.ssrc_lifecycle import is_substantial

    streams = []
    for s in analysis.rtp_streams:
        noise = not is_substantial(s)
        streams.append(
            {
                "ssrc": (f"0x{s.ssrc:08x}" if s.ssrc is not None else None),
                "src": _endpoint_dict(s.src),
                "dst": _endpoint_dict(s.dst),
                "payload_type": s.payload_type,
                "packet_count": s.packet_count,
                "first_time": s.first_timestamp_relative,
                "last_time": s.last_timestamp_relative,
                "sequence_gaps": s.sequence_gaps,
                "largest_gap": s.largest_gap,
                "rtcp_observed": s.rtcp_observed,
                "matched_siprec_stream_id": s.matched_siprec_stream_id,
                "matched_sdp_label": s.matched_sdp_label,
                "participant_aor": s.participant_aor,
                "participant_name": s.participant_name,
                "is_noise": noise,
            }
        )
    noise_stream_count = sum(1 for s in streams if s["is_noise"])
    substantial_stream_count = len(streams) - noise_stream_count

    findings = [
        {
            "severity": f.severity.value,
            "code": f.code,
            "title": f.title,
            "detail": f.detail,
            "evidence_frames": f.evidence_frames,
            "recommendation": f.recommendation,
            "owner": f.owner.value if f.owner is not None else "UNKNOWN",
            "clause": f.clause,
            "evidence_streams": f.evidence_streams,
        }
        for f in analysis.findings
    ]

    output_files = []
    if analysis.output_pcap:
        output_files.append(analysis.output_pcap.name)
    if analysis.report_html:
        output_files.append(analysis.report_html.name)
    output_files += [
        config.OUTPUT_SUMMARY_TXT,
        config.OUTPUT_SUMMARY_JSON,
        config.OUTPUT_METADATA_JSON,
        config.OUTPUT_MEDIA_JSON,
        config.OUTPUT_FINDINGS_JSON,
        "rtcp-stats.json",
        "correlation-key.json",
        "escalation.md",
    ]

    narrative = [
        {"index": s.index, "text": s.text, "frame_number": s.frame_number}
        for s in analysis.narrative
    ]

    fingerprints = [
        {
            "actor": fp.actor,
            "ip": fp.ip,
            "user_agent": fp.user_agent,
            "server": fp.server,
            "contact_host": fp.contact_host,
            "via_sent_by": fp.via_sent_by,
            "sdp_origin_addr": fp.sdp_origin_addr,
        }
        for fp in analysis.fingerprints
    ]

    rtcp = [
        {
            "ssrc": (f"0x{s.ssrc:08x}" if s.ssrc is not None else None),
            "report_count": s.report_count,
            "fraction_lost_max": s.fraction_lost_max,
            "cumulative_lost": s.cumulative_lost,
            "jitter_min": s.jitter_min,
            "jitter_avg": s.jitter_avg,
            "jitter_max": s.jitter_max,
            "max_report_gap_s": s.max_report_gap_s,
            "rtcp_bye_seen": s.rtcp_bye_seen,
        }
        for s in analysis.rtcp_stats
    ]

    mos_estimates = [
        {
            "ssrc": (f"0x{e.ssrc:08x}" if e.ssrc is not None else None),
            "label": e.label,
            "participant": e.participant,
            "codec": e.codec,
            "mos_avg": e.mos_avg,
            "mos_min": e.mos_min,
            "r_factor_avg": e.r_factor_avg,
            "loss_pct_avg": e.loss_pct_avg,
            "jitter_ms_avg": e.jitter_ms_avg,
            "one_way_delay_ms": e.one_way_delay_ms,
            "samples": [
                {"time_relative": s.time_relative, "mos": s.mos, "loss_pct": s.loss_pct, "jitter_ms": s.jitter_ms}
                for s in e.samples
            ],
        }
        for e in analysis.mos_estimates
    ]

    ssrc_changes = [
        {
            "flow_key": c.flow_key,
            "time_relative": c.time_relative,
            "from_ssrc": (f"0x{c.from_ssrc:08x}" if c.from_ssrc is not None else None),
            "to_ssrc": (f"0x{c.to_ssrc:08x}" if c.to_ssrc is not None else None),
        }
        for c in analysis.ssrc_changes
    ]

    bursts = [
        {
            "window_start": b.window_start,
            "window_end": b.window_end,
            "count": b.count,
            "codec_renegotiation": b.codec_renegotiation,
            "evidence_frames": b.evidence_frames,
        }
        for b in analysis.bursts
    ]

    capture = None
    if analysis.capture_quality is not None:
        capture = {
            "truncated": analysis.capture_quality.truncated,
            "snaplen": analysis.capture_quality.snaplen,
            "drop_count": analysis.capture_quality.drop_count,
            "file_checksums": analysis.capture_quality.file_checksums,
            "notes": analysis.capture_quality.notes,
        }

    lifecycles = [
        {
            "label": lc.label,
            "participant": lc.participant,
            "port_key": lc.port_key,
            "ssrc_change_count": lc.ssrc_change_count,
            "stability_per_min": lc.stability_per_min,
            "segments": [
                {
                    "ssrc": (f"0x{seg.ssrc:08x}" if seg.ssrc is not None else None),
                    "first_time": seg.first_time,
                    "last_time": seg.last_time,
                    "packet_count": seg.packet_count,
                    "trigger_cseq": seg.trigger_cseq,
                }
                for seg in lc.segments
            ],
        }
        for lc in analysis.label_lifecycles
    ]

    coverage_gaps = [
        {
            "label": g.label,
            "participant": g.participant,
            "start_time": g.start_time,
            "end_time": g.end_time,
            "duration_s": g.duration_s,
            "old_ssrc": (f"0x{g.old_ssrc:08x}" if g.old_ssrc is not None else None),
            "new_ssrc": (f"0x{g.new_ssrc:08x}" if g.new_ssrc is not None else None),
            "reason": g.reason,
        }
        for g in analysis.coverage_gaps
    ]

    hold_retrieve_events = [
        {"kind": e.kind, "time_relative": e.time_relative, "frame_number": e.frame_number, "cseq": e.cseq}
        for e in analysis.hold_retrieve_events
    ]

    grouped = analysis.findings_by_owner()
    findings_by_owner = {
        owner: [
            {
                "severity": f.severity.value,
                "code": f.code,
                "title": f.title,
                "detail": f.detail,
                "evidence_frames": f.evidence_frames,
                "recommendation": f.recommendation,
                "clause": f.clause,
            }
            for f in items
        ]
        for owner, items in grouped.items()
    }

    return {
        "call_id": analysis.call_id,
        "mode": "SIPREC",
        "generated_at": dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_health": _status_value(analysis.overall_health),
        "duration": _duration_str(analysis),
        "src": _endpoint_dict(analysis.src_endpoint) or ladder["src"],
        "srs": _endpoint_dict(analysis.srs_endpoint) or ladder["srs"],
        "status_cards": [
            {"name": "SIP", "status": _status_value(analysis.status_sip)},
            {"name": "SDP", "status": _status_value(analysis.status_sdp)},
            {"name": "Metadata", "status": _status_value(analysis.status_metadata)},
            {
                "name": "Streams",
                "status": _status_value(analysis.status_streams),
                "detail": f"{sum(len(m.streams) for m in analysis.metadata)} declared / "
                f"{len(analysis.rtp_streams)} observed",
            },
            {"name": "RTP", "status": _status_value(analysis.status_rtp)},
            {
                "name": "RTCP",
                "status": _status_value(analysis.status_rtcp),
                "detail": _rtcp_card_detail(analysis),
            },
            {"name": "Gaps", "status": _status_value(analysis.status_gaps)},
            {
                "name": "Findings",
                "status": "WARN" if findings else "PASS",
                "detail": f"{len(analysis.warnings())} warnings, {len(analysis.errors())} errors",
            },
        ],
        "ladder": ladder,
        "streams": streams,
        "substantial_stream_count": substantial_stream_count,
        "noise_stream_count": noise_stream_count,
        "findings": findings,
        "findings_by_owner": findings_by_owner,
        "narrative": narrative,
        "fingerprints": fingerprints,
        "rtcp_stats": rtcp,
        "rtcp_packet_summary": analysis.rtcp_packet_summary or {},
        "mos_estimates": mos_estimates,
        "ssrc_changes": ssrc_changes,
        "bursts": bursts,
        "capture_quality": capture,
        "label_lifecycles": lifecycles,
        "coverage_gaps": coverage_gaps,
        "hold_retrieve_events": hold_retrieve_events,
        "rtcp_mux_packet_count": analysis.rtcp_mux_packet_count,
        "output_files": output_files,
    }


def _load_template_text() -> str:
    try:
        package = resources.files("callscope.reporting").joinpath(
            "templates", config.DEFAULT_REPORT_TEMPLATE
        )
        return package.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise ReportGenerationError(
            f"Could not load report template {config.DEFAULT_REPORT_TEMPLATE!r}: {exc}"
        ) from exc


def render_html_report(analysis: RecordingAnalysis, output_path: Path) -> None:
    """Render the report to ``output_path``."""
    context = build_report_context(analysis)
    template_text = _load_template_text()

    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(template_text)

    report_json = json.dumps(context, default=_json_default, ensure_ascii=False)
    # Prevent a literal "</script>" inside embedded data from closing the tag.
    # "<\/" is a valid escaped solidus inside a JSON string, so this stays valid JSON.
    report_json = report_json.replace("</", "<\\/")
    try:
        html = template.render(report=context, report_json=report_json)
    except Exception as exc:  # noqa: BLE001 - surface as a clean report error
        raise ReportGenerationError(f"Failed to render report HTML: {exc}") from exc

    output_path.write_text(html, encoding="utf-8")


__all__ = ["render_html_report", "build_report_context"]
