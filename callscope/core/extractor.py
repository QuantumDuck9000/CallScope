"""Orchestration of the SIPREC extraction + analysis flow.

This wires together pcap discovery, tshark-based SIP/RTP extraction, parsing,
timeline construction, correlation, health checks, and output writing. The
heavy packet work is delegated to :mod:`callscope.core.tshark`; if the
Wireshark CLI tools are unavailable a clear error is raised.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..errors import CallIDNotFound, PcapInputError
from ..models import (
    Owner,
    RecordingAnalysis,
    RecordingFinding,
    SdpSession,
    Severity,
    SipMessage,
)
from ..siprec import (
    burst_detector,
    capture_quality,
    compliance,
    consistency,
    error_origin,
    fingerprint,
    gap_detector,
    hold_retrieve,
    labels,
    mos,
    ownership,
    recording_correlator,
    recording_health,
    rtcp_stats,
    rtp_tracker,
    session_timeline,
    sip_timing,
    ssrc_lifecycle,
    ssrc_tracker,
)
from ..siprec.siprec_parser import extract_siprec_metadata_from_message
from ..reporting import narrative
from . import sdp_parser, sip_parser, tshark, writer
from .correlation_export import build_correlation_key
from .pcap_index import discover_pcaps, index_pcaps


@dataclass
class ExtractionOptions:
    call_id: str
    pcaps: str
    out_dir: Path
    tls_keylog: Path | None = None
    keep_temp: bool = False
    output_format: str = config.DEFAULT_OUTPUT_FORMAT
    write_html: bool = True


def _escape_filter_value(value: str) -> str:
    """Escape a value for safe inclusion inside a tshark double-quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _sip_call_id_filter(call_id: str) -> str:
    return f'sip.Call-ID == "{_escape_filter_value(call_id)}"'


def _enrich_message(message: SipMessage) -> None:
    """Attach parsed SDP and SIPREC metadata to a SIP message in place."""
    for part in sip_parser.iter_body_parts(message):
        ctype = (part.content_type or "").lower()
        if "application/sdp" in ctype and part.content.strip():
            try:
                message.sdp = sdp_parser.parse_sdp(part.content)
            except Exception:  # noqa: BLE001 - tolerate malformed SDP, keep going
                message.sdp = SdpSession(
                    connection_address=None,
                    origin=None,
                    session_name=None,
                    raw=part.content,
                )
    try:
        metadata = extract_siprec_metadata_from_message(message)
    except Exception:  # noqa: BLE001 - tolerate malformed metadata
        metadata = None
    if metadata is not None:
        message.siprec_metadata = metadata


def collect_sip_messages(
    pcaps: list[Path], call_id: str, tls_keylog: Path | None
) -> list[SipMessage]:
    """Read SIP messages matching the Call-ID from all captures."""
    display_filter = _sip_call_id_filter(call_id)
    messages: list[SipMessage] = []
    for pcap in pcaps:
        rows = tshark.run_tshark_json(pcap, display_filter=display_filter, tls_keylog=tls_keylog)
        messages.extend(sip_parser.parse_sip_messages_from_tshark_json(rows))
    messages.sort(key=lambda m: (m.timestamp_relative if m.timestamp_relative is not None else 0.0))
    for msg in messages:
        _enrich_message(msg)
    return messages


def _build_combined_filter(call_id: str, messages: list[SipMessage], metadata: list) -> str:
    sip_clause = _sip_call_id_filter(call_id)
    media_filter = rtp_tracker.build_media_display_filter(messages, metadata)
    return f"({sip_clause}) or ({media_filter})"


def _analyze_media_extras(
    analysis: RecordingAnalysis,
    pcaps: list[Path],
    messages: list[SipMessage],
    metadata: list,
    tls_keylog: Path | None,
) -> None:
    """Best-effort SSRC-change and RTCP-statistics analysis.

    Both require tshark field extraction; failures are swallowed so the rest of
    the report still completes on environments without the media detail.
    """
    media_filter = rtp_tracker.build_media_display_filter(messages, metadata)

    # SSRC changes (reuse the RTP field set).
    try:
        rtp_rows: list[dict] = []
        for pcap in pcaps:
            rtp_rows += tshark.run_tshark_fields(
                pcap, rtp_tracker.RTP_FIELDS, display_filter=media_filter, tls_keylog=tls_keylog
            )
        observations = ssrc_tracker.observations_from_rtp_rows(rtp_rows)
        changes = ssrc_tracker.track_ssrc_changes(observations)
        analysis.ssrc_changes = changes
        ssrc_tracker.annotate_streams(analysis.rtp_streams, changes)
        analysis.findings.extend(ssrc_tracker.build_ssrc_findings(changes, analysis.rtp_streams))
    except Exception:  # noqa: BLE001 - media extras are optional
        pass

    # RTCP statistics.
    try:
        rtcp_fields = rtcp_stats.RTCP_FIELDS + ["rtp.p_type"]

        # 1) Native pass — no decode-as, so SDP-based RTP/RTCP tracking is intact.
        #    This is the common case (RTCP on its own port).
        rtcp_rows: list[dict] = []
        for pcap in pcaps:
            rtcp_rows += tshark.run_tshark_fields(
                pcap, rtcp_fields, display_filter="rtcp", tls_keylog=tls_keylog, occurrence="a"
            )
        summary = rtcp_stats.summarize_rtcp_packets(rtcp_rows)

        # 2) Fallback — only if the native pass found no scorable reports, try
        #    forcing rtcp-mux dissection on the media ports (RFC 5761). This is
        #    skipped in the common case because it can disturb conversation tracking.
        if not summary.get("report_blocks"):
            ports = sorted(
                {p for s in analysis.rtp_streams for p in (s.src.port, s.dst.port) if p}
            )
            if ports:
                decode_as = [f"udp.port=={p},rtcp" for p in ports]
                muxed_rows: list[dict] = []
                for pcap in pcaps:
                    muxed_rows += tshark.run_tshark_fields(
                        pcap, rtcp_fields, display_filter="rtcp",
                        tls_keylog=tls_keylog, decode_as=decode_as, occurrence="a",
                    )
                muxed_summary = rtcp_stats.summarize_rtcp_packets(muxed_rows)
                # Prefer the fallback only if it actually recovered report blocks.
                if muxed_summary.get("report_blocks") or (
                    muxed_summary.get("total", 0) > summary.get("total", 0)
                ):
                    rtcp_rows, summary = muxed_rows, muxed_summary

        analysis.rtcp_packet_summary = summary
        stats = rtcp_stats.compute_rtcp_stats(rtcp_rows)
        analysis.rtcp_stats = stats
        analysis.findings.extend(rtcp_stats.build_rtcp_findings(stats))
        analysis.findings.extend(rtcp_stats.build_rtcp_presence_findings(summary))

        estimates = mos.estimate_mos(rtcp_rows, analysis.rtp_streams)
        analysis.mos_estimates = estimates
        analysis.findings.extend(mos.build_mos_findings(estimates))
    except tshark.TsharkNotAvailable:
        pass  # expected on hosts without tshark
    except Exception as exc:  # noqa: BLE001
        # Don't fail the whole report, but make the failure visible rather than
        # presenting an empty RTCP section as if no RTCP existed.
        analysis.rtcp_packet_summary = {"error": f"{type(exc).__name__}: {exc}"}
        if os.environ.get("CALLSCOPE_DEBUG"):
            import traceback
            traceback.print_exc()


def run_siprec_extraction(opts: ExtractionOptions) -> RecordingAnalysis:
    """Run the full SIPREC extraction + analysis flow and write outputs."""
    out_dir = writer.ensure_output_dir(opts.out_dir)

    # 1-3: discover inputs and validate tooling.
    paths = discover_pcaps(opts.pcaps)
    infos = index_pcaps(paths)
    readable = [info.path for info in infos if info.readable]
    if not readable:
        raise PcapInputError("No readable capture files among the provided inputs.")

    # 4-7: find and parse SIP/SDP/metadata.
    messages = collect_sip_messages(readable, opts.call_id, opts.tls_keylog)
    if not messages:
        raise CallIDNotFound(
            f"No SIP packets found for Call-ID {opts.call_id} in {len(readable)} input files."
        )

    metadata = [m.siprec_metadata for m in messages if m.siprec_metadata is not None]

    # 8: timeline.
    timeline = session_timeline.build_session_timeline(messages)

    # 9-11: extract SIP + media into partials, then merge.
    temp_dir = writer.ensure_temp_dir(out_dir)
    combined_filter = _build_combined_filter(opts.call_id, messages, metadata)
    partials: list[Path] = []
    for idx, pcap in enumerate(readable):
        partial = temp_dir / f"partial-{idx:04d}.{opts.output_format}"
        try:
            tshark.extract_packets(
                pcap,
                partial,
                combined_filter,
                tls_keylog=opts.tls_keylog,
                output_format=opts.output_format,
            )
            if partial.exists() and partial.stat().st_size > 0:
                partials.append(partial)
        except Exception:  # noqa: BLE001 - a single bad input shouldn't abort the run
            continue

    output_pcap = out_dir / f"{config.OUTPUT_PCAP_BASENAME}.{opts.output_format}"
    writer.finalize_output_pcap(partials, output_pcap, opts.output_format)

    # 12: analyze RTP/RTCP.
    rtp_streams, rtcp_mux_count = rtp_tracker.analyze_rtp_streams_with_stats(
        readable, messages, metadata, tls_keylog=opts.tls_keylog
    )

    # 13: correlate.
    analysis = recording_correlator.correlate_recording(messages, metadata, rtp_streams)
    analysis.output_pcap = output_pcap if output_pcap.exists() else None
    analysis.rtcp_mux_packet_count = rtcp_mux_count

    # No-SDP advisory finding.
    if not any(m.sdp is not None for m in messages):
        analysis.findings.append(
            RecordingFinding(
                severity=Severity.ERROR,
                code="NO_SDP",
                title="No SDP found",
                detail="No SDP found; RTP/RTCP stream extraction may be incomplete.",
            )
        )

    # 14: v2 media analysis — SSRC changes and RTCP statistics (best effort).
    _analyze_media_extras(analysis, readable, messages, metadata, opts.tls_keylog)

    # 14b: v2.1 — bind SDP labels + SIPREC participants onto observed streams.
    labels.bind_labels(analysis)
    analysis.findings.extend(labels.build_label_findings(analysis))

    # 15: detectors (gap, consistency, bursts, SIP timing, compliance, error origin).
    analysis.findings.extend(gap_detector.detect_gaps(analysis, timeline))
    analysis.findings.extend(consistency.check_consistency(analysis))
    bursts, burst_findings = burst_detector.detect_reinvite_bursts(messages)
    analysis.bursts = bursts
    analysis.findings.extend(burst_findings)
    analysis.findings.extend(sip_timing.analyze_sip_timing(messages, timeline))
    analysis.findings.extend(compliance.check_siprec_compliance(messages, metadata))
    analysis.findings.extend(error_origin.classify_error_origins(analysis))

    # 15b: v2.1 — hold/retrieve classification, then per-label SSRC lifecycle,
    # coverage gaps, collisions, and burst->SSRC correlation.
    analysis.hold_retrieve_events = hold_retrieve.detect_hold_retrieve(analysis)
    analysis.findings.extend(hold_retrieve.build_hold_retrieve_findings(analysis.hold_retrieve_events))
    analysis.findings.extend(ssrc_lifecycle.analyze_ssrc_lifecycle(analysis))
    if analysis.rtcp_mux_packet_count:
        analysis.findings.append(
            RecordingFinding(
                severity=Severity.INFO,
                code=ssrc_lifecycle.CODE_RTCP_MUX,
                title="RTCP-mux packets on the RTP port",
                detail=(
                    f"{analysis.rtcp_mux_packet_count} RTCP packet(s) were observed on the "
                    "RTP media port (rtcp-mux); these are excluded from the stream table."
                ),
                owner=Owner.UNKNOWN,
            )
        )

    # 16: capture quality + fingerprint + ownership.
    analysis.capture_quality = capture_quality.assess_capture_quality(readable)
    analysis.findings.extend(capture_quality.build_capture_findings(analysis.capture_quality))
    analysis.fingerprints = fingerprint.build_fingerprints(analysis)
    ownership.assign_ownership(analysis.findings)

    # 17: health + narrative.
    recording_health.evaluate_recording_health(analysis, timeline)
    analysis.narrative = narrative.build_narrative(analysis, timeline)

    # 18-19: write outputs.
    write_all_outputs(analysis, timeline, out_dir, write_html=opts.write_html)

    # 20: temp cleanup.
    if not opts.keep_temp:
        _cleanup_temp(temp_dir)

    return analysis


def write_all_outputs(
    analysis: RecordingAnalysis,
    timeline,
    out_dir: Path,
    write_html: bool = True,
) -> None:
    """Write JSON outputs, summary.txt and (optionally) the HTML report."""
    writer.write_json(out_dir / config.OUTPUT_SUMMARY_JSON, _summary_dict(analysis))
    writer.write_json(out_dir / config.OUTPUT_METADATA_JSON, analysis.metadata)
    writer.write_json(out_dir / config.OUTPUT_MEDIA_JSON, analysis.rtp_streams)
    writer.write_json(out_dir / config.OUTPUT_FINDINGS_JSON, analysis.findings)

    # v2 outputs: RTCP stats, correlation key, and the escalation markdown.
    writer.write_json(out_dir / "rtcp-stats.json", analysis.rtcp_stats)
    writer.write_json(out_dir / "correlation-key.json", build_correlation_key(analysis))

    # Imported lazily so JSON-only paths stay light.
    from ..reporting.markdown_report import write_markdown_report

    write_markdown_report(analysis, out_dir)

    if write_html:
        # Imported lazily so JSON-only paths don't require jinja2.
        from ..reporting import report

        report_path = out_dir / config.OUTPUT_REPORT_HTML
        report.render_html_report(analysis, report_path)
        analysis.report_html = report_path

    writer.write_summary_txt(out_dir / config.OUTPUT_SUMMARY_TXT, analysis)


def _summary_dict(analysis: RecordingAnalysis) -> dict:
    return {
        "call_id": analysis.call_id,
        "mode": "SIPREC",
        "overall_health": analysis.overall_health,
        "status": {
            "sip": analysis.status_sip,
            "sdp": analysis.status_sdp,
            "metadata": analysis.status_metadata,
            "rtp": analysis.status_rtp,
            "rtcp": analysis.status_rtcp,
            "streams": analysis.status_streams,
            "gaps": analysis.status_gaps,
        },
        "streams_declared": sum(len(m.streams) for m in analysis.metadata),
        "streams_observed": len(analysis.rtp_streams),
        "warnings": len(analysis.warnings()),
        "errors": len(analysis.errors()),
        "sip_message_count": len(analysis.sip_messages),
        "src": analysis.src_endpoint,
        "srs": analysis.srs_endpoint,
        "output_pcap": analysis.output_pcap,
        "report_html": analysis.report_html,
    }


def _cleanup_temp(temp_dir: Path) -> None:
    try:
        for child in temp_dir.iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        temp_dir.rmdir()
    except OSError:
        pass


__all__ = [
    "ExtractionOptions",
    "run_siprec_extraction",
    "collect_sip_messages",
    "write_all_outputs",
]
