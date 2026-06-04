"""Thin recording-health summary layer.

Consumes the assembled analysis (timeline, observed streams, and any findings
already added by gap/mixer analysis) and derives per-component status values
plus an overall health severity. It does not re-run detectors.
"""

from __future__ import annotations

from ..core.sip_parser import is_siprec_metadata_content_type
from ..models import RecordingAnalysis, SessionTimeline, Severity

# Ordering for "worst severity wins" rollups.
_SEVERITY_RANK = {
    Severity.PASS: 0,
    Severity.INFO: 1,
    Severity.WARN: 2,
    Severity.ERROR: 3,
    Severity.CRITICAL: 4,
}


def _worst(*severities: Severity | None) -> Severity:
    present = [s for s in severities if s is not None]
    if not present:
        return Severity.PASS
    return max(present, key=lambda s: _SEVERITY_RANK[s])


def _has_sdp(analysis: RecordingAnalysis) -> bool:
    return any(m.sdp is not None for m in analysis.sip_messages)


def _has_metadata(analysis: RecordingAnalysis) -> bool:
    if analysis.metadata:
        return True
    return any(is_siprec_metadata_content_type(m.content_type) for m in analysis.sip_messages)


def evaluate_recording_health(
    analysis: RecordingAnalysis,
    timeline: SessionTimeline,
) -> RecordingAnalysis:
    """Populate status_* fields and overall_health on the analysis."""
    # SIP presence.
    analysis.status_sip = Severity.PASS if analysis.sip_messages else Severity.CRITICAL

    # SDP presence.
    analysis.status_sdp = Severity.PASS if _has_sdp(analysis) else Severity.ERROR

    # Metadata presence.
    analysis.status_metadata = Severity.PASS if _has_metadata(analysis) else Severity.WARN

    # RTP presence.
    analysis.status_rtp = Severity.PASS if analysis.rtp_streams else Severity.ERROR

    # RTCP presence (only meaningful if there are streams).
    summary = analysis.rtcp_packet_summary or {}
    if not analysis.rtp_streams:
        analysis.status_rtcp = Severity.WARN
    elif summary.get("report_blocks"):
        # RTCP with reception reports — quality is actually measurable.
        analysis.status_rtcp = Severity.PASS
    elif summary.get("total") or any(s.rtcp_observed for s in analysis.rtp_streams):
        # RTCP packets exist but no reception report blocks: present but not scorable.
        analysis.status_rtcp = Severity.WARN
    else:
        analysis.status_rtcp = Severity.WARN

    # Streams: declared vs observed.
    declared = sum(len(m.streams) for m in analysis.metadata)
    observed = len(analysis.rtp_streams)
    if declared == 0 and observed == 0:
        analysis.status_streams = Severity.WARN
    elif declared == observed and declared > 0:
        analysis.status_streams = Severity.PASS
    elif observed < declared:
        analysis.status_streams = Severity.ERROR if observed == 0 else Severity.WARN
    else:
        analysis.status_streams = Severity.WARN

    # Gaps.
    if any(s.sequence_gaps > 0 for s in analysis.rtp_streams):
        analysis.status_gaps = Severity.WARN
    else:
        analysis.status_gaps = Severity.PASS

    # Overall health rolls up component statuses and the worst finding.
    finding_worst = _worst(*[f.severity for f in analysis.findings]) if analysis.findings else None
    analysis.overall_health = _worst(
        analysis.status_sip,
        analysis.status_sdp,
        analysis.status_metadata,
        analysis.status_rtp,
        analysis.status_rtcp,
        analysis.status_streams,
        analysis.status_gaps,
        finding_worst,
    )
    return analysis


__all__ = ["evaluate_recording_health"]
