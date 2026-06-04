"""RTP/RTCP gap and presence detection.

Findings respect the session timeline: gaps that fall entirely within a
hold/inactive window are ignored, since silence is expected there.
"""

from __future__ import annotations

from ..models import (
    ObservedRtpStream,
    RecordingAnalysis,
    RecordingFinding,
    SessionTimeline,
    Severity,
)

CODE_SEQ_GAP = "RTP_SEQ_GAP"
CODE_MISSING_RTCP = "RTP_MISSING_RTCP"
CODE_NONE_OBSERVED = "RTP_NONE_OBSERVED"
CODE_LATE_START = "RTP_LATE_START"
CODE_EARLY_END = "RTP_EARLY_END"

# Seconds of slack before media timing is considered late/early.
_TIMING_SLACK = 2.0


def _stream_label(stream: ObservedRtpStream) -> str:
    if stream.matched_siprec_stream_id:
        return f"stream {stream.matched_siprec_stream_id}"
    if stream.ssrc is not None:
        return f"SSRC 0x{stream.ssrc:08x}"
    return f"{stream.dst.ip}:{stream.dst.port}"


def _interval_in_hold(stream: ObservedRtpStream, timeline: SessionTimeline) -> bool:
    """True if the stream's active interval sits fully inside a hold window."""
    start = stream.first_timestamp_relative
    end = stream.last_timestamp_relative
    if start is None or end is None:
        return False
    for h_start, h_end in timeline.hold_windows:
        h_end_eff = h_end if h_end is not None else float("inf")
        if start >= h_start and end <= h_end_eff:
            return True
    return False


def detect_gaps(
    analysis: RecordingAnalysis,
    timeline: SessionTimeline,
) -> list[RecordingFinding]:
    """Detect RTP sequence gaps, missing RTCP, and missing/mistimed media."""
    findings: list[RecordingFinding] = []

    declared = sum(len(m.streams) for m in analysis.metadata)
    if declared > 0 and not analysis.rtp_streams:
        findings.append(
            RecordingFinding(
                severity=Severity.ERROR,
                code=CODE_NONE_OBSERVED,
                title="No RTP observed",
                detail=(
                    f"Metadata declares {declared} stream(s) but no RTP streams "
                    "were observed in the capture."
                ),
                recommendation="Verify media reaches the recorder and the capture "
                "point sees RTP, not just SIP.",
            )
        )

    for stream in analysis.rtp_streams:
        in_hold = _interval_in_hold(stream, timeline)

        if stream.sequence_gaps > 0 and not in_hold:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_SEQ_GAP,
                    title="RTP sequence gaps",
                    detail=(
                        f"{stream.sequence_gaps} RTP sequence gap(s) on "
                        f"{_stream_label(stream)} (largest {stream.largest_gap})."
                    ),
                    recommendation="Investigate packet loss or capture drops.",
                )
            )

        if not stream.rtcp_observed and not in_hold:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_MISSING_RTCP,
                    title="Missing RTCP",
                    detail=f"No RTCP observed for {_stream_label(stream)}.",
                    recommendation="Confirm RTCP is enabled and not blocked.",
                )
            )

        # Late start / early end relative to media-expected windows.
        for win_start, win_end in timeline.media_expected_windows:
            if (
                stream.first_timestamp_relative is not None
                and stream.first_timestamp_relative - win_start > _TIMING_SLACK
            ):
                findings.append(
                    RecordingFinding(
                        severity=Severity.WARN,
                        code=CODE_LATE_START,
                        title="Media started late",
                        detail=(
                            f"{_stream_label(stream)} RTP started "
                            f"{stream.first_timestamp_relative - win_start:.2f}s "
                            "after session establishment."
                        ),
                    )
                )
            if (
                win_end is not None
                and stream.last_timestamp_relative is not None
                and win_end - stream.last_timestamp_relative > _TIMING_SLACK
            ):
                findings.append(
                    RecordingFinding(
                        severity=Severity.WARN,
                        code=CODE_EARLY_END,
                        title="Media ended early",
                        detail=(
                            f"{_stream_label(stream)} RTP ended "
                            f"{win_end - stream.last_timestamp_relative:.2f}s "
                            "before session termination."
                        ),
                    )
                )

    return findings


__all__ = [
    "detect_gaps",
    "CODE_SEQ_GAP",
    "CODE_MISSING_RTCP",
    "CODE_NONE_OBSERVED",
    "CODE_LATE_START",
    "CODE_EARLY_END",
]
