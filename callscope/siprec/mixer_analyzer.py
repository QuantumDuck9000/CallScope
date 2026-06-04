"""Thin declared-vs-observed stream consistency checks for v1.

Compares SIPREC metadata stream counts and SDP m-line counts against observed
RTP streams. Full conference/mixed-audio analysis is intentionally out of scope.
"""

from __future__ import annotations

from ..models import RecordingAnalysis, RecordingFinding, Severity

CODE_STREAMS_OK = "MIX_STREAMS_OK"
CODE_FEWER_OBSERVED = "MIX_FEWER_OBSERVED"
CODE_NONE_OBSERVED = "MIX_NONE_OBSERVED"
CODE_MORE_OBSERVED = "MIX_MORE_OBSERVED"
CODE_SDP_COUNT_MISMATCH = "MIX_SDP_COUNT_MISMATCH"

_MEDIA_TYPES = {"audio", "video"}


def _declared_stream_count(analysis: RecordingAnalysis) -> int:
    return sum(len(m.streams) for m in analysis.metadata)


def _sdp_media_count(analysis: RecordingAnalysis) -> int:
    """Largest count of real media m-lines seen across SIP messages.

    Uses the message carrying the most media sections (typically the offer or
    answer), counting only audio/video sections.
    """
    best = 0
    for msg in analysis.sip_messages:
        if msg.sdp is None:
            continue
        count = sum(1 for m in msg.sdp.media if m.media_type in _MEDIA_TYPES)
        best = max(best, count)
    return best


def analyze_mixer_consistency(analysis: RecordingAnalysis) -> list[RecordingFinding]:
    """Compare declared streams vs observed RTP streams (and SDP m-lines)."""
    findings: list[RecordingFinding] = []

    declared = _declared_stream_count(analysis)
    observed = len(analysis.rtp_streams)

    if declared > 0 or observed > 0:
        if declared == observed and declared > 0:
            findings.append(
                RecordingFinding(
                    severity=Severity.INFO,
                    code=CODE_STREAMS_OK,
                    title="Stream count consistent",
                    detail=f"{declared} declared / {observed} observed RTP stream(s).",
                )
            )
        elif observed == 0 and declared > 0:
            findings.append(
                RecordingFinding(
                    severity=Severity.ERROR,
                    code=CODE_NONE_OBSERVED,
                    title="No observed streams",
                    detail=f"{declared} stream(s) declared but none observed.",
                    recommendation="Recording is likely failing; check media path.",
                )
            )
        elif observed < declared:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_FEWER_OBSERVED,
                    title="Fewer observed than declared",
                    detail=(
                        f"{declared} declared / {observed} observed RTP stream(s); "
                        "at least one declared stream is missing."
                    ),
                    recommendation="Check for one-sided recording.",
                )
            )
        elif observed > declared:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_MORE_OBSERVED,
                    title="More observed than declared",
                    detail=(
                        f"{declared} declared / {observed} observed RTP stream(s); "
                        "extra RTP streams have no matching declared metadata."
                    ),
                )
            )

    sdp_count = _sdp_media_count(analysis)
    if declared > 0 and sdp_count > 0 and sdp_count != declared:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_SDP_COUNT_MISMATCH,
                title="SDP m-line / metadata mismatch",
                detail=(
                    f"SDP declares {sdp_count} media section(s) but metadata "
                    f"declares {declared} stream(s)."
                ),
            )
        )

    return findings


__all__ = [
    "analyze_mixer_consistency",
    "CODE_STREAMS_OK",
    "CODE_FEWER_OBSERVED",
    "CODE_NONE_OBSERVED",
    "CODE_MORE_OBSERVED",
    "CODE_SDP_COUNT_MISMATCH",
]
