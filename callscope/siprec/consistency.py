"""Three-way internal-consistency check: metadata vs SDP vs observed RTP.

All three artifacts were produced by the SBC on the single leg you captured, so
any disagreement between them is the box contradicting itself — provable from
SIPREC-only data, with no second capture and no assumptions about the original
call. This is what closes the "the call was just one-way" deflection: if the
metadata declares two streams and only one carried media, the SBC said two and
sent one.
"""

from __future__ import annotations

from ..models import Owner, RecordingAnalysis, RecordingFinding, Severity

CODE_METADATA_RTP = "CONSIST_METADATA_RTP"
CODE_METADATA_SDP = "CONSIST_METADATA_SDP"
CODE_SDP_RTP = "CONSIST_SDP_RTP"

_MEDIA_TYPES = {"audio", "video"}


def _declared(analysis: RecordingAnalysis) -> int:
    return sum(len(m.streams) for m in analysis.metadata)


def _sdp_media_count(analysis: RecordingAnalysis) -> int:
    best = 0
    for msg in analysis.sip_messages:
        if msg.sdp is None:
            continue
        count = sum(1 for m in msg.sdp.media if m.media_type in _MEDIA_TYPES)
        best = max(best, count)
    return best


def check_consistency(analysis: RecordingAnalysis) -> list[RecordingFinding]:
    """Compare declared metadata streams, SDP m-lines, and observed RTP."""
    findings: list[RecordingFinding] = []
    declared = _declared(analysis)
    sdp_count = _sdp_media_count(analysis)
    from .labels import distinct_media_count

    observed = distinct_media_count(analysis)

    if declared > 0 and observed < declared:
        findings.append(
            RecordingFinding(
                severity=Severity.ERROR,
                code=CODE_METADATA_RTP,
                title="Metadata declares more streams than were recorded",
                detail=(
                    f"The SBC's own metadata declared {declared} stream(s) but only "
                    f"{observed} carried media to the recorder. The SBC's metadata and "
                    "the media it sent disagree."
                ),
                recommendation=(
                    "This is internally inconsistent on a single leg — not attributable "
                    "to the far end. Escalate to the SBC team."
                ),
                owner=Owner.SBC,
            )
        )

    if declared > 0 and sdp_count > 0 and sdp_count != declared:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_METADATA_SDP,
                title="Metadata / SDP stream-count mismatch",
                detail=f"Metadata declares {declared} stream(s); SDP offers {sdp_count} media section(s).",
                owner=Owner.SBC,
            )
        )

    if sdp_count > 0 and observed > sdp_count:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_SDP_RTP,
                title="More RTP streams than SDP declared",
                detail=f"SDP offered {sdp_count} media section(s) but {observed} RTP stream(s) were observed.",
                owner=Owner.SBC,
            )
        )

    return findings


__all__ = [
    "check_consistency",
    "CODE_METADATA_RTP",
    "CODE_METADATA_SDP",
    "CODE_SDP_RTP",
]
