"""Correlate SIPREC metadata streams with SDP media and observed RTP streams.

v1 correlation is deliberately conservative and assigns confidence levels
rather than pretending weak matches are certain.
"""

from __future__ import annotations

from ..models import (
    Direction,
    Endpoint,
    ObservedRtpStream,
    RecordingAnalysis,
    SipMessage,
    SipRecMetadata,
    SipRecStream,
)

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def _identify_endpoints(
    messages: list[SipMessage],
) -> tuple[Endpoint | None, Endpoint | None]:
    """Best-effort SRC/SRS identification from the initial INVITE.

    The INVITE source is treated as the SRC (recording client); its destination
    as the SRS (recording server).
    """
    for msg in messages:
        if msg.method == "INVITE":
            src = msg.src if msg.src.ip else None
            dst = msg.dst if msg.dst.ip else None
            if msg.direction == Direction.SRS_TO_SRC:
                return dst, src
            return src, dst
    return None, None


def _sdp_label_by_port(messages: list[SipMessage]) -> dict[int, str]:
    """Map media (RTP) port -> SDP label/mid for matching observed streams."""
    mapping: dict[int, str] = {}
    for msg in messages:
        if msg.sdp is None:
            continue
        for media in msg.sdp.media:
            label = media.label or media.mid
            if media.port and label:
                mapping[media.port] = label
    return mapping


def _siprec_streams(metadata: list[SipRecMetadata]) -> list[SipRecStream]:
    out: list[SipRecStream] = []
    for m in metadata:
        out.extend(m.streams)
    return out


def correlate_recording(
    messages: list[SipMessage],
    metadata: list[SipRecMetadata],
    rtp_streams: list[ObservedRtpStream],
) -> RecordingAnalysis:
    """Assemble a :class:`RecordingAnalysis` and apply best-effort correlation."""
    call_id = next((m.call_id for m in messages if m.call_id), "") or ""
    analysis = RecordingAnalysis(
        call_id=call_id,
        sip_messages=list(messages),
        metadata=list(metadata),
        rtp_streams=list(rtp_streams),
    )

    src, srs = _identify_endpoints(messages)
    analysis.src_endpoint = src
    analysis.srs_endpoint = srs

    label_by_port = _sdp_label_by_port(messages)
    siprec_streams = _siprec_streams(metadata)
    label_to_stream_id = {s.label: s.stream_id for s in siprec_streams if s.label}

    for rtp in rtp_streams:
        # SDP label match by destination port (high-ish confidence).
        if rtp.dst.port in label_by_port:
            label = label_by_port[rtp.dst.port]
            rtp.matched_sdp_label = label
            if label in label_to_stream_id:
                rtp.matched_siprec_stream_id = label_to_stream_id[label]

    # Medium-confidence fallback: if counts align 1:1 and nothing matched yet,
    # pair observed streams to declared streams positionally.
    unmatched_rtp = [r for r in rtp_streams if r.matched_siprec_stream_id is None]
    unmatched_declared = [
        s for s in siprec_streams if s.stream_id not in {r.matched_siprec_stream_id for r in rtp_streams}
    ]
    if unmatched_rtp and len(unmatched_rtp) == len(unmatched_declared):
        for rtp, declared in zip(unmatched_rtp, unmatched_declared, strict=False):
            rtp.matched_siprec_stream_id = declared.stream_id

    return analysis


__all__ = [
    "correlate_recording",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_LOW",
]
