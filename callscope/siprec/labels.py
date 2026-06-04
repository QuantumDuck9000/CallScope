"""Bind observed RTP streams to SIPREC stream labels and participants.

The SBC's SDP carries ``a=label:<n>`` on each ``m=`` line, and the rs-metadata
XML binds that same label to a ``<stream>`` and, through
``participantstreamassoc``, to a ``<participant>`` (the AOR / display name).
Joining those gives every observed SSRC a human identity — "AGENT
(8777357837)" instead of "port 41134" — which every downstream label-level
check depends on (lifecycle, coverage gaps, hold/retrieve correlation).
"""

from __future__ import annotations

from ..models import RecordingAnalysis, SipMessage, SipRecMetadata


def build_port_label_map(messages: list[SipMessage]) -> dict[int, str]:
    """Map each media port seen in any SDP to its ``a=label`` value."""
    port_label: dict[int, str] = {}
    for msg in messages:
        if msg.sdp is None:
            continue
        for media in msg.sdp.media:
            if media.port and media.label:
                port_label[media.port] = media.label
    return port_label


def _label_indices(metadata: list[SipRecMetadata]):
    """Return (label -> stream_id, participant_id -> participant) indices."""
    label_to_stream: dict[str, str] = {}
    stream_to_participants: dict[str, list[str]] = {}
    participant_by_id = {}
    for md in metadata:
        for p in md.participants:
            participant_by_id[p.participant_id] = p
        for s in md.streams:
            if s.label:
                label_to_stream[s.label] = s.stream_id
            if s.participant_ids:
                stream_to_participants[s.stream_id] = s.participant_ids
    return label_to_stream, stream_to_participants, participant_by_id


def bind_labels(analysis: RecordingAnalysis) -> None:
    """Annotate each observed RTP stream with its label and participant."""
    port_label = build_port_label_map(analysis.sip_messages)
    label_to_stream, stream_to_participants, participant_by_id = _label_indices(
        analysis.metadata
    )

    for stream in analysis.rtp_streams:
        # The SBC's sending port (src) is what the SDP labels; fall back to dst.
        label = None
        for port in (stream.src.port, stream.dst.port):
            if port is not None and port in port_label:
                label = port_label[port]
                break
        if label is None:
            continue
        stream.matched_sdp_label = label
        stream_id = label_to_stream.get(label)
        if stream_id:
            stream.matched_siprec_stream_id = stream_id
            pids = stream_to_participants.get(stream_id, [])
            if pids:
                participant = participant_by_id.get(pids[0])
                if participant is not None:
                    stream.participant_aor = participant.aor
                    stream.participant_name = participant.name


def label_for_port(analysis: RecordingAnalysis, port: int | None) -> str | None:
    if port is None:
        return None
    return build_port_label_map(analysis.sip_messages).get(port)


def describe_participant(analysis: RecordingAnalysis, label: str | None) -> str | None:
    """Human label like 'AGENT (8777357837)' for a SIPREC label, if known."""
    if not label:
        return None
    for s in analysis.rtp_streams:
        if s.matched_sdp_label == label and (s.participant_name or s.participant_aor):
            name = s.participant_name or ""
            aor = s.participant_aor or ""
            ident = aor.split(":", 1)[-1].split("@", 1)[0] if aor else ""
            if name and ident:
                return f"{name} ({ident})"
            return name or ident or None
    return None


def build_label_findings(analysis: RecordingAnalysis) -> list:
    """Emit SIPREC-005 when metadata declares labels none of which bound to RTP."""
    from ..models import Owner, RecordingFinding, Severity

    declared_labels = {
        s.label for md in analysis.metadata for s in md.streams if s.label
    }
    if not declared_labels:
        return []
    bound = {s.matched_sdp_label for s in analysis.rtp_streams if s.matched_sdp_label}
    if bound:
        return []
    return [
        RecordingFinding(
            severity=Severity.WARN,
            code="SIPREC-005",
            title="SIPREC labels not bound to any RTP stream",
            detail=(
                f"Metadata declared label(s) {sorted(declared_labels)} but none could be "
                "matched to an observed SSRC by port. SSRC-level diagnosis is limited."
            ),
            owner=Owner.SBC,
        )
    ]


def distinct_media_count(analysis: RecordingAnalysis) -> int:
    """Count distinct media legs, collapsing SSRC churn within one label/port.

    With label binding, multiple SSRCs on the same SIPREC label are one leg, not
    many streams. Falls back to distinct destination ports, then raw stream count.
    """
    labels_seen = {s.matched_sdp_label for s in analysis.rtp_streams if s.matched_sdp_label}
    if labels_seen:
        return len(labels_seen)
    ports = {(s.dst.ip, s.dst.port) for s in analysis.rtp_streams if s.dst.port}
    if ports:
        return len(ports)
    return len(analysis.rtp_streams)


__all__ = [
    "bind_labels",
    "build_port_label_map",
    "label_for_port",
    "describe_participant",
    "build_label_findings",
    "distinct_media_count",
]
