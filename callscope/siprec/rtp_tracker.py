"""SIPREC-aware RTP/RTCP observation.

Builds media display filters from SDP and analyzes observed RTP/RTCP streams,
tracking SSRCs, packet counts, sequence numbers and first/last times. RTP/RTCP
fields are extracted via tshark; for v1 this is the primary path.

This module is SSRC/metadata/label aware, which is why it lives under
``siprec/`` rather than ``core/``.
"""

from __future__ import annotations

from pathlib import Path

from ..core import tshark
from ..core.sdp_parser import infer_rtcp_port
from ..models import Endpoint, ObservedRtpStream, SipMessage, SipRecMetadata

# tshark fields used for RTP/RTCP analysis.
RTP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.seq",
    "rtp.p_type",
    "rtcp.pt",
]


def _collect_media_ports(messages: list[SipMessage]) -> set[int]:
    """Gather RTP and RTCP ports from all SDP bodies in the messages."""
    ports: set[int] = set()
    for msg in messages:
        if msg.sdp is None:
            continue
        for media in msg.sdp.media:
            if media.port:
                ports.add(media.port)
            rtcp = infer_rtcp_port(media)
            if rtcp:
                ports.add(rtcp)
    return ports


def build_media_display_filter(
    messages: list[SipMessage],
    metadata: list[SipRecMetadata],
) -> str:
    """Build a tshark display filter selecting RTP/RTCP for the media ports.

    Explicit ``udp.port == N`` ``or`` clauses are used for broad tshark version
    compatibility instead of the newer ``in {...}`` set syntax.
    """
    ports = sorted(_collect_media_ports(messages))
    if not ports:
        # Nothing to select; an empty filter matches nothing meaningful here.
        return "rtp or rtcp"
    clauses = " or ".join(f"udp.port == {p}" for p in ports)
    return f"({clauses}) and (rtp or rtcp)"


def _to_int(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _to_float(value: str) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def analyze_rtp_streams(
    pcaps: list[Path],
    messages: list[SipMessage],
    metadata: list[SipRecMetadata],
    tls_keylog: Path | None = None,
) -> list[ObservedRtpStream]:
    """Analyze observed RTP/RTCP streams across the supplied captures.

    Streams are keyed by (ssrc, dst_ip, dst_port). RTCP presence is tracked per
    destination port so a stream is marked ``rtcp_observed`` when matching RTCP
    is seen on its (or its inferred companion) port.
    """
    media_filter = build_media_display_filter(messages, metadata)

    streams: dict[tuple[int | None, str, int | None], ObservedRtpStream] = {}
    rtcp_ports_seen: set[tuple[str, int | None]] = set()
    seqs_by_key: dict[tuple[int | None, str, int | None], list[int]] = {}
    rtcp_mux_count = 0

    for pcap in pcaps:
        rows = tshark.run_tshark_fields(
            pcap, RTP_FIELDS, display_filter=media_filter, tls_keylog=tls_keylog
        )
        for row in rows:
            rtcp_pt = row.get("rtcp.pt", "")
            dst_ip = row.get("ip.dst", "")
            dst_port = _to_int(row.get("udp.dstport", ""))

            if rtcp_pt:
                rtcp_ports_seen.add((dst_ip, dst_port))
                rtcp_mux_count += 1
                continue

            ssrc = _to_int(row.get("rtp.ssrc", ""))
            seq = _to_int(row.get("rtp.seq", ""))
            pt = _to_int(row.get("rtp.p_type", ""))
            # RFC 5761 §4: payload types 64-95 collide with the RTCP packet-type
            # range. If a packet was dissected as RTP with such a PT, treat it as
            # RTCP-on-the-RTP-port (rtcp-mux) rather than a media stream.
            if pt is not None and 64 <= pt <= 95:
                rtcp_ports_seen.add((dst_ip, dst_port))
                rtcp_mux_count += 1
                continue

            t_rel = _to_float(row.get("frame.time_relative", ""))
            key = (ssrc, dst_ip, dst_port)

            stream = streams.get(key)
            if stream is None:
                stream = ObservedRtpStream(
                    ssrc=ssrc,
                    src=Endpoint(ip=row.get("ip.src", ""), port=_to_int(row.get("udp.srcport", ""))),
                    dst=Endpoint(ip=dst_ip, port=dst_port),
                    payload_type=pt,
                )
                streams[key] = stream
                seqs_by_key[key] = []

            stream.packet_count += 1
            if t_rel is not None:
                if stream.first_timestamp_relative is None:
                    stream.first_timestamp_relative = t_rel
                stream.last_timestamp_relative = t_rel
            if seq is not None:
                seqs_by_key[key].append(seq)

    # Finalize per-stream sequence stats and RTCP presence.
    for key, stream in streams.items():
        seqs = seqs_by_key.get(key, [])
        if seqs:
            stream.first_sequence = seqs[0]
            stream.last_sequence = seqs[-1]
            gaps, largest = _sequence_gaps(seqs)
            stream.sequence_gaps = gaps
            stream.largest_gap = largest
        # RTCP on the RTP port (mux) or RTP port + 1 (conventional).
        dst_ip = stream.dst.ip
        port = stream.dst.port
        if port is not None:
            if (dst_ip, port) in rtcp_ports_seen or (dst_ip, port + 1) in rtcp_ports_seen:
                stream.rtcp_observed = True

    # Stash the mux count so the stats wrapper can return it.
    analyze_rtp_streams._last_rtcp_mux_count = rtcp_mux_count  # type: ignore[attr-defined]
    return list(streams.values())


def analyze_rtp_streams_with_stats(
    pcaps: list[Path],
    messages: list[SipMessage],
    metadata: list[SipRecMetadata],
    tls_keylog: Path | None = None,
) -> tuple[list[ObservedRtpStream], int]:
    """Like :func:`analyze_rtp_streams` but also returns the RTCP-mux packet count."""
    streams = analyze_rtp_streams(pcaps, messages, metadata, tls_keylog=tls_keylog)
    count = getattr(analyze_rtp_streams, "_last_rtcp_mux_count", 0)
    return streams, count


def _sequence_gaps(seqs: list[int]) -> tuple[int, int]:
    """Count RTP sequence-number gaps, accounting for 16-bit wraparound."""
    gaps = 0
    largest = 0
    for prev, cur in zip(seqs, seqs[1:], strict=False):
        delta = (cur - prev) & 0xFFFF
        if delta > 1:
            gaps += 1
            largest = max(largest, delta - 1)
    return gaps, largest


__all__ = [
    "build_media_display_filter",
    "analyze_rtp_streams",
    "analyze_rtp_streams_with_stats",
    "RTP_FIELDS",
]
