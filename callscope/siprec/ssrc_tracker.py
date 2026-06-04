"""Track SSRC changes per media flow.

An SSRC change mid-flow usually indicates a media restart, a transcoder or
media-server swap, a transfer, or the SBC re-originating the feed to the
recorder. Counting and timestamping these is a strong recording-health signal.
"""

from __future__ import annotations

from ..models import (
    ObservedRtpStream,
    Owner,
    RecordingFinding,
    Severity,
    SsrcChangeEvent,
)

CODE_SSRC_CHANGE = "RTP_SSRC_CHANGE"


def track_ssrc_changes(
    observations: list[tuple[str, float | None, int | None]],
) -> list[SsrcChangeEvent]:
    """Detect SSRC transitions within each flow.

    ``observations`` is a capture-ordered list of ``(flow_key, time, ssrc)``.
    A change is recorded whenever a flow's SSRC differs from the previous
    non-null SSRC seen on that same flow.
    """
    last_ssrc: dict[str, int] = {}
    changes: list[SsrcChangeEvent] = []
    for flow_key, t_rel, ssrc in observations:
        if ssrc is None:
            continue
        prev = last_ssrc.get(flow_key)
        if prev is not None and ssrc != prev:
            changes.append(
                SsrcChangeEvent(
                    flow_key=flow_key,
                    time_relative=t_rel,
                    from_ssrc=prev,
                    to_ssrc=ssrc,
                )
            )
        last_ssrc[flow_key] = ssrc
    return changes


def observations_from_rtp_rows(rows: list[dict]) -> list[tuple[str, float | None, int | None]]:
    """Build flow-keyed SSRC observations from tshark RTP field rows."""
    obs: list[tuple[str, float | None, int | None]] = []
    for row in rows:
        if row.get("rtcp.pt"):
            continue
        ssrc_raw = row.get("rtp.ssrc", "")
        if not ssrc_raw:
            continue
        try:
            ssrc = int(ssrc_raw, 0) if ssrc_raw.lower().startswith("0x") else int(ssrc_raw)
        except ValueError:
            continue
        flow_key = (
            f"{row.get('ip.src', '')}:{row.get('udp.srcport', '')}"
            f"->{row.get('ip.dst', '')}:{row.get('udp.dstport', '')}"
        )
        t_raw = row.get("frame.time_relative", "")
        try:
            t_rel = float(t_raw) if t_raw else None
        except ValueError:
            t_rel = None
        obs.append((flow_key, t_rel, ssrc))
    return obs


def annotate_streams(
    streams: list[ObservedRtpStream], changes: list[SsrcChangeEvent]
) -> None:
    """Set per-stream ``ssrc_changes`` counts from flow-level change events."""
    by_flow: dict[str, int] = {}
    for ch in changes:
        by_flow[ch.flow_key] = by_flow.get(ch.flow_key, 0) + 1
    for s in streams:
        flow_key = f"{s.src.ip}:{s.src.port}->{s.dst.ip}:{s.dst.port}"
        s.ssrc_changes = by_flow.get(flow_key, 0)


def build_ssrc_findings(
    changes: list[SsrcChangeEvent],
    rtp_streams: list | None = None,
) -> list[RecordingFinding]:
    """Build findings for SSRC changes, filtering out noise-stream transitions.

    Transitions where the new SSRC belongs to a low-packet-count stream (STUN,
    RTCP-mux SR, codec straggler) are excluded from the count — they are
    capture artefacts, not recording events. The filtered count is noted in
    the finding detail.
    """
    if not changes:
        return []

    # If we have the stream list, exclude transitions where the new (or old)
    # SSRC had fewer than SUBSTANTIAL_MIN_PACKETS packets.
    substantial_ssrcs: set[int] = set()
    if rtp_streams:
        from .. import config
        from .ssrc_lifecycle import is_substantial
        substantial_ssrcs = {
            s.ssrc for s in rtp_streams
            if s.ssrc is not None and is_substantial(s)
        }
        real = [c for c in changes
                if (c.from_ssrc in substantial_ssrcs or c.to_ssrc in substantial_ssrcs)]
        noise_count = len(changes) - len(real)
    else:
        real = changes
        noise_count = 0

    if not real:
        return []

    detail = f"{len(real)} SSRC change(s) observed mid-call across media flows."
    if noise_count:
        detail += (
            f" ({noise_count} additional transition(s) from low-packet-count streams "
            f"excluded — likely STUN keepalives or RTCP-mux SR noise.)"
        )
    return [
        RecordingFinding(
            severity=Severity.WARN,
            code=CODE_SSRC_CHANGE,
            title="SSRC changed mid-call",
            detail=detail,
            recommendation=(
                "Frequent SSRC changes suggest the media feed to the recorder was "
                "restarted (transcoder swap, transfer, or re-anchoring)."
            ),
            owner=Owner.SBC,
        )
    ]


__all__ = [
    "track_ssrc_changes",
    "observations_from_rtp_rows",
    "annotate_streams",
    "build_ssrc_findings",
    "CODE_SSRC_CHANGE",
]
