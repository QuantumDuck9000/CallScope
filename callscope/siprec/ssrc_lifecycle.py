"""Per-label SSRC lifecycle and the failures that hide in it.

Once each observed stream carries a SIPREC label (see :mod:`labels`), the
SSRCs that appeared on that label over time form a lifecycle. This module turns
that lifecycle into the diagnoses the raw stream table can't express:

* coverage gaps — a label whose SSRC changed (typically on retrieve) such that a
  recorder tracking the old SSRC would miss audio;
* SSRC collisions — two SSRCs active on one media port at once;
* re-INVITE-burst → SSRC correlation, including asymmetry between legs;
* an SSRC-stability rate per label.

Everything is single-sided and derived from the SIPREC capture alone.
"""

from __future__ import annotations

from ..models import (
    CoverageGap,
    LabelLifecycle,
    ObservedRtpStream,
    Owner,
    RecordingAnalysis,
    RecordingFinding,
    Severity,
    SipMessage,
    SsrcCollision,
    SsrcSegment,
)
from .. import config
from .labels import describe_participant

RETRIEVE_WINDOW_S = 3.0
BURST_WINDOW_S = 2.0
STABILITY_WARN_PER_MIN = 1.0
STABILITY_ERROR_PER_5S = 1.0  # >1 change within any 5s -> error rate


def is_substantial(stream: ObservedRtpStream, min_packets: int | None = None) -> bool:
    """Return True when a stream looks like real media rather than noise.

    Noise sources — RTCP-mux SRs with rotating SSRCs, STUN/DTLS keepalives,
    codec-negotiation stragglers — typically carry fewer than
    ``config.SUBSTANTIAL_MIN_PACKETS`` packets and vanish within seconds. Real
    media legs in a SIPREC call accumulate thousands of packets.
    """
    threshold = min_packets if min_packets is not None else config.SUBSTANTIAL_MIN_PACKETS
    return (stream.packet_count or 0) >= threshold

CODE_RETRIEVE_GAP = "SIPREC-001"
CODE_BURST_CHURN = "SIPREC-002"
CODE_SSRC_COLLISION = "SIPREC-003"
CODE_HOLD_RETRIEVE = "SIPREC-004"
CODE_LABELS_UNBOUND = "SIPREC-005"
CODE_RTCP_MUX = "SIPREC-006"


def _ssrc_hex(ssrc: int | None) -> str:
    return f"0x{ssrc:08x}" if ssrc is not None else "?"


def _reinvite_times(messages: list[SipMessage]) -> list[tuple[float, str | None]]:
    out: list[tuple[float, str | None]] = []
    seen_invite = False
    for m in messages:
        if not m.is_request:
            continue
        method = (m.method or "").upper()
        if method == "INVITE":
            if seen_invite and m.timestamp_relative is not None:
                out.append((m.timestamp_relative, m.cseq))
            seen_invite = True
        elif method == "UPDATE" and m.timestamp_relative is not None:
            out.append((m.timestamp_relative, m.cseq))
    return sorted(out)


def _trigger_for(time_rel: float | None, reinvites: list[tuple[float, str | None]]) -> str | None:
    if time_rel is None:
        return None
    best = None
    for t, cseq in reinvites:
        if t <= time_rel + 0.5:
            best = cseq
        else:
            break
    return best


def build_label_lifecycles(analysis: RecordingAnalysis) -> list[LabelLifecycle]:
    """Group observed streams into per-label SSRC lifecycles.

    Only substantial streams (>= SUBSTANTIAL_MIN_PACKETS) are included as
    lifecycle segments. Noise streams (STUN, RTCP-mux SR, codec stragglers)
    are counted separately so the report can explain the discrepancy.
    """
    reinvites = _reinvite_times(analysis.sip_messages)
    groups: dict[str, list] = {}
    for s in analysis.rtp_streams:
        key = s.matched_sdp_label or f"{s.src.port}->{s.dst.port}"
        groups.setdefault(key, []).append(s)

    lifecycles: list[LabelLifecycle] = []
    for label, all_streams in groups.items():
        substantial = [s for s in all_streams if is_substantial(s) and s.first_timestamp_relative is not None]
        noise_count = len(all_streams) - len(substantial)
        substantial.sort(key=lambda s: s.first_timestamp_relative or 0.0)
        if not substantial:
            continue
        segments = [
            SsrcSegment(
                ssrc=s.ssrc,
                first_time=s.first_timestamp_relative,
                last_time=s.last_timestamp_relative,
                packet_count=s.packet_count,
                trigger_cseq=_trigger_for(s.first_timestamp_relative, reinvites),
            )
            for s in substantial
        ]
        first_t = segments[0].first_time or 0.0
        last_t = max((seg.last_time or 0.0) for seg in segments)
        dur_min = max((last_t - first_t) / 60.0, 1e-6)
        change_count = max(len(segments) - 1, 0)
        participant = describe_participant(analysis, substantial[0].matched_sdp_label)
        lc = LabelLifecycle(
            label=label,
            participant=participant,
            port_key=f"{substantial[0].src.port}->{substantial[0].dst.port}",
            segments=segments,
            ssrc_change_count=change_count,
            stability_per_min=round(change_count / dur_min, 3),
        )
        lc.noise_stream_count = noise_count  # type: ignore[attr-defined]
        lifecycles.append(lc)
    return lifecycles


def detect_coverage_gaps(
    analysis: RecordingAnalysis, lifecycles: list[LabelLifecycle]
) -> list[CoverageGap]:
    """Estimate recording gaps where an SSRC changed on/after a retrieve."""
    retrieves = [e.time_relative for e in analysis.hold_retrieve_events if e.kind == "RETRIEVE"]
    gaps: list[CoverageGap] = []
    for lc in lifecycles:
        for prev, cur in zip(lc.segments, lc.segments[1:], strict=False):
            t = cur.first_time
            if t is None:
                continue
            near_retrieve = any(
                r is not None and abs(t - r) <= RETRIEVE_WINDOW_S for r in retrieves
            )
            if not near_retrieve:
                continue
            duration = None
            if cur.last_time is not None and cur.first_time is not None:
                duration = cur.last_time - cur.first_time
            gaps.append(
                CoverageGap(
                    label=lc.label,
                    participant=lc.participant,
                    start_time=cur.first_time,
                    end_time=cur.last_time,
                    duration_s=duration,
                    old_ssrc=prev.ssrc,
                    new_ssrc=cur.ssrc,
                    reason="SSRC changed on retrieve; a recorder tracking the prior SSRC would miss this audio.",
                )
            )
    return gaps


def detect_ssrc_collisions(lifecycles: list[LabelLifecycle]) -> list[SsrcCollision]:
    """Flag two SSRCs active on the same label/port within an overlapping window."""
    collisions: list[SsrcCollision] = []
    for lc in lifecycles:
        segs = [s for s in lc.segments if s.first_time is not None and s.last_time is not None]
        for i in range(len(segs)):
            for j in range(i + 1, len(segs)):
                a, b = segs[i], segs[j]
                start = max(a.first_time, b.first_time)
                end = min(a.last_time, b.last_time)
                if end >= start and a.ssrc != b.ssrc and a.packet_count > 1 and b.packet_count > 1:
                    collisions.append(
                        SsrcCollision(
                            label=lc.label,
                            port_key=lc.port_key or "",
                            ssrc_a=a.ssrc,
                            ssrc_b=b.ssrc,
                            overlap_start=start,
                            overlap_end=end,
                        )
                    )
    return collisions


def build_lifecycle_findings(
    analysis: RecordingAnalysis,
    lifecycles: list[LabelLifecycle],
    gaps: list[CoverageGap],
    collisions: list[SsrcCollision],
) -> list[RecordingFinding]:
    findings: list[RecordingFinding] = []

    # SIPREC-001 — coverage gap (the headline failure).
    for g in gaps:
        who = g.participant or f"label {g.label}"
        dur = f"{g.duration_s:.0f}s" if g.duration_s is not None else "unknown duration"
        findings.append(
            RecordingFinding(
                severity=Severity.CRITICAL,
                code=CODE_RETRIEVE_GAP,
                title="Recording gap after retrieve (SSRC change)",
                detail=(
                    f"Stream {who} changed SSRC from {_ssrc_hex(g.old_ssrc)} to "
                    f"{_ssrc_hex(g.new_ssrc)} at t={g.start_time:.1f}s on retrieve. "
                    f"Estimated recording gap: {dur}. Verify the recorder followed the new SSRC."
                ),
                owner=Owner.SBC,
                evidence_streams=[g.label],
                recommendation="Confirm rtpengine-recording re-learned the SSRC on retrieve; if not, this is the dropout.",
            )
        )

    # SIPREC-003 — simultaneous SSRCs on one port.
    for c in collisions:
        findings.append(
            RecordingFinding(
                severity=Severity.ERROR,
                code=CODE_SSRC_COLLISION,
                title="Two SSRCs active on one media port",
                detail=(
                    f"On label {c.label} ({c.port_key}), SSRCs {_ssrc_hex(c.ssrc_a)} and "
                    f"{_ssrc_hex(c.ssrc_b)} overlapped between t={c.overlap_start:.1f}s and "
                    f"t={c.overlap_end:.1f}s — the recorder may capture the wrong one."
                ),
                owner=Owner.SBC,
                evidence_streams=[c.label or ""],
            )
        )

    # Stability score per label.
    for lc in lifecycles:
        if lc.ssrc_change_count == 0:
            continue
        sev = Severity.WARN if (lc.stability_per_min or 0) >= STABILITY_WARN_PER_MIN else Severity.INFO
        findings.append(
            RecordingFinding(
                severity=sev,
                code=CODE_BURST_CHURN,
                title="SSRC churn on a stream",
                detail=(
                    f"{lc.participant or ('label ' + lc.label)} changed SSRC "
                    f"{lc.ssrc_change_count} time(s) "
                    f"({lc.stability_per_min}/min): "
                    + " -> ".join(_ssrc_hex(s.ssrc) for s in lc.segments)
                ),
                owner=Owner.SBC,
                evidence_streams=[lc.label],
            )
        )

    return findings


def correlate_bursts_with_ssrc(
    analysis: RecordingAnalysis, lifecycles: list[LabelLifecycle]
) -> list[RecordingFinding]:
    """For each re-INVITE burst, report which labels changed SSRC and flag asymmetry."""
    findings: list[RecordingFinding] = []
    for burst in analysis.bursts:
        if burst.window_start is None:
            continue
        lo = burst.window_start - BURST_WINDOW_S
        hi = (burst.window_end or burst.window_start) + BURST_WINDOW_S
        changed: list[str] = []
        unchanged: list[str] = []
        for lc in lifecycles:
            label_changed = any(
                seg.first_time is not None and lo <= seg.first_time <= hi
                for seg in lc.segments[1:]
            )
            name = lc.participant or f"label {lc.label}"
            (changed if label_changed else unchanged).append(name)
        if changed:
            detail = (
                f"Re-INVITE burst at t={burst.window_start:.0f}s coincided with SSRC change(s) on: "
                + ", ".join(changed) + "."
            )
            if unchanged:
                detail += (
                    " Asymmetric: " + ", ".join(unchanged)
                    + " did not change — the SBC handled the legs differently."
                )
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_BURST_CHURN,
                    title="Re-INVITE burst caused SSRC churn",
                    detail=detail,
                    owner=Owner.SBC,
                    evidence_frames=burst.evidence_frames,
                )
            )
    return findings


def analyze_ssrc_lifecycle(analysis: RecordingAnalysis) -> list[RecordingFinding]:
    """Top-level entry: populate lifecycles/gaps/collisions and return findings."""
    lifecycles = build_label_lifecycles(analysis)
    analysis.label_lifecycles = lifecycles
    gaps = detect_coverage_gaps(analysis, lifecycles)
    analysis.coverage_gaps = gaps
    collisions = detect_ssrc_collisions(lifecycles)
    analysis.ssrc_collisions = collisions
    findings = build_lifecycle_findings(analysis, lifecycles, gaps, collisions)
    findings += correlate_bursts_with_ssrc(analysis, lifecycles)
    return findings


__all__ = [
    "analyze_ssrc_lifecycle",
    "build_label_lifecycles",
    "detect_coverage_gaps",
    "detect_ssrc_collisions",
    "CODE_RETRIEVE_GAP",
    "CODE_BURST_CHURN",
    "CODE_SSRC_COLLISION",
    "CODE_HOLD_RETRIEVE",
    "CODE_LABELS_UNBOUND",
    "CODE_RTCP_MUX",
]
