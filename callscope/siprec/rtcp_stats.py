"""Compute per-stream RTCP statistics from tshark RTCP report fields.

Parses Sender/Receiver Report blocks for fraction-lost, cumulative loss,
interarrival jitter, and reporting cadence, and flags RTCP BYE. RTT estimation
from LSR/DLSR requires correlating SR and RR across endpoints and is left out of
v2 rather than reported imprecisely.
"""

from __future__ import annotations

from statistics import mean

from ..models import Owner, RecordingFinding, RtcpStreamStats, Severity

# tshark fields needed for RTCP analysis.
RTCP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "rtcp.pt",
    "rtcp.ssrc.identifier",
    "rtcp.ssrc.fraction",
    "rtcp.ssrc.cumulative",
    "rtcp.ssrc.jitter",
]

PT_BYE = 203
PT_SR = 200
PT_RR = 201
PT_SDES = 202
PT_APP = 204
_PT_NAMES = {PT_SR: "SR", PT_RR: "RR", PT_SDES: "SDES", PT_BYE: "BYE", PT_APP: "APP"}

CODE_NO_REPORTS = "RTCP_NO_REPORTS"


def _split_pts(value: str | None) -> list[int]:
    """A compound RTCP frame yields a comma-joined rtcp.pt field in -T fields."""
    if not value:
        return []
    out: list[int] = []
    for piece in value.replace(" ", "").split(","):
        v = _to_int(piece)
        if v is not None:
            out.append(v)
    return out


def summarize_rtcp_packets(rows: list[dict]) -> dict:
    """Count RTCP packets by type and how many carried a reception report block.

    Also folds in rtcp-mux packets that tshark read as RTP (rtp.p_type 64-95):
    per RFC 5761 the RTCP packet type is rtp.p_type + 128, so p_type 72 -> SR,
    73 -> RR, etc. This is why a capture can clearly contain RTCP yet yield no
    parsed stats — the reports were dissected as RTP on the media port.
    """
    counts = {"SR": 0, "RR": 0, "SDES": 0, "BYE": 0, "APP": 0, "other": 0}
    report_blocks = 0
    total = 0
    muxed_as_rtp = 0
    for row in rows:
        pts = _split_pts(row.get("rtcp.pt"))
        # rtcp-mux read as RTP: derive the RTCP PT from rtp.p_type + 128.
        rtp_pt = _to_int(row.get("rtp.p_type"))
        if not pts and rtp_pt is not None and 64 <= rtp_pt <= 95:
            pts = [rtp_pt + 128]
            muxed_as_rtp += 1
        if not pts:
            continue
        total += 1
        for pt in pts:
            counts[_PT_NAMES.get(pt, "other")] = counts.get(_PT_NAMES.get(pt, "other"), 0) + 1
        if row.get("rtcp.ssrc.fraction") or row.get("rtcp.ssrc.jitter"):
            report_blocks += sum(1 for _ in iter_report_blocks(row))
    return {
        "total": total,
        "by_type": counts,
        "report_blocks": report_blocks,
        "muxed_as_rtp": muxed_as_rtp,
    }


def build_rtcp_presence_findings(summary: dict) -> list[RecordingFinding]:
    """Explain the common case: RTCP present, but no reception reports to score."""
    if not summary or not summary.get("total"):
        return []
    if summary.get("report_blocks"):
        return []
    by = summary.get("by_type", {})
    muxed = summary.get("muxed_as_rtp", 0)
    detail = (
        f"{summary['total']} RTCP packet(s) seen "
        f"({by.get('SR', 0)} SR, {by.get('RR', 0)} RR, {by.get('SDES', 0)} SDES) "
        "but none carried a reception report block, so packet loss, jitter, and MOS "
        "cannot be computed from this capture."
    )
    if muxed:
        detail += (
            f" {muxed} of these were rtcp-mux'd onto the RTP port and dissected as RTP; "
            "re-run with rtcp-mux decoding to recover any report blocks."
        )
    else:
        detail += " The receiving side (recorder) is not sending Receiver Reports, or only one direction was captured."
    return [
        RecordingFinding(
            severity=Severity.WARN,
            code=CODE_NO_REPORTS,
            title="RTCP present but no quality reports",
            detail=detail,
            owner=Owner.UNKNOWN,
            recommendation="Capture both directions of the SBC-recorder leg; the recorder's Receiver Reports carry the loss/jitter that quality scoring needs.",
        )
    ]


HIGH_LOSS_FRACTION = 0.05  # 5%
RTCP_GAP_THRESHOLD_S = 10.0

CODE_HIGH_LOSS = "RTCP_HIGH_LOSS"
CODE_TIMEOUT = "RTCP_TIMEOUT"
CODE_BYE = "RTCP_BYE"


def _to_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _to_float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _split_ints(value: str | None) -> list[int | None]:
    if not value:
        return []
    return [_to_int(p) for p in value.replace(" ", "").split(",")]


def iter_report_blocks(row: dict):
    """Yield one (ssrc, fraction, cumulative, jitter, time) per reception block.

    A compound RTCP frame (e.g. an SR carrying several reception report blocks,
    bundled with SDES) is emitted by ``tshark -T fields`` as comma-joined lists:
    ``rtcp.ssrc.identifier="0xA,0xB"``, ``rtcp.ssrc.fraction="0,0"``, etc. Treating
    those as single integers drops the data, so we split and zip them per block.
    """
    ids = _split_ints(row.get("rtcp.ssrc.identifier"))
    fracs = _split_ints(row.get("rtcp.ssrc.fraction"))
    cums = _split_ints(row.get("rtcp.ssrc.cumulative"))
    jits = _split_ints(row.get("rtcp.ssrc.jitter"))
    t_rel = _to_float(row.get("frame.time_relative"))
    n = max(len(ids), len(fracs), len(cums), len(jits))
    for i in range(n):
        def at(seq):
            return seq[i] if i < len(seq) else None
        ssrc, frac, cum, jit = at(ids), at(fracs), at(cums), at(jits)
        if ssrc is None and frac is None and jit is None:
            continue
        yield ssrc, frac, cum, jit, t_rel


def compute_rtcp_stats(rows: list[dict]) -> list[RtcpStreamStats]:
    """Aggregate RTCP report rows into per-reported-SSRC statistics."""
    by_ssrc: dict[int | None, dict] = {}
    bye_seen: set[int | None] = set()

    for row in rows:
        if PT_BYE in _split_pts(row.get("rtcp.pt")):
            bye_seen.update(_split_ints(row.get("rtcp.ssrc.identifier")) or [None])

        for ssrc, fraction, cumulative, jitter, t_rel in iter_report_blocks(row):
            acc = by_ssrc.setdefault(
                ssrc,
                {"count": 0, "fractions": [], "cumulative": None, "jitters": [], "times": []},
            )
            acc["count"] += 1
            if fraction is not None:
                acc["fractions"].append(fraction / 256.0)
            if cumulative is not None:
                acc["cumulative"] = cumulative
            if jitter is not None:
                acc["jitters"].append(float(jitter))
            if t_rel is not None:
                acc["times"].append(t_rel)

    stats: list[RtcpStreamStats] = []
    for ssrc, acc in by_ssrc.items():
        times = sorted(acc["times"])
        max_gap = None
        if len(times) >= 2:
            max_gap = max(b - a for a, b in zip(times, times[1:], strict=False))
        jitters = acc["jitters"]
        fractions = acc["fractions"]
        stats.append(
            RtcpStreamStats(
                ssrc=ssrc,
                report_count=acc["count"],
                fraction_lost_max=max(fractions) if fractions else None,
                cumulative_lost=acc["cumulative"],
                jitter_min=min(jitters) if jitters else None,
                jitter_avg=mean(jitters) if jitters else None,
                jitter_max=max(jitters) if jitters else None,
                rtt_estimate_ms=None,
                max_report_gap_s=max_gap,
                rtcp_bye_seen=ssrc in bye_seen,
            )
        )
    return stats


def build_rtcp_findings(stats: list[RtcpStreamStats]) -> list[RecordingFinding]:
    findings: list[RecordingFinding] = []
    for s in stats:
        label = f"SSRC 0x{s.ssrc:08x}" if s.ssrc is not None else "stream"
        if s.fraction_lost_max is not None and s.fraction_lost_max > HIGH_LOSS_FRACTION:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_HIGH_LOSS,
                    title="High RTCP-reported loss",
                    detail=(
                        f"{label} reported up to {s.fraction_lost_max * 100:.1f}% packet "
                        "loss on the recording path."
                    ),
                    recommendation="Investigate the SBC-to-recorder network path.",
                    owner=Owner.NETWORK,
                )
            )
        if s.max_report_gap_s is not None and s.max_report_gap_s > RTCP_GAP_THRESHOLD_S:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_TIMEOUT,
                    title="RTCP reporting gap",
                    detail=(
                        f"{label} had a {s.max_report_gap_s:.1f}s gap between RTCP reports "
                        "(possible media stall or one-way path)."
                    ),
                    owner=Owner.NETWORK,
                )
            )
        if s.rtcp_bye_seen:
            findings.append(
                RecordingFinding(
                    severity=Severity.INFO,
                    code=CODE_BYE,
                    title="RTCP BYE observed",
                    detail=f"{label} sent an RTCP BYE (stream ended).",
                    owner=Owner.UNKNOWN,
                )
            )
    return findings


__all__ = [
    "compute_rtcp_stats",
    "build_rtcp_findings",
    "RTCP_FIELDS",
    "CODE_HIGH_LOSS",
    "CODE_TIMEOUT",
    "CODE_BYE",
]
