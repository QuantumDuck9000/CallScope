"""Detect re-INVITE / UPDATE bursts and classify likely codec renegotiation.

A periodic, evenly-spaced re-INVITE/UPDATE is usually a benign session-timer
refresh (handled in sip_timing). A *cluster* — several within a few seconds —
is the suspicious pattern, and when the offered codec set changes across the
cluster it points at codec renegotiation, which is the SBC's behavior.
"""

from __future__ import annotations

from ..models import BurstInfo, Owner, RecordingFinding, Severity, SipMessage

DEFAULT_MIN_COUNT = 3
DEFAULT_WINDOW_S = 5.0

CODE_BURST = "SIP_REINVITE_BURST"


def _cseq_method(msg: SipMessage) -> str | None:
    if msg.method:
        return msg.method.upper()
    if msg.cseq:
        parts = msg.cseq.split()
        if len(parts) >= 2:
            return parts[-1].upper()
    return None


def _audio_payload_set(msg: SipMessage) -> list[str]:
    if msg.sdp is None:
        return []
    payloads: list[str] = []
    for media in msg.sdp.media:
        if media.media_type in ("audio", "video"):
            payloads.extend(media.payload_types)
    return payloads


def detect_reinvite_bursts(
    messages: list[SipMessage],
    min_count: int = DEFAULT_MIN_COUNT,
    window_s: float = DEFAULT_WINDOW_S,
) -> tuple[list[BurstInfo], list[RecordingFinding]]:
    """Return detected bursts and corresponding findings.

    Only mid-dialog re-INVITEs (those after the first INVITE) and UPDATEs are
    considered; the initial INVITE is excluded.
    """
    candidates: list[SipMessage] = []
    seen_first_invite = False
    for msg in messages:
        method = _cseq_method(msg)
        if not msg.is_request:
            continue
        if method == "INVITE":
            if seen_first_invite:
                candidates.append(msg)
            seen_first_invite = True
        elif method == "UPDATE":
            candidates.append(msg)

    candidates = [c for c in candidates if c.timestamp_relative is not None]
    candidates.sort(key=lambda m: m.timestamp_relative or 0.0)

    bursts: list[BurstInfo] = []
    used: set[int] = set()
    for i, anchor in enumerate(candidates):
        if i in used:
            continue
        window = [anchor]
        idxs = [i]
        for j in range(i + 1, len(candidates)):
            if (candidates[j].timestamp_relative or 0.0) - (anchor.timestamp_relative or 0.0) <= window_s:
                window.append(candidates[j])
                idxs.append(j)
            else:
                break
        if len(window) >= min_count:
            used.update(idxs)
            payload_sets = [_audio_payload_set(m) for m in window]
            distinct = {tuple(s) for s in payload_sets if s}
            codec_reneg = len(distinct) > 1
            bursts.append(
                BurstInfo(
                    window_start=window[0].timestamp_relative,
                    window_end=window[-1].timestamp_relative,
                    count=len(window),
                    methods=[_cseq_method(m) or "?" for m in window],
                    codec_renegotiation=codec_reneg,
                    payload_sets=payload_sets,
                    evidence_frames=[m.frame_number for m in window],
                )
            )

    findings: list[RecordingFinding] = []
    for b in bursts:
        span = (b.window_end or 0.0) - (b.window_start or 0.0)
        detail = (
            f"{b.count} re-INVITE/UPDATE messages within {span:.1f}s "
            f"(starting at t={b.window_start:.1f}s)."
        )
        if b.codec_renegotiation:
            detail += " Offered codec set changed across the burst — consistent with codec renegotiation."
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_BURST,
                title="Re-INVITE burst",
                detail=detail,
                evidence_frames=b.evidence_frames,
                recommendation=(
                    "If codecs are flapping, review the SBC codec-policy; if the "
                    "re-INVITEs are identical, check for glare (491) or session-timer churn."
                ),
                owner=Owner.SBC,
            )
        )
    return bursts, findings


__all__ = ["detect_reinvite_bursts", "CODE_BURST"]
