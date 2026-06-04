"""Detect hold and retrieve as first-class events (not generic re-INVITEs).

A hold is unambiguous in SIPREC: a re-INVITE/UPDATE whose media lines all carry
``a=inactive`` (RFC 3264 §8.4). A retrieve is the subsequent re-INVITE/UPDATE
that returns at least one line to ``sendonly``/``sendrecv``. Hold/retrieve is the
most common trigger for recording dropout, so it is surfaced explicitly and fed
to the coverage-gap detector.
"""

from __future__ import annotations

from ..models import (
    HoldRetrieveEvent,
    Owner,
    RecordingAnalysis,
    RecordingFinding,
    Severity,
    SipMessage,
)

CODE_HOLD_RETRIEVE = "SIPREC-004"

_ACTIVE = {"sendonly", "sendrecv", "recvonly"}


def _cseq_method(msg: SipMessage) -> str | None:
    if msg.method:
        return msg.method.upper()
    if msg.cseq:
        parts = msg.cseq.split()
        if len(parts) >= 2:
            return parts[-1].upper()
    return None


def _all_inactive(msg: SipMessage) -> bool:
    if msg.sdp is None or not msg.sdp.media:
        return False
    dirs = [m.direction for m in msg.sdp.media if m.direction]
    return bool(dirs) and all(d == "inactive" for d in dirs)


def _any_active(msg: SipMessage) -> bool:
    if msg.sdp is None or not msg.sdp.media:
        return False
    return any((m.direction in _ACTIVE) for m in msg.sdp.media)


def detect_hold_retrieve(analysis: RecordingAnalysis) -> list[HoldRetrieveEvent]:
    """Return ordered HOLD/RETRIEVE events derived from SDP media directions."""
    events: list[HoldRetrieveEvent] = []
    on_hold = False
    seen_first_invite = False
    for msg in analysis.sip_messages:
        if not msg.is_request:
            continue
        method = _cseq_method(msg)
        if method not in ("INVITE", "UPDATE"):
            continue
        if method == "INVITE" and not seen_first_invite:
            seen_first_invite = True
            continue  # initial offer, not a hold/retrieve
        if _all_inactive(msg) and not on_hold:
            on_hold = True
            events.append(HoldRetrieveEvent("HOLD", msg.timestamp_relative, msg.frame_number, msg.cseq))
        elif _any_active(msg) and on_hold:
            on_hold = False
            events.append(HoldRetrieveEvent("RETRIEVE", msg.timestamp_relative, msg.frame_number, msg.cseq))
    return events


def build_hold_retrieve_findings(events: list[HoldRetrieveEvent]) -> list[RecordingFinding]:
    cycles = sum(1 for e in events if e.kind == "RETRIEVE")
    if not events:
        return []
    parts = []
    for e in events:
        t = f"t={e.time_relative:.1f}s" if e.time_relative is not None else "t=?"
        parts.append(f"{e.kind} at {t} (CSeq {e.cseq})")
    return [
        RecordingFinding(
            severity=Severity.INFO,
            code=CODE_HOLD_RETRIEVE,
            title="Hold/retrieve cycle detected",
            detail=f"{cycles} hold/retrieve cycle(s): " + "; ".join(parts) + ".",
            clause="RFC 3264 §8.4",
            owner=Owner.SBC,
            evidence_frames=[e.frame_number for e in events if e.frame_number is not None],
        )
    ]


__all__ = ["detect_hold_retrieve", "build_hold_retrieve_findings", "CODE_HOLD_RETRIEVE"]
