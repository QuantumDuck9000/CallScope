"""SIP timing and reliability analysis.

Covers post-dial delay / slow answer, request and response retransmissions,
missing ACK after a 200 OK, final failure responses (with hints for the common
SIPREC-relevant codes), and benign session-timer refresh detection (so it can
be distinguished from a re-INVITE burst).
"""

from __future__ import annotations

from ..models import (
    Owner,
    RecordingFinding,
    SessionTimeline,
    Severity,
    SipMessage,
)

SLOW_ANSWER_THRESHOLD_S = 6.0

CODE_RETRANSMISSION = "SIP_RETRANSMISSION"
CODE_SLOW_ANSWER = "SIP_SLOW_ANSWER"
CODE_MISSING_ACK = "SIP_MISSING_ACK"
CODE_FAILURE = "SIP_FAILURE_RESPONSE"
CODE_SESSION_TIMER = "SIP_SESSION_TIMER_REFRESH"

_FAILURE_HINTS = {
    488: "Not Acceptable Here — typically a codec mismatch.",
    606: "Not Acceptable — media negotiation failure.",
    491: "Request Pending — competing re-INVITEs (glare).",
    481: "Call/Transaction Does Not Exist — dialog state mismatch.",
    408: "Request Timeout — no timely response from the peer.",
    503: "Service Unavailable — peer overloaded or marked down.",
    500: "Server Internal Error.",
}


def _cseq_method(msg: SipMessage) -> str | None:
    if msg.method:
        return msg.method.upper()
    if msg.cseq:
        parts = msg.cseq.split()
        if len(parts) >= 2:
            return parts[-1].upper()
    return None


def _detect_retransmissions(messages: list[SipMessage]) -> list[RecordingFinding]:
    groups: dict[tuple, list[SipMessage]] = {}
    for msg in messages:
        if msg.is_response:
            key = ("R", msg.status_code, msg.cseq, msg.via_branch)
        else:
            key = ("Q", msg.method, msg.cseq, msg.via_branch)
        groups.setdefault(key, []).append(msg)

    findings: list[RecordingFinding] = []
    for key, group in groups.items():
        if len(group) > 1:
            for m in group[1:]:
                m.is_retransmission = True
            label = key[1] if key[0] == "Q" else f"{key[1]} response"
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_RETRANSMISSION,
                    title="SIP retransmission",
                    detail=(
                        f"{label} (CSeq {key[2]}) was transmitted {len(group)} times — "
                        "suggests packet loss or an unresponsive peer."
                    ),
                    evidence_frames=[m.frame_number for m in group],
                    owner=Owner.NETWORK,
                )
            )
    return findings


def _detect_failures(messages: list[SipMessage]) -> list[RecordingFinding]:
    findings: list[RecordingFinding] = []
    for msg in messages:
        code = msg.status_code or 0
        if code < 400:
            continue
        severity = Severity.WARN if code < 500 else Severity.ERROR
        hint = _FAILURE_HINTS.get(code)
        detail = f"{code} {msg.reason_phrase or ''}".strip()
        if hint:
            detail += f" — {hint}"
        findings.append(
            RecordingFinding(
                severity=severity,
                code=CODE_FAILURE,
                title=f"SIP {code} failure response",
                detail=detail,
                evidence_frames=[msg.frame_number],
                owner=Owner.UNKNOWN,
            )
        )
    return findings


def _detect_missing_ack(messages: list[SipMessage], timeline: SessionTimeline) -> list[RecordingFinding]:
    if timeline.established_at is None:
        return []
    has_ack = any(
        _cseq_method(m) == "ACK" and m.is_request for m in messages
    )
    if has_ack:
        return []
    return [
        RecordingFinding(
            severity=Severity.ERROR,
            code=CODE_MISSING_ACK,
            title="Missing ACK",
            detail="A 200 OK to INVITE was seen but no ACK followed — the dialog never completed.",
            owner=Owner.UNKNOWN,
        )
    ]


def _detect_slow_answer(messages: list[SipMessage], timeline: SessionTimeline) -> list[RecordingFinding]:
    if timeline.established_at is None:
        return []
    invite_t = next(
        (m.timestamp_relative for m in messages if m.method == "INVITE" and m.timestamp_relative is not None),
        None,
    )
    if invite_t is None:
        return []
    pdd = timeline.established_at - invite_t
    if pdd > SLOW_ANSWER_THRESHOLD_S:
        return [
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_SLOW_ANSWER,
                title="Slow answer (post-dial delay)",
                detail=f"INVITE to 200 OK took {pdd:.1f}s.",
                owner=Owner.UNKNOWN,
            )
        ]
    return []


def _detect_session_timer(messages: list[SipMessage]) -> list[RecordingFinding]:
    """Flag evenly-spaced re-INVITE/UPDATE as a benign session-timer refresh."""
    times = sorted(
        m.timestamp_relative
        for m in messages
        if m.is_request
        and _cseq_method(m) in ("INVITE", "UPDATE")
        and m.timestamp_relative is not None
    )
    # Need a few in-dialog refreshes (drop the first INVITE).
    times = times[1:]
    if len(times) < 2:
        return []
    intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
    if not intervals:
        return []
    avg = sum(intervals) / len(intervals)
    # Regular spacing (low relative variance) and a non-trivial period.
    if avg > 30 and all(abs(i - avg) <= 0.2 * avg for i in intervals):
        return [
            RecordingFinding(
                severity=Severity.INFO,
                code=CODE_SESSION_TIMER,
                title="Session-timer refresh pattern",
                detail=f"Re-INVITE/UPDATE recurring roughly every {avg:.0f}s — looks like a session-timer refresh, not a fault.",
                owner=Owner.UNKNOWN,
            )
        ]
    return []


def analyze_sip_timing(
    messages: list[SipMessage], timeline: SessionTimeline
) -> list[RecordingFinding]:
    """Run all SIP timing/reliability checks and return findings."""
    findings: list[RecordingFinding] = []
    findings += _detect_retransmissions(messages)
    findings += _detect_failures(messages)
    findings += _detect_missing_ack(messages, timeline)
    findings += _detect_slow_answer(messages, timeline)
    findings += _detect_session_timer(messages)
    return findings


__all__ = [
    "analyze_sip_timing",
    "CODE_RETRANSMISSION",
    "CODE_SLOW_ANSWER",
    "CODE_MISSING_ACK",
    "CODE_FAILURE",
    "CODE_SESSION_TIMER",
]
