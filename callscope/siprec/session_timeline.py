"""SIPREC recording-session phase state machine.

Turns an ordered list of :class:`SipMessage` into a normalized
:class:`SessionTimeline`: a list of phase events plus canonical time windows
(established/terminated, media-expected, and hold/inactive) that downstream
gap and mixer analysis rely on.
"""

from __future__ import annotations

from ..core.sip_parser import is_siprec_metadata_content_type
from ..models import SessionTimeline, SipMessage, TimelineEvent

# Event type constants (stable strings used by reporting and tests).
EV_INVITE = "invite"
EV_REINVITE = "reinvite"
EV_PROVISIONAL = "provisional"
EV_ESTABLISHED = "established"
EV_ACK = "ack"
EV_UPDATE = "update"
EV_METADATA = "metadata"
EV_HOLD = "hold"
EV_RESUME = "resume"
EV_BYE = "bye"
EV_TERMINATED = "terminated"

_ACTIVE_DIRECTIONS = {"sendrecv", "sendonly", "recvonly"}


def _cseq_method(message: SipMessage) -> str | None:
    if message.method:
        return message.method.upper()
    if message.cseq:
        parts = message.cseq.split()
        if len(parts) >= 2:
            return parts[-1].upper()
    return None


def _has_metadata(message: SipMessage) -> bool:
    if message.siprec_metadata is not None:
        return True
    return is_siprec_metadata_content_type(message.content_type)


def _media_direction(message: SipMessage) -> str | None:
    """Return a representative media direction for the message, if any.

    If every media line is ``inactive`` the result is ``inactive``; otherwise
    the first non-inactive direction is returned.
    """
    if message.sdp is None or not message.sdp.media:
        return None
    directions = [m.direction for m in message.sdp.media if m.direction]
    if not directions:
        return None
    if all(d == "inactive" for d in directions):
        return "inactive"
    for d in directions:
        if d in _ACTIVE_DIRECTIONS:
            return d
    return directions[0]


def build_session_timeline(messages: list[SipMessage]) -> SessionTimeline:
    """Build a :class:`SessionTimeline` from ordered SIP messages."""
    timeline = SessionTimeline()

    established = False
    hold_open_at: float | None = None

    def add(idx: int, msg: SipMessage, ev_type: str, desc: str) -> None:
        timeline.events.append(
            TimelineEvent(
                time_relative=msg.timestamp_relative,
                frame_number=msg.frame_number,
                event_type=ev_type,
                description=desc,
                related_message_index=idx,
            )
        )

    def open_hold(t: float | None) -> None:
        nonlocal hold_open_at
        if hold_open_at is None and t is not None:
            hold_open_at = t

    def close_hold(t: float | None) -> None:
        nonlocal hold_open_at
        if hold_open_at is not None:
            timeline.hold_windows.append((hold_open_at, t))
            hold_open_at = None

    for idx, msg in enumerate(messages):
        method = _cseq_method(msg)

        if msg.is_response:
            code = msg.status_code or 0
            if 100 <= code < 200:
                add(idx, msg, EV_PROVISIONAL, f"{code} {msg.reason_phrase or ''}".strip())
            elif 200 <= code < 300 and method == "INVITE" and not established:
                established = True
                timeline.established_at = msg.timestamp_relative
                add(idx, msg, EV_ESTABLISHED, "Session established (200 OK to INVITE)")
            continue

        # Requests below.
        if method == "INVITE":
            if established:
                add(idx, msg, EV_REINVITE, "re-INVITE")
            else:
                add(idx, msg, EV_INVITE, "Initial INVITE")
            if _has_metadata(msg):
                add(idx, msg, EV_METADATA, "SIPREC metadata present")
            direction = _media_direction(msg)
            if direction == "inactive":
                open_hold(msg.timestamp_relative)
                add(idx, msg, EV_HOLD, "Media set inactive (hold)")
            elif direction in _ACTIVE_DIRECTIONS and hold_open_at is not None:
                close_hold(msg.timestamp_relative)
                add(idx, msg, EV_RESUME, f"Media resumed ({direction})")
        elif method == "UPDATE":
            add(idx, msg, EV_UPDATE, "UPDATE")
            if _has_metadata(msg):
                add(idx, msg, EV_METADATA, "SIPREC metadata present")
            direction = _media_direction(msg)
            if direction == "inactive":
                open_hold(msg.timestamp_relative)
                add(idx, msg, EV_HOLD, "Media set inactive (hold)")
            elif direction in _ACTIVE_DIRECTIONS and hold_open_at is not None:
                close_hold(msg.timestamp_relative)
                add(idx, msg, EV_RESUME, f"Media resumed ({direction})")
        elif method == "ACK":
            add(idx, msg, EV_ACK, "ACK")
        elif method == "BYE":
            timeline.terminated_at = msg.timestamp_relative
            add(idx, msg, EV_BYE, "BYE")
            add(idx, msg, EV_TERMINATED, "Session terminated")

    # Close any still-open hold window at termination.
    if hold_open_at is not None:
        close_hold(timeline.terminated_at)

    if timeline.established_at is not None:
        timeline.media_expected_windows.append(
            (timeline.established_at, timeline.terminated_at)
        )

    return timeline


__all__ = [
    "build_session_timeline",
    "EV_INVITE",
    "EV_REINVITE",
    "EV_PROVISIONAL",
    "EV_ESTABLISHED",
    "EV_ACK",
    "EV_UPDATE",
    "EV_METADATA",
    "EV_HOLD",
    "EV_RESUME",
    "EV_BYE",
    "EV_TERMINATED",
]
