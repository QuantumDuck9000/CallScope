"""Build a display model for the SIPREC ladder diagram.

Converts a list of :class:`SipMessage` into ladder rows with SRC/SRS actors,
direction, human labels, and per-message detail for the side panel.
"""

from __future__ import annotations

import dataclasses
from enum import Enum

from ..models import Direction, Endpoint, SipMessage


def _endpoint_key(endpoint: Endpoint) -> str:
    if endpoint.port is not None:
        return f"{endpoint.ip}:{endpoint.port}"
    return endpoint.ip


def _identify_actors(messages: list[SipMessage]) -> tuple[Endpoint, Endpoint]:
    """Pick SRC and SRS endpoints, defaulting to the first INVITE's direction."""
    for msg in messages:
        if msg.method == "INVITE" and msg.src.ip:
            return msg.src, msg.dst
    # Fallback: first message's endpoints.
    if messages:
        return messages[0].src, messages[0].dst
    return Endpoint(ip="?"), Endpoint(ip="?")


def _label_for(message: SipMessage) -> str:
    if message.is_response:
        base = f"{message.status_code} {message.reason_phrase or ''}".strip()
    else:
        base = message.method or "UNKNOWN"
    extras = []
    if message.sdp is not None:
        extras.append("SDP")
    if message.siprec_metadata is not None:
        extras.append("Metadata")
    if extras:
        return base + " + " + " + ".join(extras)
    return base


def _sdp_to_dict(message: SipMessage) -> dict | None:
    if message.sdp is None:
        return None
    return dataclasses.asdict(message.sdp)


def _metadata_to_dict(message: SipMessage) -> dict | None:
    if message.siprec_metadata is None:
        return None
    md = message.siprec_metadata
    return {
        "version": md.version,
        "participants": [dataclasses.asdict(p) for p in md.participants],
        "streams": [dataclasses.asdict(s) for s in md.streams],
        "communication_sessions": [
            dataclasses.asdict(cs) for cs in md.communication_sessions
        ],
        "raw_xml": md.raw_xml,
    }


def _raw_text(message: SipMessage) -> str:
    parts = [message.raw_headers] if message.raw_headers else []
    if message.body:
        parts.append("")
        parts.append(message.body)
    return "\n".join(parts)


def build_ladder_model(messages: list[SipMessage]) -> dict:
    """Return a JSON-serializable ladder display model."""
    src, srs = _identify_actors(messages)
    src_key = _endpoint_key(src)
    srs_key = _endpoint_key(srs)

    rows = []
    for idx, msg in enumerate(messages):
        msg_src_key = _endpoint_key(msg.src)
        if msg_src_key == src_key:
            from_actor, to_actor = "SRC", "SRS"
            direction = Direction.SRC_TO_SRS
        elif msg_src_key == srs_key:
            from_actor, to_actor = "SRS", "SRC"
            direction = Direction.SRS_TO_SRC
        else:
            from_actor, to_actor = "SRC", "SRS"
            direction = msg.direction if isinstance(msg.direction, Direction) else Direction.UNKNOWN

        rows.append(
            {
                "index": idx,
                "frame": msg.frame_number,
                "time_relative": msg.timestamp_relative,
                "direction": direction.value if isinstance(direction, Enum) else str(direction),
                "from_actor": from_actor,
                "to_actor": to_actor,
                "is_response": msg.is_response,
                "method": msg.method,
                "status_code": msg.status_code,
                "reason": msg.reason_phrase,
                "label": _label_for(msg),
                "call_id": msg.call_id,
                "cseq": msg.cseq,
                "from_header": msg.from_header,
                "to_header": msg.to_header,
                "contact": msg.contact,
                "content_type": msg.content_type,
                "headers": msg.raw_headers,
                "sdp": _sdp_to_dict(msg),
                "metadata": _metadata_to_dict(msg),
                "raw": _raw_text(msg),
            }
        )

    return {
        "src": {"ip": src.ip, "port": src.port, "key": src_key},
        "srs": {"ip": srs.ip, "port": srs.port, "key": srs_key},
        "rows": rows,
    }


__all__ = ["build_ladder_model"]
