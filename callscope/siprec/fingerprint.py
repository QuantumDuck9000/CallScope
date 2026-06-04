"""Build a per-actor B2BUA fingerprint.

Identifies, per side (SRC/SBC and SRS/recorder), the User-Agent/Server banner,
the Via sent-by, the Contact host, and the SDP origin address. These are how
the SBC re-originates (rather than relays) signaling, so the fingerprint is
direct evidence of which box authored a given message.
"""

from __future__ import annotations

import re

from ..models import ActorFingerprint, Endpoint, RecordingAnalysis, SipMessage

_CONTACT_HOST_RE = re.compile(r"@([^>;\s]+)")


def _contact_host(contact: str | None) -> str | None:
    if not contact:
        return None
    match = _CONTACT_HOST_RE.search(contact)
    return match.group(1) if match else None


def _sdp_origin_addr(msg: SipMessage) -> str | None:
    if msg.sdp is None or not msg.sdp.origin:
        return None
    # o=<user> <id> <ver> <nettype> <addrtype> <addr>
    parts = msg.sdp.origin.split()
    return parts[-1] if parts else None


def _first(messages: list[SipMessage], attr: str):
    for m in messages:
        val = getattr(m, attr, None)
        if val:
            return val
    return None


def _fingerprint_for(actor: str, ip: str | None, messages: list[SipMessage]) -> ActorFingerprint:
    return ActorFingerprint(
        actor=actor,
        ip=ip,
        user_agent=_first(messages, "user_agent"),
        server=_first(messages, "server"),
        contact_host=next((_contact_host(m.contact) for m in messages if _contact_host(m.contact)), None),
        via_sent_by=_first(messages, "via_sent_by"),
        sdp_origin_addr=next((_sdp_origin_addr(m) for m in messages if _sdp_origin_addr(m)), None),
    )


def build_fingerprints(analysis: RecordingAnalysis) -> list[ActorFingerprint]:
    """Return one fingerprint per identified actor (SRC/SBC and SRS)."""
    src_ip = analysis.src_endpoint.ip if analysis.src_endpoint else None
    srs_ip = analysis.srs_endpoint.ip if analysis.srs_endpoint else None

    src_msgs = [m for m in analysis.sip_messages if src_ip and m.src.ip == src_ip]
    srs_msgs = [m for m in analysis.sip_messages if srs_ip and m.src.ip == srs_ip]

    fingerprints: list[ActorFingerprint] = []
    if src_ip:
        fingerprints.append(_fingerprint_for("SRC/SBC", src_ip, src_msgs))
    if srs_ip:
        fingerprints.append(_fingerprint_for("SRS/recorder", srs_ip, srs_msgs))
    return fingerprints


__all__ = ["build_fingerprints"]
