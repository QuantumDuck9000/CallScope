"""SIPREC metadata parsing (RFC 7865 style) with vendor-extension tolerance.

XML is parsed with a hardened lxml parser: external entity resolution is
disabled and network access is forbidden. ``recover=True`` lets us extract as
much as possible from slightly malformed documents rather than aborting.
"""

from __future__ import annotations

from typing import Any

from lxml import etree

from ..core.sip_parser import is_siprec_metadata_content_type, iter_body_parts
from ..errors import SipRecParseError
from ..models import (
    SipMessage,
    SipRecCommunicationSession,
    SipRecMetadata,
    SipRecParticipant,
    SipRecStream,
)

_RECORDING_NS = "urn:ietf:params:xml:ns:recording:1"


def _secure_parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        recover=True,
        huge_tree=False,
    )


def _local(tag: object) -> str:
    """Return the namespace-stripped local name of an element tag."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _text(el: etree._Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    text = el.text.strip()
    return text or None


def _children_by_local(parent: etree._Element, name: str) -> list[etree._Element]:
    return [c for c in parent if _local(c.tag) == name]


def _first_child_by_local(parent: etree._Element, name: str) -> etree._Element | None:
    for c in parent:
        if _local(c.tag) == name:
            return c
    return None


def _raw_of(el: etree._Element) -> dict[str, Any]:
    """Capture an element's attributes and immediate child text for ``raw``."""
    raw: dict[str, Any] = {"tag": _local(el.tag), "attrib": dict(el.attrib)}
    children: dict[str, Any] = {}
    for c in el:
        lname = _local(c.tag)
        val = _text(c)
        if val is not None:
            children.setdefault(lname, []).append(val)
    if children:
        raw["children"] = children
    return raw


def _parse_participant(el: etree._Element) -> SipRecParticipant:
    pid = el.get("participant_id") or el.get("participantid") or ""
    name = None
    aor = None
    name_id = _first_child_by_local(el, "nameID")
    if name_id is not None:
        aor = name_id.get("aor")
        name_el = _first_child_by_local(name_id, "name")
        name = _text(name_el)
    return SipRecParticipant(
        participant_id=pid,
        name=name,
        aor=aor,
        role=None,
        raw=_raw_of(el),
    )


def _parse_stream(el: etree._Element) -> SipRecStream:
    sid = el.get("stream_id") or el.get("streamid") or ""
    label_el = _first_child_by_local(el, "label")
    label = _text(label_el)
    media_type_el = _first_child_by_local(el, "type")
    return SipRecStream(
        stream_id=sid,
        media_type=_text(media_type_el),
        label=label,
        raw=_raw_of(el),
    )


def parse_siprec_metadata_xml(xml_text: str) -> SipRecMetadata:
    """Parse SIPREC metadata XML into a :class:`SipRecMetadata`.

    Always preserves ``raw_xml``. Unknown/vendor elements are tolerated and
    their content is retained in each object's ``raw`` map.
    """
    if xml_text is None:
        raise SipRecParseError("SIPREC metadata XML is None.")

    try:
        root = etree.fromstring(xml_text.encode("utf-8"), parser=_secure_parser())
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise SipRecParseError(f"Could not parse SIPREC metadata XML: {exc}") from exc

    if root is None:
        raise SipRecParseError("SIPREC metadata XML produced no root element.")

    version = "1" if _RECORDING_NS in (root.tag or "") else None

    participants: list[SipRecParticipant] = []
    streams: list[SipRecStream] = []
    sessions_by_id: dict[str, SipRecCommunicationSession] = {}
    session_order: list[str] = []

    # participant_id -> set(stream_id) from participantstreamassoc
    stream_participants: dict[str, set[str]] = {}
    # session_id -> set(participant_id) from participantsessionassoc
    session_participants: dict[str, set[str]] = {}

    for el in root:
        lname = _local(el.tag)
        if lname == "participant":
            participants.append(_parse_participant(el))
        elif lname == "stream":
            streams.append(_parse_stream(el))
        elif lname == "session":
            sid = el.get("session_id") or el.get("sessionid") or ""
            if sid not in sessions_by_id:
                sessions_by_id[sid] = SipRecCommunicationSession(
                    session_id=sid, raw=_raw_of(el)
                )
                session_order.append(sid)
        elif lname == "participantstreamassoc":
            pid = el.get("participant_id") or el.get("participantid") or ""
            for assoc in el:
                if _local(assoc.tag) in ("send", "recv", "sendrecv"):
                    stream_ref = _text(assoc)
                    if stream_ref:
                        stream_participants.setdefault(stream_ref, set()).add(pid)
        elif lname == "participantsessionassoc":
            pid = el.get("participant_id") or el.get("participantid") or ""
            ssid = el.get("session_id") or el.get("sessionid") or ""
            if ssid:
                session_participants.setdefault(ssid, set()).add(pid)

    # Wire participant_ids onto streams.
    for stream in streams:
        pids = stream_participants.get(stream.stream_id)
        if pids:
            stream.participant_ids = sorted(pids)

    participant_by_id = {p.participant_id: p for p in participants}

    # Attach streams (by session_id attribute) and participants to sessions.
    for sid in session_order:
        session = sessions_by_id[sid]
        for stream_el in (s for s in streams if (s.raw.get("attrib", {}).get("session_id") == sid)):
            session.streams.append(stream_el)
        for pid in sorted(session_participants.get(sid, set())):
            if pid in participant_by_id:
                session.participants.append(participant_by_id[pid])

    return SipRecMetadata(
        version=version,
        raw_xml=xml_text,
        communication_sessions=[sessions_by_id[s] for s in session_order],
        participants=participants,
        streams=streams,
    )


import re as _re

from ..core.sip_parser import (
    is_siprec_metadata_content_type,
    iter_body_parts,
    maybe_hex_decode,
)


def _salvage_metadata_xml(*texts: str | None) -> str | None:
    """Locate an rs-metadata XML document inside decoded body/raw text.

    Used when multipart segmentation is imperfect: we look for a
    ``<recording ...>...</recording>`` region, namespace-agnostic.
    """
    for text in texts:
        if not text:
            continue
        decoded = maybe_hex_decode(text) or text
        match = _re.search(
            r"<\s*([A-Za-z0-9_]*:)?recording\b.*?</\s*([A-Za-z0-9_]*:)?recording\s*>",
            decoded,
            _re.IGNORECASE | _re.DOTALL,
        )
        if match:
            return match.group(0)
    return None


def extract_siprec_metadata_from_message(message: SipMessage) -> SipRecMetadata | None:
    """Find and parse SIPREC metadata in a SIP message body, if present.

    Handles single-part bodies whose content type is a SIPREC metadata type,
    multipart bodies carrying a SIPREC metadata part, hex-encoded bodies, and a
    last-resort salvage that scans the decoded body/raw text for the metadata XML.
    """
    for part in iter_body_parts(message):
        if is_siprec_metadata_content_type(part.content_type) and part.content.strip():
            try:
                return parse_siprec_metadata_xml(part.content)
            except SipRecParseError:
                continue

    salvaged = _salvage_metadata_xml(message.body, message.raw_headers)
    if salvaged:
        try:
            return parse_siprec_metadata_xml(salvaged)
        except SipRecParseError:
            return None
    return None


__all__ = [
    "extract_siprec_metadata_from_message",
    "parse_siprec_metadata_xml",
]
