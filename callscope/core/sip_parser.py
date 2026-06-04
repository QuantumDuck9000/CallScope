"""SIP message parsing.

Two entry points:

* :func:`parse_sip_message_text` parses a raw SIP message (start line, headers,
  blank line, body) into a :class:`SipMessage`.
* :func:`parse_sip_messages_from_tshark_json` adapts tshark ``-T json`` packet
  records into :class:`SipMessage` objects on a best-effort basis.

Multipart bodies (e.g. ``multipart/mixed`` carrying SDP + SIPREC metadata) are
detected and exposed via :func:`iter_body_parts` for the SIPREC parser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..errors import SipParseError
from ..models import Direction, Endpoint, SipMessage

_STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$", re.IGNORECASE)
_REQUEST_LINE_RE = re.compile(r"^([A-Za-z]+)\s+(\S+)\s+SIP/2\.0\s*$")
_SIPREC_CONTENT_TYPES = {"application/rs-metadata", "application/rs-metadata+xml"}
_CANONICAL_SIPREC_CT = "application/rs-metadata+xml"


def is_siprec_metadata_content_type(content_type: str | None) -> bool:
    """Return True for SIPREC metadata content types.

    Accepts both ``application/rs-metadata+xml`` and ``application/rs-metadata``
    (parameters and case are ignored).
    """
    if not content_type:
        return False
    base = content_type.split(";", 1)[0].strip().lower()
    return base in _SIPREC_CONTENT_TYPES


def normalize_siprec_content_type(content_type: str | None) -> str | None:
    """Normalize a SIPREC metadata content type to the canonical form."""
    if is_siprec_metadata_content_type(content_type):
        return _CANONICAL_SIPREC_CT
    return content_type


@dataclass
class BodyPart:
    headers: dict[str, str]
    content_type: str | None
    content: str


def _extract_boundary(content_type: str | None) -> str | None:
    if not content_type:
        return None
    match = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    return match.group(1).strip() if match else None


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def maybe_hex_decode(text: str | None) -> str | None:
    """Decode a body that tshark emitted as a hex string back to text.

    SIP-over-TCP/TLS bodies are frequently surfaced as a contiguous (or
    colon-separated) hex blob. If the input is all hex, even-length, and decodes
    to mostly-printable text, the decoded form is returned; otherwise the input
    is returned unchanged.
    """
    if not text:
        return text
    candidate = text.strip().replace(":", "").replace(" ", "").replace("\n", "")
    if len(candidate) < 8 or len(candidate) % 2 != 0 or not _HEX_RE.match(candidate):
        return text
    try:
        decoded = bytes.fromhex(candidate)
    except ValueError:
        return text
    try:
        out = decoded.decode("utf-8")
    except UnicodeDecodeError:
        out = decoded.decode("latin-1", errors="replace")
    printable = sum(1 for ch in out if ch.isprintable() or ch in "\r\n\t")
    if printable / max(len(out), 1) < 0.85:
        return text
    return out


def _sniff_boundary(body: str) -> str | None:
    """Find a multipart boundary inside a body when the header lacked one."""
    match = re.search(r"^--([A-Za-z0-9'()+_,\-./:=?]+)\s*$", body, re.MULTILINE)
    return match.group(1) if match else None


def iter_body_parts(message: SipMessage) -> list[BodyPart]:
    """Split a (possibly multipart) SIP body into parts.

    For a single-part body, returns one :class:`BodyPart` carrying the message's
    own content type. Hex-encoded bodies are decoded first, and a multipart
    boundary is sniffed from the body if the Content-Type header didn't carry one.
    """
    if message.body is None:
        return []

    body = maybe_hex_decode(message.body) or message.body
    ctype = message.content_type or ""
    boundary = _extract_boundary(ctype)
    looks_multipart = "multipart/" in ctype.lower() or "--" in body[:512]
    if not boundary and looks_multipart:
        boundary = _sniff_boundary(body)

    if not boundary:
        return [BodyPart(headers={}, content_type=message.content_type, content=body)]

    parts: list[BodyPart] = []
    delimiter = f"--{boundary}"
    raw = body.replace("\r\n", "\n")
    segments = raw.split(delimiter)
    for seg in segments:
        seg = seg.strip("\n")
        if not seg or seg.strip() == "--":
            continue
        header_block, _, content = seg.partition("\n\n")
        headers: dict[str, str] = {}
        for hline in header_block.split("\n"):
            if ":" in hline:
                name, _, value = hline.partition(":")
                headers[name.strip().lower()] = value.strip()
        parts.append(
            BodyPart(
                headers=headers,
                content_type=headers.get("content-type"),
                content=content.strip("\n"),
            )
        )
    return parts


def parse_sip_message_text(raw: str) -> SipMessage:
    """Parse a raw SIP message string into a :class:`SipMessage`."""
    if not raw or not raw.strip():
        raise SipParseError("Empty SIP message.")

    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    header_block, _, body = normalized.partition("\n\n")
    lines = header_block.split("\n")
    start_line = lines[0].strip()

    method: str | None = None
    status_code: int | None = None
    reason_phrase: str | None = None

    status_match = _STATUS_LINE_RE.match(start_line)
    request_match = _REQUEST_LINE_RE.match(start_line)
    if status_match:
        status_code = int(status_match.group(1))
        reason_phrase = status_match.group(2).strip() or None
    elif request_match:
        method = request_match.group(1).upper()
    else:
        raise SipParseError(f"Unrecognized SIP start line: {start_line!r}")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

    return SipMessage(
        frame_number=0,
        timestamp_epoch=None,
        timestamp_relative=None,
        src=Endpoint(ip="", port=None),
        dst=Endpoint(ip="", port=None),
        direction=Direction.UNKNOWN,
        call_id=headers.get("call-id") or headers.get("i"),
        method=method,
        status_code=status_code,
        reason_phrase=reason_phrase,
        cseq=headers.get("cseq"),
        from_header=headers.get("from") or headers.get("f"),
        to_header=headers.get("to") or headers.get("t"),
        contact=headers.get("contact") or headers.get("m"),
        content_type=headers.get("content-type") or headers.get("c"),
        raw_headers=header_block,
        body=body if body.strip() else None,
        user_agent=headers.get("user-agent"),
        server=headers.get("server"),
        via_branch=_via_branch(headers.get("via") or headers.get("v")),
        via_sent_by=_via_sent_by(headers.get("via") or headers.get("v")),
    )


def _via_branch(via: str | None) -> str | None:
    if not via:
        return None
    match = re.search(r"branch=([^;,\s]+)", via, re.IGNORECASE)
    return match.group(1) if match else None


def _via_sent_by(via: str | None) -> str | None:
    if not via:
        return None
    # "SIP/2.0/UDP 10.0.0.1:5060;branch=..." -> "10.0.0.1:5060"
    parts = via.split()
    if len(parts) >= 2:
        return parts[1].split(";", 1)[0].strip()
    return None


# --- tshark JSON adapter ---------------------------------------------------


def _flatten_layers(layers: dict) -> dict[str, str]:
    """Flatten tshark JSON ``layers`` into a single field->value map.

    tshark may emit a field as a string or a list of strings; for lists we keep
    the first occurrence.
    """
    flat: dict[str, str] = {}

    def visit(obj: object) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    visit(value)
                elif isinstance(value, str) and key not in flat:
                    flat[key] = value
        elif isinstance(obj, list):
            for item in obj:
                visit(item)

    visit(layers)
    return flat


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _row_to_sip_message(layers: dict) -> SipMessage | None:
    flat = _flatten_layers(layers)
    if "sip.Call-ID" not in flat and "sip.msg_hdr" not in flat and "sip.Method" not in flat:
        return None

    method = flat.get("sip.Method")
    status_code = _int_or_none(flat.get("sip.Status-Code"))
    reason_phrase = flat.get("sip.Reason-Phrase") or flat.get("sip.Status-Line")

    src = Endpoint(
        ip=flat.get("ip.src") or flat.get("ipv6.src") or "",
        port=_int_or_none(flat.get("udp.srcport") or flat.get("tcp.srcport")),
    )
    dst = Endpoint(
        ip=flat.get("ip.dst") or flat.get("ipv6.dst") or "",
        port=_int_or_none(flat.get("udp.dstport") or flat.get("tcp.dstport")),
    )

    return SipMessage(
        frame_number=_int_or_none(flat.get("frame.number")) or 0,
        timestamp_epoch=_float_or_none(flat.get("frame.time_epoch")),
        timestamp_relative=_float_or_none(flat.get("frame.time_relative")),
        src=src,
        dst=dst,
        direction=Direction.UNKNOWN,
        call_id=flat.get("sip.Call-ID"),
        method=method.upper() if method else None,
        status_code=status_code,
        reason_phrase=reason_phrase,
        cseq=flat.get("sip.CSeq"),
        from_header=flat.get("sip.From"),
        to_header=flat.get("sip.To"),
        contact=flat.get("sip.Contact"),
        content_type=flat.get("sip.Content-Type"),
        raw_headers=flat.get("sip.msg_hdr", ""),
        body=flat.get("sip.msg_body") or None,
        user_agent=flat.get("sip.User-Agent"),
        server=flat.get("sip.Server"),
        via_branch=flat.get("sip.Via.branch"),
        via_sent_by=flat.get("sip.Via.sent_by") or flat.get("sip.Via"),
    )


def parse_sip_messages_from_tshark_json(rows: list[dict]) -> list[SipMessage]:
    """Convert tshark ``-T json`` packet records into SipMessage objects."""
    messages: list[SipMessage] = []
    for row in rows:
        layers = row.get("_source", {}).get("layers", {}) if isinstance(row, dict) else {}
        if not layers:
            # Allow already-flattened dicts too.
            layers = row if isinstance(row, dict) else {}
        msg = _row_to_sip_message(layers)
        if msg is not None:
            messages.append(msg)
    return messages


__all__ = [
    "parse_sip_messages_from_tshark_json",
    "parse_sip_message_text",
    "is_siprec_metadata_content_type",
    "normalize_siprec_content_type",
    "iter_body_parts",
    "BodyPart",
]
