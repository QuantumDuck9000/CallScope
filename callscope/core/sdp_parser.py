"""SDP parsing into :class:`SdpSession` / :class:`SdpMedia` objects.

Supports multiple m-lines, session- and media-level ``c=`` lines, ``a=rtcp``,
``a=rtcp-mux``, ``a=label``/``a=mid``, the standard direction attributes
(sendrecv/sendonly/recvonly/inactive), and ``a=rtpmap``/``a=fmtp``.

Parsing is deliberately tolerant: unknown attributes are preserved in the
generic ``attributes`` map rather than discarded, and malformed individual
lines are skipped rather than aborting the whole parse.
"""

from __future__ import annotations

from ..errors import SdpParseError
from ..models import SdpMedia, SdpSession

_DIRECTION_ATTRS = {"sendrecv", "sendonly", "recvonly", "inactive"}


def _split_lines(text: str) -> list[str]:
    lines = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if line:
            lines.append(line)
    return lines


def _parse_connection(value: str) -> str | None:
    """Parse the address from a ``c=`` value like ``IN IP4 10.0.0.1``."""
    parts = value.split()
    if len(parts) >= 3:
        return parts[2]
    if parts:
        return parts[-1]
    return None


def _apply_media_attribute(media: SdpMedia, attr_value: str) -> None:
    """Apply a single ``a=...`` attribute (without the leading ``a=``)."""
    if ":" in attr_value:
        name, _, value = attr_value.partition(":")
        name = name.strip()
        value = value.strip()
    else:
        name = attr_value.strip()
        value = ""

    media.attributes.setdefault(name, []).append(value)

    if name in _DIRECTION_ATTRS:
        media.direction = name
    elif name == "rtcp-mux":
        media.rtcp_mux = True
    elif name == "rtcp":
        # e.g. "30001" or "30001 IN IP4 1.2.3.4"
        token = value.split()[0] if value else ""
        if token.isdigit():
            media.rtcp_port = int(token)
    elif name == "label":
        media.label = value or media.label
    elif name == "mid":
        media.mid = value or media.mid
    elif name == "rtpmap":
        # "0 PCMU/8000"
        pt, _, rest = value.partition(" ")
        if pt:
            media.rtpmap[pt.strip()] = rest.strip()
    elif name == "fmtp":
        # "101 0-15"
        pt, _, rest = value.partition(" ")
        if pt:
            media.fmtp[pt.strip()] = rest.strip()


def _parse_media_line(value: str) -> SdpMedia:
    """Parse an ``m=`` value like ``audio 30000 RTP/AVP 0 8 101``."""
    parts = value.split()
    if len(parts) < 3:
        raise SdpParseError(f"Malformed m= line: {value!r}")
    media_type = parts[0]
    try:
        port = int(parts[1].split("/")[0])
    except ValueError as exc:
        raise SdpParseError(f"Invalid media port in m= line: {value!r}") from exc
    protocol = parts[2]
    payload_types = list(parts[3:])
    return SdpMedia(
        media_type=media_type,
        port=port,
        protocol=protocol,
        payload_types=payload_types,
    )


def parse_sdp(text: str) -> SdpSession:
    """Parse SDP text into an :class:`SdpSession`."""
    if text is None:
        raise SdpParseError("SDP text is None.")

    session = SdpSession(
        connection_address=None,
        origin=None,
        session_name=None,
        raw=text,
    )

    current_media: SdpMedia | None = None

    for line in _split_lines(text):
        if len(line) < 2 or line[1] != "=":
            # Not a well-formed "x=..." SDP line; skip tolerantly.
            continue
        key = line[0]
        value = line[2:].strip()

        if key == "m":
            try:
                current_media = _parse_media_line(value)
            except SdpParseError:
                current_media = None
                continue
            session.media.append(current_media)
        elif key == "c":
            addr = _parse_connection(value)
            if current_media is None:
                session.connection_address = addr
            else:
                current_media.connection_address = addr
        elif key == "o":
            session.origin = value
        elif key == "s":
            session.session_name = value
        elif key == "a":
            if current_media is not None:
                _apply_media_attribute(current_media, value)
            # Session-level attributes are currently not tracked individually.

    return session


def infer_rtcp_port(media: SdpMedia) -> int | None:
    """Infer the RTCP port for a media section.

    Precedence:
      1. Explicit ``a=rtcp:<port>`` if present.
      2. ``a=rtcp-mux`` -> RTCP shares the RTP port.
      3. Otherwise RTP port + 1.
    """
    if media.rtcp_port is not None:
        return media.rtcp_port
    if media.rtcp_mux:
        return media.port
    if media.port:
        return media.port + 1
    return None


__all__ = ["parse_sdp", "infer_rtcp_port"]
