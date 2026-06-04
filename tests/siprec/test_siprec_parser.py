"""Tests for SIPREC metadata XML parsing."""

from __future__ import annotations

import pytest

from callscope.errors import SipRecParseError
from callscope.siprec.siprec_parser import (
    extract_siprec_metadata_from_message,
    parse_siprec_metadata_xml,
)


def test_parses_participants_and_streams(siprec_metadata_xml):
    md = parse_siprec_metadata_xml(siprec_metadata_xml)
    assert md.version == "1"
    assert len(md.participants) == 2
    aors = sorted(p.aor for p in md.participants)
    assert aors == ["sip:alice@atlanta.example.com", "sip:bob@biloxi.example.com"]
    assert len(md.streams) == 2
    labels = sorted(s.label for s in md.streams)
    assert labels == ["96", "97"]


def test_streams_get_participant_associations(siprec_metadata_xml):
    md = parse_siprec_metadata_xml(siprec_metadata_xml)
    for stream in md.streams:
        assert stream.participant_ids  # each stream associated with >=1 participant


def test_communication_session_links_streams(siprec_metadata_xml):
    md = parse_siprec_metadata_xml(siprec_metadata_xml)
    assert len(md.communication_sessions) == 1
    session = md.communication_sessions[0]
    assert session.session_id == "hVpd7YQgEReV558xfp6r5A=="
    assert len(session.streams) == 2
    assert len(session.participants) == 2


def test_vendor_extension_is_tolerated(siprec_metadata_xml):
    # The fixture contains a vendor:tag element; parsing must not fail.
    md = parse_siprec_metadata_xml(siprec_metadata_xml)
    assert md.raw_xml  # raw preserved
    assert md.communication_sessions


def test_malformed_xml_raises():
    with pytest.raises(SipRecParseError):
        parse_siprec_metadata_xml("<<<not xml at all")


def test_extract_from_multipart_message(siprec_metadata_xml):
    from callscope.core.sip_parser import parse_sip_message_text

    boundary = "b1"
    body = (
        f"--{boundary}\n"
        "Content-Type: application/sdp\n\n"
        "v=0\n"
        f"\n--{boundary}\n"
        "Content-Type: application/rs-metadata+xml\n\n"
        f"{siprec_metadata_xml}\n"
        f"--{boundary}--\n"
    )
    raw = (
        "INVITE sip:srs SIP/2.0\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n'
        + body
    )
    msg = parse_sip_message_text(raw)
    md = extract_siprec_metadata_from_message(msg)
    assert md is not None
    assert len(md.streams) == 2


def test_extract_returns_none_when_absent():
    from callscope.core.sip_parser import parse_sip_message_text

    raw = "INVITE sip:b SIP/2.0\nContent-Type: application/sdp\n\nv=0\n"
    msg = parse_sip_message_text(raw)
    assert extract_siprec_metadata_from_message(msg) is None
