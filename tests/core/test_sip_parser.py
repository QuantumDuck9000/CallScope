"""Tests for SIP message parsing and multipart body handling."""

from __future__ import annotations

import pytest

from callscope.core.sip_parser import (
    is_siprec_metadata_content_type,
    iter_body_parts,
    normalize_siprec_content_type,
    parse_sip_message_text,
    parse_sip_messages_from_tshark_json,
)
from callscope.errors import SipParseError


def test_parse_request_line():
    raw = "INVITE sip:bob@example.com SIP/2.0\nCall-ID: abc@host\nCSeq: 1 INVITE\n\n"
    msg = parse_sip_message_text(raw)
    assert msg.is_request
    assert msg.method == "INVITE"
    assert msg.call_id == "abc@host"
    assert msg.cseq == "1 INVITE"


def test_parse_status_line():
    raw = "SIP/2.0 200 OK\nCall-ID: abc@host\nCSeq: 1 INVITE\n\n"
    msg = parse_sip_message_text(raw)
    assert msg.is_response
    assert msg.status_code == 200
    assert msg.reason_phrase == "OK"


def test_bad_start_line_raises():
    with pytest.raises(SipParseError):
        parse_sip_message_text("NOT A SIP MESSAGE\n\n")


def test_empty_message_raises():
    with pytest.raises(SipParseError):
        parse_sip_message_text("   ")


def test_siprec_content_type_detection():
    assert is_siprec_metadata_content_type("application/rs-metadata+xml")
    assert is_siprec_metadata_content_type("application/rs-metadata")
    assert is_siprec_metadata_content_type("APPLICATION/RS-METADATA+XML; charset=utf-8")
    assert not is_siprec_metadata_content_type("application/sdp")
    assert not is_siprec_metadata_content_type(None)


def test_normalize_siprec_content_type():
    assert normalize_siprec_content_type("application/rs-metadata") == "application/rs-metadata+xml"
    assert normalize_siprec_content_type("application/sdp") == "application/sdp"


def test_iter_body_parts_singlepart():
    raw = "INVITE sip:b SIP/2.0\nContent-Type: application/sdp\n\nv=0\n"
    msg = parse_sip_message_text(raw)
    parts = iter_body_parts(msg)
    assert len(parts) == 1
    assert parts[0].content_type == "application/sdp"
    assert parts[0].content.startswith("v=0")


def test_iter_body_parts_multipart():
    boundary = "uniqueBoundary"
    body = (
        f"--{boundary}\n"
        "Content-Type: application/sdp\n\n"
        "v=0\no=- 1 1 IN IP4 1.1.1.1\n"
        f"\n--{boundary}\n"
        "Content-Type: application/rs-metadata+xml\n\n"
        "<recording/>\n"
        f"--{boundary}--\n"
    )
    raw = (
        "INVITE sip:b SIP/2.0\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n'
        + body
    )
    msg = parse_sip_message_text(raw)
    parts = iter_body_parts(msg)
    ctypes = [p.content_type for p in parts]
    assert "application/sdp" in ctypes
    assert "application/rs-metadata+xml" in ctypes


def test_tshark_json_adapter_minimal():
    rows = [
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "7", "frame.time_relative": "1.250"},
                    "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                    "udp": {"udp.srcport": "5060", "udp.dstport": "5060"},
                    "sip": {
                        "sip.Method": "INVITE",
                        "sip.Call-ID": "xyz@host",
                        "sip.CSeq": "1 INVITE",
                    },
                }
            }
        }
    ]
    msgs = parse_sip_messages_from_tshark_json(rows)
    assert len(msgs) == 1
    assert msgs[0].method == "INVITE"
    assert msgs[0].call_id == "xyz@host"
    assert msgs[0].frame_number == 7
    assert msgs[0].src.ip == "10.0.0.1"
