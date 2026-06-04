"""Tests for the SDP parser."""

from __future__ import annotations

import pytest

from callscope.core.sdp_parser import infer_rtcp_port, parse_sdp
from callscope.errors import SdpParseError


def test_basic_audio(sdp_variant):
    sdp = parse_sdp(sdp_variant("basic_audio"))
    assert sdp.connection_address == "198.51.100.1"
    assert len(sdp.media) == 1
    media = sdp.media[0]
    assert media.media_type == "audio"
    assert media.port == 30000
    assert media.protocol == "RTP/AVP"
    assert media.payload_types == ["0", "8", "101"]
    assert media.direction == "sendrecv"
    assert media.label == "1"
    assert media.rtpmap["0"] == "PCMU/8000"
    assert media.fmtp["101"] == "0-15"


def test_explicit_rtcp_port(sdp_variant):
    sdp = parse_sdp(sdp_variant("explicit_rtcp"))
    media = sdp.media[0]
    assert media.rtcp_port == 40002
    assert infer_rtcp_port(media) == 40002
    assert media.direction == "sendonly"


def test_rtcp_mux(sdp_variant):
    sdp = parse_sdp(sdp_variant("rtcp_mux"))
    media = sdp.media[0]
    assert media.rtcp_mux is True
    assert infer_rtcp_port(media) == media.port == 50000
    assert media.mid == "audio1"
    assert media.direction == "recvonly"


def test_default_rtcp_is_port_plus_one(sdp_variant):
    sdp = parse_sdp(sdp_variant("basic_audio"))
    media = sdp.media[0]
    assert media.rtcp_port is None
    assert infer_rtcp_port(media) == 30001


def test_inactive_direction(sdp_variant):
    sdp = parse_sdp(sdp_variant("inactive_hold"))
    assert sdp.media[0].direction == "inactive"


def test_multiple_media_sections(sdp_variant):
    sdp = parse_sdp(sdp_variant("multi_media"))
    assert len(sdp.media) == 2
    assert sdp.media[0].media_type == "audio"
    assert sdp.media[1].media_type == "video"
    assert sdp.media[1].rtpmap["96"] == "H264/90000"


def test_media_level_connection_overrides(sdp_variant):
    sdp = parse_sdp(sdp_variant("media_level_connection"))
    # No session-level c= in this variant.
    assert sdp.connection_address is None
    assert sdp.media[0].connection_address == "198.51.100.50"


def test_malformed_m_line_is_skipped_gracefully():
    # A malformed m= line should be skipped, leaving zero media, not crash.
    sdp = parse_sdp("v=0\nm=audio\na=rtpmap:0 PCMU/8000\n")
    assert sdp.media == []


def test_tolerates_garbage_lines():
    sdp = parse_sdp("v=0\nthis is not sdp\nm=audio 100 RTP/AVP 0\n")
    assert len(sdp.media) == 1
    assert sdp.media[0].port == 100


def test_none_raises():
    with pytest.raises(SdpParseError):
        parse_sdp(None)
