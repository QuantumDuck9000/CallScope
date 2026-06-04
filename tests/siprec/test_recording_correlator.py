"""Tests for SIPREC/SDP/RTP correlation."""

from __future__ import annotations

from callscope.models import Endpoint, ObservedRtpStream, SipRecMetadata, SipRecStream
from callscope.siprec.recording_correlator import correlate_recording


def _rtp(dst_port: int, ssrc: int) -> ObservedRtpStream:
    return ObservedRtpStream(
        ssrc=ssrc, src=Endpoint("10.0.0.1", 30000), dst=Endpoint("10.0.0.2", dst_port),
        payload_type=0, packet_count=50,
    )


def test_identifies_src_and_srs(sip_factory):
    invite = sip_factory(method="INVITE", src_ip="10.0.0.1", dst_ip="10.0.0.2")
    analysis = correlate_recording([invite], [], [])
    assert analysis.src_endpoint.ip == "10.0.0.1"
    assert analysis.srs_endpoint.ip == "10.0.0.2"
    assert analysis.call_id == invite.call_id


def test_matches_rtp_to_label_and_stream(sip_factory):
    # SDP media on port 40000 with label "96"; metadata stream label "96".
    sdp = (
        "v=0\no=- 1 1 IN IP4 10.0.0.2\ns=-\nc=IN IP4 10.0.0.2\nt=0 0\n"
        "m=audio 40000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\na=label:96\na=sendrecv\n"
    )
    invite = sip_factory(method="INVITE", sdp_text=sdp)
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams.append(SipRecStream(stream_id="STREAM-A", label="96"))

    analysis = correlate_recording([invite], [md], [_rtp(40000, 0x1111)])
    s = analysis.rtp_streams[0]
    assert s.matched_sdp_label == "96"
    assert s.matched_siprec_stream_id == "STREAM-A"


def test_positional_fallback_when_counts_align(sip_factory):
    invite = sip_factory(method="INVITE")
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams.append(SipRecStream(stream_id="ONLY", label=None))
    analysis = correlate_recording([invite], [md], [_rtp(50000, 0x2222)])
    assert analysis.rtp_streams[0].matched_siprec_stream_id == "ONLY"
