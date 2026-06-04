"""Tests for RTP tracker filter building and stream aggregation."""

from __future__ import annotations

from pathlib import Path

from callscope.siprec import rtp_tracker
from callscope.siprec.rtp_tracker import analyze_rtp_streams, build_media_display_filter


def test_build_media_display_filter_from_sdp(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    flt = build_media_display_filter([msg], [])
    assert "udp.port == 30000" in flt  # RTP port
    assert "udp.port == 30001" in flt  # inferred RTCP port
    assert "(rtp or rtcp)" in flt


def test_build_media_display_filter_no_sdp(sip_factory):
    msg = sip_factory(method="INVITE")
    assert build_media_display_filter([msg], []) == "rtp or rtcp"


def test_analyze_rtp_streams_aggregates(monkeypatch, sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))

    rtp_rows = [
        {"frame.number": "1", "frame.time_relative": "0.10", "ip.src": "10.0.0.1",
         "ip.dst": "10.0.0.2", "udp.srcport": "30000", "udp.dstport": "40000",
         "rtp.ssrc": "0x1111", "rtp.seq": "100", "rtp.p_type": "0", "rtcp.pt": ""},
        {"frame.number": "2", "frame.time_relative": "0.12", "ip.src": "10.0.0.1",
         "ip.dst": "10.0.0.2", "udp.srcport": "30000", "udp.dstport": "40000",
         "rtp.ssrc": "0x1111", "rtp.seq": "102", "rtp.p_type": "0", "rtcp.pt": ""},
        # RTCP on RTP port + 1
        {"frame.number": "3", "frame.time_relative": "0.50", "ip.src": "10.0.0.1",
         "ip.dst": "10.0.0.2", "udp.srcport": "30001", "udp.dstport": "40001",
         "rtp.ssrc": "", "rtp.seq": "", "rtp.p_type": "", "rtcp.pt": "200"},
    ]
    monkeypatch.setattr(rtp_tracker.tshark, "run_tshark_fields", lambda *a, **k: rtp_rows)

    streams = analyze_rtp_streams([Path("x.pcap")], [msg], [])
    assert len(streams) == 1
    s = streams[0]
    assert s.ssrc == 0x1111
    assert s.packet_count == 2
    assert s.sequence_gaps == 1  # 100 -> 102 is a gap of one missing seq
    assert s.largest_gap == 1
    assert s.rtcp_observed is True


def test_sequence_gap_wraparound():
    gaps, largest = rtp_tracker._sequence_gaps([65534, 65535, 0, 1])
    assert gaps == 0
    assert largest == 0
