"""Exercise analyze_rtp_streams end-to-end with mocked tshark field rows.

This guards against regressions in the row->stream reduction, the sequence-gap
counter, and the RFC 5761 RTCP-mux guard (PT 64-95 on the RTP port).
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from callscope.siprec import rtp_tracker


def _row(t, sport, dport, ssrc, seq, pt):
    return {
        "frame.time_relative": t,
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
        "udp.srcport": sport,
        "udp.dstport": dport,
        "rtp.ssrc": ssrc,
        "rtp.seq": seq,
        "rtp.p_type": pt,
        "rtcp.pt": "",
    }


def test_analyze_rtp_streams_gaps_and_rtcp_mux_guard():
    rows = [
        _row("1.0", "41134", "37874", "0x6f231f4b", "5", "0"),
        _row("1.02", "41134", "37874", "0x6f231f4b", "8", "0"),  # seq gap 5->8
        _row("5.0", "15298", "33704", "0x83b569da", "1", "72"),  # PT 72 = RTCP-mux
    ]
    with mock.patch.object(rtp_tracker.tshark, "run_tshark_fields", return_value=rows):
        streams, mux = rtp_tracker.analyze_rtp_streams_with_stats([Path("x.pcap")], [], [])

    assert len(streams) == 1  # the PT-72 packet is excluded from media streams
    s = streams[0]
    assert s.ssrc == 0x6F231F4B
    assert s.sequence_gaps == 1
    assert s.largest_gap == 2
    assert mux == 1  # the PT-72 packet is counted as RTCP-on-RTP-port


def test_analyze_rtp_streams_plain_list_wrapper_matches():
    rows = [_row("1.0", "5000", "6000", "0x11", "1", "0")]
    with mock.patch.object(rtp_tracker.tshark, "run_tshark_fields", return_value=rows):
        only_streams = rtp_tracker.analyze_rtp_streams([Path("x.pcap")], [], [])
    assert len(only_streams) == 1
    assert only_streams[0].ssrc == 0x11
