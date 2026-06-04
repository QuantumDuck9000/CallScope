"""Tests for the v2 signaling/media detectors."""

from __future__ import annotations

from callscope.models import Severity
from callscope.siprec import burst_detector, rtcp_stats, sip_timing, ssrc_tracker
from callscope.siprec.session_timeline import build_session_timeline
from tests.conftest import make_sip_message

PCMU = "v=0\nm=audio 30000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\na=sendonly\n"
PCMA = "v=0\nm=audio 30000 RTP/AVP 8\na=rtpmap:8 PCMA/8000\na=sendonly\n"


def test_reinvite_burst_with_codec_renegotiation():
    msgs = [
        make_sip_message(method="INVITE", time_relative=0.0, sdp_text=PCMU),
        make_sip_message(method=None, status_code=200, time_relative=0.2),
        make_sip_message(method="INVITE", time_relative=8.0, sdp_text=PCMU),
        make_sip_message(method="INVITE", time_relative=8.7, sdp_text=PCMA),
        make_sip_message(method="INVITE", time_relative=9.4, sdp_text=PCMU),
    ]
    bursts, findings = burst_detector.detect_reinvite_bursts(msgs)
    assert len(bursts) == 1
    assert bursts[0].count == 3
    assert bursts[0].codec_renegotiation is True
    assert findings[0].code == burst_detector.CODE_BURST
    assert findings[0].severity == Severity.WARN


def test_no_burst_when_sparse():
    msgs = [
        make_sip_message(method="INVITE", time_relative=0.0),
        make_sip_message(method="INVITE", time_relative=60.0),
        make_sip_message(method="INVITE", time_relative=120.0),
    ]
    bursts, findings = burst_detector.detect_reinvite_bursts(msgs)
    assert bursts == []
    assert findings == []


def test_ssrc_change_detection():
    obs = [
        ("flowA", 0.1, 0x111),
        ("flowA", 1.0, 0x111),
        ("flowA", 5.0, 0x222),
        ("flowB", 0.5, 0x999),
    ]
    changes = ssrc_tracker.track_ssrc_changes(obs)
    assert len(changes) == 1
    assert changes[0].from_ssrc == 0x111
    assert changes[0].to_ssrc == 0x222
    assert changes[0].flow_key == "flowA"


def test_ssrc_observations_from_rows_skips_rtcp():
    rows = [
        {"ip.src": "1.1.1.1", "udp.srcport": "4", "ip.dst": "2.2.2.2", "udp.dstport": "6", "rtp.ssrc": "0x10", "frame.time_relative": "0.1"},
        {"rtcp.pt": "200", "rtp.ssrc": "0x10"},
    ]
    obs = ssrc_tracker.observations_from_rtp_rows(rows)
    assert len(obs) == 1
    assert obs[0][2] == 0x10


def test_rtcp_stats_loss_jitter_gap_and_bye():
    rows = [
        {"rtcp.pt": "201", "rtcp.ssrc.identifier": "100", "rtcp.ssrc.fraction": "26", "rtcp.ssrc.cumulative": "5", "rtcp.ssrc.jitter": "10", "frame.time_relative": "1.0"},
        {"rtcp.pt": "201", "rtcp.ssrc.identifier": "100", "rtcp.ssrc.fraction": "13", "rtcp.ssrc.cumulative": "9", "rtcp.ssrc.jitter": "30", "frame.time_relative": "20.0"},
        {"rtcp.pt": "203", "rtcp.ssrc.identifier": "100", "frame.time_relative": "21.0"},
    ]
    stats = rtcp_stats.compute_rtcp_stats(rows)
    assert len(stats) == 1
    s = stats[0]
    assert s.rtcp_bye_seen is True
    assert s.fraction_lost_max is not None and s.fraction_lost_max > 0.1
    assert s.max_report_gap_s is not None and s.max_report_gap_s >= 18.0
    findings = rtcp_stats.build_rtcp_findings(stats)
    codes = {f.code for f in findings}
    assert rtcp_stats.CODE_HIGH_LOSS in codes
    assert rtcp_stats.CODE_TIMEOUT in codes
    assert rtcp_stats.CODE_BYE in codes


def test_sip_timing_retransmission_failure_missing_ack():
    msgs = [
        make_sip_message(method="INVITE", time_relative=0.0, via_branch="zABC"),
        make_sip_message(method="INVITE", time_relative=0.5, via_branch="zABC"),
        make_sip_message(method=None, status_code=200, reason="OK", time_relative=1.0),
        make_sip_message(method=None, status_code=503, reason="Service Unavailable", time_relative=1.2),
    ]
    timeline = build_session_timeline(msgs)
    findings = sip_timing.analyze_sip_timing(msgs, timeline)
    codes = {f.code for f in findings}
    assert sip_timing.CODE_RETRANSMISSION in codes
    assert sip_timing.CODE_MISSING_ACK in codes
    assert sip_timing.CODE_FAILURE in codes
    # The duplicate INVITE is marked.
    assert any(m.is_retransmission for m in msgs)
