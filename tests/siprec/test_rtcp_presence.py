"""Tests for RTCP packet-type summary and the present-but-unscorable case."""

from __future__ import annotations

from callscope.models import Endpoint, ObservedRtpStream, RecordingAnalysis, Severity
from callscope.siprec import rtcp_stats as R
from callscope.siprec import recording_health
from callscope.siprec.session_timeline import build_session_timeline


def test_summary_counts_sender_reports_without_report_blocks():
    rows = [
        {"rtcp.pt": "200", "rtcp.ssrc.identifier": "0x111", "frame.time_relative": "1.0"},
        {"rtcp.pt": "200,202", "rtcp.ssrc.identifier": "0x111", "frame.time_relative": "6.0"},
    ]
    s = R.summarize_rtcp_packets(rows)
    assert s["total"] == 2
    assert s["by_type"]["SR"] == 2
    assert s["by_type"]["SDES"] == 1
    assert s["report_blocks"] == 0


def test_summary_detects_rtcp_mux_read_as_rtp():
    rows = [{"rtp.p_type": "72", "frame.time_relative": "1.0"}, {"rtp.p_type": "73", "frame.time_relative": "2.0"}]
    s = R.summarize_rtcp_packets(rows)
    assert s["muxed_as_rtp"] == 2
    assert s["by_type"]["SR"] == 1  # 72 -> 200
    assert s["by_type"]["RR"] == 1  # 73 -> 201


def test_presence_finding_when_no_report_blocks():
    s = R.summarize_rtcp_packets([{"rtcp.pt": "200", "frame.time_relative": "1.0"}])
    findings = R.build_rtcp_presence_findings(s)
    assert findings and findings[0].code == "RTCP_NO_REPORTS"


def test_compound_sr_sdes_with_report_block_parses():
    # tshark emits compound SR+SDES as pt="200,202"; report block present.
    rows = [
        {"rtcp.pt": "200,202", "rtcp.ssrc.identifier": "0x1a2b", "rtcp.ssrc.fraction": "0", "rtcp.ssrc.jitter": "3", "frame.time_relative": "1.0"},
    ]
    s = R.summarize_rtcp_packets(rows)
    assert s["report_blocks"] == 1
    assert R.build_rtcp_presence_findings(s) == []  # has a report block -> scorable
    stats = R.compute_rtcp_stats(rows)
    assert len(stats) == 1 and stats[0].ssrc == 0x1A2B


def test_compound_packet_with_multiple_report_blocks():
    rows = [
        {"rtcp.pt": "200,202", "rtcp.ssrc.identifier": "0xAAAA,0xBBBB", "rtcp.ssrc.fraction": "0,5", "rtcp.ssrc.jitter": "2,40", "frame.time_relative": "1.0"},
    ]
    blocks = list(R.iter_report_blocks(rows[0]))
    assert len(blocks) == 2
    stats = {st.ssrc: st for st in R.compute_rtcp_stats(rows)}
    assert 0xAAAA in stats and 0xBBBB in stats
    assert abs(stats[0xBBBB].fraction_lost_max - 5 / 256.0) < 1e-9


def _analysis_with_streams():
    return RecordingAnalysis(
        call_id="c",
        rtp_streams=[
            ObservedRtpStream(ssrc=0x111, src=Endpoint("a", 1), dst=Endpoint("b", 2), payload_type=0, packet_count=5000, rtcp_observed=True)
        ],
    )


def test_status_rtcp_warns_when_present_but_unscorable():
    a = _analysis_with_streams()
    a.rtcp_packet_summary = R.summarize_rtcp_packets([{"rtcp.pt": "200", "frame.time_relative": "1.0"}])
    recording_health.evaluate_recording_health(a, build_session_timeline([]))
    # RTCP present but no reception reports -> not PASS.
    assert a.status_rtcp == Severity.WARN


def test_status_rtcp_pass_only_with_report_blocks():
    a = _analysis_with_streams()
    a.rtcp_packet_summary = R.summarize_rtcp_packets(
        [{"rtcp.pt": "201", "rtcp.ssrc.fraction": "10", "rtcp.ssrc.jitter": "40", "frame.time_relative": "1.0"}]
    )
    recording_health.evaluate_recording_health(a, build_session_timeline([]))
    assert a.status_rtcp == Severity.PASS
