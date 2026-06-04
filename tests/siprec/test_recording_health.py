"""Tests for the recording-health summary layer."""

from __future__ import annotations

from callscope.models import (
    Endpoint,
    ObservedRtpStream,
    RecordingAnalysis,
    Severity,
    SipRecMetadata,
    SipRecStream,
)
from callscope.siprec import session_timeline
from callscope.siprec.recording_health import evaluate_recording_health


def _stream(rtcp=True, gaps=0) -> ObservedRtpStream:
    return ObservedRtpStream(
        ssrc=1, src=Endpoint("1.1.1.1", 1), dst=Endpoint("2.2.2.2", 2),
        payload_type=0, packet_count=10, rtcp_observed=rtcp, sequence_gaps=gaps,
    )


def test_healthy_session(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"),
                      content_type="application/rs-metadata+xml")
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams.append(SipRecStream(stream_id="s1", label="1"))
    analysis = RecordingAnalysis(
        call_id="x", sip_messages=[msg], metadata=[md], rtp_streams=[_stream()]
    )
    timeline = session_timeline.build_session_timeline([msg])
    evaluate_recording_health(analysis, timeline)
    assert analysis.status_sip == Severity.PASS
    assert analysis.status_sdp == Severity.PASS
    assert analysis.status_rtp == Severity.PASS
    assert analysis.status_rtcp == Severity.PASS
    assert analysis.status_streams == Severity.PASS
    assert analysis.overall_health in (Severity.PASS, Severity.INFO)


def test_no_rtp_is_unhealthy(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    analysis = RecordingAnalysis(call_id="x", sip_messages=[msg], rtp_streams=[])
    timeline = session_timeline.build_session_timeline([msg])
    evaluate_recording_health(analysis, timeline)
    assert analysis.status_rtp == Severity.ERROR
    assert analysis.overall_health == Severity.ERROR


def test_missing_rtcp_warns(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    analysis = RecordingAnalysis(
        call_id="x", sip_messages=[msg], rtp_streams=[_stream(rtcp=False)]
    )
    timeline = session_timeline.build_session_timeline([msg])
    evaluate_recording_health(analysis, timeline)
    assert analysis.status_rtcp == Severity.WARN


def test_gaps_set_status(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    analysis = RecordingAnalysis(
        call_id="x", sip_messages=[msg], rtp_streams=[_stream(gaps=3)]
    )
    timeline = session_timeline.build_session_timeline([msg])
    evaluate_recording_health(analysis, timeline)
    assert analysis.status_gaps == Severity.WARN
