"""Tests for declared-vs-observed mixer consistency checks."""

from __future__ import annotations

from callscope.models import (
    Endpoint,
    ObservedRtpStream,
    RecordingAnalysis,
    SipRecMetadata,
    SipRecStream,
)
from callscope.siprec import mixer_analyzer
from callscope.siprec.mixer_analyzer import analyze_mixer_consistency


def _metadata(n: int) -> SipRecMetadata:
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    for i in range(n):
        md.streams.append(SipRecStream(stream_id=f"s{i}", label=str(96 + i)))
    return md


def _stream(port: int) -> ObservedRtpStream:
    return ObservedRtpStream(
        ssrc=port, src=Endpoint("1.1.1.1", port), dst=Endpoint("2.2.2.2", port),
        payload_type=0, packet_count=10,
    )


def test_two_declared_two_observed_ok():
    analysis = RecordingAnalysis(
        call_id="x", metadata=[_metadata(2)], rtp_streams=[_stream(1), _stream(2)]
    )
    findings = analyze_mixer_consistency(analysis)
    assert mixer_analyzer.CODE_STREAMS_OK in [f.code for f in findings]


def test_two_declared_one_observed_warns():
    analysis = RecordingAnalysis(
        call_id="x", metadata=[_metadata(2)], rtp_streams=[_stream(1)]
    )
    findings = analyze_mixer_consistency(analysis)
    assert mixer_analyzer.CODE_FEWER_OBSERVED in [f.code for f in findings]


def test_two_declared_zero_observed_error():
    analysis = RecordingAnalysis(call_id="x", metadata=[_metadata(2)], rtp_streams=[])
    findings = analyze_mixer_consistency(analysis)
    assert mixer_analyzer.CODE_NONE_OBSERVED in [f.code for f in findings]


def test_one_declared_two_observed_warns():
    analysis = RecordingAnalysis(
        call_id="x", metadata=[_metadata(1)], rtp_streams=[_stream(1), _stream(2)]
    )
    findings = analyze_mixer_consistency(analysis)
    assert mixer_analyzer.CODE_MORE_OBSERVED in [f.code for f in findings]


def test_sdp_mline_count_mismatch(sip_factory, sdp_variant):
    # SDP has 1 audio m-line, metadata declares 2 streams -> mismatch.
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    analysis = RecordingAnalysis(
        call_id="x", metadata=[_metadata(2)], rtp_streams=[_stream(1), _stream(2)],
        sip_messages=[msg],
    )
    findings = analyze_mixer_consistency(analysis)
    assert mixer_analyzer.CODE_SDP_COUNT_MISMATCH in [f.code for f in findings]
