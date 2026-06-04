"""Tests for RTP/RTCP gap detection."""

from __future__ import annotations

from callscope.models import (
    Endpoint,
    ObservedRtpStream,
    RecordingAnalysis,
    SessionTimeline,
    SipRecMetadata,
    SipRecStream,
)
from callscope.siprec import gap_detector
from callscope.siprec.gap_detector import detect_gaps


def _stream(**kw) -> ObservedRtpStream:
    base = dict(
        ssrc=0x1111,
        src=Endpoint("10.0.0.1", 30000),
        dst=Endpoint("10.0.0.2", 40000),
        payload_type=0,
        packet_count=100,
        first_timestamp_relative=0.5,
        last_timestamp_relative=10.0,
        sequence_gaps=0,
        largest_gap=0,
        rtcp_observed=True,
    )
    base.update(kw)
    return ObservedRtpStream(**base)


def _empty_timeline() -> SessionTimeline:
    return SessionTimeline()


def test_no_findings_for_clean_stream():
    analysis = RecordingAnalysis(call_id="x", rtp_streams=[_stream()])
    findings = detect_gaps(analysis, _empty_timeline())
    assert findings == []


def test_single_sequence_gap():
    analysis = RecordingAnalysis(call_id="x", rtp_streams=[_stream(sequence_gaps=1, largest_gap=3)])
    findings = detect_gaps(analysis, _empty_timeline())
    codes = [f.code for f in findings]
    assert gap_detector.CODE_SEQ_GAP in codes


def test_multiple_gaps_reported():
    analysis = RecordingAnalysis(call_id="x", rtp_streams=[_stream(sequence_gaps=5, largest_gap=20)])
    findings = detect_gaps(analysis, _empty_timeline())
    seq = [f for f in findings if f.code == gap_detector.CODE_SEQ_GAP]
    assert seq and "5" in seq[0].detail


def test_missing_rtcp():
    analysis = RecordingAnalysis(call_id="x", rtp_streams=[_stream(rtcp_observed=False)])
    findings = detect_gaps(analysis, _empty_timeline())
    assert gap_detector.CODE_MISSING_RTCP in [f.code for f in findings]


def test_no_rtp_for_expected_stream():
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams.append(SipRecStream(stream_id="s1", label="96"))
    analysis = RecordingAnalysis(call_id="x", metadata=[md], rtp_streams=[])
    findings = detect_gaps(analysis, _empty_timeline())
    assert gap_detector.CODE_NONE_OBSERVED in [f.code for f in findings]


def test_gaps_ignored_during_hold_window():
    # Stream activity 6.0..8.0 sits inside hold window 5.0..9.0 -> gaps ignored.
    timeline = SessionTimeline(hold_windows=[(5.0, 9.0)])
    stream = _stream(
        sequence_gaps=4,
        first_timestamp_relative=6.0,
        last_timestamp_relative=8.0,
        rtcp_observed=False,
    )
    analysis = RecordingAnalysis(call_id="x", rtp_streams=[stream])
    findings = detect_gaps(analysis, timeline)
    assert gap_detector.CODE_SEQ_GAP not in [f.code for f in findings]
    assert gap_detector.CODE_MISSING_RTCP not in [f.code for f in findings]
