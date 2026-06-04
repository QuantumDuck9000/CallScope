"""Tests for the shared data model."""

from __future__ import annotations

from callscope.models import (
    Direction,
    Endpoint,
    ObservedRtpStream,
    RecordingAnalysis,
    RecordingFinding,
    Severity,
    SipRecMetadata,
    SipRecStream,
)


def test_severity_values_stable():
    assert Severity.INFO.value == "INFO"
    assert Severity.PASS.value == "PASS"
    assert Severity.WARN.value == "WARN"
    assert Severity.ERROR.value == "ERROR"
    assert Severity.CRITICAL.value == "CRITICAL"
    # str-enum: comparing to the string works.
    assert Severity.WARN == "WARN"


def test_direction_values_stable():
    assert Direction.SRC_TO_SRS.value == "SRC_TO_SRS"
    assert Direction.SRS_TO_SRC.value == "SRS_TO_SRC"
    assert Direction.UNKNOWN.value == "UNKNOWN"


def test_recording_analysis_warning_and_error_helpers():
    analysis = RecordingAnalysis(call_id="x")
    analysis.findings = [
        RecordingFinding(Severity.WARN, "W1", "warn", "d"),
        RecordingFinding(Severity.ERROR, "E1", "err", "d"),
        RecordingFinding(Severity.CRITICAL, "C1", "crit", "d"),
        RecordingFinding(Severity.INFO, "I1", "info", "d"),
    ]
    assert len(analysis.warnings()) == 1
    assert len(analysis.errors()) == 2  # ERROR + CRITICAL


def test_observed_rtp_stream_defaults():
    s = ObservedRtpStream(
        ssrc=0x1234,
        src=Endpoint("1.1.1.1", 1000),
        dst=Endpoint("2.2.2.2", 2000),
        payload_type=0,
    )
    assert s.packet_count == 0
    assert s.rtcp_observed is False
    assert s.sequence_gaps == 0


def test_metadata_stream_construction():
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams.append(SipRecStream(stream_id="abc", label="96"))
    assert md.streams[0].label == "96"
    assert md.version == "1"
