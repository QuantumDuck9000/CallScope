"""Tests for the v2 reporting/export and cross-call modules."""

from __future__ import annotations

from callscope.core.aggregate import aggregate_analyses
from callscope.core.baseline import build_baseline_profile, diff_against_baseline
from callscope.core.correlation_export import build_correlation_key
from callscope.models import (
    Endpoint,
    ObservedRtpStream,
    Owner,
    RecordingAnalysis,
    RecordingFinding,
    Severity,
    SipRecMetadata,
    SipRecParticipant,
    SipRecStream,
)
from callscope.reporting.markdown_report import render_markdown_escalation
from callscope.reporting.narrative import build_narrative
from callscope.siprec.session_timeline import build_session_timeline
from tests.conftest import make_sip_message


def _two_declared_one_observed() -> RecordingAnalysis:
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams = [SipRecStream(stream_id="s1"), SipRecStream(stream_id="s2")]
    md.participants = [SipRecParticipant(participant_id="p1", aor="sip:agent@cc")]
    src = Endpoint("10.0.0.1", 5060)
    srs = Endpoint("10.0.0.2", 5060)
    msgs = [
        make_sip_message(method="INVITE", frame_number=1, time_relative=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        make_sip_message(status_code=200, reason="OK", frame_number=2, time_relative=0.3, src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        make_sip_message(method="BYE", frame_number=9, time_relative=30.0, src_ip="10.0.0.1", dst_ip="10.0.0.2"),
    ]
    analysis = RecordingAnalysis(
        call_id="abc@sbc",
        sip_messages=msgs,
        metadata=[md],
        src_endpoint=src,
        srs_endpoint=srs,
        rtp_streams=[ObservedRtpStream(ssrc=0x1234, src=src, dst=srs, payload_type=0, packet_count=100)],
        overall_health=Severity.ERROR,
    )
    analysis.findings = [
        RecordingFinding(Severity.ERROR, "CONSIST_METADATA_RTP", "Said 2 sent 1", "detail", owner=Owner.SBC, evidence_frames=[1])
    ]
    return analysis


def test_narrative_mentions_declared_vs_observed():
    analysis = _two_declared_one_observed()
    timeline = build_session_timeline(analysis.sip_messages)
    steps = build_narrative(analysis, timeline)
    assert steps
    text = " ".join(s.text for s in steps)
    assert "INVITE" in text
    assert "1 of 2" in text  # observed of declared


def test_markdown_escalation_groups_and_checksums():
    analysis = _two_declared_one_observed()
    timeline = build_session_timeline(analysis.sip_messages)
    analysis.narrative = build_narrative(analysis, timeline)
    md = render_markdown_escalation(analysis)
    assert "# SIPREC recording analysis" in md
    assert "## What happened" in md
    assert "SBC (provable from this capture)" in md
    assert "CONSIST" not in md or "Said 2 sent 1" in md  # finding title rendered


def test_correlation_key_uses_metadata_aor():
    analysis = _two_declared_one_observed()
    key = build_correlation_key(analysis)
    assert key.call_id == "abc@sbc"
    assert "sip:agent@cc" in key.participant_aors
    assert key.start_utc is not None
    assert any("0x" in s for s in key.ssrcs)


def test_aggregate_failure_rate_and_one_way():
    a = _two_declared_one_observed()  # declared 2, observed 1 -> one-way
    b = _two_declared_one_observed()
    b.overall_health = Severity.PASS
    summary = aggregate_analyses([a, b])
    assert summary["calls"] == 2
    assert summary["failed"] == 1
    assert summary["failure_rate"] == 0.5
    assert summary["one_way_calls"] == 2
    assert "CONSIST_METADATA_RTP" in summary["findings_by_code"]


def test_baseline_diff_detects_stream_drop():
    good = _two_declared_one_observed()
    good.rtp_streams.append(
        ObservedRtpStream(ssrc=0x5678, src=good.src_endpoint, dst=good.srs_endpoint, payload_type=0)
    )  # 2 observed = healthy
    profile = build_baseline_profile(good)

    bad = _two_declared_one_observed()  # only 1 observed
    diffs = diff_against_baseline(bad, profile)
    assert any("observed streams" in f.title for f in diffs)
    assert all(f.owner == Owner.SBC for f in diffs)
