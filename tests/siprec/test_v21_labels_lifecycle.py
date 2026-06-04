"""Tests for the v2.1 SIPREC label/lifecycle/coverage features."""

from __future__ import annotations

from callscope.core.sip_parser import iter_body_parts, maybe_hex_decode
from callscope.models import (
    Endpoint,
    HoldRetrieveEvent,
    ObservedRtpStream,
    Owner,
    RecordingAnalysis,
    Severity,
    SipRecMetadata,
    SipRecParticipant,
    SipRecStream,
)
from callscope.siprec import hold_retrieve, labels, ssrc_lifecycle
from callscope.siprec.siprec_parser import extract_siprec_metadata_from_message
from tests.conftest import make_sip_message

AGENT_PORT = 41134
CUST_PORT = 15298

_XML = (
    '<?xml version="1.0"?>'
    '<recording xmlns="urn:ietf:params:xml:ns:recording:1">'
    '<participant participant_id="P1"><nameID aor="sip:+17867525459@fl"><name>FLORIDA</name></nameID></participant>'
    '<participant participant_id="P2"><nameID aor="sip:8777357837@ag"><name>AGENT</name></nameID></participant>'
    '<stream stream_id="S1" session_id="x"><label>639650446</label></stream>'
    '<stream stream_id="S2" session_id="x"><label>639650447</label></stream>'
    '<participantstreamassoc participant_id="P1"><send>S1</send></participantstreamassoc>'
    '<participantstreamassoc participant_id="P2"><send>S2</send></participantstreamassoc>'
    "</recording>"
)


def _sdp(direction: str) -> str:
    return (
        "v=0\r\no=- 1 1 IN IP4 10.25.112.204\r\n"
        f"m=audio {CUST_PORT} RTP/AVP 0\r\na=label:639650446\r\na={direction}\r\n"
        f"m=audio {AGENT_PORT} RTP/AVP 0\r\na=label:639650447\r\na={direction}\r\n"
    )


def test_hex_encoded_multipart_metadata_decodes():
    boundary = "unique-boundary-1"
    body = (
        f"--{boundary}\r\nContent-Type: application/sdp\r\n\r\n{_sdp('sendonly')}\r\n"
        f"--{boundary}\r\nContent-Type: application/rs-metadata+xml\r\n\r\n{_XML}\r\n--{boundary}--\r\n"
    )
    msg = make_sip_message(method="INVITE", content_type=f'multipart/mixed;boundary="{boundary}"')
    msg.body = body.encode().hex()  # tshark-style hex blob

    assert maybe_hex_decode(msg.body).startswith("--unique-boundary-1")
    parts = iter_body_parts(msg)
    assert any("rs-metadata" in (p.content_type or "") for p in parts)
    md = extract_siprec_metadata_from_message(msg)
    assert md is not None
    assert {s.label for s in md.streams} == {"639650446", "639650447"}


def test_salvage_metadata_without_boundary():
    msg = make_sip_message(method="INVITE", content_type="application/rs-metadata+xml")
    msg.body = _XML.encode().hex()
    md = extract_siprec_metadata_from_message(msg)
    assert md is not None and len(md.streams) == 2


def _analysis_with_binding() -> RecordingAnalysis:
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.participants = [
        SipRecParticipant("P1", name="FLORIDA", aor="sip:+17867525459@fl"),
        SipRecParticipant("P2", name="AGENT", aor="sip:8777357837@ag"),
    ]
    md.streams = [
        SipRecStream("S1", label="639650446", participant_ids=["P1"]),
        SipRecStream("S2", label="639650447", participant_ids=["P2"]),
    ]
    src = Endpoint("10.25.112.204", 5060)
    srs = Endpoint("10.139.35.38", 5060)
    msgs = [
        make_sip_message(method="INVITE", frame_number=1, time_relative=0.0, sdp_text=_sdp("sendonly"), cseq="700 INVITE"),
        make_sip_message(status_code=200, frame_number=2, time_relative=0.3),
        make_sip_message(method="INVITE", frame_number=50, time_relative=243.9, sdp_text=_sdp("inactive"), cseq="727 INVITE"),
        make_sip_message(method="INVITE", frame_number=51, time_relative=244.2, sdp_text=_sdp("sendonly"), cseq="728 INVITE"),
    ]
    streams = [
        ObservedRtpStream(ssrc=0x6F231F4B, src=Endpoint("10.25.112.204", AGENT_PORT), dst=Endpoint("10.139.35.38", 37874), payload_type=0, packet_count=7314, first_timestamp_relative=128.0, last_timestamp_relative=244.0),
        ObservedRtpStream(ssrc=0x8D476707, src=Endpoint("10.25.112.204", AGENT_PORT), dst=Endpoint("10.139.35.38", 37874), payload_type=0, packet_count=5822, first_timestamp_relative=244.3, last_timestamp_relative=364.0),
        ObservedRtpStream(ssrc=0x00020531, src=Endpoint("10.25.112.204", CUST_PORT), dst=Endpoint("10.139.35.38", 33704), payload_type=0, packet_count=12000, first_timestamp_relative=128.0, last_timestamp_relative=400.0),
    ]
    return RecordingAnalysis(call_id="c", sip_messages=msgs, metadata=[md], rtp_streams=streams, src_endpoint=src, srs_endpoint=srs)


def test_label_binding_sets_participant():
    a = _analysis_with_binding()
    labels.bind_labels(a)
    agent = next(s for s in a.rtp_streams if s.src.port == AGENT_PORT and s.ssrc == 0x6F231F4B)
    assert agent.matched_sdp_label == "639650447"
    assert agent.matched_siprec_stream_id == "S2"
    assert agent.participant_name == "AGENT"
    assert agent.participant_aor == "sip:8777357837@ag"


def test_distinct_media_count_collapses_ssrc_churn():
    a = _analysis_with_binding()
    labels.bind_labels(a)
    # 3 raw streams but only 2 labels -> 2 distinct legs.
    assert labels.distinct_media_count(a) == 2


def test_hold_retrieve_detection():
    a = _analysis_with_binding()
    events = hold_retrieve.detect_hold_retrieve(a)
    assert [e.kind for e in events] == ["HOLD", "RETRIEVE"]
    assert events[1].cseq == "728 INVITE"


def test_coverage_gap_on_retrieve_is_critical():
    a = _analysis_with_binding()
    labels.bind_labels(a)
    a.hold_retrieve_events = hold_retrieve.detect_hold_retrieve(a)
    findings = ssrc_lifecycle.analyze_ssrc_lifecycle(a)
    # Agent changed SSRC at t=244.3 (within retrieve window) -> coverage gap.
    gap = next((g for g in a.coverage_gaps if g.participant and "AGENT" in g.participant), None)
    assert gap is not None
    assert gap.old_ssrc == 0x6F231F4B and gap.new_ssrc == 0x8D476707
    assert abs(gap.duration_s - 119.7) < 1.0
    crit = [f for f in findings if f.code == "SIPREC-001" and f.severity == Severity.CRITICAL]
    assert crit and crit[0].owner == Owner.SBC


def test_lifecycle_stability_and_segments():
    a = _analysis_with_binding()
    labels.bind_labels(a)
    lcs = ssrc_lifecycle.build_label_lifecycles(a)
    agent = next(lc for lc in lcs if lc.participant and "AGENT" in lc.participant)
    assert agent.ssrc_change_count == 1
    assert [s.ssrc for s in agent.segments] == [0x6F231F4B, 0x8D476707]
