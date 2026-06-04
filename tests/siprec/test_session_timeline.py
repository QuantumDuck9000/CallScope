"""Tests for the SIPREC session timeline state machine."""

from __future__ import annotations

from callscope.siprec import session_timeline as st
from callscope.siprec.session_timeline import build_session_timeline


def _event_types(timeline):
    return [e.event_type for e in timeline.events]


def test_basic_invite_200_ack_bye(sip_factory):
    msgs = [
        sip_factory(method="INVITE", time_relative=0.0, frame_number=1),
        sip_factory(status_code=200, reason="OK", time_relative=0.2, frame_number=2,
                    src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        sip_factory(method="ACK", time_relative=0.3, frame_number=3),
        sip_factory(method="BYE", time_relative=12.0, frame_number=4),
    ]
    timeline = build_session_timeline(msgs)
    types = _event_types(timeline)
    assert st.EV_INVITE in types
    assert st.EV_ESTABLISHED in types
    assert st.EV_ACK in types
    assert st.EV_BYE in types
    assert st.EV_TERMINATED in types
    assert timeline.established_at == 0.2
    assert timeline.terminated_at == 12.0
    assert timeline.media_expected_windows == [(0.2, 12.0)]


def test_missing_bye_leaves_no_termination(sip_factory):
    msgs = [
        sip_factory(method="INVITE", time_relative=0.0),
        sip_factory(status_code=200, reason="OK", time_relative=0.2,
                    src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        sip_factory(method="ACK", time_relative=0.3),
    ]
    timeline = build_session_timeline(msgs)
    assert timeline.established_at == 0.2
    assert timeline.terminated_at is None
    assert timeline.media_expected_windows == [(0.2, None)]


def test_reinvite_hold_and_resume(sip_factory, sdp_variant):
    msgs = [
        sip_factory(method="INVITE", time_relative=0.0, sdp_text=sdp_variant("basic_audio")),
        sip_factory(status_code=200, reason="OK", time_relative=0.2,
                    src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        sip_factory(method="ACK", time_relative=0.3),
        # Hold (a=inactive)
        sip_factory(method="INVITE", time_relative=5.0, sdp_text=sdp_variant("inactive_hold")),
        # Resume (a=sendrecv)
        sip_factory(method="INVITE", time_relative=8.0, sdp_text=sdp_variant("basic_audio")),
        sip_factory(method="BYE", time_relative=10.0),
    ]
    timeline = build_session_timeline(msgs)
    types = _event_types(timeline)
    assert st.EV_REINVITE in types
    assert st.EV_HOLD in types
    assert st.EV_RESUME in types
    assert timeline.hold_windows == [(5.0, 8.0)]


def test_update_with_metadata(sip_factory):
    msgs = [
        sip_factory(method="INVITE", time_relative=0.0),
        sip_factory(status_code=200, reason="OK", time_relative=0.2,
                    src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        sip_factory(method="ACK", time_relative=0.3),
        sip_factory(method="UPDATE", time_relative=4.0,
                    content_type="application/rs-metadata+xml"),
    ]
    timeline = build_session_timeline(msgs)
    types = _event_types(timeline)
    assert st.EV_UPDATE in types
    assert st.EV_METADATA in types


def test_unclosed_hold_closes_at_termination(sip_factory, sdp_variant):
    msgs = [
        sip_factory(method="INVITE", time_relative=0.0, sdp_text=sdp_variant("basic_audio")),
        sip_factory(status_code=200, reason="OK", time_relative=0.2,
                    src_ip="10.0.0.2", dst_ip="10.0.0.1"),
        sip_factory(method="INVITE", time_relative=5.0, sdp_text=sdp_variant("inactive_hold")),
        sip_factory(method="BYE", time_relative=9.0),
    ]
    timeline = build_session_timeline(msgs)
    assert timeline.hold_windows == [(5.0, 9.0)]
