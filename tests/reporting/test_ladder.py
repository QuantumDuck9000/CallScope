"""Tests for the ladder display model."""

from __future__ import annotations

from callscope.reporting.ladder import build_ladder_model


def test_ladder_actors_and_directions(sip_factory, sdp_variant):
    invite = sip_factory(method="INVITE", frame_number=1, time_relative=0.0,
                         src_ip="10.0.0.1", dst_ip="10.0.0.2",
                         sdp_text=sdp_variant("basic_audio"))
    ok = sip_factory(status_code=200, reason="OK", frame_number=2, time_relative=0.2,
                     src_ip="10.0.0.2", dst_ip="10.0.0.1")
    model = build_ladder_model([invite, ok])

    assert model["src"]["ip"] == "10.0.0.1"
    assert model["srs"]["ip"] == "10.0.0.2"
    assert model["rows"][0]["direction"] == "SRC_TO_SRS"
    assert model["rows"][1]["direction"] == "SRS_TO_SRC"


def test_ladder_label_includes_sdp(sip_factory, sdp_variant):
    invite = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    model = build_ladder_model([invite])
    assert "SDP" in model["rows"][0]["label"]
    assert model["rows"][0]["sdp"] is not None


def test_ladder_response_label(sip_factory):
    ok = sip_factory(status_code=200, reason="OK", src_ip="10.0.0.2", dst_ip="10.0.0.1")
    model = build_ladder_model([ok])
    assert "200" in model["rows"][0]["label"]
    assert model["rows"][0]["is_response"] is True
