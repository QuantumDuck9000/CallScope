"""Tests for the E-model (G.107) MOS estimation."""

from __future__ import annotations

from callscope.models import Endpoint, ObservedRtpStream, Severity
from callscope.siprec import mos


def _stream(ssrc, pt=0, packets=5000):
    return ObservedRtpStream(
        ssrc=ssrc, src=Endpoint("a", 1), dst=Endpoint("b", 2), payload_type=pt, packet_count=packets
    )


def _rtcp(t, fraction, jitter, ssrc=0x1111):
    return {
        "frame.time_relative": str(t),
        "rtcp.ssrc.identifier": str(ssrc),
        "rtcp.ssrc.fraction": str(fraction),
        "rtcp.ssrc.jitter": str(jitter),
    }


def test_clean_g711_scores_near_top():
    # 0% loss, low jitter -> MOS ~4.4 for G.711.
    r = mos.r_factor(0.0, 30.0, 0.0, 25.1)
    assert mos.r_to_mos(r) > 4.0


def test_loss_degrades_mos_monotonically():
    m0 = mos.r_to_mos(mos.r_factor(0.0, 30.0, 0.0, 25.1))
    m5 = mos.r_to_mos(mos.r_factor(5.0, 30.0, 0.0, 25.1))
    m20 = mos.r_to_mos(mos.r_factor(20.0, 30.0, 0.0, 25.1))
    assert m0 > m5 > m20
    assert m20 < 2.6  # heavy loss is "poor"


def test_mos_clamped_to_valid_range():
    assert mos.r_to_mos(-50) == 1.0
    assert mos.r_to_mos(150) == 4.5


def test_estimate_mos_builds_trend_and_picks_codec():
    streams = [_stream(0x1111, pt=0)]
    rows = [
        _rtcp(1.0, 0, 40),     # clean
        _rtcp(250.0, 60, 800),  # ~23% loss, 100ms jitter
    ]
    est = mos.estimate_mos(rows, streams)
    assert len(est) == 1
    e = est[0]
    assert e.codec.startswith("PCMU")
    assert len(e.samples) == 2
    assert e.samples[0].mos > 4.0
    assert e.mos_min < 2.6
    # jitter conversion: 800 timestamp units @ 8kHz = 100ms
    assert abs(e.samples[1].jitter_ms - 100.0) < 0.5


def test_estimate_mos_uses_codec_clock_for_jitter():
    # G.722 (PT 9) clocks at 16kHz: 800 units = 50ms, not 100ms.
    streams = [_stream(0x2222, pt=9)]
    est = mos.estimate_mos([_rtcp(1.0, 0, 800, ssrc=0x2222)], streams)
    assert abs(est[0].samples[0].jitter_ms - 50.0) < 0.5
    assert est[0].codec == "G.722"


def test_build_mos_findings_thresholds():
    streams = [_stream(0x1111, pt=0)]
    bad = mos.estimate_mos([_rtcp(1.0, 80, 1200)], streams)
    findings = mos.build_mos_findings(bad)
    assert any(f.code == "MOS_BAD" and f.severity == Severity.ERROR for f in findings)

    good = mos.estimate_mos([_rtcp(1.0, 0, 40)], streams)
    assert mos.build_mos_findings(good) == []
