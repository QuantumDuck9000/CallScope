"""Tests for HTML report rendering."""

from __future__ import annotations

import json

from callscope.models import RecordingAnalysis, Severity
from callscope.reporting.report import build_report_context, render_html_report
from callscope.siprec import recording_health, session_timeline


def _analysis(sip_factory, sdp_variant) -> RecordingAnalysis:
    invite = sip_factory(method="INVITE", frame_number=1, time_relative=0.0,
                         time_epoch=1_700_000_000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                         sdp_text=sdp_variant("basic_audio"))
    ok = sip_factory(status_code=200, reason="OK", frame_number=2, time_relative=0.2,
                     time_epoch=1_700_000_000.2, src_ip="10.0.0.2", dst_ip="10.0.0.1")
    analysis = RecordingAnalysis(call_id="report-call@callscope", sip_messages=[invite, ok])
    timeline = session_timeline.build_session_timeline([invite, ok])
    recording_health.evaluate_recording_health(analysis, timeline)
    return analysis


def test_build_context_has_required_keys(sip_factory, sdp_variant):
    ctx = build_report_context(_analysis(sip_factory, sdp_variant))
    for key in ["call_id", "overall_health", "duration", "status_cards", "ladder",
                "streams", "findings", "output_files"]:
        assert key in ctx
    assert len(ctx["status_cards"]) == 8


def test_render_writes_html_with_callid_and_ladder(tmp_path, sip_factory, sdp_variant):
    analysis = _analysis(sip_factory, sdp_variant)
    out = tmp_path / "report.html"
    render_html_report(analysis, out)
    html = out.read_text(encoding="utf-8")

    # Call-ID must appear in the rendered HTML.
    assert "report-call@callscope" in html
    # The embedded JSON must include the ladder model.
    assert "report-data" in html
    assert '"ladder"' in html
    # Document is self-contained: no external stylesheet/script references.
    assert "<link" not in html
    assert "cdn" not in html.lower()
    assert 'src="http' not in html
    assert '<script id="report-data"' in html


def test_embedded_json_is_valid(tmp_path, sip_factory, sdp_variant):
    analysis = _analysis(sip_factory, sdp_variant)
    out = tmp_path / "report.html"
    render_html_report(analysis, out)
    html = out.read_text(encoding="utf-8")
    start = html.index(">", html.index('id="report-data"')) + 1
    end = html.index("</script>", start)
    payload = html[start:end]
    data = json.loads(payload)
    assert data["call_id"] == "report-call@callscope"
    assert "rows" in data["ladder"]
