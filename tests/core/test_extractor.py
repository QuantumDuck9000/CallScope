"""Tests for extractor helpers and the output-writing path."""

from __future__ import annotations

from pathlib import Path

import pytest

from callscope.core import extractor, writer
from callscope.core.extractor import (
    ExtractionOptions,
    _build_combined_filter,
    _enrich_message,
    _escape_filter_value,
    _sip_call_id_filter,
    write_all_outputs,
)
from callscope.core.pcap_index import PcapFileInfo
from callscope.errors import CallIDNotFound
from callscope.models import RecordingAnalysis, Severity
from callscope.siprec import recording_health, session_timeline


def test_escape_filter_value_quotes():
    assert _escape_filter_value('a"b') == 'a\\"b'
    assert _escape_filter_value("a\\b") == "a\\\\b"


def test_sip_call_id_filter():
    assert _sip_call_id_filter("abc@h") == 'sip.Call-ID == "abc@h"'


def test_enrich_message_attaches_sdp(sip_factory, sdp_variant):
    msg = sip_factory(
        method="INVITE",
        content_type="application/sdp",
        body=sdp_variant("basic_audio"),
    )
    _enrich_message(msg)
    assert msg.sdp is not None
    assert msg.sdp.media[0].port == 30000


def test_build_combined_filter_includes_sip_and_media(sip_factory, sdp_variant):
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    flt = _build_combined_filter("abc@h", [msg], [])
    assert 'sip.Call-ID == "abc@h"' in flt
    assert "udp.port == 30000" in flt


def test_callid_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(extractor, "discover_pcaps", lambda pat: [tmp_path / "a.pcap"])
    monkeypatch.setattr(
        extractor,
        "index_pcaps",
        lambda paths: [PcapFileInfo(path=paths[0], size_bytes=10, format_hint="pcap", readable=True)],
    )
    monkeypatch.setattr(extractor, "collect_sip_messages", lambda *a, **k: [])
    opts = ExtractionOptions(call_id="missing@h", pcaps="x", out_dir=tmp_path / "out")
    with pytest.raises(CallIDNotFound):
        extractor.run_siprec_extraction(opts)


def test_write_all_outputs_creates_files(tmp_path, sip_factory, sdp_variant):
    out = writer.ensure_output_dir(tmp_path / "case")
    msg = sip_factory(method="INVITE", sdp_text=sdp_variant("basic_audio"))
    analysis = RecordingAnalysis(call_id="abc@callscope", sip_messages=[msg])
    timeline = session_timeline.build_session_timeline([msg])
    recording_health.evaluate_recording_health(analysis, timeline)

    write_all_outputs(analysis, timeline, out, write_html=True)

    for name in [
        "summary.txt",
        "summary.json",
        "siprec-metadata.json",
        "media-streams.json",
        "findings.json",
        "report.html",
    ]:
        assert (out / name).exists(), f"missing {name}"

    summary = (out / "summary.txt").read_text(encoding="utf-8")
    assert "CALL-ID:" in summary
    assert "abc@callscope" in summary
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "abc@callscope" in html
