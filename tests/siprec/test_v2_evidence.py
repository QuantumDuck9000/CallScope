"""Tests for the v2 SBC-evidence modules."""

from __future__ import annotations

from pathlib import Path

from callscope.models import (
    Endpoint,
    ObservedRtpStream,
    Owner,
    RecordingAnalysis,
    RecordingFinding,
    Severity,
    SipRecMetadata,
    SipRecStream,
)
from callscope.siprec import (
    capture_quality,
    compliance,
    consistency,
    error_origin,
    fingerprint,
    ownership,
)
from tests.conftest import make_sip_message


def _metadata(n_streams: int) -> SipRecMetadata:
    md = SipRecMetadata(version="1", raw_xml="<recording/>")
    md.streams = [SipRecStream(stream_id=f"s{i}", label=str(i)) for i in range(n_streams)]
    md.participants = []
    return md


def test_compliance_no_metadata():
    inv = make_sip_message(method="INVITE")
    findings = compliance.check_siprec_compliance([inv], [])
    assert any(f.code == compliance.CODE_NO_METADATA for f in findings)
    assert all(f.owner == Owner.SBC for f in findings)


def test_compliance_bad_direction_cites_clause():
    inv = make_sip_message(
        method="INVITE",
        sdp_text="v=0\nm=audio 30000 RTP/AVP 0\na=sendrecv\n",
    )
    md = _metadata(1)
    findings = compliance.check_siprec_compliance([inv], [md])
    bad = [f for f in findings if f.code == compliance.CODE_BAD_DIRECTION]
    assert bad
    assert bad[0].clause == "RFC 7866 §7.1.1"


def test_consistency_declared_two_observed_one():
    md = _metadata(2)
    analysis = RecordingAnalysis(
        call_id="x",
        metadata=[md],
        rtp_streams=[
            ObservedRtpStream(
                ssrc=1, src=Endpoint("1.1.1.1", 1), dst=Endpoint("2.2.2.2", 2), payload_type=0
            )
        ],
    )
    findings = consistency.check_consistency(analysis)
    contradiction = [f for f in findings if f.code == consistency.CODE_METADATA_RTP]
    assert contradiction
    assert contradiction[0].severity == Severity.ERROR
    assert contradiction[0].owner == Owner.SBC


def test_error_origin_attributes_failure_to_sbc():
    src = Endpoint("10.0.0.1", 5060)
    srs = Endpoint("10.0.0.2", 5060)
    analysis = RecordingAnalysis(
        call_id="x",
        src_endpoint=src,
        srs_endpoint=srs,
        sip_messages=[
            make_sip_message(
                status_code=488, reason="Not Acceptable Here",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
            )
        ],
    )
    findings = error_origin.classify_error_origins(analysis)
    assert findings
    assert findings[0].code == error_origin.CODE_ERR_ORIGIN_SBC
    assert findings[0].owner == Owner.SBC


def test_fingerprint_picks_up_user_agent_and_via():
    src = Endpoint("10.0.0.1", 5060)
    srs = Endpoint("10.0.0.2", 5060)
    analysis = RecordingAnalysis(
        call_id="x",
        src_endpoint=src,
        srs_endpoint=srs,
        sip_messages=[
            make_sip_message(
                method="INVITE", src_ip="10.0.0.1", dst_ip="10.0.0.2",
                user_agent="Oracle SBC 8.4", via_sent_by="10.0.0.1:5060",
            )
        ],
    )
    fps = fingerprint.build_fingerprints(analysis)
    src_fp = next(fp for fp in fps if fp.ip == "10.0.0.1")
    assert src_fp.user_agent == "Oracle SBC 8.4"
    assert src_fp.via_sent_by == "10.0.0.1:5060"


def test_ownership_fills_missing_owner():
    findings = [
        RecordingFinding(Severity.ERROR, "RTP_NONE_OBSERVED", "t", "d"),
        RecordingFinding(Severity.WARN, "UNKNOWN_CODE", "t", "d"),
        RecordingFinding(Severity.WARN, "CONSIST_METADATA_RTP", "t", "d", owner=Owner.SBC),
    ]
    ownership.assign_ownership(findings)
    assert findings[0].owner == Owner.SBC
    assert findings[1].owner == Owner.UNKNOWN
    assert findings[2].owner == Owner.SBC  # untouched


def test_capture_quality_checksums(tmp_path: Path):
    f = tmp_path / "siprec.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1 capture bytes")
    quality = capture_quality.assess_capture_quality([f])
    assert str(f) in quality.file_checksums
    assert len(quality.file_checksums[str(f)]) == 64  # sha256 hex
