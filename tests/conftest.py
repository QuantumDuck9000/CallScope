"""Shared pytest fixtures and in-memory builders for CallScope tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from callscope.core import sdp_parser
from callscope.models import Direction, Endpoint, SipMessage

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def siprec_metadata_xml() -> str:
    return (FIXTURES_DIR / "siprec_multipart_metadata.xml").read_text(encoding="utf-8")


def load_sdp_variant(name: str) -> str:
    """Return one named SDP block from sample_sdp_variants.txt."""
    text = (FIXTURES_DIR / "sample_sdp_variants.txt").read_text(encoding="utf-8")
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    if name not in blocks:
        raise KeyError(f"No SDP variant named {name!r}")
    # Trim trailing blank lines.
    lines = blocks[name]
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


@pytest.fixture
def sdp_variant():
    return load_sdp_variant


def make_sip_message(
    *,
    frame_number: int = 1,
    time_relative: float | None = 0.0,
    time_epoch: float | None = 1_700_000_000.0,
    src_ip: str = "10.0.0.1",
    src_port: int | None = 5060,
    dst_ip: str = "10.0.0.2",
    dst_port: int | None = 5060,
    method: str | None = None,
    status_code: int | None = None,
    reason: str | None = None,
    call_id: str = "test-call-id@callscope",
    cseq: str | None = None,
    content_type: str | None = None,
    body: str | None = None,
    sdp_text: str | None = None,
    direction: Direction = Direction.UNKNOWN,
    via_branch: str | None = None,
    via_sent_by: str | None = None,
    user_agent: str | None = None,
    server: str | None = None,
) -> SipMessage:
    """Construct a SipMessage in memory, optionally parsing an SDP body."""
    if cseq is None:
        cseq = f"1 {method}" if method else "1 INVITE"
    msg = SipMessage(
        frame_number=frame_number,
        timestamp_epoch=time_epoch,
        timestamp_relative=time_relative,
        src=Endpoint(ip=src_ip, port=src_port),
        dst=Endpoint(ip=dst_ip, port=dst_port),
        direction=direction,
        call_id=call_id,
        method=method,
        status_code=status_code,
        reason_phrase=reason,
        cseq=cseq,
        from_header="<sip:src@callscope>",
        to_header="<sip:dst@callscope>",
        contact=None,
        content_type=content_type,
        raw_headers="(headers)",
        body=body,
        via_branch=via_branch,
        via_sent_by=via_sent_by,
        user_agent=user_agent,
        server=server,
    )
    if sdp_text is not None:
        msg.sdp = sdp_parser.parse_sdp(sdp_text)
    return msg


@pytest.fixture
def sip_factory():
    return make_sip_message
