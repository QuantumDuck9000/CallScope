"""Assign a likely owner to each finding for triage and escalation routing.

Most v2 detectors set an owner directly. This module fills in owners for the
v1 findings (gap/mixer/extractor codes) and provides the canonical code→owner
map, so the report and the escalation summary can group by who should act.
"""

from __future__ import annotations

from ..models import Owner, RecordingFinding

# Canonical mapping. SBC = the box authored or emitted it on the captured leg;
# NETWORK = recording-path quality; CAPTURE = measurement artifact;
# UNPROVABLE = cannot be isolated from SIPREC-only data.
OWNER_BY_CODE: dict[str, Owner] = {
    # v1 findings
    "NO_SDP": Owner.SBC,
    "RTP_NONE_OBSERVED": Owner.SBC,
    "RTP_SEQ_GAP": Owner.NETWORK,
    "RTP_MISSING_RTCP": Owner.NETWORK,
    "RTP_LATE_START": Owner.SBC,
    "RTP_EARLY_END": Owner.SBC,
    "MIX_STREAMS_OK": Owner.UNKNOWN,
    "MIX_NONE_OBSERVED": Owner.SBC,
    "MIX_FEWER_OBSERVED": Owner.SBC,
    "MIX_MORE_OBSERVED": Owner.SBC,
    "MIX_SDP_COUNT_MISMATCH": Owner.SBC,
    # v2.1 SIPREC protocol-correctness family
    "SIPREC-001": Owner.SBC,
    "SIPREC-002": Owner.SBC,
    "SIPREC-003": Owner.SBC,
    "SIPREC-004": Owner.SBC,
    "SIPREC-005": Owner.SBC,
    "SIPREC-006": Owner.UNKNOWN,
    "MOS_LOW": Owner.NETWORK,
    "MOS_BAD": Owner.NETWORK,
    "RTCP_NO_REPORTS": Owner.UNKNOWN,
}


def assign_ownership(findings: list[RecordingFinding]) -> None:
    """Fill ``owner`` on findings that don't already have one."""
    for f in findings:
        if f.owner is not None:
            continue
        f.owner = OWNER_BY_CODE.get(f.code, Owner.UNKNOWN)


__all__ = ["assign_ownership", "OWNER_BY_CODE"]
