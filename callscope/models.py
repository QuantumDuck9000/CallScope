"""Shared, typed data model for CallScope.

These dataclasses and enums are the stable contract used across the core,
siprec, and reporting layers. Keep them typed and importable everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Finding/status severity, ordered from least to most serious."""

    INFO = "INFO"
    PASS = "PASS"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Direction(str, Enum):
    """Direction of a SIP message relative to SRC/SRS."""

    SRC_TO_SRS = "SRC_TO_SRS"
    SRS_TO_SRC = "SRS_TO_SRC"
    UNKNOWN = "UNKNOWN"


class Owner(str, Enum):
    """Likely owner of a finding, for triage and escalation routing."""

    SBC = "SBC"
    GENESYS = "GENESYS"
    NETWORK = "NETWORK"
    CAPTURE = "CAPTURE"
    UNPROVABLE = "UNPROVABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Endpoint:
    ip: str
    port: int | None = None
    label: str | None = None


@dataclass
class SipMessage:
    frame_number: int
    timestamp_epoch: float | None
    timestamp_relative: float | None
    src: Endpoint
    dst: Endpoint
    direction: Direction
    call_id: str | None
    method: str | None
    status_code: int | None
    reason_phrase: str | None
    cseq: str | None
    from_header: str | None
    to_header: str | None
    contact: str | None
    content_type: str | None
    raw_headers: str
    body: str | None = None
    sdp: SdpSession | None = None
    siprec_metadata: SipRecMetadata | None = None
    # v2: B2BUA fingerprint + reliability fields.
    user_agent: str | None = None
    server: str | None = None
    via_branch: str | None = None
    via_sent_by: str | None = None
    is_retransmission: bool = False

    @property
    def is_request(self) -> bool:
        return self.method is not None and self.status_code is None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None


@dataclass
class SdpMedia:
    media_type: str
    port: int
    protocol: str
    payload_types: list[str] = field(default_factory=list)
    connection_address: str | None = None
    direction: str | None = None
    label: str | None = None
    mid: str | None = None
    rtcp_port: int | None = None
    rtcp_mux: bool = False
    rtpmap: dict[str, str] = field(default_factory=dict)
    fmtp: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class SdpSession:
    connection_address: str | None
    origin: str | None
    session_name: str | None
    media: list[SdpMedia] = field(default_factory=list)
    raw: str | None = None


@dataclass
class SipRecParticipant:
    participant_id: str
    name: str | None = None
    aor: str | None = None
    role: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SipRecStream:
    stream_id: str
    media_type: str | None = None
    label: str | None = None
    participant_ids: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SipRecCommunicationSession:
    session_id: str
    participants: list[SipRecParticipant] = field(default_factory=list)
    streams: list[SipRecStream] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SipRecMetadata:
    version: str | None
    raw_xml: str
    communication_sessions: list[SipRecCommunicationSession] = field(default_factory=list)
    participants: list[SipRecParticipant] = field(default_factory=list)
    streams: list[SipRecStream] = field(default_factory=list)


@dataclass
class ObservedRtpStream:
    ssrc: int | None
    src: Endpoint
    dst: Endpoint
    payload_type: int | None
    packet_count: int = 0
    first_timestamp_relative: float | None = None
    last_timestamp_relative: float | None = None
    first_sequence: int | None = None
    last_sequence: int | None = None
    sequence_gaps: int = 0
    largest_gap: int = 0
    rtcp_observed: bool = False
    matched_siprec_stream_id: str | None = None
    matched_sdp_label: str | None = None
    # v2: media-quality detail.
    ssrc_changes: int = 0
    payload_types_seen: list[int] = field(default_factory=list)
    comfort_noise_ratio: float | None = None
    dtmf_events: int = 0
    timestamp_resets: int = 0
    # v2.1: SIPREC label/participant binding.
    participant_aor: str | None = None
    participant_name: str | None = None


@dataclass
class RecordingFinding:
    severity: Severity
    code: str
    title: str
    detail: str
    evidence_frames: list[int] = field(default_factory=list)
    recommendation: str | None = None
    # v2: ownership + spec citation + stream-level evidence.
    owner: Owner | None = None
    clause: str | None = None
    evidence_streams: list[str] = field(default_factory=list)


# --- Session timeline models (used by the SIPREC phase state machine) -------


@dataclass
class TimelineEvent:
    time_relative: float | None
    frame_number: int | None
    event_type: str
    description: str
    related_message_index: int | None = None


@dataclass
class SessionTimeline:
    events: list[TimelineEvent] = field(default_factory=list)
    established_at: float | None = None
    terminated_at: float | None = None
    media_expected_windows: list[tuple[float, float | None]] = field(default_factory=list)
    hold_windows: list[tuple[float, float | None]] = field(default_factory=list)


@dataclass
class RtcpStreamStats:
    ssrc: int | None
    report_count: int = 0
    fraction_lost_max: float | None = None
    cumulative_lost: int | None = None
    jitter_min: float | None = None
    jitter_avg: float | None = None
    jitter_max: float | None = None
    rtt_estimate_ms: float | None = None
    max_report_gap_s: float | None = None
    rtcp_bye_seen: bool = False


@dataclass
class MosSample:
    """A single MOS estimate at one RTCP reporting interval."""

    time_relative: float | None
    mos: float
    r_factor: float
    loss_pct: float
    jitter_ms: float


@dataclass
class MosEstimate:
    """E-model (ITU-T G.107) MOS estimate for one media stream."""

    ssrc: int | None
    label: str | None
    participant: str | None
    codec: str
    mos_avg: float
    mos_min: float
    r_factor_avg: float
    loss_pct_avg: float
    jitter_ms_avg: float
    one_way_delay_ms: float
    samples: list[MosSample] = field(default_factory=list)


@dataclass
class SsrcChangeEvent:
    flow_key: str
    time_relative: float | None
    from_ssrc: int | None
    to_ssrc: int | None


@dataclass
class BurstInfo:
    window_start: float | None
    window_end: float | None
    count: int
    methods: list[str] = field(default_factory=list)
    codec_renegotiation: bool = False
    payload_sets: list[list[str]] = field(default_factory=list)
    evidence_frames: list[int] = field(default_factory=list)


@dataclass
class CaptureQuality:
    truncated: bool = False
    snaplen: int | None = None
    drop_count: int | None = None
    duplicate_estimate: int | None = None
    clock_ok: bool = True
    file_checksums: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class ActorFingerprint:
    actor: str
    ip: str | None = None
    user_agent: str | None = None
    server: str | None = None
    contact_host: str | None = None
    via_sent_by: str | None = None
    sdp_origin_addr: str | None = None


@dataclass
class NarrativeStep:
    index: int
    text: str
    frame_number: int | None = None


@dataclass
class CorrelationKey:
    call_id: str
    start_utc: str | None
    end_utc: str | None
    participant_aors: list[str] = field(default_factory=list)
    media_5tuples: list[str] = field(default_factory=list)
    ssrcs: list[str] = field(default_factory=list)


@dataclass
class SsrcSegment:
    """One contiguous SSRC observed for a label (a leg of its lifecycle)."""

    ssrc: int | None
    first_time: float | None
    last_time: float | None
    packet_count: int
    trigger_cseq: str | None = None
    trigger_event: str | None = None


@dataclass
class LabelLifecycle:
    """The full SSRC history for one SIPREC stream label."""

    label: str
    participant: str | None
    port_key: str | None
    segments: list[SsrcSegment] = field(default_factory=list)
    ssrc_change_count: int = 0
    stability_per_min: float | None = None


@dataclass
class CoverageGap:
    """An estimated stretch of missing recording for a label."""

    label: str
    participant: str | None
    start_time: float | None
    end_time: float | None
    duration_s: float | None
    old_ssrc: int | None
    new_ssrc: int | None
    reason: str


@dataclass
class SsrcCollision:
    """Two SSRCs active on the same media port within an overlap window."""

    label: str | None
    port_key: str
    ssrc_a: int | None
    ssrc_b: int | None
    overlap_start: float | None
    overlap_end: float | None


@dataclass
class HoldRetrieveEvent:
    kind: str  # "HOLD" or "RETRIEVE"
    time_relative: float | None
    frame_number: int | None
    cseq: str | None


@dataclass
class RecordingAnalysis:
    call_id: str
    sip_messages: list[SipMessage] = field(default_factory=list)
    metadata: list[SipRecMetadata] = field(default_factory=list)
    rtp_streams: list[ObservedRtpStream] = field(default_factory=list)
    findings: list[RecordingFinding] = field(default_factory=list)
    output_pcap: Path | None = None
    report_html: Path | None = None

    # Convenience health status fields populated by recording_health.
    # Values are Severity members (or None if not yet evaluated).
    status_sip: Severity | None = None
    status_sdp: Severity | None = None
    status_metadata: Severity | None = None
    status_rtp: Severity | None = None
    status_rtcp: Severity | None = None
    status_streams: Severity | None = None
    status_gaps: Severity | None = None
    overall_health: Severity | None = None

    # SRC/SRS endpoints once identified.
    src_endpoint: Endpoint | None = None
    srs_endpoint: Endpoint | None = None

    # v2: extended analysis products.
    rtcp_stats: list[RtcpStreamStats] = field(default_factory=list)
    ssrc_changes: list[SsrcChangeEvent] = field(default_factory=list)
    bursts: list[BurstInfo] = field(default_factory=list)
    capture_quality: CaptureQuality | None = None
    fingerprints: list[ActorFingerprint] = field(default_factory=list)
    narrative: list[NarrativeStep] = field(default_factory=list)
    status_compliance: Severity | None = None
    # v2.1: label lifecycle + coverage + hold/retrieve.
    label_lifecycles: list[LabelLifecycle] = field(default_factory=list)
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    ssrc_collisions: list[SsrcCollision] = field(default_factory=list)
    hold_retrieve_events: list[HoldRetrieveEvent] = field(default_factory=list)
    rtcp_mux_packet_count: int = 0
    rtcp_packet_summary: dict = field(default_factory=dict)
    # v0.4: per-stream MOS estimates (E-model).
    mos_estimates: list[MosEstimate] = field(default_factory=list)

    def warnings(self) -> list[RecordingFinding]:
        return [f for f in self.findings if f.severity == Severity.WARN]

    def errors(self) -> list[RecordingFinding]:
        return [
            f
            for f in self.findings
            if f.severity in (Severity.ERROR, Severity.CRITICAL)
        ]

    def findings_by_owner(self) -> dict[str, list[RecordingFinding]]:
        grouped: dict[str, list[RecordingFinding]] = {}
        for f in self.findings:
            key = f.owner.value if isinstance(f.owner, Owner) else "UNKNOWN"
            grouped.setdefault(key, []).append(f)
        return grouped


__all__ = [
    "Severity",
    "Direction",
    "Owner",
    "Endpoint",
    "SipMessage",
    "SdpMedia",
    "SdpSession",
    "SipRecParticipant",
    "SipRecStream",
    "SipRecCommunicationSession",
    "SipRecMetadata",
    "ObservedRtpStream",
    "RecordingFinding",
    "TimelineEvent",
    "SessionTimeline",
    "RtcpStreamStats",
    "MosSample",
    "MosEstimate",
    "SsrcChangeEvent",
    "BurstInfo",
    "CaptureQuality",
    "ActorFingerprint",
    "NarrativeStep",
    "CorrelationKey",
    "SsrcSegment",
    "LabelLifecycle",
    "CoverageGap",
    "SsrcCollision",
    "HoldRetrieveEvent",
    "RecordingAnalysis",
]
