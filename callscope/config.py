"""Default configuration values for CallScope.

These are plain module-level constants. User-supplied config-file parsing is
intentionally out of scope for v1.
"""

from __future__ import annotations

DEFAULT_OUTPUT_FORMAT = "pcapng"
DEFAULT_SIP_PORTS = [5060, 5061]
DEFAULT_RTP_GAP_THRESHOLD = 1
DEFAULT_REPORT_TEMPLATE = "report.html.j2"

# Streams with fewer than this many packets are treated as noise (STUN keepalives,
# RTCP-mux SRs with rotating SSRCs, codec-transition stragglers, etc.) and excluded
# from SSRC-lifecycle analysis and change counting. Real media legs in a call of
# any useful length carry thousands of packets; 100 ≈ 2 seconds of G.711 at 50 pps.
SUBSTANTIAL_MIN_PACKETS = 100

# Assumed network one-way (mouth-to-ear) delay in ms for MOS/E-model estimation.
# RTCP round-trip is not reliably recoverable from a single SIPREC leg, so this is
# an explicit baseline; the de-jitter buffer term is added on top from measured jitter.
DEFAULT_ONE_WAY_DELAY_MS = 30.0
SUPPORTED_OUTPUT_FORMATS = {"pcap", "pcapng"}

# Canonical output file names within the output directory.
OUTPUT_PCAP_BASENAME = "recording-session"
OUTPUT_REPORT_HTML = "report.html"
OUTPUT_SUMMARY_TXT = "summary.txt"
OUTPUT_SUMMARY_JSON = "summary.json"
OUTPUT_METADATA_JSON = "siprec-metadata.json"
OUTPUT_MEDIA_JSON = "media-streams.json"
OUTPUT_FINDINGS_JSON = "findings.json"
TEMP_DIRNAME = "temp"

__all__ = [
    "DEFAULT_OUTPUT_FORMAT",
    "DEFAULT_SIP_PORTS",
    "DEFAULT_RTP_GAP_THRESHOLD",
    "DEFAULT_REPORT_TEMPLATE",
    "SUPPORTED_OUTPUT_FORMATS",
    "OUTPUT_PCAP_BASENAME",
    "OUTPUT_REPORT_HTML",
    "OUTPUT_SUMMARY_TXT",
    "OUTPUT_SUMMARY_JSON",
    "OUTPUT_METADATA_JSON",
    "OUTPUT_MEDIA_JSON",
    "OUTPUT_FINDINGS_JSON",
    "TEMP_DIRNAME",
]
