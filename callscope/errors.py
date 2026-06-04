"""Custom exceptions for CallScope.

All CLI-facing exceptions derive from :class:`CallScopeError` and carry a
human-readable message suitable for printing directly to a terminal.
"""

from __future__ import annotations


class CallScopeError(Exception):
    """Base class for all CallScope errors.

    The string form of any CallScopeError is intended to be safe to show
    directly to an end user.
    """


# --- Tool availability / execution -----------------------------------------


class TsharkNotAvailable(CallScopeError):
    """Raised when the ``tshark`` executable cannot be located."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "tshark was not found on PATH. Install Wireshark CLI tools and "
            "ensure 'tshark' is available."
        )


class MergecapNotAvailable(CallScopeError):
    """Raised when the ``mergecap`` executable cannot be located."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "mergecap was not found on PATH. Install Wireshark CLI tools and "
            "ensure 'mergecap' is available."
        )


class TsharkExecutionError(CallScopeError):
    """Raised when a tshark/mergecap subprocess fails."""


# --- Input / capture problems ----------------------------------------------


class PcapInputError(CallScopeError):
    """Raised when pcap inputs are missing, empty, or otherwise invalid."""


class PcapCorrupt(CallScopeError):
    """Raised when a capture file cannot be read or appears corrupt."""


class CallIDNotFound(CallScopeError):
    """Raised when no SIP packets match the requested Call-ID."""


# --- Parsing problems ------------------------------------------------------


class SipParseError(CallScopeError):
    """Raised when a SIP message cannot be parsed."""


class SdpParseError(CallScopeError):
    """Raised when an SDP body cannot be parsed."""


class SipRecParseError(CallScopeError):
    """Raised when SIPREC metadata cannot be parsed."""


class MetadataNotFound(CallScopeError):
    """Raised when expected SIPREC metadata is absent."""


# --- Analysis / reporting --------------------------------------------------


class RtpAnalysisError(CallScopeError):
    """Raised when RTP/RTCP analysis fails irrecoverably."""


class ReportGenerationError(CallScopeError):
    """Raised when the HTML report cannot be rendered."""


__all__ = [
    "CallScopeError",
    "TsharkNotAvailable",
    "MergecapNotAvailable",
    "CallIDNotFound",
    "PcapInputError",
    "PcapCorrupt",
    "TsharkExecutionError",
    "SipParseError",
    "SdpParseError",
    "SipRecParseError",
    "MetadataNotFound",
    "RtpAnalysisError",
    "ReportGenerationError",
]
