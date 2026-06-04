"""SIPREC compliance checks (RFC 7865 metadata, RFC 7866 protocol).

Because the SBC acts as the SRC and authors the recording INVITE, anything
malformed or non-compliant here is provably the SBC's own output from a single
SIPREC-side capture. Findings cite the relevant RFC clause so they read as
spec non-compliance rather than opinion.
"""

from __future__ import annotations

from ..core.sip_parser import is_siprec_metadata_content_type, iter_body_parts
from ..models import (
    Owner,
    RecordingFinding,
    Severity,
    SipMessage,
    SipRecMetadata,
)

CODE_NO_METADATA = "SIPREC_NO_METADATA"
CODE_BAD_CONTENT_TYPE = "SIPREC_BAD_CONTENT_TYPE"
CODE_METADATA_INVALID = "SIPREC_METADATA_INVALID"
CODE_METADATA_INCOMPLETE = "SIPREC_METADATA_INCOMPLETE"
CODE_NO_VERSION_INCREMENT = "SIPREC_NO_VERSION_INCREMENT"
CODE_BAD_DIRECTION = "SIPREC_BAD_DIRECTION"

_ACTIVE_RECORD_DIRECTIONS = {"sendonly", "inactive"}


def _initial_invite(messages: list[SipMessage]) -> SipMessage | None:
    return next((m for m in messages if m.method == "INVITE"), None)


def check_siprec_compliance(
    messages: list[SipMessage], metadata: list[SipRecMetadata]
) -> list[RecordingFinding]:
    """Validate the recording INVITE and its metadata against the SIPREC RFCs."""
    findings: list[RecordingFinding] = []
    invite = _initial_invite(messages)

    # 1. Metadata must be present on the recording INVITE.
    if not metadata:
        findings.append(
            RecordingFinding(
                severity=Severity.ERROR,
                code=CODE_NO_METADATA,
                title="No SIPREC metadata",
                detail="The recording INVITE carried no application/rs-metadata body.",
                clause="RFC 7866 §6",
                owner=Owner.SBC,
            )
        )
        return findings

    # 2. Content-Type sanity on the metadata part(s).
    if invite is not None:
        for part in iter_body_parts(invite):
            ctype = (part.content_type or "").lower()
            if "rs-metadata" in ctype and "+xml" not in ctype:
                findings.append(
                    RecordingFinding(
                        severity=Severity.WARN,
                        code=CODE_BAD_CONTENT_TYPE,
                        title="Non-standard metadata Content-Type",
                        detail=f"Metadata part declared Content-Type {part.content_type!r}; expected application/rs-metadata+xml.",
                        clause="RFC 7865 §6",
                        evidence_frames=[invite.frame_number],
                        owner=Owner.SBC,
                    )
                )

    # 3. Metadata that was present but failed to parse, or is incomplete.
    for md in metadata:
        if not md.communication_sessions and not md.participants and not md.streams:
            findings.append(
                RecordingFinding(
                    severity=Severity.ERROR,
                    code=CODE_METADATA_INVALID,
                    title="SIPREC metadata invalid or empty",
                    detail="Metadata XML was present but contained no session, participant, or stream elements.",
                    clause="RFC 7865 §6",
                    owner=Owner.SBC,
                )
            )
            continue
        missing = []
        if not md.communication_sessions:
            missing.append("session")
        if not md.participants:
            missing.append("participant")
        if not md.streams:
            missing.append("stream")
        if missing:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_METADATA_INCOMPLETE,
                    title="SIPREC metadata incomplete",
                    detail="Metadata is missing required element(s): " + ", ".join(missing) + ".",
                    clause="RFC 7865 §7",
                    owner=Owner.SBC,
                )
            )

    # 4. Version increment: multiple metadata snapshots that are byte-identical.
    if len(metadata) > 1:
        raws = [m.raw_xml.strip() for m in metadata]
        if len(set(raws)) == 1:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_NO_VERSION_INCREMENT,
                    title="Metadata not updated across snapshots",
                    detail="Multiple metadata bodies were sent but all were identical — updates should reflect state changes.",
                    clause="RFC 7865 §6",
                    owner=Owner.SBC,
                )
            )

    # 5. Direction sanity: the SRC offers media to the recorder as sendonly
    #    (recorder answers recvonly). A sendrecv offer to the SRS is suspect.
    if invite is not None and invite.sdp is not None:
        for media in invite.sdp.media:
            if media.direction and media.direction not in _ACTIVE_RECORD_DIRECTIONS:
                findings.append(
                    RecordingFinding(
                        severity=Severity.WARN,
                        code=CODE_BAD_DIRECTION,
                        title="Unexpected media direction to recorder",
                        detail=(
                            f"Recording offer has a={media.direction} on a media line; "
                            "the SRC should offer sendonly to the SRS."
                        ),
                        clause="RFC 7866 §7.1.1",
                        evidence_frames=[invite.frame_number],
                        owner=Owner.SBC,
                    )
                )

    return findings


__all__ = [
    "check_siprec_compliance",
    "CODE_NO_METADATA",
    "CODE_BAD_CONTENT_TYPE",
    "CODE_METADATA_INVALID",
    "CODE_METADATA_INCOMPLETE",
    "CODE_NO_VERSION_INCREMENT",
    "CODE_BAD_DIRECTION",
]
