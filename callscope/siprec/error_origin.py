"""Attribute failure responses and BYEs to the IP that emitted them.

Because the SBC is a B2BUA, every packet it sends carries its own source
address. If a 4xx/5xx/6xx or the dialog-terminating BYE originated from the
SBC's own IP (rather than being relayed), that is the SBC's packet to explain.
If instead it came from the recorder/Genesys IP, that points the other way —
which is worth showing too, for fairness.
"""

from __future__ import annotations

from ..models import Owner, RecordingAnalysis, RecordingFinding, Severity, SipMessage

CODE_ERR_ORIGIN_SBC = "ERR_ORIGIN_SBC"
CODE_ERR_ORIGIN_GENESYS = "ERR_ORIGIN_GENESYS"
CODE_BYE_ORIGIN_SBC = "BYE_ORIGIN_SBC"
CODE_BYE_ORIGIN_GENESYS = "BYE_ORIGIN_GENESYS"


def _cseq_method(msg: SipMessage) -> str | None:
    if msg.method:
        return msg.method.upper()
    if msg.cseq:
        parts = msg.cseq.split()
        if len(parts) >= 2:
            return parts[-1].upper()
    return None


def classify_error_origins(analysis: RecordingAnalysis) -> list[RecordingFinding]:
    """Label failures and BYEs by whether the SBC or Genesys IP emitted them."""
    src_ip = analysis.src_endpoint.ip if analysis.src_endpoint else None
    srs_ip = analysis.srs_endpoint.ip if analysis.srs_endpoint else None
    findings: list[RecordingFinding] = []

    def owner_for(ip: str | None) -> tuple[Owner, str]:
        if ip and src_ip and ip == src_ip:
            return Owner.SBC, "SBC"
        if ip and srs_ip and ip == srs_ip:
            return Owner.GENESYS, "Genesys/SRS"
        return Owner.UNKNOWN, ip or "unknown"

    for msg in analysis.sip_messages:
        if msg.is_response and (msg.status_code or 0) >= 400:
            owner, who = owner_for(msg.src.ip)
            code = CODE_ERR_ORIGIN_SBC if owner == Owner.SBC else (
                CODE_ERR_ORIGIN_GENESYS if owner == Owner.GENESYS else CODE_ERR_ORIGIN_SBC
            )
            findings.append(
                RecordingFinding(
                    severity=Severity.ERROR if (msg.status_code or 0) >= 500 else Severity.WARN,
                    code=code,
                    title=f"{msg.status_code} emitted by {who}",
                    detail=(
                        f"A {msg.status_code} {msg.reason_phrase or ''} response was sent from "
                        f"{msg.src.ip} ({who})."
                    ).strip(),
                    evidence_frames=[msg.frame_number],
                    owner=owner,
                )
            )
        elif msg.is_request and _cseq_method(msg) == "BYE":
            owner, who = owner_for(msg.src.ip)
            code = CODE_BYE_ORIGIN_SBC if owner != Owner.GENESYS else CODE_BYE_ORIGIN_GENESYS
            findings.append(
                RecordingFinding(
                    severity=Severity.INFO,
                    code=code,
                    title=f"BYE sent by {who}",
                    detail=f"The recording dialog was terminated by a BYE from {msg.src.ip} ({who}).",
                    evidence_frames=[msg.frame_number],
                    owner=owner,
                )
            )
    return findings


__all__ = [
    "classify_error_origins",
    "CODE_ERR_ORIGIN_SBC",
    "CODE_ERR_ORIGIN_GENESYS",
    "CODE_BYE_ORIGIN_SBC",
    "CODE_BYE_ORIGIN_GENESYS",
]
