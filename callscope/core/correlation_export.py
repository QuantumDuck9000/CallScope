"""Build a correlation key to join SIPREC analysis against external systems.

A SIPREC capture has its own Call-ID, different from the original call and from
Genesys component logs. Exporting timestamps, participant AORs, media 5-tuples,
and SSRCs lets an engineer line a recording up against GVP/MCP, IRWS, SIP
Server, CDRs, or OCOM by time and AOR even without a shared Call-ID.
"""

from __future__ import annotations

import datetime as dt
import re

from ..models import CorrelationKey, RecordingAnalysis

_AOR_RE = re.compile(r"sip:[^>;\s]+", re.IGNORECASE)


def _epoch_to_utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_correlation_key(analysis: RecordingAnalysis) -> CorrelationKey:
    epochs = [m.timestamp_epoch for m in analysis.sip_messages if m.timestamp_epoch is not None]
    start = min(epochs) if epochs else None
    end = max(epochs) if epochs else None

    aors: list[str] = []
    for md in analysis.metadata:
        for p in md.participants:
            if p.aor:
                aors.append(p.aor)
    # Fall back to From/To AORs if metadata had none.
    if not aors:
        for m in analysis.sip_messages:
            for hdr in (m.from_header, m.to_header):
                if hdr:
                    match = _AOR_RE.search(hdr)
                    if match:
                        aors.append(match.group(0))
    aors = sorted(set(aors))

    tuples = sorted(
        {
            f"{s.src.ip}:{s.src.port}->{s.dst.ip}:{s.dst.port}"
            for s in analysis.rtp_streams
        }
    )
    ssrcs = sorted(
        {f"0x{s.ssrc:08x}" for s in analysis.rtp_streams if s.ssrc is not None}
    )

    return CorrelationKey(
        call_id=analysis.call_id,
        start_utc=_epoch_to_utc(start),
        end_utc=_epoch_to_utc(end),
        participant_aors=aors,
        media_5tuples=tuples,
        ssrcs=ssrcs,
    )


__all__ = ["build_correlation_key"]
