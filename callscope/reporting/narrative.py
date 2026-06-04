"""Generate a plain-English, numbered "what happened" narrative.

Written for a non-expert reviewer (or a ticket): each step is one sentence,
referencing a frame where possible, so the story of the recording session can
be read top to bottom without SIP knowledge.
"""

from __future__ import annotations

from ..models import NarrativeStep, RecordingAnalysis, SessionTimeline, SipMessage


def _who(analysis: RecordingAnalysis, ip: str | None) -> str:
    if ip and analysis.src_endpoint and ip == analysis.src_endpoint.ip:
        return "the SBC"
    if ip and analysis.srs_endpoint and ip == analysis.srs_endpoint.ip:
        return "the recorder"
    return ip or "an endpoint"


def build_narrative(
    analysis: RecordingAnalysis, timeline: SessionTimeline
) -> list[NarrativeStep]:
    """Build the numbered narrative steps from the analysis and timeline."""
    steps: list[NarrativeStep] = []
    n = 0

    def add(text: str, frame: int | None = None) -> None:
        nonlocal n
        n += 1
        steps.append(NarrativeStep(index=n, text=text, frame_number=frame))

    declared = sum(len(m.streams) for m in analysis.metadata)
    from ..siprec.labels import distinct_media_count

    observed = distinct_media_count(analysis)

    invite = next((m for m in analysis.sip_messages if m.method == "INVITE"), None)
    if invite is not None:
        meta_clause = (
            f" carrying SIPREC metadata that declared {declared} stream(s)"
            if declared
            else " (no SIPREC metadata present)"
        )
        add(
            f"{_who(analysis, invite.src.ip)} sent an INVITE to {_who(analysis, invite.dst.ip)}{meta_clause}.",
            invite.frame_number,
        )

    answer = next(
        (m for m in analysis.sip_messages if m.is_response and 200 <= (m.status_code or 0) < 300),
        None,
    )
    if answer is not None:
        add(f"{_who(analysis, answer.src.ip)} answered {answer.status_code} {answer.reason_phrase or ''}.".strip(), answer.frame_number)

    if analysis.rtp_streams:
        first_start = min(
            (s.first_timestamp_relative for s in analysis.rtp_streams if s.first_timestamp_relative is not None),
            default=None,
        )
        if first_start is not None and timeline.established_at is not None:
            delay = first_start - timeline.established_at
            if delay > 2.0:
                add(f"RTP to the recorder did not start until {delay:.1f}s after the session was established (clipped start).")
            else:
                add("RTP began flowing to the recorder shortly after answer.")
    elif declared:
        add("No RTP reached the recorder at all, despite metadata declaring media.")

    for b in analysis.bursts:
        extra = " and the offered codec set changed (codec renegotiation)" if b.codec_renegotiation else ""
        add(f"A burst of {b.count} re-INVITE/UPDATE messages occurred around t={b.window_start:.0f}s{extra}.")

    for ev in analysis.hold_retrieve_events:
        t = f"t={ev.time_relative:.1f}s" if ev.time_relative is not None else "an unknown time"
        verb = "placed on hold" if ev.kind == "HOLD" else "retrieved"
        add(f"The call was {verb} at {t} (CSeq {ev.cseq}).", ev.frame_number)

    for g in analysis.coverage_gaps:
        who = g.participant or f"label {g.label}"
        dur = f"{g.duration_s:.0f}s" if g.duration_s is not None else "an unknown duration"
        add(
            f"After retrieve, {who} changed SSRC from 0x{(g.old_ssrc or 0):08x} to "
            f"0x{(g.new_ssrc or 0):08x}; if the recorder did not follow the new SSRC, "
            f"about {dur} of that stream's audio is missing."
        )

    if analysis.ssrc_changes and not analysis.coverage_gaps:
        add(f"The media SSRC changed {len(analysis.ssrc_changes)} time(s) mid-call, indicating the feed was restarted.")

    for f in analysis.errors():
        add(f"A problem was detected: {f.title} — {f.detail}")

    bye = next(
        (m for m in analysis.sip_messages if m.is_request and (m.method or "").upper() == "BYE"),
        None,
    )
    if bye is not None:
        add(f"The recording dialog was ended by a BYE from {_who(analysis, bye.src.ip)}.", bye.frame_number)
    elif timeline.terminated_at is None:
        add("No BYE was seen — the recording dialog did not close cleanly in this capture.")

    add(
        f"In total, {observed} of {declared} declared stream(s) carried media to the recorder."
        if declared
        else f"In total, {observed} RTP stream(s) were observed."
    )

    return steps


__all__ = ["build_narrative"]
