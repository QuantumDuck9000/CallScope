"""Golden-baseline profiling and diff.

You can't diff a SIPREC call against the original call leg, but you can diff it
against a known-good recording from the same SBC. Save a profile from a working
call, then diff a failing one against it — differences are expressed against the
box's own correct output, which is harder to argue with than an RFC abstraction.
"""

from __future__ import annotations

from ..models import Owner, RecordingAnalysis, RecordingFinding, Severity

CODE_BASELINE_DIFF = "BASELINE_DIFF"

_MEDIA_TYPES = {"audio", "video"}


def _codec_sets(analysis: RecordingAnalysis) -> list[list[str]]:
    sets: list[list[str]] = []
    for m in analysis.sip_messages:
        if m.sdp is None:
            continue
        for media in m.sdp.media:
            if media.media_type in _MEDIA_TYPES and media.payload_types:
                sets.append(list(media.payload_types))
    return sets


def build_baseline_profile(analysis: RecordingAnalysis) -> dict:
    """Capture a comparable profile from a known-good recording."""
    fingerprint_banners = sorted(
        {fp.user_agent or fp.server for fp in analysis.fingerprints if (fp.user_agent or fp.server)}
    )
    return {
        "declared_streams": sum(len(m.streams) for m in analysis.metadata),
        "observed_streams": len(analysis.rtp_streams),
        "codec_sets": _codec_sets(analysis),
        "metadata_present": bool(analysis.metadata),
        "fingerprint_banners": fingerprint_banners,
        "media_directions": sorted(
            {
                media.direction
                for m in analysis.sip_messages
                if m.sdp
                for media in m.sdp.media
                if media.direction
            }
        ),
    }


def diff_against_baseline(
    analysis: RecordingAnalysis, profile: dict
) -> list[RecordingFinding]:
    """Compare a call against a saved baseline profile and flag differences."""
    findings: list[RecordingFinding] = []

    def diff(what: str, expected, actual) -> None:
        if expected != actual:
            findings.append(
                RecordingFinding(
                    severity=Severity.WARN,
                    code=CODE_BASELINE_DIFF,
                    title=f"Differs from baseline: {what}",
                    detail=f"Baseline {what} = {expected!r}; this call = {actual!r}.",
                    owner=Owner.SBC,
                )
            )

    diff("declared streams", profile.get("declared_streams"), sum(len(m.streams) for m in analysis.metadata))
    diff("observed streams", profile.get("observed_streams"), len(analysis.rtp_streams))
    diff("metadata present", profile.get("metadata_present"), bool(analysis.metadata))

    base_codecs = {tuple(s) for s in profile.get("codec_sets", [])}
    this_codecs = {tuple(s) for s in _codec_sets(analysis)}
    new_codecs = this_codecs - base_codecs
    if new_codecs:
        findings.append(
            RecordingFinding(
                severity=Severity.WARN,
                code=CODE_BASELINE_DIFF,
                title="Differs from baseline: codec set",
                detail=f"Codec set(s) not seen in the baseline: {[list(c) for c in new_codecs]}.",
                owner=Owner.SBC,
            )
        )

    base_dirs = set(profile.get("media_directions", []))
    this_dirs = {
        media.direction
        for m in analysis.sip_messages
        if m.sdp
        for media in m.sdp.media
        if media.direction
    }
    if this_dirs - base_dirs:
        diff("media directions", sorted(base_dirs), sorted(this_dirs))

    return findings


__all__ = ["build_baseline_profile", "diff_against_baseline", "CODE_BASELINE_DIFF"]
