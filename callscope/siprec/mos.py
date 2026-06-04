"""Estimate call quality (MOS) from RTCP, using the ITU-T G.107 E-model.

This is a fully local, dependency-free implementation of the simplified
narrowband E-model. It turns the raw RTCP numbers CallScope already extracts
(loss fraction, interarrival jitter) into an R-factor and a MOS-CQ score per
stream and per reporting interval, so the report speaks the language everyone in
a QoS conversation already uses ("the agent stream dropped to MOS 1.9 during the
hold/retrieve window") instead of raw fractions.

Method (ITU-T G.107 simplified, A=0, narrowband):

    Id     = delay impairment from one-way mouth-to-ear delay Ta (ms)
    Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)     (random loss, BurstR = 1)
    R      = 93.2 - Id - Ie_eff
    MOS    = 1 + 0.035 R + 7e-6 R (R-60)(100-R)      (clamped to [1.0, 4.5])

Inputs and assumptions:
  * Ppl (packet-loss %) comes straight from the RTCP report block fraction.
  * One-way delay Ta = a configurable network baseline + a de-jitter buffer
    term estimated as 2x the measured jitter. RTCP round-trip is not reliably
    recoverable from a single SIPREC leg, so the network baseline is an explicit,
    documented assumption (config.DEFAULT_ONE_WAY_DELAY_MS) rather than a guess
    dressed up as a measurement.
  * Ie / Bpl are per-codec equipment-impairment and packet-loss-robustness
    factors from ITU-T G.113 Appendix I.

The narrowband model is applied to all codecs; for wideband codecs (e.g. G.722)
the absolute MOS is approximate, but the *trend* and the relative impact of loss
and jitter remain informative. Codecs are labelled so this is visible.
"""

from __future__ import annotations

from statistics import mean

from .. import config
from ..models import MosEstimate, MosSample, ObservedRtpStream, Owner, RecordingFinding, Severity

# payload type -> (codec name, clock Hz, Ie, Bpl)   [ITU-T G.113 App. I]
CODEC_TABLE: dict[int, tuple[str, int, float, float]] = {
    0: ("PCMU (G.711u)", 8000, 0.0, 25.1),
    8: ("PCMA (G.711a)", 8000, 0.0, 25.1),
    9: ("G.722", 16000, 13.0, 18.0),
    18: ("G.729", 8000, 11.0, 19.0),
    4: ("G.723.1", 8000, 15.0, 16.1),
    3: ("GSM", 8000, 20.0, 10.0),
    15: ("G.728", 8000, 7.0, 19.0),
}
_DEFAULT_CODEC = ("dynamic", 8000, 0.0, 25.1)

MOS_WARN_BELOW = 3.6   # below "good" (toll quality ~4.0; 3.6 = users start to notice)
MOS_ERROR_BELOW = 2.6  # below "poor" (many users dissatisfied)

CODE_MOS_LOW = "MOS_LOW"
CODE_MOS_BAD = "MOS_BAD"


def _to_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _to_float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def r_factor(loss_pct: float, one_way_delay_ms: float, ie: float, bpl: float) -> float:
    """Compute the E-model R-factor for given loss, delay, and codec factors."""
    ta = one_way_delay_ms
    # Delay impairment (simplified Idd term used across the industry).
    id_delay = 0.024 * ta
    if ta > 177.3:
        id_delay += 0.11 * (ta - 177.3)
    # Equipment + packet-loss impairment (random loss, burst ratio 1).
    ie_eff = ie + (95.0 - ie) * (loss_pct / (loss_pct + bpl)) if (loss_pct + bpl) else ie
    return 93.2 - id_delay - ie_eff


def r_to_mos(r: float) -> float:
    """Convert an R-factor to MOS-CQ, clamped to the valid [1.0, 4.5] range."""
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    mos = 1.0 + 0.035 * r + 7e-6 * r * (r - 60.0) * (100.0 - r)
    return max(1.0, min(4.5, round(mos, 2)))


def _codec_for_ssrc(ssrc: int | None, streams: list[ObservedRtpStream]):
    for s in streams:
        if s.ssrc == ssrc and s.payload_type is not None:
            return CODEC_TABLE.get(s.payload_type, _DEFAULT_CODEC)
    return _DEFAULT_CODEC


def _label_for_ssrc(ssrc: int | None, streams: list[ObservedRtpStream]):
    for s in streams:
        if s.ssrc == ssrc:
            return s.matched_sdp_label, (s.participant_name or s.participant_aor)
    return None, None


def estimate_mos(
    rtcp_rows: list[dict],
    streams: list[ObservedRtpStream],
    one_way_delay_ms: float | None = None,
) -> list[MosEstimate]:
    """Build a per-stream MOS estimate (with an interval trend) from RTCP rows."""
    base_delay = (
        one_way_delay_ms if one_way_delay_ms is not None else config.DEFAULT_ONE_WAY_DELAY_MS
    )
    from .rtcp_stats import iter_report_blocks

    by_ssrc: dict[int | None, list[tuple]] = {}
    for row in rtcp_rows:
        for ssrc, fraction, _cum, jitter, t_rel in iter_report_blocks(row):
            if fraction is None and jitter is None:
                continue
            by_ssrc.setdefault(ssrc, []).append((fraction or 0, jitter or 0, t_rel))

    estimates: list[MosEstimate] = []
    for ssrc, blocks in by_ssrc.items():
        codec_name, clock_hz, ie, bpl = _codec_for_ssrc(ssrc, streams)
        label, participant = _label_for_ssrc(ssrc, streams)
        samples: list[MosSample] = []
        for fraction, jitter_units, t_rel in blocks:
            loss_pct = (fraction / 256.0) * 100.0
            jitter_ms = jitter_units * 1000.0 / clock_hz if clock_hz else 0.0
            # de-jitter buffer adds roughly 2x the jitter to mouth-to-ear delay.
            delay = base_delay + 2.0 * jitter_ms
            r = r_factor(loss_pct, delay, ie, bpl)
            samples.append(
                MosSample(
                    time_relative=t_rel,
                    mos=r_to_mos(r),
                    r_factor=round(r, 1),
                    loss_pct=round(loss_pct, 2),
                    jitter_ms=round(jitter_ms, 2),
                )
            )
        if not samples:
            continue
        moses = [s.mos for s in samples]
        estimates.append(
            MosEstimate(
                ssrc=ssrc,
                label=label,
                participant=participant,
                codec=codec_name,
                mos_avg=round(mean(moses), 2),
                mos_min=round(min(moses), 2),
                r_factor_avg=round(mean(s.r_factor for s in samples), 1),
                loss_pct_avg=round(mean(s.loss_pct for s in samples), 2),
                jitter_ms_avg=round(mean(s.jitter_ms for s in samples), 2),
                one_way_delay_ms=base_delay,
                samples=sorted(samples, key=lambda s: (s.time_relative is None, s.time_relative or 0.0)),
            )
        )
    return estimates


def build_mos_findings(estimates: list[MosEstimate]) -> list[RecordingFinding]:
    findings: list[RecordingFinding] = []
    for e in estimates:
        who = e.participant or (f"label {e.label}" if e.label else (f"SSRC 0x{e.ssrc:08x}" if e.ssrc is not None else "stream"))
        if e.mos_min < MOS_ERROR_BELOW:
            sev, code = Severity.ERROR, CODE_MOS_BAD
            band = "poor"
        elif e.mos_min < MOS_WARN_BELOW:
            sev, code = Severity.WARN, CODE_MOS_LOW
            band = "degraded"
        else:
            continue
        findings.append(
            RecordingFinding(
                severity=sev,
                code=code,
                title=f"Low call quality (MOS {e.mos_min:.1f})",
                detail=(
                    f"{who} ({e.codec}) reached a {band} MOS of {e.mos_min:.1f} "
                    f"(avg {e.mos_avg:.1f}); avg loss {e.loss_pct_avg:.1f}%, "
                    f"avg jitter {e.jitter_ms_avg:.0f}ms, assumed one-way delay "
                    f"{e.one_way_delay_ms:.0f}ms."
                ),
                owner=Owner.NETWORK,
                recommendation="Correlate the low-MOS window with the timeline; if it aligns with a hold/retrieve or burst, the cause is signalling, not the path.",
            )
        )
    return findings


__all__ = [
    "estimate_mos",
    "build_mos_findings",
    "r_factor",
    "r_to_mos",
    "CODEC_TABLE",
    "MOS_WARN_BELOW",
    "MOS_ERROR_BELOW",
    "CODE_MOS_LOW",
    "CODE_MOS_BAD",
]
