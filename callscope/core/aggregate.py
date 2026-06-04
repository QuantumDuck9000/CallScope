"""Aggregate analysis across many SIPREC calls.

One failed recording is a fluke; a *rate* with a trend line is evidence. This
turns per-call findings into batch statistics — failure rate, finding counts by
code and owner, codec-flap rate, one-way rate — plus a daily time series so
failures can be lined up against a change window.
"""

from __future__ import annotations

import datetime as dt

from ..models import Owner, RecordingAnalysis, Severity


def _call_failed(analysis: RecordingAnalysis) -> bool:
    return analysis.overall_health in (Severity.ERROR, Severity.CRITICAL)


def _start_day(analysis: RecordingAnalysis) -> str | None:
    epochs = [m.timestamp_epoch for m in analysis.sip_messages if m.timestamp_epoch is not None]
    if not epochs:
        return None
    return dt.datetime.fromtimestamp(min(epochs), tz=dt.timezone.utc).strftime("%Y-%m-%d")


def aggregate_analyses(analyses: list[RecordingAnalysis]) -> dict:
    """Compute batch statistics and a daily time series over the analyses."""
    total = len(analyses)
    failed = sum(1 for a in analyses if _call_failed(a))

    by_code: dict[str, int] = {}
    by_owner: dict[str, int] = {}
    codec_flaps = 0
    one_way = 0

    for a in analyses:
        for f in a.findings:
            by_code[f.code] = by_code.get(f.code, 0) + 1
            owner = f.owner.value if isinstance(f.owner, Owner) else "UNKNOWN"
            by_owner[owner] = by_owner.get(owner, 0) + 1
        if any(b.codec_renegotiation for b in a.bursts):
            codec_flaps += 1
        declared = sum(len(m.streams) for m in a.metadata)
        if declared >= 2 and len(a.rtp_streams) < declared:
            one_way += 1

    # Daily time series of total vs failed.
    series: dict[str, dict[str, int]] = {}
    for a in analyses:
        day = _start_day(a)
        if day is None:
            continue
        bucket = series.setdefault(day, {"total": 0, "failed": 0})
        bucket["total"] += 1
        if _call_failed(a):
            bucket["failed"] += 1

    time_series = [
        {"date": day, "total": v["total"], "failed": v["failed"]}
        for day, v in sorted(series.items())
    ]

    return {
        "calls": total,
        "failed": failed,
        "failure_rate": round(failed / total, 4) if total else 0.0,
        "codec_flap_calls": codec_flaps,
        "one_way_calls": one_way,
        "findings_by_code": dict(sorted(by_code.items(), key=lambda kv: -kv[1])),
        "findings_by_owner": by_owner,
        "time_series": time_series,
    }


__all__ = ["aggregate_analyses"]
