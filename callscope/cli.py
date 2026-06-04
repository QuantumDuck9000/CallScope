"""Command-line interface for CallScope."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__, config
from .errors import CallScopeError
from .platform_utils import normalize_path


def _echo_verbose(enabled: bool, message: str) -> None:
    """Emit a verbose log line, using rich if available, else plain click."""
    if not enabled:
        return
    try:
        from rich.console import Console  # noqa: PLC0415 - optional dependency

        Console(stderr=True).log(message)
    except Exception:  # noqa: BLE001 - rich is optional; fall back to click
        click.echo(message, err=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="callscope")
def main() -> None:
    """CallScope — a SIPREC packet capture analyzer."""


@main.command("siprec")
@click.option("--call-id", "call_id", required=True, help="SIPREC Recording Session Call-ID.")
@click.option(
    "--pcaps",
    "pcaps",
    required=True,
    help="Capture input: a file, a directory, or a glob pattern.",
)
@click.option(
    "--out",
    "out",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Output directory.",
)
@click.option(
    "--tls-keylog",
    "tls_keylog",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="TLS key log file for decrypting SIP-over-TLS.",
)
@click.option("--keep-temp", is_flag=True, default=False, help="Keep temporary extracted files.")
@click.option("--verbose", is_flag=True, default=False, help="Verbose logging.")
@click.option("--no-html", "no_html", is_flag=True, default=False, help="Skip HTML report.")
@click.option(
    "--format",
    "output_format",
    default=config.DEFAULT_OUTPUT_FORMAT,
    show_default=True,
    help="Output capture format: pcapng or pcap.",
)
@click.option(
    "--save-baseline",
    "save_baseline",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a golden-baseline profile from this (known-good) call.",
)
@click.option(
    "--baseline",
    "baseline",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Diff this call against a saved baseline profile.",
)
def siprec_command(
    call_id: str,
    pcaps: str,
    out: Path,
    tls_keylog: Path | None,
    keep_temp: bool,
    verbose: bool,
    no_html: bool,
    output_format: str,
    save_baseline: Path | None,
    baseline: Path | None,
) -> None:
    """Analyze a SIPREC recording session and build a report."""
    output_format = output_format.lower()
    if output_format not in config.SUPPORTED_OUTPUT_FORMATS:
        raise click.BadParameter(
            f"Unsupported format {output_format!r}. "
            f"Choose one of: {', '.join(sorted(config.SUPPORTED_OUTPUT_FORMATS))}.",
            param_hint="--format",
        )

    # Imported here so `--help` works even on a minimal environment.
    from .core.extractor import ExtractionOptions, run_siprec_extraction

    opts = ExtractionOptions(
        call_id=call_id,
        pcaps=pcaps,
        out_dir=normalize_path(out),
        tls_keylog=normalize_path(tls_keylog) if tls_keylog else None,
        keep_temp=keep_temp,
        output_format=output_format,
        write_html=not no_html,
    )

    _echo_verbose(verbose, f"Starting SIPREC extraction for Call-ID {call_id}")
    try:
        analysis = run_siprec_extraction(opts)
    except CallScopeError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    health = analysis.overall_health.value if analysis.overall_health else "UNKNOWN"
    click.echo(f"Done. Overall health: {health}")
    click.echo(f"Output written to: {opts.out_dir}")

    if save_baseline is not None:
        import json

        from .core.baseline import build_baseline_profile

        profile = build_baseline_profile(analysis)
        normalize_path(save_baseline).write_text(json.dumps(profile, indent=2), encoding="utf-8")
        click.echo(f"Baseline profile written to: {save_baseline}")

    if baseline is not None:
        import json

        from .core.baseline import diff_against_baseline

        profile = json.loads(normalize_path(baseline).read_text(encoding="utf-8"))
        diffs = diff_against_baseline(analysis, profile)
        from .core import writer

        writer.write_json(opts.out_dir / "baseline-diff.json", diffs)
        click.echo(f"Baseline diff: {len(diffs)} difference(s) vs {baseline}")

    _echo_verbose(
        verbose,
        f"{len(analysis.sip_messages)} SIP messages, "
        f"{len(analysis.rtp_streams)} RTP streams, "
        f"{len(analysis.findings)} findings",
    )


@main.command("extract")
@click.option("--call-id", "call_id", required=True, help="SIPREC Recording Session Call-ID.")
@click.option("--pcaps", "pcaps", required=True, help="Capture input: file, directory, or glob.")
@click.option(
    "--out",
    "out",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Output directory.",
)
@click.option(
    "--tls-keylog",
    "tls_keylog",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="TLS key log file.",
)
@click.option(
    "--format",
    "output_format",
    default=config.DEFAULT_OUTPUT_FORMAT,
    show_default=True,
    help="Output capture format: pcapng or pcap.",
)
def extract_command(
    call_id: str,
    pcaps: str,
    out: Path,
    tls_keylog: Path | None,
    output_format: str,
) -> None:
    """Extract the focused recording-session capture only (no analysis report)."""
    output_format = output_format.lower()
    if output_format not in config.SUPPORTED_OUTPUT_FORMATS:
        raise click.BadParameter(
            f"Unsupported format {output_format!r}.",
            param_hint="--format",
        )

    from .core.extractor import ExtractionOptions, run_siprec_extraction

    opts = ExtractionOptions(
        call_id=call_id,
        pcaps=pcaps,
        out_dir=normalize_path(out),
        tls_keylog=normalize_path(tls_keylog) if tls_keylog else None,
        keep_temp=False,
        output_format=output_format,
        write_html=False,
    )
    try:
        analysis = run_siprec_extraction(opts)
    except CallScopeError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    pcap_name = analysis.output_pcap.name if analysis.output_pcap else "(none)"
    click.echo(f"Extracted capture: {pcap_name}")


@main.command("batch")
@click.option("--pcaps", "pcaps", required=True, help="Capture input shared by all calls: file, directory, or glob.")
@click.option(
    "--call-ids",
    "call_ids_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Text file with one SIPREC Call-ID per line.",
)
@click.option(
    "--out",
    "out",
    default=Path("callscope-batch"),
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Output directory (one subfolder per call, plus aggregate.json).",
)
@click.option("--no-html", "no_html", is_flag=True, default=False, help="Skip per-call HTML reports.")
@click.option("--verbose", is_flag=True, default=False, help="Verbose logging.")
def batch_command(pcaps: str, call_ids_file: Path, out: Path, no_html: bool, verbose: bool) -> None:
    """Analyze many SIPREC calls and emit an aggregate report (rates + time series)."""
    import json

    from .core.aggregate import aggregate_analyses
    from .core.extractor import ExtractionOptions, run_siprec_extraction

    out_dir = normalize_path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    call_ids = [
        line.strip()
        for line in normalize_path(call_ids_file).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not call_ids:
        raise click.BadParameter("No Call-IDs found in the file.", param_hint="--call-ids")

    analyses = []
    for cid in call_ids:
        safe = cid.replace("@", "_at_").replace("/", "_")
        opts = ExtractionOptions(
            call_id=cid,
            pcaps=pcaps,
            out_dir=out_dir / safe,
            tls_keylog=None,
            keep_temp=False,
            output_format=config.DEFAULT_OUTPUT_FORMAT,
            write_html=not no_html,
        )
        try:
            analyses.append(run_siprec_extraction(opts))
            _echo_verbose(verbose, f"Analyzed {cid}")
        except CallScopeError as exc:
            click.echo(f"warning: {cid}: {exc}", err=True)

    summary = aggregate_analyses(analyses)
    (out_dir / "aggregate.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    click.echo(
        f"Batch done: {summary['calls']} call(s), "
        f"{summary['failed']} failed ({summary['failure_rate'] * 100:.1f}%)."
    )
    click.echo(f"Aggregate written to: {out_dir / 'aggregate.json'}")


if __name__ == "__main__":  # pragma: no cover
    main()
