"""Tests for the CLI surface (help and argument validation)."""

from __future__ import annotations

from click.testing import CliRunner

from callscope.cli import main


def test_main_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "siprec" in result.output


def test_siprec_help_lists_options():
    result = CliRunner().invoke(main, ["siprec", "--help"])
    assert result.exit_code == 0
    for opt in ["--call-id", "--pcaps", "--out", "--tls-keylog", "--format"]:
        assert opt in result.output


def test_siprec_missing_call_id_fails():
    result = CliRunner().invoke(main, ["siprec", "--pcaps", "x.pcap", "--out", "outdir"])
    assert result.exit_code != 0
    assert "call-id" in result.output.lower()


def test_siprec_missing_pcaps_fails():
    result = CliRunner().invoke(main, ["siprec", "--call-id", "abc", "--out", "outdir"])
    assert result.exit_code != 0
    assert "pcaps" in result.output.lower()


def test_siprec_bad_format_rejected(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            "siprec",
            "--call-id", "abc",
            "--pcaps", "x.pcap",
            "--out", str(tmp_path / "out"),
            "--format", "bogus",
        ],
    )
    assert result.exit_code != 0
    assert "format" in result.output.lower()


def test_version_option():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "callscope" in result.output.lower()
