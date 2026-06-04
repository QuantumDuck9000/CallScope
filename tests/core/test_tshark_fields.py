"""run_tshark_fields must survive tshark field-name drift across versions."""

from __future__ import annotations

import types
from pathlib import Path
from unittest import mock

from callscope.core import tshark
from callscope.errors import TsharkExecutionError


def test_invalid_field_is_dropped_and_retried():
    calls = []

    def fake_run(cmd, timeout=60):
        calls.append(cmd)
        if "rtcp.ssrc.cumulative" in cmd:
            raise TsharkExecutionError(
                "tshark exited with code 1: tshark: Some fields aren't valid:\n\trtcp.ssrc.cumulative"
            )
        out = "rtcp.pt\trtcp.ssrc.fraction\n200\t0\n"
        return types.SimpleNamespace(stdout=out, stderr="", returncode=0)

    with mock.patch.object(tshark, "_run", side_effect=fake_run), mock.patch.object(
        tshark, "_require_tshark", return_value="/usr/bin/tshark"
    ):
        rows = tshark.run_tshark_fields(
            Path("x.pcap"),
            ["rtcp.pt", "rtcp.ssrc.fraction", "rtcp.ssrc.cumulative"],
            display_filter="rtcp",
        )
    assert len(calls) == 2
    assert "rtcp.ssrc.cumulative" not in calls[1]
    assert rows and rows[0]["rtcp.pt"] == "200"


def test_parse_invalid_fields_extracts_names():
    msg = "tshark: Some fields aren't valid:\n\trtcp.ssrc.cumulative\n\tfoo.bar"
    assert tshark._parse_invalid_fields(msg) == ["rtcp.ssrc.cumulative", "foo.bar"]


def test_all_fields_invalid_raises():
    def fake_run(cmd, timeout=60):
        raise TsharkExecutionError("Some fields aren't valid:\n\tonly.field")

    with mock.patch.object(tshark, "_run", side_effect=fake_run), mock.patch.object(
        tshark, "_require_tshark", return_value="/usr/bin/tshark"
    ):
        try:
            tshark.run_tshark_fields(Path("x.pcap"), ["only.field"])
            raise AssertionError("expected TsharkExecutionError")
        except TsharkExecutionError:
            pass
