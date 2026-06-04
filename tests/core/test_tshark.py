"""Tests for the tshark/mergecap wrappers.

These avoid requiring a real tshark by monkeypatching tool discovery and the
subprocess runner, while still exercising argument-building and output parsing.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from callscope.core import tshark
from callscope.errors import TsharkExecutionError, TsharkNotAvailable


def test_availability_returns_bool():
    assert isinstance(tshark.tshark_available(), bool)
    assert isinstance(tshark.mergecap_available(), bool)


def test_run_tshark_fields_requires_fields():
    with pytest.raises(ValueError):
        tshark.run_tshark_fields(Path("x.pcap"), [])


def test_merge_pcaps_empty_inputs_raises():
    with pytest.raises(TsharkExecutionError):
        tshark.merge_pcaps([], Path("out.pcapng"))


def test_run_tshark_json_without_tool_raises(monkeypatch):
    monkeypatch.setattr(tshark.platform_utils, "find_tshark", lambda: None)
    with pytest.raises(TsharkNotAvailable):
        tshark.run_tshark_json(Path("x.pcap"))


def _fake_completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["tshark"], returncode=0, stdout=stdout, stderr="")


def test_run_tshark_fields_parses_tab_output(monkeypatch):
    monkeypatch.setattr(tshark.platform_utils, "find_tshark", lambda: "/usr/bin/tshark")
    output = "frame.number\trtp.ssrc\n1\t0x1111\n2\t0x2222\n"
    monkeypatch.setattr(tshark, "_run", lambda cmd, timeout=600: _fake_completed(output))
    rows = tshark.run_tshark_fields(Path("x.pcap"), ["frame.number", "rtp.ssrc"])
    assert rows == [
        {"frame.number": "1", "rtp.ssrc": "0x1111"},
        {"frame.number": "2", "rtp.ssrc": "0x2222"},
    ]


def test_run_tshark_json_parses(monkeypatch):
    monkeypatch.setattr(tshark.platform_utils, "find_tshark", lambda: "/usr/bin/tshark")
    monkeypatch.setattr(tshark, "_run", lambda cmd, timeout=600: _fake_completed('[{"a": 1}]'))
    data = tshark.run_tshark_json(Path("x.pcap"))
    assert data == [{"a": 1}]


def test_run_tshark_json_empty_output(monkeypatch):
    monkeypatch.setattr(tshark.platform_utils, "find_tshark", lambda: "/usr/bin/tshark")
    monkeypatch.setattr(tshark, "_run", lambda cmd, timeout=600: _fake_completed(""))
    assert tshark.run_tshark_json(Path("x.pcap")) == []
