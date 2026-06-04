"""Tests for pcap discovery and lightweight indexing."""

from __future__ import annotations

import struct

import pytest

from callscope.core.pcap_index import discover_pcaps, index_pcaps
from callscope.errors import PcapInputError


def _write_classic_pcap(path, ts_sec=1_700_000_111, ts_usec=500000):
    # 24-byte global header (little-endian, microsecond) + one record header.
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", ts_sec, ts_usec, 4, 4)
    path.write_bytes(global_header + record_header + b"\x00\x00\x00\x00")


def test_discover_single_file(tmp_path):
    p = tmp_path / "capture.pcap"
    _write_classic_pcap(p)
    found = discover_pcaps(str(p))
    assert found == [p]


def test_discover_directory(tmp_path):
    (tmp_path / "a.pcap").write_bytes(b"\xa1\xb2\xc3\xd4")
    (tmp_path / "b.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")
    (tmp_path / "ignore.txt").write_text("nope")
    found = discover_pcaps(str(tmp_path))
    names = sorted(p.name for p in found)
    assert names == ["a.pcap", "b.pcapng"]


def test_discover_glob(tmp_path):
    (tmp_path / "one.pcap").write_bytes(b"\xa1\xb2\xc3\xd4")
    (tmp_path / "two.pcap").write_bytes(b"\xa1\xb2\xc3\xd4")
    found = discover_pcaps(str(tmp_path / "*.pcap"))
    assert len(found) == 2


def test_discover_none_raises(tmp_path):
    with pytest.raises(PcapInputError):
        discover_pcaps(str(tmp_path / "does-not-exist-*.pcap"))


def test_index_detects_format_and_time(tmp_path):
    p = tmp_path / "capture.pcap"
    _write_classic_pcap(p, ts_sec=1_700_000_111, ts_usec=500000)
    infos = index_pcaps([p])
    assert len(infos) == 1
    info = infos[0]
    assert info.format_hint == "pcap"
    assert info.readable is True
    assert info.first_packet_time == pytest.approx(1_700_000_111.5, abs=0.01)


def test_index_detects_pcapng(tmp_path):
    p = tmp_path / "capture.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    infos = index_pcaps([p])
    assert infos[0].format_hint == "pcapng"


def test_index_unrecognized_format(tmp_path):
    p = tmp_path / "weird.pcap"
    p.write_bytes(b"\x00\x01\x02\x03")
    infos = index_pcaps([p])
    assert infos[0].readable is False
