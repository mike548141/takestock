"""The CrowdStrike Falcon outbound connection reader in takestock's readers library.

Each export is composed in its test, under the reader's default headings (or
others named in the settings), with made-up machine names and agent IDs and
small counts. Nothing here was captured from a real export.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import config, coverage
from takestock.readers import falcon_connections as reader
from takestock.readers import library

COLUMNS = ("aid", "ComputerName", "RemotePort", "_count")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    c = dataclasses.replace(ctx(reader.PLUGIN, path, settings),
                            port_table=config.load_port_encryption())
    return reader.step(c)


def _row(agent: str, port: str, n: int) -> dict:
    return {"aid": agent, "ComputerName": f"ws-{agent}", "RemotePort": port, "_count": str(n)}


def test_the_reader_is_in_the_library():
    assert library()["falcon_connections"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_COLLECTED
    assert coverage.nature_of(g) == coverage.NO_DATA
    assert coverage.impact_kind_of(g) == coverage.CHANGES_CONCLUSION


def test_an_empty_export_gives_the_same_gap(tmp_path):
    out = _run(_export(tmp_path / "empty.csv", []))
    assert out.records == [] and "holds no rows" in str(out.gaps[0])


def test_one_row_per_port_graded_by_the_port_table(tmp_path):
    path = _export(tmp_path / "c.csv", [
        _row("a1", "80", 30), _row("a2", "80", 12),      # cleartext
        _row("a1", "143", 5),                             # opportunistic
        _row("a2", "443", 9),                             # encrypted
        _row("a3", "8000", 2),                           # not in the table
    ])
    out = _run(path)
    rows = by_name(out.records)
    http = rows["Outbound http (80/tcp)"]
    assert http.verdict == "weak"
    assert http.flags == ["cleartext-egress:http", "cleartext-exposure:content"]
    assert http.usage_count == 42 and http.hosts_count == 2
    assert http.extra["host_share"] == "66%" and http.extra["estate_hosts"] == "3"
    assert http.port == "80" and http.collected_at == "2030-03-17"
    imap = rows["Outbound imap (143/tcp)"]
    assert imap.verdict == "unknown" and imap.flags == ["unverified-egress:imap"]
    assert rows["Outbound https (443/tcp)"].verdict == "n/a"
    other = rows["Outbound port-8000 (8000/tcp)"]
    assert other.verdict == "unknown"
    assert other.flags == ["ungraded:port-encryption:8000"]
    assert other.extra["posture"] == "unclassified"
    assert out.gaps == []


def test_machines_are_counted_never_named(tmp_path):
    out = _run(_export(tmp_path / "c.csv", [_row("a1", "80", 3), _row("a2", "80", 4)]))
    for a in out.records:
        assert "ws-a1" not in a.notes and "ws-a1" not in str(a.extra)


def test_the_scope_row_counts_machines_and_ports(tmp_path):
    out = _run(_export(tmp_path / "c.csv", [_row("a1", "80", 3), _row("a2", "21", 1),
                                            _row("", "80", 2)]))
    scope = by_name(out.records)["Outbound connection scope"]
    assert scope.verdict == "n/a" and scope.flags == ["scope-cleartext-ports-only"]
    assert scope.extra == {"machines": "3", "ports": "2"}  # a blank ID falls back to the name


def test_a_row_with_no_id_and_no_name_is_counted_but_no_machine(tmp_path):
    path = _export(tmp_path / "c.csv", [_row("a1", "80", 3),
                                        {"aid": "", "ComputerName": "", "RemotePort": "80",
                                         "_count": "5"}])
    rows = by_name(_run(path).records)
    assert rows["Outbound http (80/tcp)"].usage_count == 8
    assert rows["Outbound http (80/tcp)"].hosts_count == 1
    assert rows["Outbound connection scope"].extra["machines"] == "1"


def test_a_blank_count_counts_one_event(tmp_path):
    path = _export(tmp_path / "c.csv", [{"aid": "a1", "RemotePort": "80", "_count": ""}])
    assert by_name(_run(path).records)["Outbound http (80/tcp)"].usage_count == 1


def test_other_headings_are_named_in_settings(tmp_path):
    path = _export(tmp_path / "c.csv", [{"Agent": "a1", "Port": "23", "Seen": "6"}],
                   ("Agent", "Port", "Seen"))
    out = _run(path, {"columns": {"agent_id": "Agent", "port": "Port", "count": "seen"}})
    telnet = by_name(out.records)["Outbound telnet (23/tcp)"]
    assert telnet.verdict == "weak" and telnet.usage_count == 6
