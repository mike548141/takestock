"""The CrowdStrike Falcon SHA-1 module-signature reader in takestock's readers library.

Each export is composed in its test with made-up machine names and small
counts. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import falcon_sha1_signed_modules as reader
from takestock.readers import library

COLUMNS = ("aid", "ComputerName", "_count")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["falcon_sha1_signed_modules"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_an_export_with_no_machine_column_is_refused(tmp_path):
    out = _run(_export(tmp_path / "m.csv", [{"Thing": "x", "_count": "3"}], ("Thing", "_count")))
    assert out.records == [] and "no column for the machine" in str(out.gaps[0])


def test_one_row_for_the_population_with_the_primitive_and_a_gap(tmp_path):
    path = _export(tmp_path / "m.csv", [
        {"aid": "a1", "ComputerName": "WS-01.example.test", "_count": "7"},
        {"aid": "a1", "ComputerName": "ws-01", "_count": "2"},
        {"aid": "a2", "ComputerName": "ws-02", "_count": "1"},
        {"aid": "a3", "ComputerName": "ws-03", "_count": "40"},
        {"aid": "a4", "ComputerName": "", "_count": ""},     # no name: keyed by sensor, count 1
    ])
    out = _run(path, {"top_machines": 2})
    assert len(out.records) == 1
    row = out.records[0]
    assert row.name == "Software signed with SHA-1, loaded on the machines"
    assert row.hashes == ["sha1"] and row.verdict == "unknown"
    assert row.flags == ["sha1-signing-position-unresolved"]
    assert row.hosts_count == 4 and row.usage_count == 51
    assert row.extra["median_events_per_machine"] == "5"
    assert row.extra["max_events_per_machine"] == "40"
    assert row.extra["busiest_machines"] == "ws-03=40; ws-01=9"
    assert row.collected_at == "2030-03-17"
    assert len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_MEASURED
    assert coverage.nature_of(g) == coverage.LOW_FIDELITY and "4 machines" in str(g)


def test_the_platform_export_places_the_machines(tmp_path):
    path = _export(tmp_path / "m.csv", [
        {"aid": "a1", "ComputerName": "ws-01", "_count": "3"},
        {"aid": "a2", "ComputerName": "hostq-1", "_count": "1"},
        {"aid": "a3", "ComputerName": "ws-09", "_count": "1"},
    ])
    platforms = write(tmp_path / "p.csv", ("Name", "Platform"), [
        {"Name": "WS-01.example.test", "Platform": "Windows 99"},
        {"Name": "ws-01.example.test", "Platform": "Windows 99"},   # a second adapter
        {"Name": "ws-02", "Platform": "Windows 99"},
        {"Name": "hostq-1", "Platform": "Exampix 9"},
    ])
    out = _run(path, {"platforms": {"file": str(platforms), "host_column": "Name",
                                    "os_column": "Platform"}})
    extra = out.records[0].extra
    assert (extra["machines_windows"], extra["machines_other_platform"],
            extra["machines_not_in_census"]) == ("1", "1", "1")
    # Two rows for one machine count once.
    assert extra["census_windows_machines"] == "2"
    assert "reaches 1 of them" in out.records[0].notes


def test_without_a_platform_export_nothing_is_placed(tmp_path):
    path = _export(tmp_path / "m.csv", [{"aid": "a1", "ComputerName": "ws-01", "_count": "3"}])
    extra = _run(path).records[0].extra
    assert extra["machines_not_in_census"] == "1" and extra["census_windows_machines"] == "0"


def test_another_count_heading_is_named_in_columns(tmp_path):
    path = _export(tmp_path / "m.csv", [{"ComputerName": "ws-01", "hits": "6"}],
                   ("ComputerName", "hits"))
    assert _run(path, {"columns": {"count": "hits"}}).records[0].usage_count == 6
