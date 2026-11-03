"""The CrowdStrike Falcon outbound TLS handshake reader in takestock's readers library.

Each export is composed in its test, under the reader's default headings (or
others named in the settings), with made-up machines and programs,
``example.test`` destinations and small counts. Nothing here was captured
from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_tls_clienthello as reader
from takestock.readers import library

COLUMNS = ("ComputerName", "aid", "DomainName", "RemotePort", "TlsVersion", "ImageFileName",
           "_count")
OLD = "/opt/example/bin/fetch-a"
NEW = "/opt/example/bin/fetch-b"
SCOPE = "Outbound handshake scope"


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _hello(machine: str, name: str, value: str, n: int, program: str = OLD) -> dict:
    return {"ComputerName": machine, "aid": f"id-{machine}", "DomainName": name,
            "RemotePort": "443", "TlsVersion": value, "ImageFileName": program,
            "_count": str(n)}


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _rows(tmp_path: Path) -> Path:
    return _export(tmp_path / "t.csv", [
        _hello("m-a", "feeds.example.test", "2", 6),
        _hello("m-b", "feeds.example.test", "2", 4),
        _hello("m-a", "api.example.test", "3", 9, NEW),
        _hello("m-b", "", "2", 2, NEW),
        _hello("m-c", "api.example.test", "3", 5, NEW),
    ])


def test_the_reader_is_in_the_library():
    assert library()["falcon_tls_clienthello"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED


def test_one_row_per_program_asking_for_a_lower_value(tmp_path):
    rows = by_name(_run(_rows(tmp_path)).records)
    old = rows[f"Outbound handshakes — {OLD}"]
    assert old.software == OLD and old.verdict == "n/a" and old.protocol == "tls"
    assert old.flags == ["outbound-tls-lower-tier:10", "outbound-tls-lower-tier-only"]
    assert old.hosts_count == 2
    assert old.extra == {"program": OLD, "lower_tier_handshakes": "10",
                         "upper_tier_handshakes": "0", "machines": "2",
                         "named_destinations": "1"}
    new = rows[f"Outbound handshakes — {NEW}"]
    assert new.flags == ["outbound-tls-lower-tier:2"]
    assert new.extra["upper_tier_handshakes"] == "14"
    assert len(rows) == 3  # two programs and the scope row


def test_without_names_no_version_is_named_and_a_gap_says_so(tmp_path):
    out = _run(_rows(tmp_path))
    assert len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_MEASURED
    assert coverage.impact_kind_of(g) == coverage.NARROWS_CONFIDENCE
    assert coverage.nature_of(g) == coverage.LOW_FIDELITY
    assert "TLS 1." not in " ".join(a.notes for a in out.records)
    assert by_name(out.records)[SCOPE].flags == ["scope-enum-unnamed"]


def test_version_names_name_the_values_and_close_the_gap(tmp_path):
    names = {"0": "TLS 1.0", "1": "TLS 1.1", "2": "TLS 1.2", "3": "TLS 1.3"}
    out = _run(_rows(tmp_path), {"version_names": names})
    assert out.gaps == []
    rows = by_name(out.records)
    assert "TLS 1.2 (value 2)" in rows[f"Outbound handshakes — {OLD}"].notes
    assert rows[SCOPE].flags == []
    assert all(a.verdict == "n/a" for a in out.records)


def test_the_scope_row_counts_the_population(tmp_path):
    scope = by_name(_run(_rows(tmp_path)).records)[SCOPE]
    assert scope.hosts_count == 3
    assert scope.extra == {"handshakes": "26", "machines": "3", "rows": "5",
                           "named_destinations": "2", "lower_tier_handshakes": "12",
                           "upper_tier_handshakes": "14", "programs": "2",
                           "programs_in_lower_tier": "2", "unfiltered_export_handshakes": "0"}
    assert "2 handshakes carry no destination name" in scope.notes


def test_a_value_not_listed_is_placed_nowhere(tmp_path):
    path = _export(tmp_path / "t.csv", [_hello("m-a", "a.example.test", "3", 4, NEW),
                                        _hello("m-a", "a.example.test", "9", 3)])
    out = _run(path)
    rows = by_name(out.records)
    assert list(rows) == [SCOPE]
    assert rows[SCOPE].extra["handshakes"] == "7"
    assert "carry a value this reader does not place (9)" in rows[SCOPE].notes


def test_the_values_setting_moves_the_upper_value(tmp_path):
    out = _run(_rows(tmp_path), {"values": ["2", "3", "4"]})
    rows = by_name(out.records)
    assert rows[f"Outbound handshakes — {NEW}"].extra["lower_tier_handshakes"] == "16"


def test_the_distribution_export_reconciles_the_population(tmp_path):
    main = _rows(tmp_path)
    whole = _export(tmp_path / "d.csv", [{"TlsVersion": "2", "_count": "12"},
                                         {"TlsVersion": "3", "_count": "14"}],
                    ("TlsVersion", "_count"))
    scope = by_name(_run(main, {"distribution": str(whole)}).records)[SCOPE]
    assert scope.flags == ["scope-enum-unnamed", "scope-reconciled-to-whole-event-population"]
    assert scope.extra["unfiltered_export_handshakes"] == "26"
    assert "whole event population" in scope.notes
    part = _export(tmp_path / "e.csv", [{"TlsVersion": "2", "_count": "52"}],
                   ("TlsVersion", "_count"))
    scope = by_name(_run(main, {"distribution": str(part)}).records)[SCOPE]
    assert "holds 50% of the events and is a selection" in scope.notes
    assert scope.flags == ["scope-enum-unnamed"]
    assert scope.extra["unfiltered_export_handshakes"] == "52"


def test_a_platform_export_names_the_machines_operating_systems(tmp_path):
    platforms = _export(tmp_path / "p.csv", [
        {"Name": "M-A.example.test", "Platform": "Example OS A"},
        {"Name": "m-b", "Platform": "Example OS B"},
        {"Name": "m-z", "Platform": "Example OS A"},
    ], ("Name", "Platform"))
    settings = {"platforms": {"file": str(platforms), "host_column": "Name",
                              "os_column": "Platform"}}
    scope = by_name(_run(_rows(tmp_path), settings).records)[SCOPE]
    assert ("By the platform export, the machines here run: (no operating system recorded): 1, "
            "Example OS A: 1, Example OS B: 1.") in scope.notes


def test_other_headings_are_named_in_settings(tmp_path):
    path = _export(tmp_path / "t.csv",
                   [{"Host": "m-a", "Version": "2", "Hellos": "3", "Exe": OLD}],
                   ("Host", "Version", "Hellos", "Exe"))
    out = _run(path, {"columns": {"machine": "Host", "version": "Version",
                                  "count": "Hellos", "program": "Exe"}})
    assert by_name(out.records)[f"Outbound handshakes — {OLD}"].extra[
        "lower_tier_handshakes"] == "3"
