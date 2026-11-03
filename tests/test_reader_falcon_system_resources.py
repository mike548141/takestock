"""The CrowdStrike Falcon firmware reader in takestock's readers library.

Each export is composed in its test with made-up machines, makers and
firmware versions. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import falcon_system_resources as reader
from takestock.readers import library

COLUMNS = ("hostname", "os_version", "bios_manufacturer", "bios_version")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _row(machine: str, maker: str, version: str, os_name: str = "Exampix 9") -> dict:
    return {"hostname": machine, "os_version": os_name, "bios_manufacturer": maker,
            "bios_version": version}


def _by_name(records):
    return {a.name: a for a in records}


def test_the_reader_is_in_the_library():
    assert library()["falcon_system_resources"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.NARROWS_CONFIDENCE


def test_families_shapes_and_order():
    assert reader.family_of("Q91 Ver. 3.41") == "Q91"
    assert reader.family_of("XYZ12.00V.77") == "XYZ12"
    assert reader.shape("Q91 Ver. 3.41") == reader.shape("Q91 Ver. 12.9")
    assert reader.order_key("Q91 Ver. 12.9") > reader.order_key("Q91 Ver. 3.41")


def test_behind_the_estates_own_newest_within_one_family(tmp_path):
    path = _export(tmp_path / "f.csv", [
        _row("ws-01", "Acme", "Q91 Ver. 3.41"), _row("ws-02", "Acme", "Q91 Ver. 3.41"),
        _row("ws-03", "Acme", "Q91 Ver. 3.52"),
        _row("ws-04", "Acme", "Q91 Ver. 12.9"),
        _row("ws-05", "Acme", "R07 Ver. 1.01"),         # another family: never compared
    ])
    out = _run(path)
    rows = _by_name(out.records)
    old = rows["Firmware Acme Q91 Ver. 3.41"]
    assert old.flags == ["firmware-census:2", "firmware-behind-estate-peers:2"]
    assert old.verdict == "n/a" and old.extra["family_hosts"] == "4"
    assert "Q91 Ver. 12.9" in old.notes and "50%" in old.notes
    assert rows["Firmware Acme Q91 Ver. 3.52"].flags[1] == "firmware-behind-estate-peers:1"
    assert rows["Firmware Acme Q91 Ver. 12.9"].flags == ["firmware-census:1"]
    assert rows["Firmware Acme R07 Ver. 1.01"].flags == ["firmware-census:1"]
    scope = rows["Firmware census scope"]
    assert scope.flags == ["scope-no-firmware-currency-baseline"]
    assert scope.extra["behind_estate_pairs"] == "2" and scope.extra["behind_estate_hosts"] == "3"
    assert scope.extra["manufacturers"] == "1" and scope.extra["pairs"] == "4"
    assert out.gaps == []


def test_a_family_numbered_two_ways_is_not_ranked(tmp_path):
    path = _export(tmp_path / "f.csv", [
        _row("ws-01", "Acme", "Q91 Ver. 3.41"), _row("ws-02", "Acme", "Q91 Build 3"),
    ])
    rows = _by_name(_run(path).records)
    for name in ("Firmware Acme Q91 Ver. 3.41", "Firmware Acme Q91 Build 3"):
        assert rows[name].flags == ["firmware-census:1", "firmware-spread-unordered"]


def test_machines_count_once_and_blank_firmware_is_counted(tmp_path):
    path = _export(tmp_path / "f.csv", [
        _row("ws-01", "Acme", "Q91 Ver. 3.41"), _row("WS-01", "Acme", "Q91 Ver. 3.41"),
        _row("ws-02", "", ""),
    ])
    rows = _by_name(_run(path).records)
    assert rows["Firmware Acme Q91 Ver. 3.41"].hosts_count == 1
    scope = rows["Firmware census scope"]
    assert scope.extra["rows"] == "3" and scope.extra["distinct_hosts"] == "2"
    assert "1 row(s) carried no firmware fields" in scope.notes


def test_other_headings_are_named_in_columns(tmp_path):
    path = _export(tmp_path / "f.csv", [
        {"Device": "ws-01", "Platform": "Exampix 9", "Maker": "Acme", "Firmware": "Q91 Ver. 3.41"},
    ], ("Device", "Platform", "Maker", "Firmware"))
    out = _run(path, {"columns": {"machine": ["hostname", "Device"], "os": "Platform",
                                  "bios_manufacturer": "Maker", "bios_version": "Firmware"}})
    row = _by_name(out.records)["Firmware Acme Q91 Ver. 3.41"]
    assert row.extra["os_mix"] == "Exampix 9: 1"
