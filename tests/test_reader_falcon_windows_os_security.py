"""The CrowdStrike Falcon Windows platform protection reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (the
fields' own names) or others named in the settings, with made-up machines
and signal names. Nothing here was captured from a real export.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import falcon_windows_os_security as reader
from takestock.readers import library

CONTROLS = tuple(field for field, _ in reader.CONTROLS)
COLUMNS = ("hostname", "mac_address", *CONTROLS)


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _row(machine: str, state: str = "Enabled", **over: str) -> dict:
    return {"hostname": machine, "mac_address": "00-00-5E-00-53-01",
            **{c: state for c in CONTROLS}, **over}


def _by_name(records):
    return {a.name: a for a in records}


def test_the_reader_is_in_the_library():
    assert library()["falcon_windows_os_security"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED


def test_one_row_per_control_counting_readings(tmp_path):
    path = _export(tmp_path / "w.csv", [
        _row("ws-01"), _row("ws-02", vbs="Disabled"), _row("ws-02", vbs="Not available"),
        _row("ws-03", credential_guard="Disabled"),
    ])
    out = _run(path)
    rows = _by_name(out.records)
    vbs = rows["Windows platform protection — vbs"]
    assert vbs.verdict == "n/a" and vbs.flags == ["platform-control-readings:4"]
    assert (vbs.extra["enabled"], vbs.extra["disabled"], vbs.extra["not_available"]) == (
        "2", "1", "1")
    assert vbs.hosts_count == 3 and "hypervisor" in vbs.notes
    assert len([r for r in out.records if r.name.startswith("Windows platform protection — ")]
               ) == len(CONTROLS)
    scope = rows["Windows platform protection scope"]
    assert scope.flags == ["scope-windows-only"] and scope.extra["rows"] == "4"
    assert scope.extra["distinct_hosts"] == "3" and scope.extra["columns_unread"] == "0"
    assert out.gaps == []


def test_a_protection_off_on_every_reading_is_flagged(tmp_path):
    path = _export(tmp_path / "w.csv", [_row("ws-01", system_guard="Disabled"),
                                        _row("ws-02", system_guard="Disabled")])
    row = _by_name(_run(path).records)["Windows platform protection — system_guard"]
    assert "platform-control-off-everywhere" in row.flags


def test_an_unidentified_column_is_counted_flagged_and_a_gap(tmp_path):
    columns = (*COLUMNS, "Widget shield status")
    path = _export(tmp_path / "w.csv", [{**_row("ws-01"), "Widget shield status": "Disabled"}],
                   columns)
    out = _run(path, {"unidentified": ["Widget shield status"]})
    row = _by_name(out.records)["Windows platform protection — Widget shield status"]
    assert row.flags == ["platform-control-readings:1", "platform-control-not-identified"]
    assert "not established" in row.notes
    assert len(out.gaps) == 1 and coverage.kind_of(out.gaps[0]) == coverage.NOT_MEASURED
    assert coverage.nature_of(out.gaps[0]) == coverage.LOW_FIDELITY
    # Not listed as unidentified, the same column is reported as not read.
    out = _run(path)
    scope = _by_name(out.records)["Windows platform protection scope"]
    assert scope.extra["columns_unread"] == "1" and "Widget shield status" in scope.notes


def test_a_control_missing_from_the_export_gets_no_row(tmp_path):
    columns = tuple(c for c in COLUMNS if c != "iommu")
    path = _export(tmp_path / "w.csv", [{k: v for k, v in _row("ws-01").items()
                                         if k != "iommu"}], columns)
    rows = _by_name(_run(path).records)
    assert "Windows platform protection — iommu" not in rows
    assert "Not in the file, so not read: iommu" in rows["Windows platform protection scope"].notes


def test_a_second_reading_is_compared_machine_by_machine(tmp_path):
    path = _export(tmp_path / "w.csv", [
        _row("ws-01"), _row("ws-02", vbs="Disabled"), _row("ws-03", vbs="Disabled"),
        _row("ws-04"),
    ])
    records = [
        {"@rawstring": json.dumps({"name": "WS-01", "signals": {"iso_on": "yes"}})},
        {"@rawstring": json.dumps({"name": "ws-02", "signals": {"iso_on": "yes"}})},
        {"name": "ws-03", "signals": {"iso_on": "yes"}},
        {"name": "ws-04", "signals": {"iso_on": None}},
    ]
    other = tmp_path / "other.json"
    other.write_text(json.dumps(records), encoding="utf-8")
    compare = {"file": str(other), "host_field": "name", "signals_field": "signals",
               "pairs": {"vbs": "iso_on"}}
    row = _by_name(_run(path, {"compare": compare}).records)[
        "Windows platform protection — vbs"]
    assert row.extra["second_instrument_agrees"] == "1"
    assert row.extra["second_instrument_differs"] == "2"
    assert "platform-control-reading-contested" in row.flags
    # A control with no pair is not compared, and says nothing about a second reading.
    other_row = _by_name(_run(path, {"compare": compare}).records)[
        "Windows platform protection — iommu"]
    assert other_row.extra["second_instrument_agrees"] == "0"
    assert "second reading" not in other_row.notes


def test_the_platform_export_says_whether_any_windows_machine_is_missing(tmp_path):
    path = _export(tmp_path / "w.csv", [_row("ws-01"), _row("ws-02")])
    platforms = write(tmp_path / "p.csv", ("hostname", "os_version"), [
        {"hostname": "ws-01", "os_version": "Windows 99"},
        {"hostname": "ws-02", "os_version": "Windows 99"},
        {"hostname": "hostq-1", "os_version": "Exampix 9"},
    ])
    scope = _by_name(_run(path, {"platforms": str(platforms)}).records)[
        "Windows platform protection scope"]
    assert scope.extra["sibling_export_hosts"] == "3"
    assert scope.extra["absent_from_this_export"] == "1"
    assert "None of the 1 machine in the platform export" in scope.notes
    path = _export(tmp_path / "w2.csv", [_row("ws-01")])
    scope = _by_name(_run(path, {"platforms": {"file": str(platforms)}}).records)[
        "Windows platform protection scope"]
    assert "1 Windows machine in the platform export" in scope.notes


def test_other_headings_and_state_words_are_settings(tmp_path):
    path = _export(tmp_path / "w.csv", [{"Device": "ws-01", "Boot check": "On"},
                                        {"Device": "ws-02", "Boot check": "Off"}],
                   ("Device", "Boot check"))
    out = _run(path, {"columns": {"machine": "Device", "secure_boot_enabled": "Boot check"},
                      "on": ["on"], "off": ["off"]})
    row = _by_name(out.records)["Windows platform protection — Boot check"]
    assert (row.extra["enabled"], row.extra["disabled"]) == ("1", "1")
