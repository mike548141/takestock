"""The CrowdStrike Falcon vulnerability reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (the
API record's field paths) or others named in the settings, with made-up
machines, products, made-up identifiers in the year 2030 and small counts. Nothing
here was captured from a real export.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import falcon_vulnerabilities as reader
from takestock.readers import library

COLUMNS = tuple(reader.HEADINGS.values())


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _rec(machine: str, product: str, cve: str, **kw: str) -> dict:
    row = {"host_info.hostname": machine, "host_info.os_version": kw.pop("os", "Exampix 9"),
           "host_info.product_type_desc": kw.pop("kind", "Server"),
           "host_info.asset_criticality": kw.pop("crit", ""),
           "status": kw.pop("status", "open"), "created_timestamp": kw.pop("created", "2030-01-10T08:00:00Z"),
           "cve.id": cve, "cve.description": kw.pop("description", "A flaw in a widget."),
           "cve.severity": kw.pop("severity", "MEDIUM"), "cve.base_score": kw.pop("score", "5.5"),
           "cve.exploit_status": kw.pop("exploit", "0"),
           "cve.cisa_info.is_cisa_kev": kw.pop("kev", "false"),
           "cve.cisa_info.due_date": kw.pop("due", ""),
           "app.product_name_normalized": product,
           "app.product_name_version": kw.pop("versions", "")}
    assert not kw
    return row


def _by_name(records):
    return {a.name: a for a in records}


def test_the_reader_is_in_the_library():
    assert library()["falcon_vulnerabilities"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_COLLECTED
    assert coverage.nature_of(g) == coverage.NO_DATA


def test_an_empty_export_gives_the_same_gap(tmp_path):
    out = _run(_export(tmp_path / "empty.csv", []))
    assert out.records == [] and "holds no rows" in str(out.gaps[0])


def test_a_cryptographic_package_is_one_row_however_many_records(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("hostq-1", "openssl-libs", "CVE-2030-X1A", severity="HIGH", score="7.5",
             versions="openssl-libs 9.9.93"),
        _rec("hostq-2", "openssl-libs", "CVE-2030-X1A", versions="openssl-libs 9.9.93"),
        _rec("hostq-2", "openssl-libs", "CVE-2030-X1B", severity="LOW", score="2.1"),
        _rec("hostq-3", "gadget-viewer", "CVE-2030-X1C"),       # not cryptographic
        _rec("hostq-3", "openssl-libs", "CVE-2030-X1D", status="closed"),  # not open
    ])
    out = _run(path)
    rows = _by_name(out.records)
    ssl = rows["openssl-libs — open defects"]
    assert ssl.verdict == "unknown" and ssl.hosts_count == 2
    assert ssl.flags == ["crypto-defect-open:3", "crypto-defect-attribution:package-name"]
    assert ssl.extra["distinct_defects"] == "2" and ssl.extra["worst_technical_severity"] == "HIGH"
    assert ssl.extra["max_cvss"] == "7.5" and ssl.extra["installed_on"] == ["hostq-1", "hostq-2"]
    assert ssl.extra["versions"] == "openssl-libs 9.9.93" and ssl.data_state == "in-transit"
    assert not any("gadget" in n for n in rows)
    scope = rows["Vulnerability evidence scope"]
    assert scope.extra["records"] == "5" and scope.extra["open_records"] == "4"
    assert scope.extra["crypto_open_records"] == "3" and scope.extra["hosts"] == "3"
    assert scope.flags == ["scope-technical-severity-only",
                           "scope-defect-window:2030-01-10..2030-01-10"]
    assert scope.extra["criticality_(blank)"] == "5"


def test_a_microsoft_component_is_found_in_the_advisory_text(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("ws-01", "Windows", "CVE-2030-X2A",
             description="Improper input validation in Windows Kerberos allows an attacker to "
                         "do something."),
        _rec("ws-01", "Windows", "CVE-2030-X2B",
             description="A flaw in Windows Paint allows an attacker to do something."),
    ])
    rows = _by_name(_run(path).records)
    krb = rows["Windows Kerberos — open defects"]
    assert krb.flags[1] == "crypto-defect-attribution:advisory-prose"
    assert krb.protocol == "kerberos"
    assert not any("Paint" in n for n in rows)


def test_netlogon_is_its_own_component_unless_the_profile_maps_it(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("ws-01", "Windows", "CVE-2030-X8A",
             description="A flaw in Windows Netlogon allows an attacker to do something."),
        _rec("ws-01", "Windows", "CVE-2030-X8B",
             description="A flaw in Kerberos allows an attacker to do something."),
    ])
    rows = _by_name(_run(path).records)
    assert rows["Windows Netlogon — open defects"].protocol == "netlogon"
    assert rows["Windows Netlogon — open defects"].data_state == "in-transit"
    assert not any(n.startswith("Kerberos") for n in rows)  # only "Windows <name>" is read
    mapped = _by_name(_run(path, {"components": {"windows netlogon": "key-material"}}).records)
    assert mapped["Windows Netlogon — open defects"].protocol == "key-material"
    assert mapped["Windows Netlogon — open defects"].data_state == "key-material"


def test_exploited_and_catalogued_defects_are_weak_and_dated(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("hostq-1", "gnutls", "CVE-2030-X3A", exploit="99", kev="true",
             due="2030-01-05", created="2030-01-20T00:00:00Z"),
        _rec("hostq-2", "gnutls", "CVE-2030-X3B", kev="true", due="2030-02-28"),
        _rec("hostq-2", "gadget-viewer", "CVE-2030-X3C", exploit="99"),
    ])
    out = _run(path, {"exploit_in_use": ["99"]})
    rows = _by_name(out.records)
    g = rows["gnutls — open defects"]
    assert g.verdict == "weak"
    assert "crypto-defect-exploited:1" in g.flags and "crypto-defect-catalogued:2" in g.flags
    over = rows["CVE-2030-X3A — catalogued exploited defect"]
    assert over.flags == ["exploited-defect-overdue:2030-01-05"] and over.verdict == "weak"
    assert over.extra["exploit_in_use"] == "yes"
    due = rows["CVE-2030-X3B — catalogued exploited defect"]
    assert due.flags == ["exploited-defect-due:2030-02-28"]
    scope = rows["Vulnerability evidence scope"]
    assert scope.extra["exploited_uncatalogued"] == "1" and scope.extra["exploited_hosts"] == "2"
    assert scope.extra["catalogued_overdue"] == "1"
    # With no exploit_in_use values set, no record counts as exploited.
    rows = _by_name(_run(path).records)
    assert "crypto-defect-exploited:1" not in rows["gnutls — open defects"].flags


def test_one_census_row_per_operating_system_and_type(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("hostq-1", "gadget", "CVE-2030-X4A", os="Exampix 9", kind="Server"),
        _rec("hostq-2", "gadget", "CVE-2030-X4A", os="Exampix 9", kind="Server"),
        _rec("ws-01", "gadget", "CVE-2030-X4A", os="Exampix 9", kind="Workstation"),
    ])
    rows = _by_name(_run(path).records)
    srv = rows["Exampix 9 (server)"]
    assert srv.flags == ["os-census:2"] and srv.verdict == "n/a"
    assert srv.extra["open_defect_rows"] == "2" and "67%" in srv.notes
    assert rows["Exampix 9 (workstation)"].hosts_count == 1


def test_unset_criticality_is_a_gap(tmp_path):
    path = _export(tmp_path / "v.csv", [
        _rec("hostq-1", "gadget", "CVE-2030-X5A", crit="Untiered"),
        _rec("hostq-2", "gadget", "CVE-2030-X5A", crit="High"),
        _rec("hostq-3", "gadget", "CVE-2030-X5A"),
    ])
    gaps = _run(path).gaps
    assert len(gaps) == 1 and "1 of 3 records" in str(gaps[0])
    assert coverage.kind_of(gaps[0]) == coverage.NOT_MEASURED
    assert coverage.nature_of(gaps[0]) == coverage.LOW_FIDELITY
    gaps = _run(path, {"criticality_unset": ["untiered"]}).gaps
    assert "2 of 3 records" in str(gaps[0])
    path = _export(tmp_path / "w.csv", [_rec("hostq-1", "gadget", "CVE-2030-X5A", crit="High")])
    assert _run(path).gaps == []


def test_other_headings_and_words_are_settings(tmp_path):
    path = _export(tmp_path / "v.csv", [
        {"Machine": "hostq-1", "State": "Again", "Package": "openssl", "Id": "CVE-2030-X6A"},
    ], ("Machine", "State", "Package", "Id"))
    settings = {"columns": {"machine": "Machine", "status": "State", "product": "Package",
                            "cve": "Id"},
                "open_statuses": ["again"]}
    rows = _by_name(_run(path, settings).records)
    assert rows["openssl — open defects"].extra["installed_on"] == ["hostq-1"]
    settings["packages"] = [["sprocket", "tls"]]
    assert "openssl — open defects" not in _by_name(_run(path, settings).records)


def test_a_field_holding_line_breaks_is_read_whole(tmp_path):
    columns = (*COLUMNS, "notes.long")
    blob = "{\n" + "\n".join(f'  "k{i}": "{"x" * 40}",' for i in range(2**12)) + "\n}"
    path = _export(tmp_path / "v.csv", [
        {**_rec("hostq-1", "gnutls", "CVE-2030-X7A"), "notes.long": blob},
        _rec("hostq-2", "gnutls", "CVE-2030-X7B"),
    ], columns)
    assert len(blob) > 131072  # beyond the csv module's default field limit
    # Another reader raises the limit for the whole process when imported; put the
    # default back, so this test shows the reader raises it itself.
    old = csv.field_size_limit(131072)
    try:
        rows = _by_name(_run(path).records)
    finally:
        csv.field_size_limit(old)
    assert csv.field_size_limit() == old
    assert rows["Vulnerability evidence scope"].extra["records"] == "2"
    assert rows["gnutls — open defects"].hosts_count == 2
