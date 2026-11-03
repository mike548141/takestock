"""The CrowdStrike Falcon installed-software reader in takestock's readers library.

Each export and register is composed in its test, with made-up machine names,
products and version numbers. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import falcon_software as reader
from takestock.readers import library

COLUMNS = ("aid", "ComputerName", "AppName", "AppVersion")
REGISTER_COLUMNS = ("product", "match", "provides", "branch", "max_tls", "citation", "note")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _register(path: Path) -> Path:
    return write(path, REGISTER_COLUMNS, [
        {"product": "Widget TLS", "match": "^widgettls$", "provides": "tls"},
        {"product": "Widget TLS", "match": "^widgettls$", "provides": "tls", "branch": "1.4",
         "max_tls": "TLSv1.1", "citation": "Widget TLS release notes", "note": "No 1.4 release has 1.2"},
        {"product": "Widget TLS", "match": "^widgettls$", "provides": "tls", "branch": "1.6",
         "max_tls": "TLSv1.2", "citation": "Widget TLS release notes"},
        {"product": "Widget TLS", "match": "^widgettls$", "provides": "tls", "branch": "7",
         "max_tls": "TLSv1.3", "citation": "Widget TLS release notes"},
        {"product": "Sprocket Sign", "match": "^sprocketsign", "provides": "signing"},
    ])


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _row(machine: str, name: str, version: str, aid: str = "") -> dict:
    return {"aid": aid or f"a-{machine}", "ComputerName": machine, "AppName": name,
            "AppVersion": version}


def _by_name(records):
    return {a.name: a for a in records}


def test_the_reader_is_in_the_library():
    assert library()["falcon_software"] is reader.PLUGIN
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


def test_release_lines_and_versions():
    assert reader.branch_of("1.4.17") == "1.4"
    assert reader.branch_of("1:1.6.93-41.fc99") == "1.6"
    assert reader.branch_of("7.12.4") == "7"
    assert reader.branch_of("") == ""
    assert reader.upstream_version("2:5.31p1-19.fc99") == "5.31p1"


def test_each_line_is_graded_only_by_its_own_register_entry(tmp_path):
    reg = _register(tmp_path / "reg.csv")
    path = _export(tmp_path / "apps.csv", [
        _row("ws-01", "widgettls", "1.4.17"), _row("ws-02", "widgettls", "1.4.93"),
        _row("ws-03", "widgettls", "1.6.93"),
        _row("ws-04", "widgettls", "7.12.4"),
        _row("ws-05", "widgettls", "9.0.93"),          # no entry for line 9
        _row("ws-05", "sprocketsign2", "4.4.93"),
        _row("ws-06", "Gadget Editor", "1.0"),         # not cryptographic: not reported
    ])
    out = _run(path, {"register": str(reg)})
    rows = _by_name(out.records)
    old = rows["Widget TLS 1.4"]
    assert old.verdict == "weak" and old.flags == ["capability-ceiling:TLSv1.1"]
    assert old.hosts_count == 2 and old.extra["installed_on"] == ["ws-01", "ws-02"]
    assert old.extra["versions"] == "1.4.17 1.4.93" and old.extra["version_count"] == "2"
    # The baseline's floor is TLS 1.2, so a TLS 1.2 ceiling is recorded and not weak.
    mid = rows["Widget TLS 1.6"]
    assert mid.verdict == "unknown" and mid.flags == ["capability-ceiling:TLSv1.2"]
    assert rows["Widget TLS 7"].verdict == "acceptable" and rows["Widget TLS 7"].flags == []
    assert rows["Widget TLS 9"].flags == ["ungraded:crypto-software:Widget TLS 9"]
    assert rows["Sprocket Sign 4"].data_state == "key-material"
    assert rows["Widget TLS 7"].data_state == "in-transit"
    assert not any("Gadget" in n for n in rows)
    spread = rows["Widget TLS version spread"]
    assert spread.flags == ["version-spread:5"] and spread.verdict == "n/a"
    assert spread.extra["branch_count"] == "4"
    scope = rows["Cryptographic software scope"]
    assert scope.flags == ["scope-register-limited"]
    assert scope.extra["install_records"] == "7" and scope.extra["hosts"] == "6"
    assert scope.extra["register_entries"] == "5" and scope.extra["products_found"] == "2"
    assert scope.collected_at == "2030-03-17"


def test_weak_below_moves_the_line_between_weak_and_recorded(tmp_path):
    reg = _register(tmp_path / "reg.csv")
    path = _export(tmp_path / "apps.csv", [_row("ws-03", "widgettls", "1.6.93")])
    out = _run(path, {"register": str(reg), "weak_below": "TLSv1.3"})
    assert _by_name(out.records)["Widget TLS 1.6"].verdict == "weak"


def test_the_bundled_register_is_read_when_none_is_named(tmp_path):
    out = _run(_export(tmp_path / "apps.csv", [_row("ws-01", "openssl", "3.77.1")]))
    rows = _by_name(out.records)
    assert "OpenSSL 3" in rows and rows["OpenSSL 3"].verdict == "acceptable"


def test_the_ssh_server_package_gets_a_row_per_exact_version(tmp_path):
    path = _export(tmp_path / "apps.csv", [
        _row("hostq-1", "openssh-server", "5.31p1-19.fc99"),
        _row("hostq-2", "openssh-server", "5.31p1-19.fc99"),
        _row("hostq-3", "openssh-server", "6.02p1"),
        _row("hostq-3", "openssh-clients", "6.02p1"),   # a client: no server row
    ])
    rows = _by_name(_run(path).records)
    one = rows["OpenSSH server 5.31p1-19.fc99"]
    assert one.flags == ["sshd-version-census:2", "ungraded:crypto-software:OpenSSH 5"]
    assert one.extra["hosts"] == "hostq-1 hostq-2"
    assert one.extra["package_release"] == "19.fc99" and one.extra["upstream_version"] == "5.31p1"
    assert one.extra["sshd_hosts_total"] == "3" and one.extra["package"] == "openssh-server"
    assert "fixes backported" in one.notes
    assert rows["OpenSSH server 6.02p1"].extra["package_release"] == ""
    assert not any("6.02p1" in n and "client" in n.lower() for n in rows)


def test_a_last_used_column_counts_installs_never_seen_running(tmp_path):
    reg = _register(tmp_path / "reg.csv")
    columns = (*COLUMNS, "Ran")
    path = _export(tmp_path / "apps.csv", [
        {**_row("ws-01", "widgettls", "7.1"), "Ran": "2030-02-01"},
        {**_row("ws-02", "widgettls", "7.2"), "Ran": ""},
    ], columns)
    rows = _by_name(_run(path, {"register": str(reg),
                                "columns": {"last_used": "Ran"}}).records)
    assert rows["Widget TLS 7"].extra["installs_never_used"] == "1"
    assert rows["Widget TLS 7"].extra["installs_with_usage_data"] == "2"
    # Without the column nothing is counted, rather than every install counted as unused.
    rows = _by_name(_run(path, {"register": str(reg)}).records)
    assert "installs_never_used" not in rows["Widget TLS 7"].extra


def test_other_headings_are_named_in_columns_and_tried_in_order(tmp_path):
    reg = _register(tmp_path / "reg.csv")
    path = _export(tmp_path / "apps.csv", [
        {"Device": "ws-01", "Package": "widgettls", "Release": "7.1"},
    ], ("Device", "Package", "Release"))
    out = _run(path, {"register": str(reg), "columns": {
        "machine": ["ComputerName", "Device"], "product": "Package", "version": ["Release"]}})
    assert _by_name(out.records)["Widget TLS 7"].extra["installed_on"] == ["ws-01"]


def test_a_row_naming_no_machine_is_counted_by_its_sensor(tmp_path):
    reg = _register(tmp_path / "reg.csv")
    path = _export(tmp_path / "apps.csv", [
        {"aid": "a-77", "ComputerName": "", "AppName": "widgettls", "AppVersion": "7.1"}])
    rows = _by_name(_run(path, {"register": str(reg)}).records)
    assert rows["Widget TLS 7"].extra["installed_on"] == ["a-77"]


def test_an_unreadable_register_is_a_gap(tmp_path):
    path = _export(tmp_path / "apps.csv", [_row("ws-01", "widgettls", "7.1")])
    bad = tmp_path / "reg.csv"
    bad.write_bytes(b"\xff\xfe\xc3\x28")
    out = _run(path, {"register": str(bad)})
    assert out.records == [] and "register" in str(out.gaps[0])
