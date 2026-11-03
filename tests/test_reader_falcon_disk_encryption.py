"""The CrowdStrike Falcon drive encryption reader in takestock's readers library.

Each export is composed in its test with made-up machines, platforms and
volumes. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_disk_encryption as reader
from takestock.readers import library

COLUMNS = ("hostname", "platform", "encryption_status", "encrypted_drives_count",
           "unencrypted_drives_count", "encrypted_drives", "unencrypted_drives")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _row(machine: str, status: str, enc: int, unenc: int, platform: str = "Mac",
         enc_list: str = "", unenc_list: str = "") -> dict:
    return {"hostname": machine, "platform": platform, "encryption_status": status,
            "encrypted_drives_count": str(enc), "unencrypted_drives_count": str(unenc),
            "encrypted_drives": enc_list, "unencrypted_drives": unenc_list}


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["falcon_disk_encryption"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_each_state_is_graded_and_unencrypted_is_never_read_as_encrypted(tmp_path):
    path = _export(tmp_path / "d.csv", [
        _row("lt-01", "Encrypted", 2, 0, enc_list="C:, D:"),
        _row("lt-02", "Unencrypted", 0, 1, platform="Windows"),
        _row("lt-03", "Encrypted", 1, 2, unenc_list="E:, F:"),
        _row("lt-04", "Suspended", 1, 0),
        _row("lt-05", "", 0, 1, platform="Windows"),
    ])
    out = _run(path)
    rows = by_name(out.records)
    assert rows["Drive encryption lt-01"].verdict == "strong"
    assert rows["Drive encryption lt-01"].flags == []
    assert "C:, D:" in rows["Drive encryption lt-01"].notes
    assert rows["Drive encryption lt-02"].verdict == "weak"
    assert rows["Drive encryption lt-02"].flags == ["drive-unencrypted"]
    assert rows["Drive encryption lt-03"].flags == ["drive-partially-encrypted:2"]
    assert rows["Drive encryption lt-04"].verdict == "unknown"
    assert rows["Drive encryption lt-04"].flags == ["ungraded:drive-encryption:Suspended"]
    assert rows["Drive encryption lt-05"].flags == ["drive-unencrypted"]
    assert rows["Drive encryption lt-01"].data_state == "at-rest"
    assert rows["Drive encryption lt-01"].host == "lt-01"
    scope = rows["Drive encryption scope"]
    assert scope.flags == ["scope-platform-limited"] and scope.verdict == "n/a"
    assert scope.extra["encrypted"] == "1" and scope.extra["unencrypted"] == "3"
    assert scope.extra["ungraded"] == "1"
    assert scope.extra["platform_mac"] == "3" and scope.extra["platform_windows"] == "2"
    # No key-custody export named: one gap says the recovery-key half is unanswered.
    assert len(out.gaps) == 1 and coverage.nature_of(out.gaps[0]) == coverage.LOW_FIDELITY
    assert all("key-custody-unknown" not in a.flags for a in out.records)


def test_status_words_are_settings(tmp_path):
    path = _export(tmp_path / "d.csv", [_row("lt-01", "Protected", 1, 0),
                                        _row("lt-02", "Off", 0, 0)])
    rows = by_name(_run(path, {"encrypted": "protected", "unencrypted": ["off"]}).records)
    assert rows["Drive encryption lt-01"].verdict == "strong"
    assert rows["Drive encryption lt-02"].flags == ["drive-unencrypted"]


def test_machines_a_key_custody_export_names_are_left_to_it(tmp_path):
    escrow = write(tmp_path / "escrow.csv", ("DeviceName", "IsEncrypted", "EscrowRecordFound"),
                   [{"DeviceName": "LT-04", "IsEncrypted": "True", "EscrowRecordFound": "True"},
                    {"DeviceName": "lt-09", "IsEncrypted": "True", "EscrowRecordFound": "True"}])
    path = _export(tmp_path / "d.csv", [
        _row("lt-01", "Encrypted", 1, 0), _row("lt-02", "Unencrypted", 0, 1),
        _row("lt-02", "Unencrypted", 0, 1), _row("lt-03", "Encrypted", 2, 0),
        _row("lt-04", "Encrypted", 1, 0),
    ])
    out = _run(path, {"escrow": str(escrow)})
    rows = by_name(out.records)
    assert "Drive encryption lt-04" not in rows
    assert rows["Drive encryption lt-01"].flags == ["key-custody-unknown"]
    assert len([a for a in out.records if a.name == "Drive encryption lt-02"]) == 2
    scope = rows["Drive encryption scope"]
    assert scope.flags == ["scope-platform-limited", "scope-yielded-to-key-custody:1"]
    assert scope.extra["yielded_to_key_custody"] == "1"
    assert scope.extra["machines"] == "5" and scope.extra["distinct_hosts"] == "4"
    assert scope.hosts_count == 5
    assert out.gaps == []


def test_other_headings_and_dashes(tmp_path):
    path = _export(tmp_path / "d.csv", [
        {"Device": "lt-01", "State": "Encrypted", "On": "1", "Off": "--"},
    ], ("Device", "State", "On", "Off"))
    out = _run(path, {"columns": {"machine": "Device", "status": "State",
                                  "encrypted_count": "On", "unencrypted_count": "Off"}})
    row = by_name(out.records)["Drive encryption lt-01"]
    assert row.verdict == "strong" and row.extra["unencrypted_drives"] == "0"
    assert row.extra["platform"] == "unknown"


def test_an_empty_export_is_a_gap(tmp_path):
    path = _export(tmp_path / "d.csv", [])
    out = _run(path)
    assert out.records == [] and "holds no rows" in out.gaps[0]


def test_the_status_is_compared_whole(tmp_path):
    # With no volume counts, only the status decides: "Unencrypted" holds the
    # word "encrypted" and must never be read as it.
    path = _export(tmp_path / "d.csv", [_row("lt-01", "Unencrypted", 0, 0)])
    row = by_name(_run(path).records)["Drive encryption lt-01"]
    assert row.verdict == "weak" and row.flags == ["drive-unencrypted"]
