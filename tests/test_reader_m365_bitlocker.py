"""The Windows drive encryption and recovery-key escrow reader in takestock's readers library.

Every export is composed in its test, in the columns the reader reads, with
made-up device names (``PC-01``…), models and serials, and dates in 2030.
Nothing here was captured from a real export.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import ctx, write

from takestock import coverage
from takestock.readers import library
from takestock.readers import m365_bitlocker as reader

ESCROW = ("DeviceName", "IsEncrypted", "EscrowRecordFound", "EscrowRecordCount",
          "NewestEscrowDateUtc", "RiskState", "OperatingSystem", "OSVersion",
          "UserPrincipalName", "UserDisplayName", "SerialNumber", "Manufacturer", "Model",
          "ComplianceState", "ManagementAgent")
REPORT = ("Device name", "OS", "OS version", "TpmSpecificationVersion", "Encryption readiness",
          "Encryption status", "User principal name", "Profile state summary",
          "BitLocker State")
DEVICES = ("Device name", "OS", "SkuFamily")
DIRECTORY = ("displayName", "operatingSystem", "isManaged", "isCompliant", "trustType")
OTHER = ("Computer", "Disk protection")

#: Microsoft's wording for the OS volume's method not matching policy, from its
#: Intune encryption report page.
DRIFT = "The encryption method of the OS volume doesn't match the BitLocker policy."


def _dev(name: str, enc: str = "True", esc: str = "True", count: str = "1",
         date: str = "2030-03-04T05:06:07Z", risk: str = "EncryptedEscrowConfirmed",
         **more: str) -> dict:
    row = {"DeviceName": name, "IsEncrypted": enc, "EscrowRecordFound": esc,
           "EscrowRecordCount": count, "NewestEscrowDateUtc": date, "RiskState": risk,
           "OperatingSystem": "Windows", "OSVersion": "10.0.30000.1",
           "UserPrincipalName": "person@example.test", "UserDisplayName": "Example Person",
           "SerialNumber": f"SN-{name}", "Manufacturer": "Example Ltd",
           "Model": "Example Laptop 13", "ComplianceState": "compliant",
           "ManagementAgent": "mdm"}
    row.update(more)
    return row


def _rep(name: str, status: str = "Encrypted", tpm: str = "2.0", ready: str = "Ready",
         profile: str = "Compliant", state: str = "Success") -> dict:
    return {"Device name": name, "OS": "Windows", "OS version": "10.0.30000.1",
            "TpmSpecificationVersion": tpm, "Encryption readiness": ready,
            "Encryption status": status, "User principal name": "person@example.test",
            "Profile state summary": profile, "BitLocker State": state}


def _escrow(tmp: Path, rows: list[dict], name: str = "escrow.csv") -> Path:
    return write(tmp / name, ESCROW, rows)


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _rows(out) -> dict[str, object]:
    return {r.name: r for r in out.records}


def _device(out, name: str):
    return _rows(out)[f"Disk encryption and key custody {name}"]


def _scope(out):
    return _rows(out)["Endpoint at-rest population reconciliation"]


def test_the_reader_is_in_the_library():
    assert library()["m365_bitlocker"] is reader.PLUGIN


def test_no_export_named_is_a_gap_and_no_rows():
    out = _run(None)
    assert out.records == []
    assert len(out.gaps) == 1
    gap = out.gaps[0]
    assert gap.kind == coverage.NOT_COLLECTED and gap.nature == coverage.NO_DATA
    assert gap.impact_kind == coverage.CHANGES_CONCLUSION


def test_the_four_grades(tmp_path):
    path = _escrow(tmp_path, [
        _dev("pc-01"),
        _dev("PC-02", esc="False", count="0", date="", risk="EncryptedNoEscrowRecord"),
        _dev("PC-03", enc="False", esc="False", count="0", date="",
             risk="NotEncryptedOrUnknown"),
        _dev("PC-04", enc="False", esc="False", count="0", date="", risk=""),
        _dev("PC-05", enc="maybe", risk=""),
        _dev("PC-06", esc="pending", risk=""),
    ])
    out = _run(path)
    held = _device(out, "PC-01")
    assert held.verdict == "strong" and held.host == "PC-01"
    assert held.notes.startswith("This device's drive is encrypted and a copy")
    missing = _device(out, "PC-02")
    assert missing.verdict == "weak" and missing.flags[0] == "key-escrow-missing"
    assert "the encryption is not the finding" in missing.notes
    assert _device(out, "PC-03").flags[0] == "drive-unencrypted-or-unknown"
    assert _device(out, "PC-04").flags[0] == "drive-unencrypted"
    assert _device(out, "PC-04").verdict == "weak"
    assert _device(out, "PC-05").verdict == "unknown"
    assert _device(out, "PC-05").flags[0] == "ungraded:device-encryption:blank"
    assert _device(out, "PC-06").flags[0] == "ungraded:key-escrow:blank"
    scope = _scope(out)
    assert scope.extra["escrow_confirmed"] == "1" and scope.extra["escrow_missing"] == "1"
    assert scope.extra["not_encrypted"] == "2" and scope.extra["ungraded"] == "1"


def test_no_person_is_carried_into_a_row(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01")]))
    for row in out.records:
        text = repr(row)
        assert "person@example.test" not in text and "Example Person" not in text


def test_a_risk_label_that_contradicts_the_columns_is_flagged_not_graded(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01", risk="EncryptedNoEscrowRecord")]))
    row = _device(out, "PC-01")
    assert row.verdict == "strong"
    assert "risk-state-disagrees:EncryptedNoEscrowRecord" in row.flags
    assert _scope(out).extra["risk_label_disagreements"] == "1"


def test_extra_carries_the_escrow_row_and_copies_note(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01", count="3")]))
    row = _device(out, "PC-01")
    assert row.serial == "SN-PC-01"
    assert row.extra["escrow_records"] == "3" and row.extra["model"] == "Example Laptop 13"
    assert row.extra["newest_escrow_date"] == "2030-03-04"
    assert row.extra["management_agent"] == "mdm"
    assert "3 copies held" in row.notes
    assert _scope(out).extra["model_example_laptop_13"] == "1"


def test_a_day_first_column_is_read_day_first(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01", date="25/01/2030 21:00:00"),
                                  _dev("PC-02", date="03/02/2030 09:00:00")]))
    assert _device(out, "PC-02").extra["newest_escrow_date"] == "2030-02-03"
    scope = _scope(out)
    assert scope.extra["escrow_date_convention"] == "day-first"
    assert scope.extra["oldest_escrow_record"] == "2030-01-25"
    assert scope.extra["newest_escrow_record"] == "2030-02-03"


def test_a_month_first_column_is_read_month_first(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01", date="01/25/2030"),
                                  _dev("PC-02", date="03/02/2030")]))
    assert _device(out, "PC-02").extra["newest_escrow_date"] == "2030-03-02"


def test_an_ambiguous_column_is_left_unparsed(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01", date="03/02/2030")]))
    row = _device(out, "PC-01")
    assert "newest_escrow_date" not in row.extra
    assert row.extra["newest_escrow_date_unparsed"] == "03/02/2030"
    assert "could not read" in row.notes
    assert _scope(out).extra["escrow_date_convention"] == "undetermined"


def test_contradicting_dates_settle_nothing():
    assert reader.date_order(["25/01/2030", "01/25/2030"]) == ""
    assert reader.to_iso("2030-01-02T03:04:05Z", "") == "2030-01-02"
    assert reader.to_iso("31/13/2030", "day-first") == ""


def test_the_encryption_report_folds_by_device_and_keeps_the_worst(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01"), _dev("PC-02")])
    report = write(tmp_path / "report.csv", REPORT, [
        _rep("PC-01"), _rep("pc-01", profile="Error"),
        _rep("PC-02", tpm="1.2", ready="Not ready", profile="Unknown"),
    ])
    out = _run(path, {"encryption_report": str(report)})
    one = _device(out, "PC-01")
    assert one.extra["encryption_report_rows"] == "2"
    assert one.extra["encryption_profile_state"] == "Compliant, Error"
    assert "encryption-profile-state:Error" in one.flags
    two = _device(out, "PC-02")
    assert "tpm-below-2:1.2" in two.flags and "encryption-not-ready:Not ready" in two.flags
    assert "encryption-profile-state:Unknown" in two.flags
    assert not any(f == "encryption-profile-state:Compliant" for f in one.flags)
    scope = _scope(out)
    assert scope.extra["encryption_report_rows"] == "3"
    assert scope.extra["encryption_report_devices"] == "2"
    hardware = _rows(out)["Endpoint key-storage hardware"]
    assert hardware.verdict == "n/a" and hardware.hosts_count == 2
    assert hardware.flags == ["key-storage-hardware-recorded", "tpm-below-2:1"]
    assert out.gaps == []


def test_an_os_volume_method_that_differs_from_policy_caps_the_grade(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    report = write(tmp_path / "report.csv", REPORT, [_rep("PC-01", state=DRIFT)])
    row = _device(_run(path, {"encryption_report": str(report)}), "PC-01")
    assert row.verdict == "acceptable" and "fde-cipher-policy-drift" in row.flags


def test_method_wording():
    assert reader.method_differs_from_policy(DRIFT)
    assert reader.method_differs_from_policy(
        "Encryption method of the OS volume is different from the one set by policy")
    assert not reader.method_differs_from_policy(
        "The encryption method of the fixed drive doesn't match the BitLocker policy.")
    assert not reader.method_differs_from_policy("Success")


def test_a_device_only_in_the_report_is_graded_from_its_status(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    report = write(tmp_path / "report.csv", REPORT, [_rep("PC-01"), _rep("PC-09")])
    out = _run(path, {"encryption_report": str(report)})
    row = _device(out, "PC-09")
    assert row.verdict == "unknown" and row.flags[0] == "ungraded:key-escrow:blank"
    assert "no-escrow-record-row" in row.flags and row.serial == ""
    assert _scope(out).extra["no_escrow_row"] == "1"


def test_an_unrecognised_report_status_is_ungraded_not_unencrypted(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    report = write(tmp_path / "report.csv", REPORT, [_rep("PC-01", status="Pending"),
                                                     _rep("PC-09", status="Pending"),
                                                     _rep("PC-08", status="Not encrypted")])
    out = _run(path, {"encryption_report": str(report)})
    one = _device(out, "PC-01")
    assert one.verdict == "strong"
    assert "encryption-report-status-unread:Pending" in one.flags
    assert not any(f.startswith("encryption-source-conflict") for f in one.flags)
    nine = _device(out, "PC-09")
    assert nine.verdict == "unknown"
    assert nine.flags[0] == "ungraded:device-encryption:Pending"
    eight = _device(out, "PC-08")
    assert eight.verdict == "weak" and eight.flags[0] == "drive-unencrypted"


def test_mixed_report_rows_read_as_the_worse(tmp_path):
    assert reader.report_encrypted({"Encrypted", "Not encrypted"}) is False
    assert reader.report_encrypted({"Encrypted"}) is True
    assert reader.report_encrypted({"Encrypted", "Pending"}) is None
    assert reader.report_encrypted(set()) is None


def test_a_report_that_contradicts_the_escrow_export_is_unknown(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    report = write(tmp_path / "report.csv", REPORT, [_rep("PC-01", status="Not encrypted")])
    out = _run(path, {"encryption_report": str(report)})
    row = _device(out, "PC-01")
    assert row.verdict == "unknown"
    assert "encryption-source-conflict:intune-encryption-report" in row.flags
    assert "encryption-sources-disagree:1" in _scope(out).flags


def test_no_report_named_is_a_low_fidelity_gap(tmp_path):
    out = _run(_escrow(tmp_path, [_dev("PC-01")]))
    assert "no-encryption-report-row" in _device(out, "PC-01").flags
    assert "Endpoint key-storage hardware" not in _rows(out)
    assert len(out.gaps) == 1
    assert out.gaps[0].kind == coverage.NOT_COLLECTED
    assert out.gaps[0].nature == coverage.LOW_FIDELITY


def test_the_cross_check_defaults(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01"), _dev("PC-02")])
    other = write(tmp_path / "other.csv", ("Device name", "Encryption status"), [
        {"Device name": "pc-01", "Encryption status": "encrypted"},
        {"Device name": "PC-02", "Encryption status": "Not encrypted"},
        {"Device name": "ZZ-OTHER", "Encryption status": "Encrypted"},
    ])
    out = _run(path, {"cross_check": str(other)})
    one, two = _device(out, "PC-01"), _device(out, "PC-02")
    assert one.extra["cross_check_drive_encryption"] == "encrypted"
    assert one.verdict == "strong"
    assert two.verdict == "unknown" and "encryption-source-conflict:cross_check" in two.flags
    scope = _scope(out)
    assert scope.extra["cross_check_hosts"] == "3"
    assert scope.extra["cross_check_only_hosts"] == "1"
    assert scope.extra["source_conflicts"] == "1"


def test_the_cross_check_names_and_columns_are_settings(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    other = write(tmp_path / "other.csv", OTHER, [
        {"Computer": "PC-01", "Disk protection": "Protected"}])
    out = _run(path, {"cross_check": {
        "file": str(other), "name": "tool", "label": "Example Tool",
        "row_key": "tool_state", "host_column": ["Host", "Computer"],
        "status_column": "Disk protection", "encrypted": ["Protected"]}})
    row = _device(out, "PC-01")
    assert row.extra["tool_state"] == "Protected" and row.verdict == "strong"
    assert _scope(out).extra["tool_hosts"] == "1"
    assert "Example Tool" in _scope(out).notes


def test_the_cross_check_file_may_be_a_pattern(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    write(tmp_path / "other-2030-01.csv", ("Device name", "Encryption status"),
          [{"Device name": "PC-01", "Encryption status": "Not encrypted"}])
    write(tmp_path / "other-2030-02.csv", ("Device name", "Encryption status"),
          [{"Device name": "PC-01", "Encryption status": "Encrypted"}])
    out = _run(path, {"cross_check": {"file": str(tmp_path / "other-*.csv")}})
    assert _device(out, "PC-01").extra["cross_check_drive_encryption"] == "Encrypted"
    none = _run(path, {"cross_check": {"file": str(tmp_path / "absent-*.csv")}})
    assert [g.kind for g in none.gaps].count(coverage.COULD_NOT_TEST) == 1


def test_a_cross_check_that_cannot_be_read_is_a_gap(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    out = _run(path, {"cross_check": {"file": str(tmp_path / "absent.csv"), "label": "X"}})
    kinds = [g.kind for g in out.gaps]
    assert coverage.COULD_NOT_TEST in kinds
    assert "cross_check_drive_encryption" not in _device(out, "PC-01").extra


def test_the_no_key_list_is_checked_against_the_main_export(tmp_path):
    rows = [_dev("PC-01"), _dev("PC-02", esc="False", count="0", date="",
                                 risk="EncryptedNoEscrowRecord")]
    path = _escrow(tmp_path, rows)
    agrees = _escrow(tmp_path, [rows[1]], "agrees.csv")
    differs = _escrow(tmp_path, [rows[0], rows[1]], "differs.csv")
    stray = _escrow(tmp_path, [_dev("PC-07")], "stray.csv")
    assert "escrow-missing" not in " ".join(_scope(_run(path)).flags)
    assert _scope(_run(path, {"escrow_missing": str(agrees)})).flags == [
        "scope-population-reconciled"]
    assert "escrow-missing-list-differs" in _scope(
        _run(path, {"escrow_missing": str(differs)})).flags
    assert "escrow-missing-list-stray:1" in _scope(
        _run(path, {"escrow_missing": str(stray)})).flags


def test_device_list_and_directory(tmp_path):
    path = _escrow(tmp_path, [_dev("PC-01")])
    devices = write(tmp_path / "devices.csv", DEVICES, [
        {"Device name": "PC-01", "OS": "Windows", "SkuFamily": "Enterprise"},
        {"Device name": "PH-01", "OS": "iOS/iPadOS"},
        {"Device name": "PH-02", "OS": "Android"},
    ])
    directory = write(tmp_path / "directory.csv", DIRECTORY, [
        {"displayName": "PC-01", "operatingSystem": "Windows", "isManaged": "True",
         "isCompliant": "True", "trustType": "AzureAd"},
        {"displayName": "OWN-01", "operatingSystem": "Windows", "isManaged": "False",
         "isCompliant": "", "trustType": "Workplace"},
    ])
    out = _run(path, {"managed_devices": str(devices), "directory_devices": str(directory)})
    row = _device(out, "PC-01")
    assert row.extra["os"] == "Windows" and row.extra["sku_family"] == "Enterprise"
    scope = _scope(out)
    assert scope.extra["intune_managed_devices"] == "3"
    assert scope.extra["entra_registrations"] == "2"
    assert scope.extra["entra_windows"] == "2" and scope.extra["entra_managed"] == "1"
    assert scope.extra["entra_workplace_registered"] == "1"
    others = _rows(out)["Managed non-Windows device encryption"]
    assert others.verdict == "unknown" and others.hosts_count == 2
    assert others.extra == {"os_ios_ipados": "1", "os_android": "1"}
    assert "OWN-01" not in repr(out.records)


def test_registers_not_named_are_not_counted(tmp_path):
    scope = _scope(_run(_escrow(tmp_path, [_dev("PC-01")])))
    assert "entra_registrations" not in scope.extra
    assert "intune_managed_devices" not in scope.extra


def test_a_virtual_machine_serial_is_written_in_byte_pairs(tmp_path):
    out = _run(_escrow(tmp_path, [
        _dev("VM-01", SerialNumber="VMware-0000000011111111-2222222233333333")]))
    assert _device(out, "VM-01").serial == (
        "VMware-00 00 00 00 11 11 11 11-22 22 22 22 33 33 33 33")
    assert reader.serial_display("ABC-XYZ") == "ABC-XYZ"


def test_escrowed_devices(tmp_path):
    path = _escrow(tmp_path, [_dev("pc-01"), _dev("PC-02")])
    assert reader.escrowed_devices(path) == {"PC-01", "PC-02"}
    assert reader.escrowed_devices(tmp_path / "absent.csv") == set()
