"""The CrowdStrike Falcon Zero Trust Assessment reader in takestock's readers library.

Each export is composed in its test as the event shapes the reader takes,
with made-up machine names, sensor IDs and assessment answers. Nothing here
was captured from a real export.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.model import is_informational_flag
from takestock.readers import falcon_zta as reader
from takestock.readers import library

ALL_YES = {item: "yes" for item in reader.CONTROLS}


def _event(aid: str, host: str, items: dict, *, platform: str = "Win",
           kind: str = "Workstation", os_version: str = "Windows 11") -> dict:
    return {"aid": aid, "hostname": host, "os_version": os_version,
            "product_name": f"{os_version} Pro", "product_type_desc": kind,
            "event_platform": platform, "scores": {"os": 50, "sensor": 90, "overall": 70},
            "assessments": items, "event_type": "ZeroTrustHostAssessment"}


def _raw(event: dict, when: int) -> dict:
    return {"@timestamp": when, "aid": event["aid"], "@rawstring": json.dumps(event)}


def _export(path: Path, rows: list) -> Path:
    path.write_text(json.dumps(rows), encoding="utf-8")
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["falcon_zta"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_gives_one_gap():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_one_row_per_machine_from_its_latest_event(tmp_path):
    off = {**ALL_YES, "secure_boot_enabled": "no", "firmware_is_uefi": "no"}
    path = _export(tmp_path / "z.json", [
        _raw(_event("aid-1", "alpha", ALL_YES), 500),          # older: ignored
        _raw(_event("aid-1", "alpha", off), 1_000),
        _raw(_event("aid-2", "bravo", ALL_YES, kind="Server"), 900),
        _raw(_event("aid-3", "charlie",
                    {"sip_enabled_mac": "yes", "file_vault_enabled_mac": "yes"},
                    platform="Mac", os_version="Sonoma (14)"), 900),
        _raw(_event("aid-4", "delta", {k: v for k, v in ALL_YES.items()
                                        if k != "iommu_in_use"} | {"hvci_enabled": "maybe"}),
             900),
        {"@timestamp": 1, "aid": "aid-9", "@rawstring": "not json"},
        "not an object",
    ])
    out = _run(path)
    rows = by_name(out.records)
    alpha = rows["Platform integrity — alpha"]
    assert alpha.verdict == "weak"
    assert "no-secure-boot" in alpha.flags and "legacy-bios-firmware" in alpha.flags
    assert reader.LEGACY_BIOS_FLAG in alpha.flags
    assert alpha.flags == sorted(alpha.flags)
    assert alpha.data_state == "platform-integrity" and alpha.protocol == ""
    assert alpha.host == "alpha" and alpha.version == "Windows 11"
    assert alpha.software == "Windows 11 Pro" and alpha.collected_at == "2030-03-17"
    assert alpha.extra["zta.secure_boot_enabled"] == "no"
    assert alpha.extra["zta_crypto_items_assessed"] == len(reader.CONTROLS)
    assert alpha.extra["scores"] == {"os": 50, "sensor": 90, "overall": 70}
    assert alpha.extra["host_type_basis"] == reader.BASIS_ASSESSMENT
    assert rows["Platform integrity — bravo"].verdict == "acceptable"
    assert rows["Platform integrity — bravo"].flags == []
    charlie = rows["Platform integrity — charlie"]
    assert charlie.verdict == "unknown" and charlie.flags == [reader.NOT_ASSESSED_AT_ALL]
    delta = rows["Platform integrity — delta"]
    assert delta.verdict == "unknown"
    assert set(delta.flags) == {"not-assessed:iommu_in_use", "unreadable-assessment:hvci_enabled"}
    assert all(is_informational_flag(f) for f in delta.flags)
    assert len(out.records) == 4
    # Two rows unreadable, then the machine with no graded item: two gaps in that order.
    assert [coverage.kind_of(g) for g in out.gaps] == [coverage.EXTENT_UNKNOWN] * 2
    assert "2 of 7 row(s)" in str(out.gaps[0])
    assert "1 of 4 machine(s) (1 Mac)" in str(out.gaps[1])
    assert coverage.impact_kind_of(out.gaps[1]) == coverage.CHANGES_CONCLUSION


def test_the_event_itself_and_the_flattened_event_are_read(tmp_path):
    flat = {"aid": "aid-2", "hostname": "bravo", "@timestamp": 5,
            "assessments.secure_boot_enabled": "no", "scores.os": 10}
    path = tmp_path / "z.jsonl"
    path.write_text(json.dumps(_event("aid-1", "alpha", ALL_YES)) + "\n" + json.dumps(flat)
                    + "\n", encoding="utf-8")
    rows = by_name(_run(path).records)
    assert rows["Platform integrity — alpha"].verdict == "acceptable"
    bravo = rows["Platform integrity — bravo"]
    assert bravo.verdict == "weak" and bravo.extra["scores"] == {"os": 10}
    assert bravo.extra["zta.secure_boot_enabled"] == "no"


def test_a_csv_export_with_the_raw_event_is_read(tmp_path):
    path = tmp_path / "z.csv"
    write(path, ("aid", "@timestamp", "@rawstring"),
          [_raw(_event("aid-1", "alpha", ALL_YES), 7)])
    rows = by_name(_run(path).records)
    assert rows["Platform integrity — alpha"].verdict == "acceptable"


def test_a_machine_type_the_other_exports_agree_on_is_kept(tmp_path):
    path = _export(tmp_path / "z.json", [
        _raw(_event("aid-1", "alpha", ALL_YES, kind="Workstation",
                    os_version="Windows Server 2025"), 1),
        _raw(_event("aid-2", "bravo", ALL_YES, kind="Server"), 1),
        _raw(_event("aid-3", "charlie", ALL_YES, kind="Server"), 1)])
    types = tmp_path / "types.csv"
    write(types, ("aid", "ProductType"), [{"aid": "aid-1", "ProductType": "Server"},
                                          {"aid": "aid-2", "ProductType": "server"},
                                          {"aid": "aid-3", "ProductType": "Workstation"}])
    other = tmp_path / "types2.csv"
    write(other, ("Sensor", "Kind"), [{"Sensor": "aid-1", "Kind": "Server"},
                                      {"Sensor": "aid-3", "Kind": "Domain Controller"}])
    settings = {"host_types": [str(types), str(other)],
                "columns": {"host_types": {"sensor_id": ["Sensor", "aid"],
                                           "machine_type": ["Kind", "ProductType"]}}}
    rows = by_name(_run(path, settings).records)
    alpha = rows["Platform integrity — alpha"].extra
    assert alpha["host_type"] == "Server" and alpha["host_type_reported"] == "Workstation"
    assert alpha["host_type_basis"] == reader.BASIS_INVENTORY
    bravo = rows["Platform integrity — bravo"].extra
    assert bravo["host_type"] == "Server" and bravo["host_type_basis"] == reader.BASIS_ASSESSMENT
    charlie = rows["Platform integrity — charlie"].extra   # the exports disagree: kept as reported
    assert charlie["host_type"] == "Server"


def test_the_graded_controls_are_a_setting(tmp_path):
    path = _export(tmp_path / "z.json", [
        _raw(_event("aid-1", "alpha", {"firewall_enabled": "no", "secure_boot_enabled": "no"}),
             1)])
    row = _run(path, {"controls": {"firewall_enabled": "no-firewall"}}).records[0]
    assert row.verdict == "weak" and row.flags == ["no-firewall"]


def test_an_unreadable_file_is_the_not_collected_gap(tmp_path):
    path = tmp_path / "z.json"
    path.write_text("this is not json\n", encoding="utf-8")
    out = _run(path)
    assert out.records == [] and coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
