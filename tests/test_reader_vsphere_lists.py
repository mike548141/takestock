"""The vSphere Client list exports reader in takestock's readers library.

The fixtures in ``fixtures/vsphere_lists/`` are written by hand in the shape
the vSphere Client's Export action gives (UTF-8 with a byte-order mark, every
value quoted, one heading holding a line break), with the columns the reader
reads and a few it does not. Every machine, host, datastore and device name
is synthetic. The files join the site label to the list name with an
underscore, which the reader reads as it reads a space. Two sites; a Site
Recovery Manager placeholder at each, one with the name of a machine at the
other site; machines encrypted, not
encrypted and in neither state; hosts whose certificates are valid, near
expiry, expired and unreadable; datastores on arrays, on a virtual-volume
container, on vSAN, on disks inside hosts and with no maker prefix.
"""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, plugin_kinds, roles
from takestock.model import CryptoAsset
from takestock.plugins import Context, StepResult
from takestock.policy import Policy
from takestock.readers import library, vsphere_lists

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vsphere_lists"
EXPORTED = datetime(2030, 1, 15, 12, 0, tzinfo=UTC)

LIFECYCLE = """\
schema: 1
sources:
  example-source: {url: 'https://example.com/lifecycle', read: '2030-01-01', says: 'Example dates.'}
lines:
  - id: example-rhel-9
    match:
      - {kind: os, product: "Red Hat Enterprise Linux 9 (64-bit)"}
    variants:
      - {name: Example, source: example-source,
         phases: [{band: supported, until: "2031-05-31"}], after: end-of-support}
  - id: example-esxi-8
    match:
      - {kind: hypervisor, product_pattern: 'VMware ESXi 8\\.0(\\.\\d+)?'}
    variants:
      - {name: Example, source: example-source,
         phases: [{band: supported, until: "2029-10-11"}], after: end-of-support}
"""


def _copy(tmp_path: Path) -> Path:
    folder = tmp_path / "lists"
    shutil.copytree(FIXTURES, folder)
    for p in folder.iterdir():
        os.utime(p, (EXPORTED.timestamp(), EXPORTED.timestamp()))
    return folder


def _ctx(path: Path | None, settings: dict | None = None) -> Context:
    return Context(plugin=vsphere_lists.PLUGIN, target={}, settings=settings or {}, input=path,
                   ref_time=datetime(2030, 2, 1, tzinfo=UTC), raw_dir=Path("."),
                   policy=Policy(config.load_baseline()), baseline={}, dictionary={},
                   port_table={}, collected_on="2030-02-01")


def _by_name(rows: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


@pytest.fixture()
def lifecycle_table(tmp_path) -> Path:
    path = tmp_path / "lifecycle.yaml"
    path.write_text(LIFECYCLE)
    return path


@pytest.fixture()
def result(tmp_path, lifecycle_table) -> StepResult:
    return vsphere_lists.read(_ctx(_copy(tmp_path), {"lifecycle": str(lifecycle_table)}))


def test_the_rows_in_order(result):
    assert [a.name for a in result.records] == [
        "VM encryption, SiteA vCenter", "Virtual TPM, SiteA vCenter",
        "Virtualisation-based security setting, SiteA vCenter",
        "VM encryption, SiteB vCenter", "Virtual TPM, SiteB vCenter",
        "Virtualisation-based security setting, SiteB vCenter",
        "vSphere guest OS Microsoft Windows Server 2022 (64-bit)",
        "vSphere guest OS Red Hat Enterprise Linux 9 (64-bit)",
        "vSphere guest OS Microsoft Windows Server 2019 (64-bit)",
        "vSphere guest OS Other Linux (64-bit)",
        "vSphere guest OS Ubuntu Linux (64-bit)",
        "ESXi host certificate esx-a1.example.test", "ESXi host certificate esx-a2.example.test",
        "ESXi host certificate esx-a3.example.test", "ESXi host certificate esx-b1.example.test",
        "VMware ESXi 8.0.9", "VMware ESXi 7.0.9",
        "Datastores, SiteA vCenter",
        "vSphere list exports scope"]
    for a in result.records:
        assert (a.source, a.source_class, a.collected_at) == ("vsphere_lists", "private",
                                                             "2030-01-15")
        assert a.source_name == "vSphere Client list exports, files dated 2030-01-15"
        assert plugin_kinds.check_asset("general", a) == []


def test_placeholders_are_not_machines(result):
    scope = _by_name(result.records)["vSphere list exports scope"]
    assert scope.extra == {
        "files": ("datastoresForVCenter_Name_SiteA.csv, hostsForVCenter_Name_SiteA.csv, "
                  "hostsForVCenter_Name_SiteB.csv, vmsForDatacenter_Name_SiteA.csv, "
                  "vmsForDatacenter_Name_SiteB.csv"),
        "vm_rows": "9", "placeholders": "2", "machines": "7", "powered_on": "6", "hosts": "4",
        "datastores": "6", "export_dates": "2030-01-15"}
    assert scope.hosts_count == 7
    assert scope.flags == ["scope-vsphere-lists"]
    assert "2 rows marked protected by Site Recovery Manager" in scope.notes


def test_vm_encryption_off_is_a_fact_and_on_is_graded(result):
    rows = _by_name(result.records)
    a = rows["VM encryption, SiteA vCenter"]
    assert (a.verdict, a.flags, a.symmetric, a.hosts_count) == (
        "n/a", ["vm-encryption-off:4", "vsphere-vm-census:4"], [], 4)
    assert a.extra == {"site": "SiteA", "vms": "4", "encryption_on": "0",
                       "encryption_off": "4", "encryption_other": ""}
    assert "No machine here is encrypted by vSphere." in a.notes
    b = rows["VM encryption, SiteB vCenter"]
    assert (b.verdict, b.symmetric) == ("strong", ["aes256_xts"])
    assert b.flags == ["ungraded:vm-encryption:pending", "vm-encryption-off:1",
                       "vsphere-vm-census:3"]
    assert b.extra["encryption_other"] == "pending=1"
    assert (a.data_state, a.protocol, a.software) == ("at-rest", "vm-encryption",
                                                      "VMware vSphere VM Encryption")
    assert a.role == roles.vm_encryption_population(4)


def test_virtual_tpm_and_virtualisation_based_security(result):
    rows = _by_name(result.records)
    tpm = rows["Virtual TPM, SiteA vCenter"]
    assert tpm.flags == ["vsphere-vm-census:4", "vtpm-absent:3"]
    assert tpm.extra["no_vtpm"] == "3" and tpm.extra["no_vtpm_windows"] == "1"
    assert tpm.extra["vtpm_precondition_source"] == vsphere_lists.VTPM_SOURCE
    vbs = rows["Virtualisation-based security setting, SiteA vCenter"]
    assert vbs.flags == ["vbs-enabled:1", "vsphere-vm-census:2"]
    assert vbs.extra == {"site": "SiteA", "windows_vms": "2", "vbs_enabled": "1",
                         "vbs_enabled_powered_on": "1"}
    assert "1 machine(s) not configured as Windows have it enabled too." in vbs.notes


def test_guest_types_take_support_from_the_named_table(result):
    rows = _by_name(result.records)
    rhel = rows["vSphere guest OS Red Hat Enterprise Linux 9 (64-bit)"]
    assert rhel.extra == {"guest_os": "Red Hat Enterprise Linux 9 (64-bit)", "vms": "2",
                          "powered_on": "1", "sites": "SiteA=1, SiteB=1",
                          "vendor_support_band": "supported", "lifecycle_line": "example-rhel-9",
                          "vendor_support_until": "2031-05-31"}
    assert rhel.flags == ["guest-os-census:2"]
    assert "https://example.com/lifecycle" in rhel.notes
    other = rows["vSphere guest OS Other Linux (64-bit)"]
    assert (other.extra["vendor_support_band"], other.extra["lifecycle_line"]) == ("", "")
    assert "no lifecycle line matches this name exactly" in other.notes
    esxi = rows["VMware ESXi 8.0.9"]
    assert esxi.extra == {"esx_version": "8.0.9",
                          "hosts": "esx-a1.example.test esx-a2.example.test esx-b1.example.test",
                          "sites": "SiteA, SiteB", "vendor_support_band": "end-of-support",
                          "lifecycle_line": "example-esxi-8"}
    assert (esxi.software, esxi.version, esxi.hosts_count) == ("VMware ESXi 8.0.9", "8.0.9", 3)


def test_the_bundled_lifecycle_table_is_the_default(tmp_path):
    rows = _by_name(vsphere_lists.read(_ctx(_copy(tmp_path))).records)
    assert rows["VMware ESXi 8.0.9"].extra["lifecycle_line"]


def test_a_lifecycle_table_that_cannot_be_read_is_a_gap(tmp_path):
    out = vsphere_lists.read(_ctx(_copy(tmp_path), {"lifecycle": str(tmp_path / "none.yaml")}))
    assert out.records
    texts = [str(g) for g in out.gaps]
    assert any("lifecycle table named in the vsphere_lists settings" in t for t in texts)


def test_host_certificates_are_dated_from_the_export(result):
    rows = _by_name(result.records)
    p = "ESXi host certificate "
    expect = {
        "esx-a1.example.test": (["not-assessed:certificate-key-and-signature"], "2031-03-04"),
        "esx-a2.example.test": (["expiry-soon", "not-assessed:certificate-key-and-signature"],
                                "2030-02-01"),
        "esx-a3.example.test": (["expired", "not-assessed:certificate-key-and-signature"],
                                "2029-12-01"),
        "esx-b1.example.test": (["not-assessed:certificate-key-and-signature"], "not available"),
    }
    for host, (flags, not_after) in expect.items():
        a = rows[p + host]
        assert (a.verdict, a.flags, a.extra["cert_not_after"], a.host) == (
            "unknown", flags, not_after, host), host
        assert (a.data_state, a.protocol) == ("certificate", "tls")
    assert rows[p + "esx-a2.example.test"].extra["cert_days_remaining_at_export"] == "17"
    assert rows[p + "esx-b1.example.test"].extra["cert_days_remaining_at_export"] == ""
    assert "could not be read" in rows[p + "esx-b1.example.test"].notes


def test_datastores_by_what_backs_them(result):
    ds = _by_name(result.records)["Datastores, SiteA vCenter"]
    assert ds.extra == {"site": "SiteA", "datastores": "6", "vsan": "1", "on_array": "3",
                        "off_array": "2", "off_array_capacity_gb": "2048", "unplaced": "1",
                        "types": "VMFS 6=4, vSAN=1, vVol=1"}
    assert ds.flags == ["datastore-census:6"]
    [gap] = result.gaps
    assert str(gap).startswith("2 datastores are on disks inside hosts")
    assert coverage.kind_of(gap) == coverage.NOT_MEASURED
    assert coverage.impact_kind_of(gap) == coverage.NARROWS_CONFIDENCE
    assert coverage.nature_of(gap) == coverage.LOW_FIDELITY


@pytest.mark.parametrize(("device", "prefix"), [
    ("naa.600a0980000000000000000000000002", "00a098"),
    ("NAA.50025380000000A1", "002538"),
    ("t10.ATA_____Example_SSD_0001", ""),
    ("", ""),
])
def test_maker_prefix(device, prefix):
    assert vsphere_lists.maker_prefix(device) == prefix


@pytest.mark.parametrize(("text", "gb"), [
    ("1,788.5 GB", 1788.5), ("2 TB", 2048.0), ("512 MB", 0.5), ("unknown", 0.0),
])
def test_capacity(text, gb):
    assert vsphere_lists.capacity_gb(text) == gb


def test_headings_fold_line_breaks_and_case():
    assert vsphere_lists.heading("VMware Tools Running \nStatus") == "vmware tools running status"
    assert vsphere_lists.heading("Guest OS") == vsphere_lists.heading("guest  os")


def test_the_site_comes_from_the_file_name():
    assert vsphere_lists.site_of(Path("vmsForDatacenter_Name SiteA.csv"),
                                 vsphere_lists.VM_LIST) == "SiteA"
    assert vsphere_lists.site_of(Path("vmsForDatacenter_Name_SiteA.csv"),
                                 vsphere_lists.VM_LIST) == "SiteA"
    assert vsphere_lists.site_of(Path("vmsForDatacenter_Name.csv"),
                                 vsphere_lists.VM_LIST) == "(unnamed)"


def test_nothing_to_read_writes_nothing(tmp_path):
    assert vsphere_lists.read(_ctx(None)) == StepResult()
    assert vsphere_lists.read(_ctx(tmp_path)) == StepResult()


def test_an_unreadable_export_is_a_gap_and_the_rest_are_read(tmp_path):
    folder = _copy(tmp_path)
    (folder / "vmsForDatacenter_Name SiteC.csv").write_bytes(b"\xff\xfe\x00\x81")
    out = vsphere_lists.read(_ctx(folder))
    assert "VM encryption, SiteA vCenter" in _by_name(out.records)
    unread = [g for g in out.gaps if "could not be read" in str(g)]
    assert len(unread) == 1 and "SiteC" in str(unread[0])
    assert coverage.kind_of(unread[0]) == coverage.NOT_COLLECTED


def test_vm_lists_present(tmp_path):
    assert not vsphere_lists.vm_lists_present(None)
    assert not vsphere_lists.vm_lists_present(tmp_path)
    assert vsphere_lists.vm_lists_present(_copy(tmp_path))


def test_the_declaration():
    p = vsphere_lists.PLUGIN
    assert (p.name, p.kind, p.input, p.gap_prefix) == ("vsphere_lists", "general", "", False)
    assert library()["vsphere_lists"] is p
