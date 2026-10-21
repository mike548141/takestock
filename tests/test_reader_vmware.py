"""The VMware VM Encryption and vSAN encryption reader in takestock's readers library.

The fixture, ``fixtures/vmware/example-vm-encryption.csv``, is written by
hand in the reader's columns (``docs/COLLECTORS.md``), with key provider
types as vSphere names them. Every machine, cluster and key provider name is
synthetic. It holds a machine and a cluster in each state the reader grades,
each kind of key custody, a cipher the baseline does not grade, and rows
that record encryption by a key provider alone.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, plugin_kinds, roles
from takestock.model import CryptoAsset
from takestock.plugins import Context, StepResult
from takestock.policy import Policy
from takestock.readers import library, vmware

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vmware" / "example-vm-encryption.csv"
LISTS = Path(__file__).resolve().parent / "fixtures" / "vsphere_lists"


def _ctx(path: Path | None, settings: dict | None = None) -> Context:
    return Context(plugin=vmware.PLUGIN, target={}, settings=settings or {}, input=path,
                   ref_time=datetime(2030, 1, 31, tzinfo=UTC), raw_dir=Path("."),
                   policy=Policy(config.load_baseline()), baseline={}, dictionary={},
                   port_table={}, collected_on="2030-01-31")


def _by_name(rows: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


@pytest.fixture()
def result() -> StepResult:
    return vmware.read(_ctx(FIXTURE))


def test_verdicts_and_flags(result):
    vm, vsan = "VMware vSphere VM Encryption ", "VMware vSAN "
    expect = {
        f"{vm}example-app-01": ("strong", ["key-custody:native-key-provider"], ["aes256_xts"]),
        f"{vm}example-app-02": ("n/a", ["vm-encryption-off"], []),
        f"{vm}example-db-01": ("strong", ["key-custody:external-kms"], ["aes256_xts"]),
        f"{vm}example-web-01": ("n/a", ["vm-encryption-off"], []),
        f"{vm}example-web-02": ("weak", ["encryption-status:pending"], []),
        f"{vm}example-lab-01": ("unknown", ["key-custody:trust-authority",
                                            "ungraded:symmetric:example-cipher"], []),
        f"{vsan}example-cluster-a": ("strong", ["key-custody:external-kms"], ["aes256_xts"]),
        f"{vsan}example-cluster-b": ("weak", ["encryption-off"], []),
        f"{vsan}example-cluster-c": ("strong", ["key-custody:example-kms"], ["aes256_xts"]),
    }
    rows = _by_name(result.records)
    assert list(rows) == list(expect)
    for name, (verdict, flags, symmetric) in expect.items():
        row = rows[name]
        assert (row.verdict, row.flags, row.symmetric) == (verdict, flags, symmetric), name
        assert row.source == "vmware" and row.data_state == "at-rest"
        assert plugin_kinds.check_asset("general", row) == []
    assert result.gaps == []


def test_a_row_keeps_what_the_export_said(result):
    rows = _by_name(result.records)
    cluster = rows["VMware vSAN example-cluster-a"]
    assert (cluster.protocol, cluster.software, cluster.host) == (
        "vsan-encryption", "VMware vSAN", "example-cluster-a")
    assert cluster.extra == {"scope": "vsan-cluster", "key_provider": "example-kms",
                             "key_provider_type": "Standard", "cipher": "XTS-AES-256"}
    assert cluster.role == roles.virtual_storage_encryption("example-cluster-a", True)
    machine = rows["VMware vSphere VM Encryption example-app-01"]
    assert (machine.protocol, machine.extra["scope"]) == ("vm-encryption", "vm")
    assert machine.notes == ("VM encryption is on. Key provider example-nkp (Native Key "
                             "Provider). Cipher not recorded; vSphere uses XTS-AES-256.")
    assert rows["VMware vSphere VM Encryption example-app-02"].notes == "VM encryption is off."
    assert "neither on nor off" in rows["VMware vSphere VM Encryption example-web-02"].notes
    assert machine.source_name.startswith("VMware vSphere encryption export (PowerCLI), "
                                          "file dated ")


@pytest.mark.parametrize(("written", "token"), [
    ("", "aes256_xts"), ("AES-256-XTS", "aes256_xts"), ("xts-aes-256", "aes256_xts"),
    ("Example-Cipher", "example-cipher"),
])
def test_cipher_names(written, token):
    assert vmware.cipher_token(written) == token


@pytest.mark.parametrize(("kind", "name", "flag"), [
    ("vSphere Native Key Provider", "", "key-custody:native-key-provider"),
    ("Trusted Key Provider", "", "key-custody:trust-authority"),
    ("KMIP", "", "key-custody:external-kms"),
    ("", "Example KMS", "key-custody:example-kms"),
    ("", "", ""),
])
def test_custody(kind, name, flag):
    assert vmware.custody(kind, name) == flag


def test_headings_may_vary_in_case_and_joining(tmp_path):
    path = tmp_path / "vm.csv"
    path.write_text("Scope,VM Name,Encryption Enabled,Key Provider\n"
                    "vm,example-app-09,Enabled,example-nkp\n")
    [row] = vmware.read(_ctx(path)).records
    assert (row.name, row.verdict) == ("VMware vSphere VM Encryption example-app-09", "strong")


@pytest.mark.parametrize(("content", "why"), [
    (None, "no input was given"),
    ("scope,name,encrypted\n", "holds no rows"),
])
def test_nothing_read_is_one_gap(tmp_path, content, why):
    path = None
    if content is not None:
        path = tmp_path / "vm.csv"
        path.write_text(content)
    out = vmware.read(_ctx(path))
    assert out.records == []
    [gap] = out.gaps
    assert why in str(gap)
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(gap) == coverage.NO_DATA


def test_no_gap_when_the_named_list_exports_answer_it(tmp_path):
    lists = tmp_path / "lists"
    shutil.copytree(LISTS, lists)
    assert vmware.read(_ctx(None, {"vsphere_lists": str(lists)})) == StepResult()
    # A folder with no virtual-machine list does not stand in for the export.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert len(vmware.read(_ctx(None, {"vsphere_lists": str(empty)})).gaps) == 1


def test_the_declaration():
    p = vmware.PLUGIN
    assert (p.name, p.kind, p.input, p.gap_prefix) == ("vmware", "general", "", False)
    assert library()["vmware"] is p
