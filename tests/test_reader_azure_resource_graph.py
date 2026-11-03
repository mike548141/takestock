"""The Azure Resource Graph reader in takestock's readers library.

Each export is composed in its test, under the reader's default headings (or
other headings named in the settings), with made-up resource names, synthetic
subscription IDs and small counts. Nothing here was captured from a real
export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import ctx, guid, write

from takestock import config, coverage
from takestock.policy import Policy
from takestock.readers import azure_resource_graph as reader
from takestock.readers import library

COLUMNS = tuple(reader.HEADINGS.values())
STORAGE = "Microsoft.Storage/storageAccounts"
DISK = "Microsoft.Compute/disks"
SNAPSHOT = "Microsoft.Compute/snapshots"
VAULT = "Microsoft.RecoveryServices/vaults"
KEY_VAULT = "Microsoft.KeyVault/vaults"
SUB_A, SUB_B = guid(1), guid(2)
HEX32 = "0123456789abcdef" * 2


def _row(name: str, rtype: str, sub: str = SUB_A, **cells: str) -> dict:
    return {"name": name, "type": rtype, "subscriptionId": sub, **cells}


def _storage(name: str, **cells: str) -> dict:
    base = {"minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": "true",
            "publicNetworkAccess": "Disabled", "allowBlobPublicAccess": "false",
            "keySource": "Microsoft.Storage"}
    base.update(cells)
    return _row(name, STORAGE, **base)


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def _by_name(out) -> dict:
    return {a.name: a for a in out.records}


def _scope(out):
    return _by_name(out)["Azure resource-graph encryption scope"]


def test_the_reader_is_in_the_library():
    assert library()["azure_resource_graph"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_COLLECTED
    assert coverage.nature_of(g) == coverage.NO_DATA
    assert "no Azure Resource Graph export" in str(g)


def test_a_missing_or_empty_file_gives_the_same_gap(tmp_path):
    assert len(_run(tmp_path / "absent.csv").gaps) == 1
    empty = _export(tmp_path / "empty.csv", [])
    out = _run(empty)
    assert out.records == [] and "holds no rows" in str(out.gaps[0])


def test_a_storage_account_gives_an_at_rest_row_and_a_tls_floor_row(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [_storage("stexample01")]))
    rows = _by_name(out)
    rest = rows["Azure storage account stexample01"]
    floor = rows["Azure storage account stexample01 TLS floor"]
    assert (rest.data_state, rest.protocol, rest.verdict) == ("at-rest", "azure-storage", "strong")
    assert rest.flags == ["key-custody:platform-managed"]
    assert rest.extra == {"resource_type": STORAGE.lower(), "subscription": SUB_A,
                          "public_network_access": "Disabled"}
    assert "256-bit AES" in rest.notes and "a platform-managed key" in rest.notes
    assert (floor.data_state, floor.protocol) == ("in-transit", "tls")
    assert floor.protocol_versions == ["TLSv1.2"] and floor.flags == []
    assert floor.notes == (
        "The account's configured minimum TLS version is TLSv1.2; Microsoft says a request "
        "using an older version fails. HTTPS-only is on, so plain HTTP is refused. Microsoft "
        "also says Azure Storage itself supports only TLS 1.2 and 1.3. This row is the "
        "configured setting read from Azure, not a handshake observed.")
    assert rest.collected_at == floor.collected_at == "2030-03-17"
    assert rest.source == reader.NAME and rest.source_name.endswith("file dated 2030-03-17")
    assert rest.role.startswith("Stored-data encryption for the Azure storage account stexample01")
    assert floor.role.startswith("The oldest TLS version the Azure storage account stexample01")


def test_the_baseline_grades_the_tls_floor_row(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [_storage("stexample01", minimumTlsVersion="TLS1_0"),
                                            _storage("stexample02"),
                                            _storage("stexample03", minimumTlsVersion="TLS1_1")]))
    policy = Policy(config.load_baseline())
    rows = {a.name: policy.apply(a) for a in out.records}
    assert rows["Azure storage account stexample01 TLS floor"].verdict == "weak"
    assert rows["Azure storage account stexample02 TLS floor"].verdict == "acceptable"
    assert rows["Azure storage account stexample03 TLS floor"].verdict == "weak"
    assert _scope(out).extra["storage_tls_floor_below_TLSv1.2"] == "2"


def test_an_unset_floor_reads_as_tls_1_0_and_http_settings_are_reported(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [
        _storage("stexample01", minimumTlsVersion="", supportsHttpsTrafficOnly="null"),
        _storage("stexample02", supportsHttpsTrafficOnly="FALSE")]))
    rows = _by_name(out)
    unset = rows["Azure storage account stexample01 TLS floor"]
    assert unset.protocol_versions == ["TLSv1.0"] and unset.flags == ["tls-floor-unset"]
    assert "not set" in unset.notes and "not in the export" in unset.notes
    http = rows["Azure storage account stexample02 TLS floor"]
    assert http.flags == ["https-only-off"]
    assert ("older version fails. It also accepts plain HTTP: HTTPS-only is off. Microsoft "
            "also says") in http.notes
    for row in (unset, http):
        assert "  " not in row.notes
        assert all(s[:1].isupper() for s in row.notes.split(". ")), row.notes
    assert _scope(out).extra["storage_tls_floor_below_TLSv1.2"] == "1"


def test_an_unrecognised_floor_is_passed_to_the_baseline_as_written(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [_storage("stexample01", minimumTlsVersion="TLS9_9")]))
    assert _by_name(out)["Azure storage account stexample01 TLS floor"].protocol_versions == [
        "TLS9_9"]


def test_storage_exposure_flags(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [
        _storage("stexample01", allowBlobPublicAccess="TRUE", publicNetworkAccess="Enabled"),
        _storage("stexample02", publicNetworkAccess=""),
        _storage("stexample03", publicNetworkAccess="SecuredByPerimeter",
                 allowBlobPublicAccess="")]))
    rows = _by_name(out)
    open_ = rows["Azure storage account stexample01"]
    assert open_.flags == ["key-custody:platform-managed", "blob-public-access",
                           "public-network-access:enabled"]
    assert "anyone can read it with no credential" in open_.notes
    assert open_.extra["public_network_access"] == "Enabled"
    unset = rows["Azure storage account stexample02"]
    assert unset.flags[-1] == "public-network-access:unset"
    assert unset.extra["public_network_access"] == reader.NETWORK_UNSET_NOTE
    perimeter = rows["Azure storage account stexample03"]
    assert perimeter.flags == ["key-custody:platform-managed"]
    assert perimeter.extra["public_network_access"] == "SecuredByPerimeter"
    # The TLS floor row carries the same extra as its account.
    assert rows["Azure storage account stexample02 TLS floor"].extra == unset.extra
    scope = _scope(out).extra
    assert scope["blob_public_access_accounts"] == "1"
    assert scope["public_network_access_enabled_storage"] == "1"
    assert scope["public_network_access_unset_storage"] == "1"


def test_key_sources(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [_storage("stexample01", keySource="Microsoft.Keyvault"),
                                            _storage("stexample02", keySource="Example.Other"),
                                            _storage("stexample03", keySource="")]))
    rows = _by_name(out)
    assert rows["Azure storage account stexample01"].flags == ["key-custody:customer-managed"]
    other = rows["Azure storage account stexample02"]
    assert other.verdict == "unknown"
    assert other.flags == ["ungraded:storage-key-source:Example.Other"]
    assert rows["Azure storage account stexample03"].flags == ["ungraded:storage-key-source:blank"]
    assert _scope(out).extra["key_custody_customer_managed"] == "1"


def test_disks_and_snapshots(tmp_path):
    set_id = "/subscriptions/" + SUB_A + "/diskEncryptionSets/des-example"
    out = _run(_export(tmp_path / "r.csv", [
        _row("md-sample-a", DISK, encryptionType="EncryptionAtRestWithPlatformKey",
             publicNetworkAccess="Enabled"),
        _row("md-sample-b", DISK, encryptionType="EncryptionAtRestWithCustomerKey",
             diskEncryptionSetId=set_id),
        _row("snap-sample-a", SNAPSHOT,
             encryptionType="EncryptionAtRestWithPlatformAndCustomerKeys"),
        _row("md-sample-c", DISK, encryptionType="ExampleNewType")]))
    rows = _by_name(out)
    one = rows["Azure managed disk md-sample-a"]
    assert (one.protocol, one.verdict, one.flags) == ("azure-disk", "strong",
                                                      ["key-custody:platform-managed"])
    assert one.extra["public_network_access"] == f"Enabled ({reader.DISK_EXPORT_NOTE})"
    two = rows["Azure managed disk md-sample-b"]
    assert two.flags == ["key-custody:customer-managed"]
    assert two.extra["disk_encryption_set"] == set_id
    snap = rows["Azure disk snapshot snap-sample-a"]
    assert snap.flags == ["key-custody:platform-and-customer"]
    assert "read from the snapshot itself" in snap.notes and "two layers" in snap.notes
    odd = rows["Azure managed disk md-sample-c"]
    assert odd.verdict == "unknown"
    assert odd.flags == ["ungraded:disk-encryption-type:ExampleNewType"]
    custody = {k: v for k, v in _scope(out).extra.items() if k.startswith("key_custody_")}
    assert custody == {"key_custody_customer_managed": "1", "key_custody_platform_managed": "1",
                       "key_custody_platform_and_customer": "1"}


def test_disk_name_shapes_split_a_name_into_its_parts(tmp_path):
    name = f"vm-example-01_disk1_{HEX32}"
    path = _export(tmp_path / "r.csv", [
        _row(name, DISK, encryptionType="EncryptionAtRestWithPlatformKey"),
        _row("other-disk", DISK, encryptionType="EncryptionAtRestWithPlatformKey"),
        _row(name + "-copy", SNAPSHOT, encryptionType="EncryptionAtRestWithPlatformKey")])
    shape = r"(?P<machine>.+?)_(?P<role>disk\d+)_(?P<uid>[0-9a-f]{32})"
    rows = _by_name(_run(path, {"disk_name_shapes": [shape]}))
    split = rows[f"Azure managed disk vm-example-01 disk1 {HEX32}"]
    assert (split.extra["azure_disk_machine"], split.extra["azure_disk_role"],
            split.extra["azure_disk_uid"]) == ("vm-example-01", "disk1", HEX32)
    assert name not in split.role and name not in split.name
    assert "Azure managed disk other-disk" in rows
    # A shape must match the whole name, not a part of it.
    assert f"Azure disk snapshot {name}-copy" in rows
    assert "azure_disk_uid" not in rows["Azure managed disk other-disk"].extra
    # With no shape named, the name is shown as it is.
    assert f"Azure managed disk {name}" in _by_name(_run(path))


def test_an_unusable_disk_name_shape_is_ignored_and_said(tmp_path):
    path = _export(tmp_path / "r.csv", [_row("disk-a_b_c", DISK,
                                             encryptionType="EncryptionAtRestWithPlatformKey")])
    out = _run(path, {"disk_name_shapes": ["(unclosed", r"(?P<machine>.+)_(?P<role>.+)"]})
    assert "Azure managed disk disk-a_b_c" in _by_name(out)
    assert "2 disk name shape(s)" in _scope(out).notes


def test_vaults(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [
        _row("rsv-example", VAULT, publicNetworkAccess="Enabled"),
        _row("kv-example-01", KEY_VAULT, enableRbacAuthorization="false"),
        _row("kv-example-02", KEY_VAULT, enableRbacAuthorization="true",
             publicNetworkAccess="Disabled"),
        _row("kv-example-03", KEY_VAULT)]))
    rows = _by_name(out)
    vault = rows["Azure backup vault rsv-example"]
    assert (vault.protocol, vault.verdict, vault.flags) == (
        "azure-backup", "unknown", ["not-assessed:backup-vault-encryption"])
    assert vault.extra["public_network_access"] == "Enabled"
    assert "not the same as not encrypted" in vault.notes
    policies = rows["Azure key vault kv-example-01"]
    assert (policies.data_state, policies.verdict) == ("key-material", "n/a")
    assert policies.flags == ["kv-access-policy-authorisation"]
    assert "legacy" in policies.notes
    rbac = rows["Azure key vault kv-example-02"]
    assert rbac.flags == [] and rbac.extra["public_network_access"] == "Disabled"
    assert rows["Azure key vault kv-example-03"].flags == ["not-assessed:key-vault-authorisation"]


def test_an_unrecognised_type_is_recorded_not_dropped(tmp_path):
    out = _run(_export(tmp_path / "r.csv", [_row("thing-example", "Microsoft.Example/things"),
                                            _row("", STORAGE)]))
    rows = _by_name(out)
    thing = rows["Azure resource thing-example"]
    assert thing.verdict == "unknown"
    assert thing.flags == ["ungraded:azure-resource-type:microsoft.example/things"]
    assert len(out.records) == 2  # the row with no name is skipped
    assert _scope(out).extra["rows"] == "1"


def test_the_scope_row_and_the_database_gap(tmp_path):
    subs = write(tmp_path / "subs.csv", ("name", "subscriptionId"),
                 [{"name": "Example Production", "subscriptionId": SUB_A},
                  {"name": "Example Test", "subscriptionId": SUB_B}])
    path = _export(tmp_path / "r.csv", [_storage("stexample01"),
                                        _row("rsv-example", VAULT, sub=SUB_B)])
    out = _run(path, {"subscriptions": str(subs)})
    scope = _scope(out)
    assert (scope.verdict, scope.flags, scope.hosts_count) == ("n/a", ["scope-queried-types-only"],
                                                               2)
    assert scope.extra["subscriptions_listed"] == "2"
    assert scope.extra["subscriptions_in_rows"] == "2"
    assert "every one contributed rows" in scope.notes
    assert "backup vault: 1, storage account: 1" in scope.notes
    assert _by_name(out)["Azure backup vault rsv-example"].extra["subscription"] == "Example Test"
    assert len(out.gaps) == 1 and "no database" in str(out.gaps[0])
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION

    partial = _run(_export(tmp_path / "p.csv", [_storage("stexample01")]),
                   {"subscriptions": str(subs)})
    assert ("1 of them (Example Test) contributed no row (each holds none of the queried "
            "types, or was not read)") in _scope(partial).notes
    alone = _scope(_run(path))
    assert alone.extra["subscriptions_listed"] == "not supplied"
    assert "No subscription list was read" in alone.notes


def test_other_headings_are_named_in_the_settings(tmp_path):
    columns = ("NAME", "Type", "sub", "floor", "https", "net", "anon", "keysrc", "enc",
               "encset", "rbac")
    row = {"NAME": "stexample01", "Type": STORAGE, "sub": SUB_A, "floor": "tls1_1",
           "https": "TRUE", "net": "null", "anon": "False", "keysrc": "microsoft.storage",
           "enc": "null", "encset": "null", "rbac": "null"}
    path = _export(tmp_path / "r.csv", [row], columns)
    settings = {"columns": {"subscription": "sub", "tls_floor": "floor", "https_only": "https",
                            "public_network": "net", "anonymous_blob": "anon",
                            "key_source": "keysrc", "disk_encryption": "enc",
                            "disk_encryption_set": "encset", "rbac": "rbac",
                            "not_a_field": "ignored"}}
    rows = _by_name(_run(path, settings))
    assert rows["Azure storage account stexample01"].flags == [
        "key-custody:platform-managed", "public-network-access:unset"]
    assert rows["Azure storage account stexample01 TLS floor"].protocol_versions == ["TLSv1.1"]
