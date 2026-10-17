"""The CycloneDX reader in takestock's readers library.

The fixture, ``fixtures/cyclonedx/example-orders-api.cdx.json``, was written by
hand from the CycloneDX 1.6 JSON schema and checked against that schema
(``bom-1.6.schema.json`` from the CycloneDX specification repository). Every
name in it is synthetic. It holds a component of each class, one the classes
do not match, a nested component, a component classed by its group, two
pre-release versions and a dependency graph.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import coverage, model, plugins
from takestock.model import CryptoAsset
from takestock.readers import cyclonedx

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cyclonedx" / "example-orders-api.cdx.json"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)


def _ctx(path: Path | None) -> plugins.Context:
    from takestock.policy import Policy
    return plugins.Context(plugin=cyclonedx.PLUGIN, target={}, settings={}, input=path,
                           ref_time=NOW, raw_dir=Path("."), policy=Policy({}), baseline={},
                           dictionary={}, port_table={}, collected_on="2030-01-31")


def _by_name(rows: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


@pytest.fixture()
def result() -> plugins.StepResult:
    return cyclonedx.read(_ctx(FIXTURE))


def test_the_classes_are_whole_words_and_the_first_match_wins():
    assert cyclonedx.classify("example-crypto").key == "primitives"
    assert cyclonedx.classify("example-cryptic-names") is None
    # SSH outranks the cipher package an SSH library ships; a token library
    # outranks the identity framework it belongs to.
    assert cyclonedx.classify("Example.Ssh.Cryptography").key == "ssh"
    assert cyclonedx.classify("Example.Identity.TokenCache").key == "tokens"
    assert cyclonedx.classify("example-provider", group="org.example.crypto").key == "primitives"
    assert cyclonedx.classify("@example/oauth-client").key == "identity"
    assert cyclonedx.classify("example_redis_pool").key == "transport"


@pytest.mark.parametrize(("version", "pre"), [
    ("1.0.0-beta.3", True), ("2.0.0-preview.1", True), ("13.29.0-rc.4", True),
    ("1.0-SNAPSHOT", True), ("2.0b1", True), ("1.4.dev2", True), ("3.0.0-alpha", True),
    ("8.14.3", False), ("1.80", False), ("17.6.21-linux-x64", False), ("2.47.9-devops", False),
])
def test_pre_release_versions(version, pre):
    assert cyclonedx.is_prerelease(version) is pre


def test_one_row_per_classified_component_then_the_application_then_the_scope(result):
    names = [a.name for a in result.records]
    assert names == [
        "example-crypto 2.47.9", "example-jwt 1.0.0-beta.3", "example-ssh-client 0.63.7",
        "example-redis-client 13.29.0-rc.4", "example-oauth 17.6.21", "example-oauth-kms-bridge 17.6.21",
        "example-provider 1.80", "Application example-orders-api 8.14.3",
        "Application-layer SBOM scope"]
    assert all(a.data_state == "discovery" and a.protocol == "software" for a in result.records)
    rows = _by_name(result.records)
    assert rows["example-oauth-kms-bridge 17.6.21"].extra["provides"] == "key-management"
    assert rows["example-provider 1.80"].extra["provides"] == "primitives"


def test_component_flags(result):
    rows = _by_name(result.records)
    assert rows["example-crypto 2.47.9"].flags == [
        "sbom-declared-dependency", "sbom-provides:primitives", "sbom-direct-dependency"]
    # A pre-release of a token library is flagged; of a transport client, not.
    assert cyclonedx.PRERELEASE_FLAG in rows["example-jwt 1.0.0-beta.3"].flags
    assert cyclonedx.PRERELEASE_FLAG not in rows["example-redis-client 13.29.0-rc.4"].flags
    assert cyclonedx.SSH_FLAG in rows["example-ssh-client 0.63.7"].flags
    # Reached only through another component, so not direct.
    assert "sbom-direct-dependency" not in rows["example-ssh-client 0.63.7"].flags
    assert all(a.verdict == "unknown" for a in result.records if a.name[0].islower())


def test_component_rows_carry_the_application_and_the_sboms_date(result):
    row = _by_name(result.records)["example-crypto 2.47.9"]
    assert row.software == "example-crypto" and row.version == "2.47.9"
    assert row.collected_at == "2030-01-15"
    assert row.source_name == "CycloneDX 1.6 SBOM of example-orders-api, generated 2030-01-15"
    assert row.extra == {"sbom_subject": "example-orders-api 8.14.3", "provides": "primitives",
                         "purl": "pkg:pypi/example-crypto", "spec_version": "1.6"}
    assert row.role.startswith("A cryptographic library component")
    assert "can do, not a measurement" in row.notes


def test_the_application_and_scope_rows(result):
    rows = _by_name(result.records)
    app = rows["Application example-orders-api 8.14.3"]
    assert app.verdict == "n/a" and app.flags == ["sbom-subject"]
    assert app.extra == {"components": "8", "classified": "7", "with_hashes": "2",
                         "direct_dependencies": "4", "spec_version": "1.6"}
    scope = rows["Application-layer SBOM scope"]
    assert scope.flags == ["sbom-scope"] and scope.collected_at == ""
    assert scope.extra == {"sboms_read": "1", "components": "8", "classified": "7"}


def test_the_rest_of_the_applications_is_a_gap(result):
    [gap] = result.gaps
    assert "1 application(s) have one here" in gap
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.nature_of(gap) == coverage.NO_DATA


def test_a_library_that_encrypts_by_default_is_flagged_from_its_documented_version():
    bom = cyclonedx.Bom(path=FIXTURE, spec="1.6", subject="example-app", subject_version="1",
                        subject_ref="", date="2030-01-15")
    cls = cyclonedx.classify("Microsoft.Data.SqlClient")
    assert cls is not None and cls.key == "transport"
    for version, flagged in (("9.31.6", True), ("4.0.59", True), ("3.47.2", False)):
        row = cyclonedx._component_row({"name": "Microsoft.Data.SqlClient", "version": version},
                                       cls, bom, "")
        assert ("sbom-encrypts-by-default" in row.flags) is flagged, version
        assert row.verdict == "unknown"


def test_a_folder_is_read_file_by_file_and_unreadable_files_are_a_gap(tmp_path):
    shutil.copy(FIXTURE, tmp_path / "a.cdx.json")
    doc = json.loads(FIXTURE.read_text())
    doc["metadata"]["component"].update(name="example-billing-api", version="1.0.0")
    doc["metadata"]["component"]["bom-ref"] = "example-billing-api-1.0.0"
    doc["dependencies"][0]["ref"] = "example-billing-api-1.0.0"
    (tmp_path / "b.cdx.json").write_text(json.dumps(doc))
    (tmp_path / "c.json").write_text('{"spdxVersion": "SPDX-2.3"}')
    (tmp_path / "d.json").write_text("not json")
    (tmp_path / "notes.txt").write_text("ignored")
    out = cyclonedx.read(_ctx(tmp_path))
    scope = _by_name(out.records)["Application-layer SBOM scope"]
    assert scope.extra["sboms_read"] == "2"
    assert "example-billing-api 1.0.0" in scope.notes
    unreadable, rest = out.gaps
    assert "c.json (not a CycloneDX document" in unreadable and "d.json (not readable" in unreadable
    assert "2 application(s)" in rest


def test_nothing_readable_is_a_gap_and_no_scope_row(tmp_path):
    out = cyclonedx.read(_ctx(tmp_path))
    assert out.records == [] and "holds no .json file" in out.gaps[0]
    (tmp_path / "x.json").write_text("[]")
    out = cyclonedx.read(_ctx(tmp_path))
    assert out.records == [] and len(out.gaps) == 1 and "x.json" in out.gaps[0]


def test_without_a_timestamp_the_files_date_is_used(tmp_path):
    doc = json.loads(FIXTURE.read_text())
    del doc["metadata"]["timestamp"]
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc))
    stamp = datetime(2030, 1, 20, 12, tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    out = cyclonedx.read(_ctx(path))
    assert _by_name(out.records)["example-crypto 2.47.9"].collected_at == "2030-01-20"


def test_flags_other_than_a_pre_release_are_informational():
    for flag in ("sbom-declared-dependency", "sbom-provides:ssh", "sbom-direct-dependency",
                 cyclonedx.SSH_FLAG, "sbom-encrypts-by-default", "sbom-subject", "sbom-scope"):
        assert model.is_informational_flag(flag), flag
    assert not model.is_informational_flag(cyclonedx.PRERELEASE_FLAG)


def test_the_declaration():
    p = cyclonedx.PLUGIN
    assert (p.name, p.kind, p.input, p.gap_prefix, p.date_rows) == (
        "sbom", "general", "inbox/sbom", False, False)
