"""The ``software_support`` plug-in: which software releases carry a decision.

Every product, source and identifier is invented. A census is a handful of
rows in the columns the reader names; no file but the ones composed here is
read.
"""

from __future__ import annotations

import csv
import json
import shutil
import socket
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from takestock import cmdb, config, coverage, observe, plugins
from takestock.model import dump_assets
from takestock.plugins import Context
from takestock.policy import Policy
from takestock.readers import library
from takestock.readers import software_support as ss

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 3, 5, 9, 30, tzinfo=UTC)

AS_OF = "2030-03-01"
EXPORT = "2030-02-10"

DATASET = {
    "sources": {"vendor-a": {"url": "https://vendor-a.example.test/lifecycle", "read": AS_OF}},
    "lines": [
        {"id": "wdg-os-3", "variants": [
            {"name": "Widget OS 3", "source": "vendor-a",
             "phases": [{"band": "supported", "until": "2029-12"},
                        {"band": "security-only", "until": "2032-07", "condition": "paid extension"}],
             "after": "end-of-support"}]},
        {"id": "wdg-os-5", "variants": [
            {"name": "Widget OS 5", "source": "vendor-a",
             "phases": [{"band": "supported", "until": "2031-06-30"}], "after": "end-of-support"}]},
        {"id": "spr-runtime-4", "variants": [
            {"name": "Sprocket Runtime 4", "source": "vendor-a",
             "phases": [{"band": "supported", "until": "2029-01-01"}], "after": "end-of-life"}]},
        {"id": "trn-build-6", "variants": [
            {"name": "Trinket 6 Pro", "source": "vendor-a",
             "phases": [{"band": "supported", "until": "2030-10-01"}], "after": "end-of-support"},
            {"name": "Trinket 6 Lite", "source": "vendor-a",
             "phases": [{"band": "supported", "until": "2029-10-01"}], "after": "end-of-support"}]},
        {"id": "status-only", "variants": [
            {"name": "Status Only", "source": "vendor-a", "known_from": AS_OF, "phases": [],
             "after": "end-of-life"}]},
    ],
}


def _row(columns: Sequence[str], **values: object) -> dict[str, str]:
    unknown = set(values) - set(columns)
    assert not unknown, f"not a column the reader names: {unknown}"
    return {c: str(values.get(c, "")) for c in columns}


def census(**v: object) -> dict[str, str]:
    return _row(ss.CENSUS_COLUMNS, **v)


def support(**v: object) -> dict[str, str]:
    return _row(ss.SUPPORT_COLUMNS, **{"as_of": AS_OF, "matched_by": "dataset", **v})


def vuln(**v: object) -> dict[str, str]:
    return _row(ss.PRODUCT_COLUMNS, **v)


def catalogue(**v: object) -> dict[str, str]:
    return _row(ss.CATALOGUE_COLUMNS, **v)


def _inputs():
    census_rows = [
        census(source="agent-hosts", source_date=EXPORT, kind="os", product="Widget OS 3.2",
               population=10, population_unit="hosts", seen_within_90_days=8),
        census(source="hypervisor", source_date="2030-01-26", kind="os",
               product="Widget OS 3 (x64)", population=20, population_unit="virtual machines"),
        census(source="agent-apps", source_date=EXPORT, kind="application",
               product="Sprocket Runtime 4.3", version="4.3.62", population=1, population_unit="hosts"),
        census(source="agent-aggregate", source_date=EXPORT, kind="application",
               product="Sprocket Runtime 4.3", version="4.3.62", installs=5),
        census(source="agent-hosts", source_date=EXPORT, kind="os", product="Widget OS 5.1",
               population=30, population_unit="hosts"),
        census(source="hypervisor", source_date="2030-01-26", kind="os",
               product="Widget OS 5 (x64)", population=5, population_unit="virtual machines"),
        census(source="agent-apps", source_date=EXPORT, kind="application", product="Gasket",
               version="1.0", population=3, population_unit="hosts"),
        census(source="observation-2030-02-01T0000Z:agent", source_date="2030-02-01",
               kind="observed", product="Widget OS 3.2", population=3, population_unit="hosts"),
    ]
    support_rows = [
        support(source="agent-hosts", kind="os", product="Widget OS 3.2", line="wdg-os-3",
                band_at_as_of="security-only", condition_at_as_of="paid extension",
                vendor_sources="https://vendor-a.example.test/lifecycle"),
        support(source="hypervisor", kind="os", product="Widget OS 3 (x64)", line="wdg-os-3",
                band_at_as_of="security-only", condition_at_as_of="paid extension"),
        support(source="agent-apps", kind="application", product="Sprocket Runtime 4.3",
                version="4.3.62", line="spr-runtime-4", band_at_as_of="end-of-life"),
        support(source="agent-hosts", kind="os", product="Widget OS 5.1", line="wdg-os-5",
                band_at_as_of="supported", holds_until="2031-06-30"),
        support(source="hypervisor", kind="os", product="Widget OS 5 (x64)", line="wdg-os-5",
                band_at_as_of="supported", holds_until="2031-06-30"),
        # A row restating an earlier observation: ignored, though it grades past.
        support(source="observation-2030-02-01T0000Z:agent", kind="observed",
                product="Old Part", line="spr-runtime-4", band_at_as_of="end-of-life"),
        # A product graded under a line in one row and under none in another.
        support(source="agent-hosts", kind="os", product="Trinket", version="6.1",
                line="trn-build-6", band_at_as_of="unknown"),
        support(source="agent-hosts", kind="os", product="Trinket", version="", line="",
                band_at_as_of="unknown"),
    ]
    vuln_rows = [
        vuln(product="Widget OS 5.1", hosts_open=30, cves_open=30, kev_listed_cves=2,
             kev_detail=("CVE-2099-11 (added 2030-01-01, due 2030-01-22); "
                         "CVE-2099-12 (added 2030-02-18, due 2030-02-25)")),
        # A second spelling of the same line, sharing one identifier.
        vuln(product="Widget OS 5 (x64)", hosts_open=5, cves_open=20, kev_listed_cves=2,
             kev_detail=("CVE-2099-11 (added 2030-01-01, due 2030-01-22); "
                         "CVE-2099-14 (added 2030-02-01, due 2030-02-22)")),
        # No line covers this spelling: it stays its own release.
        vuln(product="Gasket", version="1.0", hosts_open=3, cves_open=4, kev_listed_cves=1,
             kev_detail="CVE-2099-15 (added 2030-01-01, due 2030-01-22)"),
        # Catalogued, but open on no host.
        vuln(product="Bracket", hosts_open=0, cves_open=0, kev_listed_cves=1,
             kev_detail="CVE-2099-13 (added 2030-01-01, due 2030-01-22)"),
    ]
    catalogue_rows = [
        catalogue(cve="CVE-2099-11", known_ransomware_use="Known", hosts_open=30,
                  catalogue_vendor="Vendor A", catalogue_product="Widget OS"),
        catalogue(cve="CVE-2099-12", known_ransomware_use="Unknown", hosts_open=30,
                  catalogue_vendor="Vendor A", catalogue_product="Widget OS"),
        catalogue(cve="CVE-2099-13", known_ransomware_use="Unknown", hosts_open=0,
                  catalogue_vendor="Vendor A", catalogue_product="Widget OS"),
        # The catalogue files this one under another vendor's component: the export
        # attributes it to the widget line, the catalogue does not.
        catalogue(cve="CVE-2099-14", known_ransomware_use="Unknown", hosts_open=5,
                  catalogue_vendor="Vendor Z", catalogue_product="Sprocket Engine"),
        catalogue(cve="CVE-2099-15", known_ransomware_use="Unknown", hosts_open=3),
    ]
    return census_rows, support_rows, vuln_rows, catalogue_rows


def _fold(**kw):
    c, s, v, k = _inputs()
    return ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date=EXPORT, **kw)


def _line(line_id: str) -> dict:
    return next(ln for ln in DATASET["lines"] if ln["id"] == line_id)


def _release(releases: list[dict], label: str) -> dict:
    return next(r for r in releases if r["label"] == label)


def test_the_reader_is_in_the_library():
    plugin = library()["software_support"]
    assert plugin is ss.PLUGIN
    assert plugin.kind == "general" and plugin.gap_prefix is False and plugin.input == ""


# ── which releases are written ──

def test_only_a_release_a_decision_hangs_on_is_written():
    releases, scope = _fold()
    assert {r["label"]: r["promoted_because"] for r in releases} == {
        "Widget OS 3": [ss.SUPPORT_PAST],
        "Sprocket Runtime 4": [ss.SUPPORT_PAST],
        # Supported, but a defect known to be exploited is open: two spellings of one line.
        "Widget OS 5": [ss.EXPLOITED_OPEN],
        # No line covers this spelling, so it stays on its own.
        "Gasket 1.0": [ss.EXPLOITED_OPEN],
    }
    assert scope["promoted"] == 4
    assert (scope["promoted_vendor_lines"], scope["promoted_unmapped_spellings"]) == (3, 1)
    assert scope["promoted_covered_spellings"] == 6
    assert (scope["promoted_support_past_date"], scope["promoted_exploited_open"]) == (2, 2)


def test_a_release_with_both_reasons_lists_them_in_a_fixed_order():
    c, s, v, k = _inputs()
    v.append(vuln(product="Widget OS 3.2", hosts_open=2, cves_open=1, kev_listed_cves=1,
                  kev_detail="CVE-2099-12 (added 2030-02-18, due 2030-02-25)"))
    releases, _ = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date=EXPORT)
    assert _release(releases, "Widget OS 3")["promoted_because"] == [ss.SUPPORT_PAST,
                                                                      ss.EXPLOITED_OPEN]


def test_a_supported_band_or_a_defect_open_on_no_host_promotes_nothing():
    assert ss.promotion_reasons([support(line="wdg-os-5", band_at_as_of="supported")], None) == []
    assert ss.promotion_reasons([], vuln(kev_listed_cves=1, hosts_open=0)) == []
    assert ss.promotion_reasons([], vuln(kev_listed_cves=0, hosts_open=9)) == []
    # A band with no lifecycle line behind it is not a vendor date passing.
    assert ss.promotion_reasons([support(line="", band_at_as_of="end-of-support")], None) == []
    # Security-only under a paid condition means the unconditional date has passed.
    assert ss.promotion_reasons(
        [support(line="x", band_at_as_of="security-only", condition_at_as_of="paid")],
        None) == [ss.SUPPORT_PAST]


def test_a_malformed_count_reads_as_zero_not_an_error():
    assert ss.promotion_reasons([], vuln(kev_listed_cves="many", hosts_open=9)) == []
    assert ss.promotion_reasons([], vuln(kev_listed_cves="2", hosts_open="some")) == []


def test_rows_restating_an_earlier_observation_are_never_written_or_counted():
    releases, scope = _fold()
    assert not [c for r in releases for c in r["covered"] if c["product"] == "Old Part"]
    populations = [p for r in releases for c in r["covered"] for p in c["populations"]]
    assert not [p for p in populations if p["source"].startswith("observation-")]
    assert scope["census_rows"] == 7


# ── a release is the vendor's line ──

def test_a_line_is_named_by_the_vendor_and_lists_the_spellings_it_covers():
    releases, _ = _fold()
    line = _release(releases, "Widget OS 3")
    assert line["keyed_on"] == "vendor-line" and line["line"] == "wdg-os-3"
    assert [(c["product"], c["version"]) for c in line["covered"]] == [
        ("Widget OS 3 (x64)", ""), ("Widget OS 3.2", "")]
    assert ss.line_label(_line("trn-build-6")) == "Trinket 6 Pro or Trinket 6 Lite"


def test_a_spelling_no_line_covers_keeps_itself_and_says_why():
    releases, _ = _fold()
    own = _release(releases, "Gasket 1.0")
    assert own["keyed_on"] == "spelling" and own["line"] == ""
    assert "no vendor lifecycle line" in own["unmapped_reason"]


def test_a_spelling_graded_under_two_lines_is_not_filed_under_either():
    c, s, v, k = _inputs()
    s += [support(source="agent-hosts", kind="os", product="Valve", version="1",
                  line="wdg-os-3", band_at_as_of="end-of-support"),
          support(source="hypervisor", kind="os", product="Valve", version="1",
                  line="spr-runtime-4", band_at_as_of="end-of-support")]
    releases, _ = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date=EXPORT)
    own = _release(releases, "Valve 1")
    assert own["keyed_on"] == "spelling"
    assert "2 vendor lifecycle lines (spr-runtime-4, wdg-os-3)" in own["unmapped_reason"]


def test_a_product_graded_under_two_lines_is_ambiguous_by_name():
    _, scope = _fold()
    assert "trn-build-6" in scope["ambiguous_products"]["trinket"]
    assert scope["products"]["widget os 5.1"]["end_of_support"] == "2031-06-30"


def test_an_empty_table_still_folds_and_labels_by_line_id():
    c, s, v, k = _inputs()
    releases, _ = ss.fold(c, s, v, k, {}, as_of=AS_OF, export_date=EXPORT)
    assert "end_of_support" not in _release(releases, "wdg-os-3")["support"]
    assert {r["label"] for r in releases} == {"wdg-os-3", "spr-runtime-4", "wdg-os-5",
                                              "Gasket 1.0"}


# ── counts keep their unit ──

def test_each_population_keeps_its_own_source_and_unit_and_is_never_summed():
    releases, _ = _fold()
    (sprocket,) = _release(releases, "Sprocket Runtime 4")["covered"]
    assert sprocket["populations"] == [
        {"source": "agent-aggregate", "valid_at": EXPORT, "count": 5, "unit": "installs",
         "note": ""},
        {"source": "agent-apps", "valid_at": EXPORT, "count": 1, "unit": "hosts", "note": ""}]
    (three_two, three_x64) = [c["populations"] for c in
                              reversed(_release(releases, "Widget OS 3")["covered"])]
    assert three_two[0]["note"] == "8 seen within 90 days of the export date"
    assert three_x64[0]["unit"] == "virtual machines"


def test_identifiers_are_unioned_across_a_lines_spellings_never_added():
    releases, _ = _fold()
    line = _release(releases, "Widget OS 5")
    assert [c["exploited"]["open"] for c in line["covered"] if c["exploited"]] == [2, 2]
    assert line["exploited"]["identifiers"] == ["CVE-2099-11", "CVE-2099-12", "CVE-2099-14"]
    assert line["exploited"]["open"] == 3
    assert line["exploited"]["known_ransomware_use"] == 1


def test_the_exploited_block_counts_past_due_on_the_export_date():
    releases, _ = _fold()
    # due 2030-01-22 and 2030-02-22 are before the 2030-02-10 export? only the first is.
    assert _release(releases, "Widget OS 5")["exploited"]["past_due_at_export"] == 1
    c, s, v, k = _inputs()
    releases, _ = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date="2030-03-30")
    assert _release(releases, "Widget OS 5")["exploited"]["past_due_at_export"] == 3
    releases, _ = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date="")
    assert _release(releases, "Widget OS 5")["exploited"]["past_due_at_export"] == 0


# ── whose attribution a defect's product is ──

def test_every_row_carrying_a_count_says_whose_attribution_the_product_is():
    releases, scope = _fold()
    line = _release(releases, "Widget OS 5")
    assert line["exploited"]["catalogue_attribution"] == {
        "CVE-2099-11": "Vendor A — Widget OS",
        "CVE-2099-12": "Vendor A — Widget OS",
        "CVE-2099-14": "Vendor Z — Sprocket Engine"}
    built = ss.rows(releases, scope, collected_at=AS_OF)
    by_name = {a.name: a for a in built}
    note = by_name["Widget OS 5"].notes
    assert ss.ATTRIBUTION_NOTE in note
    assert "CVE-2099-14 (Vendor Z — Sprocket Engine)" in note
    # The scope row carries it too, because it publishes the written count.
    assert ss.ATTRIBUTION_NOTE in built[-1].notes
    for asset in built:
        rec = asset.extra.get(ss.RELEASE_KEY)
        if rec and rec.get("exploited"):
            assert ss.ATTRIBUTION_NOTE in asset.notes, asset.name


def test_an_identifier_the_catalogue_file_does_not_name_carries_no_invented_attribution():
    releases, _ = _fold()
    own = _release(releases, "Gasket 1.0")
    assert own["exploited"]["identifiers"] == ["CVE-2099-15"]
    assert own["exploited"]["catalogue_attribution"] == {}
    assert ss.ATTRIBUTION_NOTE in ss._release_note(own)


# ── the vendor's end dates ──

def test_end_of_support_is_the_last_date_that_needs_no_paid_contract():
    ends = ss.line_end_dates(_line("wdg-os-3"))
    assert ends["end_of_support"] == "2029-12"
    assert ends["end_of_life"] == "" and ends["end_of_life_absent"] == "not-measured"


def test_an_end_of_life_line_states_both_dates():
    ends = ss.line_end_dates(_line("spr-runtime-4"))
    assert (ends["end_of_support"], ends["end_of_life"]) == ("2029-01-01", "2029-01-01")


def test_variants_that_disagree_leave_the_date_unstated_with_the_reason():
    ends = ss.line_end_dates(_line("trn-build-6"))
    assert ends["end_of_support"] == "" and ends["end_of_support_absent"] == "could-not-test"
    assert "2030-10-01" in ends["end_of_support_reason"]
    assert "2029-10-01" in ends["end_of_support_reason"]


def test_a_status_with_no_printed_date_is_not_measured():
    ends = ss.line_end_dates(_line("status-only"))
    assert ends["end_of_support"] == "" and ends["end_of_support_absent"] == "not-measured"
    assert "no date" in ends["end_of_support_reason"]


# ── a measurement supersedes a declaration ──

def _declared_census():
    c, s, v, k = _inputs()
    c.append(census(source="portfolio", source_date=EXPORT, kind="system", product="Widget OS 3.2",
                    population=9, population_unit="systems"))
    s.append(support(source="portfolio", kind="system", product="Widget OS 3.2", line="wdg-os-3",
                     band_at_as_of="security-only", condition_at_as_of="paid extension"))
    return c, s, v, k


def test_a_declaration_the_measurement_contradicts_carries_no_support_finding():
    c, s, v, k = _declared_census()
    # The measuring sources report Widget OS 5.1, and none of their rows grades to wdg-os-3.
    c.append(census(source="agent-hosts", source_date=EXPORT, kind="os", product="Widget OS",
                    version="5.1", population=8, population_unit="hosts"))
    entry = {"line": "wdg-os-3", "declared_source": "portfolio",
             "measured_sources": ["agent-hosts"], "measured_product": "Widget OS"}
    s = [r for r in s if not (r["source"] == "agent-hosts" and r["line"] == "wdg-os-3")]
    releases, scope = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date=EXPORT,
                              supersede=[entry])
    (one,) = scope["superseded_declarations"]
    assert one["declared_source"] == "portfolio" and one["line"] == "wdg-os-3"
    assert one["measured"] == "Widget OS 5.1 on 8 hosts"
    # The hypervisor still grades Widget OS 3 past its date, so the line stays.
    assert _release(releases, "Widget OS 3")["promoted_because"] == [ss.SUPPORT_PAST]
    assert scope["promoted_support_past_date"] == 2
    built = ss.rows(releases, scope, collected_at=AS_OF)
    assert "Measurement supersedes declaration: portfolio declares" in built[-1].notes


def test_nothing_is_superseded_where_the_measuring_sources_report_nothing():
    c, s, v, k = _declared_census()
    entry = {"line": "wdg-os-3", "declared_source": "portfolio",
             "measured_sources": ["agent-none"], "measured_product": "Widget OS"}
    _, scope = ss.fold(c, s, v, k, DATASET, as_of=AS_OF, export_date=EXPORT, supersede=[entry])
    assert scope["superseded_declarations"] == []


def test_a_declaration_note_rides_the_release_of_its_line():
    releases, _ = _fold(declaration_notes=[{"line": "wdg-os-3",
                                            "note": "Support is extended by contract."}])
    line = _release(releases, "Widget OS 3")
    assert line["declaration_note"] == "Support is extended by contract."
    assert ss._release_note(line).endswith("Support is extended by contract.")
    assert _release(releases, "Widget OS 5")["declaration_note"] == ""


# ── the rows ──

def test_the_rows_are_the_releases_then_one_scope_row():
    releases, scope = _fold()
    built = ss.rows(releases, scope, collected_at=AS_OF)
    assert [a.name for a in built][:-1] == [r["label"] for r in releases]
    assert built[-1].extra[ss.SCOPE_KEY] is scope
    for a in built:
        assert (a.data_state, a.protocol, a.source, a.verdict, a.collected_at) == (
            "discovery", "software-lifecycle", "software_support", "n/a", AS_OF)
    assert ss.RELEASES_KEY not in built[-1].extra
    assert built[0].role.startswith("A software version in use where")
    assert built[-1].extra[ss.SCOPE_KEY]["promoted"] == len(releases)


def test_a_line_release_holds_no_single_version_and_a_spelling_holds_its_own():
    releases, scope = _fold()
    built = {a.name: a for a in ss.rows(releases, scope, collected_at=AS_OF)}
    assert built["Widget OS 3"].version == ""
    # Two product names under one line: the product is the vendor's line name.
    assert built["Widget OS 3"].software == "Widget OS 3"
    assert built["Gasket 1.0"].version == "1.0" and built["Gasket 1.0"].software == "Gasket"


def test_each_row_carries_its_release_in_the_registers_shape():
    releases, scope = _fold()
    built = ss.rows(releases, scope, collected_at=AS_OF)
    got = {a.name: a.extra[ss.RELEASES_KEY][0] for a in built if ss.RELEASES_KEY in a.extra}
    assert set(got) == {"Widget OS 3", "Sprocket Runtime 4", "Widget OS 5", "Gasket 1.0"}
    line = got["Widget OS 3"]
    assert (line["label"], line["line"]) == ("Widget OS 3", "wdg-os-3")
    assert line["versions"] == ["Widget OS 3 (x64)", "Widget OS 3.2"]
    assert line["support"] == {"status": "security-only, only with paid extension",
                               "end_of_support": "2029-12", "end_of_life": "", "as_of": AS_OF}
    assert "exploited" not in line
    own = got["Gasket 1.0"]
    assert (own["product"], own["line"], own["versions"]) == ("Gasket", "", ["1.0"])
    assert got["Widget OS 5"]["exploited"] == {
        "identifiers": ["CVE-2099-11", "CVE-2099-12", "CVE-2099-14"], "past_due": 1,
        "as_of": EXPORT}


# ── the register reads what the reader writes ──

def _observation(tmp_path: Path) -> Path:
    releases, scope = _fold()
    assets = dump_assets(ss.rows(releases, scope, collected_at=AS_OF))
    folder = tmp_path / "2030-03-05T0000Z"
    folder.mkdir()
    (folder / "assets.json").write_text(json.dumps(assets))
    (folder / "summary.json").write_text(json.dumps({"total_assets": len(assets), "gaps": []}))
    return folder


def _item(built: cmdb.Cmdb, label: str) -> str:
    keys = [k for k, i in built.items.items()
            if i.label == label and i.item_class == "Software Release"]
    assert len(keys) == 1, (label, keys)
    return keys[0]


def test_the_register_holds_each_release_with_its_dates_and_identifiers(tmp_path):
    built = cmdb.build(_observation(tmp_path), recorded_at="2030-03-05")
    resolved = built.resolved()
    three = resolved[_item(built, "Widget OS 3")]
    assert three["covered_versions"].value == "Widget OS 3 (x64); Widget OS 3.2"
    assert cmdb.is_absent(three["version"].value) and three["version"].value.reason == "not-applicable"
    assert three["end_of_support"].value == "2029-12"
    assert three["end_of_support"].evidence_strength == cmdb.DECLARED
    assert three["support_status"].value == "security-only, only with paid extension"
    five = resolved[_item(built, "Widget OS 5")]
    assert str(five["exploited_defect_ids"].value).split("; ") == [
        "CVE-2099-11", "CVE-2099-12", "CVE-2099-14"]
    assert resolved[_item(built, "Gasket 1.0")]["version"].value == "1.0"


# ── reading the files ──

def _write(folder: Path, name: str, columns: Sequence[str], rows: list[dict]) -> None:
    with (folder / name).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _census_files(folder: Path, manifest: dict | None = None) -> dict:
    """The four files and a manifest beside ``folder/example.yaml``; the profile it returns."""
    c, s, v, k = _inputs()
    _write(folder, "census.csv", ss.CENSUS_COLUMNS, c)
    _write(folder, "census-support.csv", ss.SUPPORT_COLUMNS, s)
    _write(folder, "vuln-products.csv", ss.PRODUCT_COLUMNS, v)
    _write(folder, "vuln-catalogue.csv", ss.CATALOGUE_COLUMNS, k)
    spec = manifest or {
        "output": "census.csv",
        "support": {"output": "census-support.csv", "as_of": AS_OF},
        "vulnerabilities": {"products_output": "vuln-products.csv",
                            "kev_output": "vuln-catalogue.csv", "dated": EXPORT}}
    (folder / "example.software-census.yaml").write_text(yaml.safe_dump(spec), encoding="utf-8")
    return {"_path": str(folder / "example.yaml")}


def test_collect_reads_the_named_files_and_returns_the_same_rows_as_the_fold(tmp_path):
    target = _census_files(tmp_path)
    built, gaps = ss.collect(target, DATASET)
    releases, scope = _fold()
    assert gaps == []
    assert dump_assets(built) == dump_assets(ss.rows(releases, scope, collected_at=AS_OF))


def test_the_manifest_carries_the_supersede_and_note_entries(tmp_path):
    spec = {"output": "census.csv",
            "support": {"output": "census-support.csv", "as_of": AS_OF,
                        "declaration_notes": [{"line": "wdg-os-5", "note": "A note."}]},
            "vulnerabilities": {"products_output": "vuln-products.csv",
                                "kev_output": "vuln-catalogue.csv", "dated": EXPORT}}
    built, _ = ss.collect(_census_files(tmp_path, spec), DATASET)
    assert next(a for a in built if a.name == "Widget OS 5").notes.endswith("A note.")


def test_no_manifest_is_one_not_collected_gap_and_no_rows(tmp_path):
    for target in ({}, {"_path": str(tmp_path / "example.yaml")}, {"_path": "noextension"}):
        built, gaps = ss.collect(target, DATASET)
        assert built == []
        (gap,) = gaps
        assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
        assert coverage.nature_of(gap) == coverage.NO_DATA
        assert coverage.impact_kind_of(gap) == coverage.NARROWS_CONFIDENCE
        assert "example" not in gap and "<profile>.software-census.yaml" in gap


@pytest.mark.parametrize("break_it", ["missing-file", "missing-key", "not-yaml", "not-a-mapping"])
def test_an_output_that_cannot_be_read_is_a_gap_and_no_rows(tmp_path, break_it):
    target = _census_files(tmp_path)
    manifest = tmp_path / "example.software-census.yaml"
    if break_it == "missing-file":
        (tmp_path / "vuln-catalogue.csv").unlink()
    elif break_it == "missing-key":
        manifest.write_text("output: census.csv\n", encoding="utf-8")
    elif break_it == "not-yaml":
        manifest.write_text("output: [unclosed\n", encoding="utf-8")
    else:
        manifest.write_text("- a\n- b\n", encoding="utf-8")
    built, gaps = ss.collect(target, DATASET)
    assert built == [] and len(gaps) == 1
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert "could not be read" in gaps[0] and "example.software-census.yaml" in gaps[0]


# ── the step ──

def _ctx(target: dict, settings: dict | None = None) -> Context:
    return Context(plugin=ss.PLUGIN, target=target, settings=settings or {}, input=None,
                   ref_time=NOW, raw_dir=Path("."), policy=Policy(config.load_baseline()),
                   baseline={}, dictionary={}, port_table={}, collected_on="2030-03-05")


def test_the_step_reads_the_table_the_settings_name(tmp_path):
    target = _census_files(tmp_path)
    table = tmp_path / "lifecycle.yaml"
    table.write_text(yaml.safe_dump(DATASET), encoding="utf-8")
    out = ss.step(_ctx(target, {"lifecycle": str(table)}))
    assert out.gaps == [] and [r.name for r in out.records][:4] == [
        "Sprocket Runtime 4", "Widget OS 3", "Widget OS 5", "Gasket 1.0"]
    assert out.records[1].extra[ss.RELEASE_KEY]["support"]["end_of_support"] == "2029-12"


def test_the_step_falls_back_to_the_bundled_table(tmp_path):
    out = ss.step(_ctx(_census_files(tmp_path)))
    # Our invented lines are not in the bundled table, so no line is named, and the
    # step still returns the rows the census supports rather than failing.
    assert out.gaps == [] and out.records and out.records[-1].extra[ss.SCOPE_KEY]


@pytest.mark.parametrize("content", [None, "lines: [unclosed\n", "- a\n- b\n", "just text\n"])
def test_a_lifecycle_table_that_cannot_be_read_is_a_gap_not_a_stop(tmp_path, content):
    target = _census_files(tmp_path)
    table = tmp_path / "lifecycle.yaml"
    if content is not None:
        table.write_text(content, encoding="utf-8")
    out = ss.step(_ctx(target, {"lifecycle": str(table)}))
    assert out.records == []
    (gap,) = out.gaps
    assert coverage.kind_of(gap) == coverage.COULD_NOT_TEST
    assert "settings: lifecycle:" in gap


# ── an observation end to end ──

@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(plugins.metadata, "entry_points", lambda group="": [])
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    shutil.copytree(SAMPLE / "exports", tmp_path / "inbox")
    config.set_workspace(tmp_path)
    config.set_inbox(tmp_path / "inbox")
    return tmp_path


def test_an_observation_carries_the_releases_and_the_scope(workspace):
    _census_files(workspace / "targets")
    # The manifest is named for the profile, so rename it to sit beside example-widgets.
    (workspace / "targets" / "example.software-census.yaml").rename(
        workspace / "targets" / "example-widgets.software-census.yaml")
    table = workspace / "lifecycle.yaml"
    table.write_text(yaml.safe_dump(DATASET), encoding="utf-8")
    target = config.load_target("example-widgets")
    target["plugins"] = [{"name": "software_support", "settings": {"lifecycle": str(table)}}]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    rows = [a for a in result.assets if a.source == "software_support"]
    assert [r.name for r in rows][-1] == "Software census support and exploited-defect fold — scope"
    assert len(rows) == 5
    assert all(r.extra["plugin"] == "software_support" for r in rows)
    assert result.summary["plugins"]["software_support"]["rows"] == 5


def test_an_observation_without_a_manifest_says_so_and_still_completes(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = ["software_support"]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    assert not [a for a in result.assets if a.source == "software_support"]
    assert result.summary["plugins"]["software_support"]["status"] == "ran"
    assert any("software census manifest" in g for g in result.summary["gaps"])
