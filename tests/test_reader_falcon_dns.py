"""The CrowdStrike Falcon DNS lookup reader in takestock's readers library.

Each export, vendor table, profile and positions file is composed in its test
with invented organisations under the reserved ``example.com``, ``example.net``
and ``example.org`` domains, invented counts and invented dates. Nothing here
was captured from a real export.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import yaml
from entra_helpers import by_name, ctx, write

from takestock import coverage, model
from takestock.readers import falcon_dns as reader
from takestock.readers import library

COLUMNS = ("DomainName", "_count")
TABLE_COLUMNS = ("domain", "vendor", "category", "notes")


def _export(path: Path, rows: list[tuple[str, object]],
            columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, [{columns[0]: n, columns[1]: str(c)} for n, c in rows])
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _table(path: Path) -> Path:
    return write(path, TABLE_COLUMNS, [
        {"domain": "orbita.example.com", "vendor": "Orbita Cloud", "category": "cloud"},
        {"domain": "quillstone.example.com", "vendor": "Quillstone", "category": "saas"},
        {"domain": "glimmer.example.com", "vendor": "Glimmer Media", "category": "cdn"},
        {"domain": "gadgetry.example.com", "vendor": "Gadgetry Inc.", "category": "devtools"},
    ])


EXPORT = [
    ("login.orbita.example.com", 800),
    ("files.orbita.example.com.", 200),       # trailing dot, same organisation
    ("API.Quillstone.example.com", 400),      # case folded
    ("img.glimmer.example.com", 300),         # cdn: incidental
    ("portal.tessellate.example.com", 30),    # named only by the profile's domains:
    ("build.gadgetry.example.com", 70),
    ("a.mystery.example.net", 200),           # unattributed, one group
    ("b.mystery.example.net", 100),
    ("stray.example.org", 0),                 # unattributed, below the threshold
    ("intranet.ours.example.org", 70),        # the organisation's own
    ("printer.lan", 5),                       # not public
    ("wpad", 9),                              # a single label
    ("host.test", 2),                         # reserved
    ("blank.orbita.example.com", ""),         # a blank count is 0 lookups
]


def _profile(tmp_path: Path, positions: list[dict] | None = None) -> dict:
    target = {
        "discovery": {"domains": ["ours.example.org"]},
        "third_party": [
            {"name": "Quillstone Ledger Service"},
            {"name": "Tessellate Labs", "domains": ["tessellate.example.com"],
             "pq_roadmap": "hybrid key exchange promised in the next major release"},
            {"name": "Orbitalis Hosting"},          # shares a prefix with Orbita, not a word
            {"name": "Vellum Archive"},             # declared, never looked up
        ],
        "scan_targets": {"saas_443": [{"vendor": "Quillstone", "host": "api.quillstone.example.com"}]},
    }
    path = tmp_path / "acme.yaml"
    path.write_text(yaml.safe_dump(target), encoding="utf-8")
    if positions is not None:
        (tmp_path / "acme.pqc-positions.yaml").write_text(
            yaml.safe_dump({"schema": 1, "positions": positions}), encoding="utf-8")
    return {**target, "_path": str(path)}


POSITIONS = [
    {"provider": "Quillstone", "state": "shipped", "since": "4.2",
     "summary": "hybrid key exchange on by default",
     "source": "https://docs.quillstone.example.com/pq", "publisher": "Quillstone",
     "published": "2025-01-10", "read": "2025-02-01", "recheck_by": "2099-01-01"},
    {"provider": "Vellum Archive", "state": "planned",
     "summary": "a roadmap entry without a date",
     "source": "https://vellum.example.net/roadmap", "read": "2025-02-01",
     "recheck_by": "2025-06-01"},
]


def _run(tmp_path: Path, export: Path | None, settings: dict | None = None,
         positions: list[dict] | None = None):
    c = ctx(reader.PLUGIN, export, {"vendor_domains": str(_table(tmp_path / "vd.csv")),
                                    **(settings or {})})
    c = dataclasses.replace(c, target=_profile(tmp_path, positions))
    return reader.step(c)


def test_the_reader_is_in_the_library():
    assert library()["falcon_dns"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""
    assert reader.PLUGIN.summarise is not None


def test_no_export_named_gives_one_gap_and_no_rows():
    out = reader.step(ctx(reader.PLUGIN, None))
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(out.gaps[0]) == coverage.NO_DATA


def test_an_export_without_the_name_column_is_a_gap_not_an_empty_answer(tmp_path):
    path = _export(tmp_path / "dns.csv", [("a.orbita.example.com", 3)], ("host", "_count"))
    out = _run(tmp_path, path)
    assert out.records == [] and len(out.gaps) == 1
    assert "`DomainName`" in str(out.gaps[0])


def test_a_vendor_table_named_and_missing_is_a_gap(tmp_path):
    path = _export(tmp_path / "dns.csv", EXPORT)
    out = _run(tmp_path, path, {"vendor_domains": str(tmp_path / "absent.csv")})
    assert out.records == [] and "vendor table" in str(out.gaps[0])


def test_rows_flags_and_verdicts(tmp_path):
    out = _run(tmp_path, _export(tmp_path / "dns.csv", EXPORT), positions=POSITIONS)
    rows = by_name(out.records)
    assert all(a.data_state == "third-party" and a.protocol == "dependency"
               and a.source == "falcon_dns" and a.source_class == "private"
               and a.collected_at == "2030-03-17" for a in out.records)

    orbita = rows["Third-party dependency: Orbita Cloud"]
    assert orbita.verdict == "unknown"
    assert orbita.flags == ["pq-roadmap-unrecorded", "third-party-undeclared:orbita-cloud"]
    assert orbita.extra["lookups"] == "1000" and orbita.extra["names"] == "3"
    assert orbita.extra["registrable_domains"] == ["example.com"]
    assert orbita.extra["declared"] is False and orbita.extra["declared_as"] == ""
    assert orbita.extra["pq_roadmap"] == "unrecorded" and orbita.extra["pq_position"] == {}
    assert orbita.extra["evidence"] == "dns-resolution-only"

    quill = rows["Third-party dependency: Quillstone"]
    assert quill.verdict == "n/a" and quill.flags == ["third-party-observed:quillstone"]
    # The vendor's one word is a whole word of the declared name.
    assert quill.extra["declared_as"] == "Quillstone"
    assert quill.extra["pq_position"]["state"] == "shipped"
    assert quill.extra["pq_position"]["stale"] is False
    assert quill.extra["pq_roadmap"].startswith("shipped (4.2)")

    tess = rows["Third-party dependency: Tessellate Labs"]
    assert tess.flags == ["third-party-observed:tessellate-labs"]
    assert tess.extra["categories"] == ["declared"]
    # The profile's own roadmap wins, and carries no published payload.
    assert tess.extra["pq_roadmap"].startswith("hybrid key exchange")
    assert tess.extra["pq_position"] == {}

    assert rows["Third-party dependency: Gadgetry Inc."].flags[1] == \
        "third-party-undeclared:gadgetry-inc"

    incidental = rows["Names resolved that are not organisational dependencies"]
    assert incidental.flags == ["third-party-incidental"] and incidental.verdict == "n/a"
    assert incidental.extra["named"] == ["Glimmer Media"]

    # Declared and never looked up; Orbitalis is not Orbita (whole words, not prefixes).
    vellum = rows["Third-party dependency: Vellum Archive"]
    assert vellum.flags == ["third-party-not-observed:vellum-archive"]
    assert vellum.extra["pq_position"]["stale"] is True
    assert "Due for re-checking" in vellum.extra["pq_roadmap"]
    assert "Third-party dependency: Orbitalis Hosting" in rows
    # Quillstone Ledger Service is accounted for by the Quillstone lookups.
    assert "Third-party dependency: Quillstone Ledger Service" not in rows

    unattributed = rows["Unattributed external domain: example.net"]
    assert unattributed.verdict == "unknown"
    assert unattributed.flags == ["dns-name-unattributed:example.net"]
    assert unattributed.extra["names"] == "2" and unattributed.extra["lookups"] == "300"
    assert "Unattributed external domain: example.org" not in rows  # below the threshold

    scope = rows["Third-party dependency scope"].extra
    assert scope["rows"] == str(len(EXPORT))
    assert scope["names_own_domains"] == "1" and scope["names_non_public"] == "3"
    not_external = {"intranet.ours.example.org", "printer.lan", "wpad", "host.test"}
    external = sum(int(c or 0) for n, c in EXPORT if n not in not_external)
    unattributed_lookups = int(unattributed.extra["lookups"])
    assert scope["names_external"] == "10" and scope["lookups_external"] == str(external)
    assert scope["lookups_attributed"] == str(external - unattributed_lookups)
    assert scope["attributed_share"] == "85.7%"
    assert scope["unattributed_domains"] == "2" and scope["unattributed_below_threshold"] == "1"
    assert scope["threshold_share"] == "0.1%"


def test_gaps_name_the_undeclared_the_unpositioned_and_the_stale(tmp_path):
    out = _run(tmp_path, _export(tmp_path / "dns.csv", EXPORT), positions=POSITIONS)
    assert len(out.gaps) == 3
    undeclared, unpositioned, stale = out.gaps
    assert coverage.kind_of(undeclared) == coverage.EXTENT_UNKNOWN
    assert coverage.impact_kind_of(undeclared) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(undeclared) == coverage.NO_DATA
    assert "Orbita Cloud (1,000), Gadgetry Inc. (70)" in str(undeclared)
    for g in (unpositioned, stale):
        assert coverage.kind_of(g) == coverage.NOT_COLLECTED
        assert coverage.impact_kind_of(g) == coverage.NARROWS_CONFIDENCE
        assert coverage.nature_of(g) == coverage.LOW_FIDELITY
    # Orbita, Gadgetry and Orbitalis have none; Quillstone and Vellum are read.
    assert "for 3 of" in str(unpositioned) and "against 2" in str(unpositioned)
    assert "Vellum Archive" in str(stale) and "2025-06-01" in str(stale)


def test_no_stale_gap_when_every_position_shown_is_current(tmp_path):
    out = _run(tmp_path, _export(tmp_path / "dns.csv", EXPORT), positions=POSITIONS[:1])
    assert len(out.gaps) == 2


def test_settings_change_what_counts(tmp_path):
    path = _export(tmp_path / "dns.csv", EXPORT, ("name", "lookups"))
    out = _run(tmp_path, path, {
        "columns": {"name": "name", "lookups": "lookups"},
        "dependency_categories": ["cloud", "saas", "cdn"],
        "non_public_suffixes": [".mystery.example.net"],
        "second_level_labels": ["ours"],
        "unattributed_share": 0.0})
    rows = by_name(out.records)
    # cdn now counts; devtools no longer does.
    assert "Third-party dependency: Glimmer Media" in rows
    assert rows["Names resolved that are not organisational dependencies"].extra["named"] == \
        ["Gadgetry Inc."]
    assert "Unattributed external domain: example.net" not in rows
    assert "Unattributed external domain: example.org" in rows  # no threshold now
    assert rows["Third-party dependency scope"].extra["names_non_public"] == "5"
    assert rows["Third-party dependency scope"].extra["threshold_share"] == "0%"


def test_summarise_gives_the_third_party_block(tmp_path):
    out = _run(tmp_path, _export(tmp_path / "dns.csv", EXPORT), positions=POSITIONS)
    block = reader.summarise(out.records)
    assert block["dependencies"] == 4
    assert block["declared_and_observed"] == ["Quillstone", "Tessellate Labs"]
    assert block["undeclared"] == ["Gadgetry Inc.", "Orbita Cloud"]
    assert block["undeclared_count"] == 2
    assert block["declared_not_observed"] == ["Orbitalis Hosting", "Vellum Archive"]
    assert block["without_pq_roadmap"] == ["Gadgetry Inc.", "Orbita Cloud", "Orbitalis Hosting"]
    assert block["with_pq_position"] == ["Quillstone", "Vellum Archive"]
    assert block["pq_position_states"] == {"shipped": ["Quillstone"], "planned": ["Vellum Archive"]}
    assert block["unattributed_domains"] == ["example.net"]
    assert block["attributed_share"] == "85.7%"
    assert reader.summarise([]) == {}


def test_attribution_is_the_table_the_rows_were_built_with(tmp_path):
    table = _table(tmp_path / "vd.csv")
    target = _profile(tmp_path, POSITIONS)
    att = reader.attribution(target, {"vendor_domains": str(table)})
    assert set(att.vendor_table) == {"orbita.example.com", "quillstone.example.com",
                                     "glimmer.example.com", "gadgetry.example.com"}
    assert att.declared_domains == {"tessellate.example.com": "Tessellate Labs"}
    assert att.own_suffixes == ("ours.example.org",)
    assert [p.provider for p in att.positions] == ["Quillstone", "Vellum Archive"]
    assert reader.attribute("x.tessellate.example.com", att) == ("Tessellate Labs", "declared")
    assert reader.attribute("a.orbita.example.com", att) == ("Orbita Cloud", "cloud")
    assert reader.attribute("nobody.example.net", att) == ("", "")
    # With no table named, the bundled one.
    assert reader.attribution({}).vendor_table_file == ""


def test_every_flag_is_informational():
    for flag in ("third-party-observed:x", "third-party-undeclared:x",
                 "third-party-not-observed:x", "third-party-incidental",
                 "dns-name-unattributed:example.net", "pq-roadmap-unrecorded",
                 "scope-dns-evidence-only"):
        assert model.is_informational_flag(flag), flag


def test_the_default_dependency_categories_are_the_bundled_table_less_cdn():
    from takestock import config
    bundled = {row["category"] for row in config.load_vendor_domains().values()}
    assert reader.DEPENDENCY_CATEGORIES == bundled - {"cdn"}


def test_a_declared_supplier_the_table_files_under_cdn_is_incidental_and_seen(tmp_path):
    # Whether the profile names it alone or with its domains, the table's category
    # decides: it is not a dependency, and its declaration is not reported unseen.
    table = write(tmp_path / "vd.csv", TABLE_COLUMNS, [
        {"domain": "glimmer.example.com", "vendor": "Glimmer Media", "category": "cdn"}])
    export = _export(tmp_path / "dns.csv", [("img.glimmer.example.com", 40)])
    for entry in ({"name": "Glimmer Media Edge"},
                  {"name": "Glimmer Media Edge", "domains": ["glimmer.example.com"]}):
        c = ctx(reader.PLUGIN, export, {"vendor_domains": str(table)})
        out = reader.step(dataclasses.replace(c, target={"third_party": [entry]}))
        rows = by_name(out.records)
        assert set(rows) == {"Names resolved that are not organisational dependencies",
                             "Third-party dependency scope"}, entry


def test_an_unusable_unattributed_share_is_a_gap_and_the_default_is_used(tmp_path):
    path = _export(tmp_path / "dns.csv", EXPORT)
    for bad in (1, 1.5, -0.1, "lots", True):
        out = _run(tmp_path, path, {"unattributed_share": bad}, positions=POSITIONS[:1])
        setting = [g for g in out.gaps if "unattributed_share" in str(g)]
        assert len(setting) == 1, bad
        assert coverage.kind_of(setting[0]) == coverage.COULD_NOT_TEST
        assert coverage.impact_kind_of(setting[0]) == coverage.NARROWS_CONFIDENCE
        scope = by_name(out.records)["Third-party dependency scope"]
        assert scope.extra["threshold_share"] == "0.1%"
    out = _run(tmp_path, path, {"unattributed_share": 0.002}, positions=POSITIONS[:1])
    assert not [g for g in out.gaps if "unattributed_share" in str(g)]
