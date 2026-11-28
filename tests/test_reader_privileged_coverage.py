"""The ``privileged_coverage`` plug-in: one bounded gap per declared supplier.

Every supplier, host and register row is composed here for an invented
organisation (``.example.test`` names), with small round counts.
"""

from __future__ import annotations

import csv
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, observe, plugins
from takestock.model import CryptoAsset
from takestock.plugins import Context
from takestock.policy import Policy
from takestock.readers import endpoint_coverage, library
from takestock.readers import privileged_coverage as pc

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)

SUPPLIERS = [
    {"name": "Translation Co (translation.example.test)", "role": "language-services",
     "uses": ["document translation"], "domains": ["translation.example.test"]},
    {"name": "Mapping Co (mapping.example.test)", "role": "geospatial",
     "uses": ["route planning"], "domains": ["mapping.example.test"]},
]


def _privileged(host: str, source: str = "entra_app_credentials") -> CryptoAsset:
    return CryptoAsset(name=f"Directory application {host}", host=host, data_state="identity",
                       source=source, source_class="private", verdict="unknown")


def _gaps(target: dict, assets: list[CryptoAsset] | None = None, **kw) -> list:
    return pc.collect(target, assets or [], **kw)


def _party_gaps(gaps: list) -> list:
    return [g for g in gaps if pc.UNDECLARED_TOKEN in g]


def _supplier_gaps(gaps: list) -> list:
    return [g for g in gaps if pc.SUPPLIER_TOKEN in g]


@pytest.fixture(autouse=True)
def _empty_inbox(tmp_path: Path):
    """Every test reads an empty inbox in a scratch workspace, unless it writes a register."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    config.set_workspace(tmp_path)
    config.set_inbox(inbox)
    yield inbox
    config.set_workspace(None)
    config.set_inbox(None)


def test_the_reader_is_in_the_library():
    plugin = library()["privileged_coverage"]
    assert plugin is pc.PLUGIN
    assert plugin.kind == "coverage-check" and plugin.late
    assert plugin.gap_prefix is False and plugin.input == ""


# ── the unit is a supplier, and the population is exact ──

def test_one_gap_per_supplier_with_no_privileged_answer():
    gaps = _gaps({"third_party": SUPPLIERS})
    assert len(gaps) == 2 and len(_supplier_gaps(gaps)) == 2


def test_each_gap_names_its_supplier_and_the_exact_population():
    text = "\n".join(_gaps({"third_party": SUPPLIERS}))
    assert "Translation Co" in text and "Mapping Co" in text
    assert text.count("2 declared supplier(s) out of 2") == 2


def test_a_supplier_with_a_privileged_row_under_its_domain_raises_no_gap():
    # Any privileged fact counts as an answer: a gap for a supplier with partial
    # evidence would overstate what is missing.
    gaps = _gaps({"third_party": SUPPLIERS}, [_privileged("admin.translation.example.test")])
    assert len(gaps) == 1
    assert "Mapping Co" in gaps[0] and "Translation Co" not in gaps[0]
    assert "1 declared supplier(s) out of 2" in gaps[0]


def test_the_domain_match_is_whole_labels_and_ignores_case_and_padding():
    target = {"third_party": SUPPLIERS}
    assert len(_gaps(target, [_privileged(" ADMIN.Translation.Example.Test ")])) == 1
    # "xtranslation.example.test" is another organisation's domain, not a name under it.
    assert len(_gaps(target, [_privileged("xtranslation.example.test")])) == 2


def test_a_row_outside_the_privileged_lens_is_not_an_answer():
    tls = CryptoAsset(name="TLS translation.example.test:443", host="translation.example.test",
                      data_state="in-transit", protocol="tls", source="tls_scan",
                      source_class="public", verdict="strong")
    assert len(_gaps({"third_party": SUPPLIERS}, [tls])) == 2


@pytest.mark.parametrize("asset", [
    CryptoAsset(name="a", host="x.translation.example.test", data_state="identity", source="other"),
    CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest",
                source="falcon_logins"),
    CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest", source="other",
                flags=["privileged-accounts:3"]),
    CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest", source="other",
                flags=["shared-credential"]),
])
def test_each_way_into_the_privileged_lens_answers(asset: CryptoAsset):
    assert len(_gaps({"third_party": SUPPLIERS}, [asset])) == 1


def test_a_flag_that_only_resembles_a_privileged_one_does_not():
    a = CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest",
                    source="other", flags=["privilegedx", "weak-cipher"])
    assert len(_gaps({"third_party": SUPPLIERS}, [a])) == 2


def test_a_setting_adds_an_instrument_to_the_lens():
    a = CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest",
                    source="vendor_admin_export")
    assert len(_gaps({"third_party": SUPPLIERS}, [a])) == 2
    assert len(_gaps({"third_party": SUPPLIERS}, [a], extra_sources=["vendor_admin_export"])) == 1


# ── it never produces the area-shaped sentence ──

def test_no_gap_at_all_when_no_register_is_declared():
    # Without a declared register there is no bounded population, and a gap
    # without one is the shape the validity test refuses.
    assert _gaps({}) == []
    assert _gaps({"third_party": []}) == []


def test_every_gap_survives_the_scope_area_validity_test():
    for g in _gaps({"third_party": SUPPLIERS}):
        assert coverage.scope_area_subject(str(g)) is None


def test_a_supplier_with_no_name_is_skipped_rather_than_guessed():
    register = [{"role": "language-services"}, {"name": "  "}, "not a mapping", None, *SUPPLIERS]
    assert len(_gaps({"third_party": register})) == 2


def test_gaps_carry_kind_nature_impact_and_harvest():
    for g in _gaps({"third_party": SUPPLIERS}):
        assert coverage.kind_of(g) == coverage.NOT_COLLECTED
        assert coverage.nature_of(g) == coverage.LOW_FIDELITY
        assert coverage.impact_kind_of(g) == coverage.CHANGES_CONCLUSION
        assert coverage.impact_of(g).strip() and coverage.harvest_of(g).strip()


def test_the_gap_says_what_is_held_not_only_what_is_missing():
    # `low-fidelity` means a record exists and is too coarse; the reader has to
    # see the coarse record or the label is unsupported.
    first = _gaps({"third_party": SUPPLIERS})[0]
    assert "declared in the third-party register" in first
    assert "role `language-services`" in first and "used for document translation" in first


def test_the_use_list_is_cut_to_three():
    supplier = {"name": "Ledger Co", "uses": ["a", "b", "c", "d"]}
    (gap,) = _gaps({"third_party": [supplier]})
    assert "used for a; b; c. What" in gap


def test_all_three_questions_are_named_in_every_gap():
    for g in _gaps({"third_party": SUPPLIERS}):
        for q in pc.QUESTIONS:
            assert q in g


def test_it_writes_no_rows_and_leaves_the_rows_it_reads_alone():
    row = _privileged("admin.translation.example.test")
    before = (list(row.flags), dict(row.extra))
    gaps = _gaps({"third_party": SUPPLIERS}, [row])
    assert all(isinstance(g, str) for g in gaps)
    assert (list(row.flags), dict(row.extra)) == before


# ── parties the information-sharing register names that no declaration knows ──

def _register(inbox: Path, parties: list[str], name: str = "information-flows.csv") -> Path:
    path = inbox / name
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["flow_id", "external_party"])
        writer.writerows((i, p) for i, p in enumerate(parties, 1))
    return path


def _profile(tmp_path: Path, register: str = "inbox/information-flows.csv") -> dict:
    """A profile at ``tmp_path/example.yaml`` with a channel map beside it declaring the register."""
    (tmp_path / "example.flows.yaml").write_text(
        f'register:\n  path: "{register}"\nchannels: {{}}\n', encoding="utf-8")
    return {"third_party": SUPPLIERS, "_path": str(tmp_path / "example.yaml")}


def test_a_party_no_declaration_knows_is_reported_with_an_exact_count(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Mapping Co", "Ledger Systems Ltd", "(unspecified)"])
    gaps = _gaps(_profile(tmp_path))
    (party,) = _party_gaps(gaps)
    assert "1 of the 2" in party and "Ledger Systems Ltd" in party
    assert "(unspecified)" not in party
    assert coverage.kind_of(party) == coverage.EXTENT_UNKNOWN
    assert coverage.nature_of(party) == coverage.NO_DATA


def test_a_party_a_declaration_names_is_not_reported(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Mapping Co", "TRANSLATION"])
    assert _party_gaps(_gaps(_profile(tmp_path))) == []


@pytest.mark.parametrize("value", ["", " ", "-", "N/A", "n/a", "None", "TBC", "(unspecified)",
                                   "[none]"])
def test_a_value_that_names_no_organisation_is_not_a_party(tmp_path, _empty_inbox, value):
    _register(_empty_inbox, [value])
    assert _party_gaps(_gaps(_profile(tmp_path))) == []


def test_a_party_spelt_twice_counts_once(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Ledger Systems Ltd", "LEDGER SYSTEMS LTD", "(Ledger Systems Ltd)"])
    (party,) = _party_gaps(_gaps(_profile(tmp_path)))
    assert "1 of the 1" in party


def test_short_words_do_not_make_a_party_declared(tmp_path, _empty_inbox):
    # "Co" and "Ltd" are in a supplier's name; words of three characters or fewer are
    # dropped because they match half the register by accident.
    _register(_empty_inbox, ["Unrelated Co Ltd"])
    (party,) = _party_gaps(_gaps(_profile(tmp_path)))
    assert "Unrelated Co Ltd" in party


def test_a_declared_list_makes_a_party_declared(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Gateway Networks"])
    target = _profile(tmp_path)
    assert len(_party_gaps(_gaps(target))) == 1
    target["infrastructure"] = [{"name": "Gateway Networks edge"}, "not a mapping"]
    assert _party_gaps(_gaps(target)) == []
    # The default lists are `asset_classes` and `infrastructure`; others are named by setting.
    target["partners"] = target.pop("infrastructure")
    assert len(_party_gaps(_gaps(target))) == 1
    assert _party_gaps(_gaps(target, declared_lists=("partners",))) == []


def test_a_supplier_domain_makes_a_party_declared(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Tools Group"])
    target = _profile(tmp_path)
    target["third_party"] = [{"name": "Alpha Ltd", "domains": ["beta-tools.example.test"]}]
    assert _party_gaps(_gaps(target)) == []
    target["third_party"] = [{"name": "Alpha Ltd", "domains": ["beta.example.test"]}]
    assert len(_party_gaps(_gaps(target))) == 1


def test_no_party_gap_when_the_register_is_absent(tmp_path):
    # A missing register is the `flows` reader's gap; a second voice saying the same
    # thing is noise. Asserted with no map, and with a map whose register never arrived.
    assert _party_gaps(_gaps({"third_party": SUPPLIERS})) == []
    assert _party_gaps(_gaps(_profile(tmp_path))) == []


def test_the_register_is_found_where_the_map_declares_it(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Ledger Systems Ltd"], name="parties.csv")
    assert _party_gaps(_gaps(_profile(tmp_path))) == []
    assert len(_party_gaps(_gaps(_profile(tmp_path, "inbox/parties.csv")))) == 1


def test_a_register_written_as_a_script_constant_is_read(tmp_path, _empty_inbox):
    (_empty_inbox / "information-flows.json").write_text(
        '<html><script>const RAW = [{"flow_id": "1", "external_party": "Ledger Systems Ltd"}];'
        "</script></html>", encoding="utf-8")
    assert len(_party_gaps(_gaps({"third_party": SUPPLIERS}))) == 1


def test_the_party_gap_is_one_gap_and_not_one_per_party(tmp_path, _empty_inbox):
    # The unit is not a party: the column can mix organisations with categories of
    # people, and one gap each would assert every value names a system.
    _register(_empty_inbox, [f"Party {i} Ltd" for i in range(30)])
    assert len(_party_gaps(_gaps(_profile(tmp_path)))) == 1


def test_the_party_gap_caps_the_names_but_never_the_count(tmp_path, _empty_inbox):
    _register(_empty_inbox, [f"Party {i} Ltd" for i in range(30)])
    (party,) = _party_gaps(_gaps(_profile(tmp_path)))
    assert "30 of the 30" in party and "and 18 more" in party
    assert party.count("`Party ") == pc.NAME_LIMIT


def test_the_party_gap_passes_the_scope_area_validity_test(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Ledger Systems Ltd"])
    for g in _gaps(_profile(tmp_path)):
        assert coverage.scope_area_subject(str(g)) is None


def test_party_gaps_come_after_the_supplier_gaps(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Ledger Systems Ltd"])
    gaps = _gaps(_profile(tmp_path))
    assert [pc.SUPPLIER_TOKEN in g for g in gaps] == [True, True, False]


def test_its_tokens_do_not_collide_with_the_endpoint_instrument():
    assert not pc.TOKEN_PREFIX.startswith(endpoint_coverage.TOKEN_PREFIX)
    assert not endpoint_coverage.TOKEN_PREFIX.startswith(pc.TOKEN_PREFIX)


# ── the step ──

def _ctx(target: dict, assets: list[CryptoAsset], settings: dict | None = None) -> Context:
    return Context(plugin=pc.PLUGIN, target=target, settings=settings or {}, input=None,
                   ref_time=NOW, raw_dir=Path("."), policy=Policy(config.load_baseline()),
                   baseline={}, dictionary={}, port_table={}, collected_on="2030-01-31",
                   assets=tuple(assets))


def test_the_step_reads_its_settings(tmp_path, _empty_inbox):
    _register(_empty_inbox, ["Gateway Networks"])
    target = _profile(tmp_path)
    target["partners"] = [{"name": "Gateway Networks"}]
    admin = CryptoAsset(name="a", host="x.translation.example.test", data_state="at-rest",
                        source="vendor_admin_export")
    out = pc.step(_ctx(target, [admin]))
    assert len(_supplier_gaps(out.gaps)) == 2 and len(_party_gaps(out.gaps)) == 1
    out = pc.step(_ctx(target, [admin], {"privileged_sources": ["vendor_admin_export"],
                                         "declared_lists": ["partners"]}))
    assert len(_supplier_gaps(out.gaps)) == 1 and _party_gaps(out.gaps) == []
    assert out.records == []


def test_a_setting_that_is_not_a_list_is_ignored_and_reported():
    out = pc.step(_ctx({"third_party": SUPPLIERS}, [], {"privileged_sources": "vendor_admin_export"}))
    (profile,) = [g for g in out.gaps if pc.PROFILE_TOKEN in g]
    assert coverage.kind_of(profile) == coverage.COULD_NOT_TEST
    assert "privileged_sources" in profile and len(_supplier_gaps(out.gaps)) == 2


# ── an observation end to end ──

@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(plugins.metadata, "entry_points", lambda group="": [])
    root = tmp_path / "workspace"
    shutil.copytree(SAMPLE / "targets", root / "targets")
    shutil.copytree(SAMPLE / "exports", root / "inbox")
    config.set_workspace(root)
    config.set_inbox(root / "inbox")
    return root


def test_an_observation_files_the_supplier_gaps_and_writes_no_row(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = ["privileged_coverage"]
    target["third_party"] = SUPPLIERS
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    assert not [a for a in result.assets if a.source == "privileged_coverage"]
    record = result.summary["plugins"]["privileged_coverage"]
    assert record["status"] == "ran" and record["rows"] == 0
    filed = [g for g in result.summary["gaps"] if pc.SUPPLIER_TOKEN in g]
    assert len(filed) == 2 and any("Translation Co" in g for g in filed)
