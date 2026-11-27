"""The ``estate`` plug-in: declared asset classes against the instruments that ran.

Every declaration, row and run record is composed here, for an invented
organisation, with invented class names and round numbers.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, observe, plugins
from takestock.model import CryptoAsset
from takestock.plugins import Context, RunInfo
from takestock.policy import Policy
from takestock.readers import estate, library

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)

BUILT = {"tls_scan", "ssh_audit", "ike_scan", "vendor_export"}


def _row(source: str, source_class: str = "private", host: str = "") -> CryptoAsset:
    return CryptoAsset(name=f"{source} row", data_state="in-transit", source=source,
                       source_class=source_class, host=host)


def _rows(source: str, n: int, **kw: str) -> list[CryptoAsset]:
    return [_row(source, **kw) for _ in range(n)]


def _check(classes: list[dict], assets: list[CryptoAsset], **kw):
    target = {"asset_classes": classes}
    kw.setdefault("built", BUILT)
    kw.setdefault("discovered_vendors", {})
    return estate.collect(target, assets, **kw)


def _one(entry: dict, assets: list[CryptoAsset], **kw) -> tuple[CryptoAsset, list]:
    rows, gaps = _check([entry], assets, **kw)
    assert len(rows) == 1
    return rows[0], gaps


def test_the_reader_is_in_the_library():
    plugin = library()["estate"]
    assert plugin is estate.PLUGIN
    assert plugin.kind == "general" and plugin.late and plugin.date_rows is False
    assert plugin.gap_prefix is False and plugin.input == ""


@pytest.mark.parametrize("spec, expected", [
    ("tls_scan/ssh-audit", (["tls_scan", "ssh_audit"], False)),
    ("vendor-export (planned)", (["vendor_export"], True)),
    (["a", "b-c"], (["a", "b_c"], False)),
    ("none", ([], False)),
    ("-", ([], False)),
    ("", ([], False)),
    (None, ([], False)),
])
def test_a_collect_value_is_read_into_instrument_names(spec, expected):
    assert estate.parse_collect(spec) == expected


# ── the six states ──

def test_a_class_with_no_instrument_named_is_dark_and_says_so():
    row, gaps = _one({"name": "Backup appliances", "crypto": ["data at rest"], "collect": "none"},
                     [])
    assert row.extra["estate_state"] == "no-instrument"
    assert row.extra["estate_reason"] == "none-declared"
    assert row.verdict == "unknown" and row.extra["dark"] is True
    assert row.flags == ["no-instrument:none-declared"]
    assert row.data_state == "estate" and row.source == "estate"
    assert row.extra["declared_crypto"] == ["data at rest"]
    (gap,) = gaps
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.nature_of(gap) == coverage.NO_DATA
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION
    assert "Backup appliances" in gap and "data at rest" in gap


def test_a_class_naming_only_absent_instruments_is_dark_and_unbuilt():
    row, gaps = _one({"name": "Edge firewalls", "collect": "device_export/other"}, [])
    assert row.extra["estate_state"] == "no-instrument"
    assert row.extra["estate_reason"] == "unbuilt"
    assert row.flags == ["collector-unbuilt:device_export", "collector-unbuilt:other",
                         "no-instrument:unbuilt"]
    assert row.extra["collectors_unbuilt"] == ["device_export", "other"]
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert "unmeasured" in gaps[0] and "crypto (unstated)" in gaps[0]


def test_an_instrument_the_run_skipped_is_not_run_not_silent():
    row, gaps = _one({"name": "Edge firewalls", "collect": "ike_scan"}, [],
                     skipped={"ike_scan"})
    assert row.extra["estate_state"] == "instrument-not-run"
    assert row.flags == ["instrument-not-run:ike_scan"]
    assert coverage.kind_of(gaps[0]) == coverage.COULD_NOT_TEST
    assert "was not run" in gaps[0]


def test_an_instrument_that_sent_no_probe_is_unmeasured_not_instrumented():
    # Two placeholder rows are not two measurements: counting them as output
    # would make the class read as instrumented on the one run that measured nothing.
    placeholders = _rows("ike_scan", 2, source_class="unknown")
    row, gaps = _one({"name": "Edge firewalls", "collect": "ike_scan"}, placeholders)
    assert row.extra["estate_state"] == "instrument-unmeasured"
    assert row.extra["collectors_unprobed"] == ["ike_scan"]
    assert row.flags == ["instrument-unmeasured:ike_scan"]
    assert "estate-evidenced" not in " ".join(row.flags)
    # Nothing was asked, so this is not-collected, not could-not-test.
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.nature_of(gaps[0]) == coverage.NO_DATA


def test_an_instrument_that_ran_and_wrote_nothing_is_silent():
    row, gaps = _one({"name": "Edge firewalls", "collect": "tls_scan"}, [])
    assert row.extra["estate_state"] == "instrument-silent"
    assert row.flags == ["instrument-silent:tls_scan"]
    assert coverage.kind_of(gaps[0]) == coverage.COULD_NOT_TEST
    assert "not evidence that the class is absent" in gaps[0]


def test_one_silent_and_one_skipped_instrument_are_both_named():
    row, gaps = _one({"name": "Edge firewalls", "collect": "tls_scan/ike_scan"}, [],
                     skipped={"ike_scan"})
    assert row.extra["estate_state"] == "instrument-silent"
    assert row.flags == ["instrument-not-run:ike_scan", "instrument-silent:tls_scan"]
    assert "ike_scan was not run" in gaps[0] and "tls_scan produced nothing" in gaps[0]


def test_some_instruments_producing_rows_is_partial_and_low_fidelity():
    row, gaps = _one({"name": "Edge firewalls", "collect": "tls_scan/ssh_audit/gone"},
                     _rows("tls_scan", 3))
    assert row.extra["estate_state"] == "instrument-partial"
    assert row.extra["collectors_live"] == ["tls_scan"]
    assert row.extra["collectors_silent"] == ["ssh_audit"]
    assert row.extra["collectors_unbuilt"] == ["gone"]
    assert coverage.kind_of(gaps[0]) == coverage.COULD_NOT_TEST
    assert coverage.nature_of(gaps[0]) == coverage.LOW_FIDELITY


def test_every_instrument_producing_rows_is_instrumented_with_no_gap():
    row, gaps = _one({"name": "Edge firewalls", "collect": "tls_scan"}, _rows("tls_scan", 4))
    assert row.extra["estate_state"] == "instrumented" and row.extra["dark"] is False
    assert row.verdict == "n/a" and gaps == []
    assert row.extra["attributed_assets"] == 4 and row.flags == ["estate-evidenced:4"]
    assert row.extra["attribution"] == "exclusive-collector"


# ── attribution ──

def test_a_shared_instrument_claims_no_count():
    classes = [{"name": "Edge firewalls", "collect": "tls_scan"},
               {"name": "Web servers", "collect": "tls_scan/ssh_audit"}]
    rows, _ = _check(classes, _rows("tls_scan", 5) + _rows("ssh_audit", 2))
    firewalls, web = rows
    assert firewalls.flags == ["instrument-shared:tls_scan"]
    assert firewalls.extra["attributed_assets"] == 0 and firewalls.extra["attribution"] == "none"
    # The exclusive instrument's rows are the class's; the shared one's are nobody's.
    assert web.extra["attributed_assets"] == 2
    assert web.flags == ["estate-evidenced:2", "instrument-shared:tls_scan"]


def test_a_planned_marker_the_build_contradicts_is_reported_not_believed():
    row, _ = _one({"name": "Edge firewalls", "collect": "tls_scan (planned)"},
                  _rows("tls_scan", 1))
    assert row.extra["declared_planned"] is True
    assert "declaration-stale:planned-but-built:tls_scan" in row.flags
    assert row.extra["estate_state"] == "instrumented"


def test_a_planned_marker_on_an_absent_instrument_is_not_stale():
    row, _ = _one({"name": "Edge firewalls", "collect": "device_export (planned)"}, [])
    assert row.extra["estate_state"] == "no-instrument"
    assert not any(f.startswith("declaration-stale") for f in row.flags)


def test_rows_are_undated_and_make_no_cryptographic_claim():
    row, _ = _one({"name": "Edge firewalls", "collect": "tls_scan"}, _rows("tls_scan", 1))
    assert row.collected_at == "" and row.protocol == "" and row.host == ""
    assert row.name == "Declared asset class: Edge firewalls"
    assert row.role.startswith("A kind of equipment in the estate: Edge firewalls.")


# ── the declaration itself ──

def test_no_declaration_is_one_gap_and_no_rows():
    rows, gaps = estate.collect({}, [], built=BUILT, discovered_vendors={})
    assert rows == [] and len(gaps) == 1
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert "`asset_classes:`" in gaps[0]


def test_the_profile_key_can_be_named():
    target = {"equipment": [{"name": "Edge firewalls", "collect": "none"}]}
    rows, _ = estate.collect(target, [], built=BUILT, discovered_vendors={}, key="equipment")
    assert [r.extra["estate_class"] for r in rows] == ["Edge firewalls"]


def test_an_entry_that_is_not_a_mapping_is_skipped_and_reported():
    rows, gaps = _check(["Edge firewalls", {"name": "Web servers", "collect": "none"}], [])
    assert [r.extra["estate_class"] for r in rows] == ["Web servers"]
    assert any("not mappings" in g for g in gaps)


def test_an_unnamed_class_is_still_a_row():
    row, _ = _one({"collect": "none"}, [])
    assert row.extra["estate_class"] == "(unnamed class)"


# ── the other direction ──

def test_with_no_vendor_evidence_a_gap_says_the_comparison_was_not_made():
    rows, gaps = estate.collect({"asset_classes": [{"name": "Edge firewalls", "collect": "none"}]},
                                [], built=BUILT)
    assert len(rows) == 1
    gap = gaps[-1]
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(gap) == coverage.NARROWS_CONFIDENCE
    assert "not checked against the devices discovered" in gap


def test_a_discovered_vendor_no_class_names_is_a_gap_with_its_count():
    classes = [{"name": "Acme Widgets firewalls", "collect": "none"}]
    _, gaps = _check(classes, [], discovered_vendors={"Acme Widgets, Inc.": 12,
                                                      "Globex Networks": 7, "": 3})
    gap = gaps[-1]
    assert coverage.kind_of(gap) == coverage.EXTENT_UNKNOWN
    assert "1 vendor(s)" in gap and "Globex Networks (7)" in gap and "Acme" not in gap


def test_every_discovered_vendor_declared_is_no_gap():
    classes = [{"name": "Acme Widgets firewalls", "collect": "tls_scan"}]
    _, gaps = _check(classes, _rows("tls_scan", 1), discovered_vendors={"Acme Widgets, Inc.": 12})
    assert gaps == []


# ── what the run was made of ──

def test_instruments_map_registered_names_to_the_modules_rows_name():
    run = RunInfo(collectors=("tls_scan", "ssh_audit", "ssh_audit_inbox"),
                  ran=("ssh_audit_inbox",), skipped={"tls_scan": "offline",
                                                     "ssh_audit": "offline"},
                  plugins={"vendor_export": "ran", "estate": "pending"})
    built, skipped = estate.instruments(run)
    assert built == {"tls_scan", "ssh_audit", "vendor_export", "estate"}
    # ssh_audit is not skipped when its input-reading entry ran: same module, same rows.
    assert skipped == {"tls_scan"}


def test_without_a_run_record_the_registered_modules_are_built_and_none_skipped():
    from takestock import collectors
    built, skipped = estate.instruments(None)
    assert built == {c.module for c in collectors.REGISTRY.values()} and skipped == set()


# ── the summary ──

def test_the_summary_is_derived_from_the_rows():
    classes = [{"name": "Edge firewalls", "collect": "tls_scan"},
               {"name": "Backup appliances", "collect": "none"},
               {"name": "Web servers", "collect": "ssh_audit (planned)"},
               {"name": "Tape libraries", "collect": "ike_scan"}]
    rows, _ = _check(classes, _rows("tls_scan", 2) + _rows("ssh_audit", 1), skipped={"ike_scan"})
    summary = estate.summarise(rows + [_row("tls_scan")])
    assert summary == {
        "declared_classes": 4,
        "dark": ["Backup appliances", "Tape libraries"],
        "dark_count": 2,
        "by_state": {"instrument-not-run": ["Tape libraries"],
                     "instrumented": ["Edge firewalls", "Web servers"],
                     "no-instrument": ["Backup appliances"]},
        "stale_declarations": ["Web servers"],
        "not_run": ["Tape libraries"],
    }
    assert estate.summarise([_row("tls_scan")]) == {}


# ── the step ──

def _ctx(target: dict, assets: list[CryptoAsset], run: RunInfo | None,
         settings: dict | None = None) -> Context:
    return Context(plugin=estate.PLUGIN, target=target, settings=settings or {}, input=None,
                   ref_time=NOW, raw_dir=Path("."), policy=Policy(config.load_baseline()),
                   baseline={}, dictionary={}, port_table={}, collected_on="2030-01-31",
                   assets=tuple(assets), run=run)


def test_the_step_reads_the_run_and_the_settings():
    run = RunInfo(collectors=("tls_scan", "ike_scan"), ran=("tls_scan",),
                  skipped={"ike_scan": "no scan was asked for"})
    target = {"classes": [{"name": "Edge firewalls", "collect": "ike_scan"},
                          {"name": "Web servers", "collect": "tls_scan"}]}
    out = estate.step(_ctx(target, _rows("tls_scan", 2), run,
                           {"key": "classes", "discovered_vendors": {"Globex": 4}}))
    states = {r.extra["estate_class"]: r.extra["estate_state"] for r in out.records}
    assert states == {"Edge firewalls": "instrument-not-run", "Web servers": "instrumented"}
    assert any("Globex (4)" in g for g in out.gaps)


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


def test_an_observation_writes_one_row_per_class_and_a_summary(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = ["estate"]
    target["asset_classes"] = [
        {"name": "Build servers", "crypto": ["SSH"], "collect": "ssh_audit"},
        {"name": "Backup appliances", "crypto": ["data at rest"], "collect": "none"}]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    rows = [a for a in result.assets if a.source == "estate"]
    assert [r.extra["estate_class"] for r in rows] == ["Build servers", "Backup appliances"]
    assert all(r.collected_at == "" for r in rows)
    states = {r.extra["estate_class"]: r.extra["estate_state"] for r in rows}
    assert states["Backup appliances"] == "no-instrument"
    assert states["Build servers"] in ("instrumented", "instrument-silent")
    record = result.summary["plugins"]["estate"]
    assert record["rows"] == 2 and record["summary"]["declared_classes"] == 2
    assert any("Backup appliances" in g for g in result.summary["gaps"])
