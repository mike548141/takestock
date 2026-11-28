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


def test_a_declared_plugin_the_run_records_as_not_run_is_skipped_not_silent():
    run = RunInfo(collectors=("tls_scan",), ran=("tls_scan",),
                  plugins={"vendor_export": "not-run", "device_export": "ran",
                           "later_export": "pending"})
    built, skipped = estate.instruments(run)
    assert built == {"tls_scan", "vendor_export", "device_export", "later_export"}
    # A plug-in whose turn has not come is neither run nor skipped yet.
    assert skipped == {"vendor_export"}
    assert estate.plugins_not_run(run) == {"vendor_export": estate.NOT_RUN}
    assert estate.plugins_not_run(None) == {}


def test_a_plugin_that_did_not_run_for_want_of_input_reads_as_not_run():
    run = RunInfo(collectors=("tls_scan",), ran=("tls_scan",),
                  plugins={"vendor_export": "not-run", "estate": "pending"})
    target = {"asset_classes": [{"name": "Edge firewalls", "crypto": ["IPsec VPN"],
                                 "collect": "vendor_export"}]}
    out = estate.step(_ctx(target, _rows("tls_scan", 2), run, {"discovered_vendors": {}}))
    (row,) = out.records
    assert row.extra["estate_state"] == "instrument-not-run"
    assert row.flags == ["instrument-not-run:vendor_export"]
    assert row.extra["dark"] is True and row.verdict == "unknown"
    assert row.notes.startswith("NOT RUN: vendor_export")
    (gap,) = out.gaps
    assert coverage.kind_of(gap) == coverage.COULD_NOT_TEST
    assert "dark because it did not run" in gap and "by this run's choice" not in gap
    assert "its input was not supplied" in gap
    assert coverage.harvest_of(gap).startswith("Give each plug-in that did not run its input")
    assert estate.summarise(out.records)["not_run"] == ["Edge firewalls"]


# A library reader named with no `input:` is called, finds nothing to read, files its own
# gap and writes no rows. The run records it as having run.
NO_INPUT_RUN = RunInfo(plugins={"commvault": "ran", "oracle_tde": "ran", "sbom": "ran"})
BACKUP_CLASS = {"name": "Backup appliances", "crypto": ["backup encryption"], "collect": "commvault"}


def _step_for(plugins_declared: list, classes: list[dict], assets: list[CryptoAsset],
              run: RunInfo = NO_INPUT_RUN):
    target = {"plugins": plugins_declared, "asset_classes": classes}
    return estate.step(_ctx(target, assets, run, {"discovered_vendors": {}}))


def test_a_plugin_given_no_input_that_wrote_nothing_reads_as_not_run_not_silent():
    out = _step_for(["commvault"], [BACKUP_CLASS], [])
    (row,) = out.records
    assert row.extra["estate_state"] == "instrument-not-run"
    assert row.extra["estate_reason"] == "not-run"
    assert row.flags == ["instrument-not-run:commvault"]
    assert estate.summarise(out.records)["not_run"] == ["Backup appliances"]
    (gap,) = out.gaps
    assert "it was given no input to read" in gap and "produced nothing" not in gap
    assert coverage.harvest_of(gap).startswith("Give each plug-in")
    assert estate.plugins_not_run(NO_INPUT_RUN, {"plugins": ["commvault"]}) == {
        "commvault": estate.NO_INPUT}


def test_the_same_plugin_given_an_input_that_wrote_nothing_stays_silent():
    # It ran, with something to read, and found nothing: that is silence.
    out = _step_for([{"name": "commvault", "input": "inbox/policies.csv"}], [BACKUP_CLASS], [])
    assert out.records[0].extra["estate_state"] == "instrument-silent"
    assert out.records[0].flags == ["instrument-silent:commvault"]
    assert "produced nothing" in out.gaps[0]


def test_a_plugin_given_no_input_that_wrote_rows_is_instrumented():
    out = _step_for(["commvault"], [BACKUP_CLASS], _rows("commvault", 3))
    assert out.records[0].extra["estate_state"] == "instrumented"


def test_a_plugin_that_names_a_module_or_a_path_is_not_judged_by_its_input():
    # Its default input is not known here, so nothing is claimed about it.
    for declared in ({"name": "commvault", "module": "somewhere.else"},
                     {"name": "commvault", "path": "plugins/commvault.py"}):
        out = _step_for([declared], [BACKUP_CLASS], [])
        assert out.records[0].extra["estate_state"] == "instrument-silent"


def test_a_plugin_that_writes_no_rows_by_design_is_not_judged_by_its_rows():
    run = RunInfo(plugins={"privileged_coverage": "ran", "flows": "ran"})
    classes = [{"name": "Suppliers", "collect": "privileged_coverage"},
               {"name": "Channels", "collect": "flows"}]
    out = _step_for(["privileged_coverage", "flows"], classes, [], run)
    assert [r.extra["estate_state"] for r in out.records] == ["instrument-silent"] * 2


def test_a_plugin_not_in_the_library_is_not_judged_by_its_input():
    run = RunInfo(plugins={"vendor_export": "ran"})
    out = _step_for(["vendor_export"], [{"name": "Edge", "collect": "vendor_export"}], [], run)
    assert out.records[0].extra["estate_state"] == "instrument-silent"


def test_one_plugin_not_run_beside_one_that_ran_is_partial_and_flagged_not_run():
    run = RunInfo(plugins={"vendor_export": "not-run", "device_export": "ran"})
    target = {"asset_classes": [{"name": "Edge firewalls",
                                 "collect": "vendor_export/device_export"}]}
    out = estate.step(_ctx(target, _rows("device_export", 3), run, {"discovered_vendors": {}}))
    (row,) = out.records
    assert row.extra["estate_state"] == "instrument-partial"
    assert "instrument-not-run:vendor_export" in row.flags
    assert "instrument-silent:vendor_export" not in row.flags


def test_a_plugin_not_run_beside_a_collector_that_ran_dark_keeps_the_class_silent():
    # The collector ran and wrote nothing: that is silence, and the class is not
    # "not run". Only the not-run plug-in's own flag changes.
    run = RunInfo(collectors=("tls_scan",), ran=("tls_scan",), plugins={"vendor_export": "not-run"})
    target = {"asset_classes": [{"name": "Edge firewalls", "collect": "tls_scan/vendor_export"}]}
    out = estate.step(_ctx(target, [], run, {"discovered_vendors": {}}))
    (row,) = out.records
    assert row.extra["estate_state"] == "instrument-silent"
    assert row.flags == ["instrument-not-run:vendor_export", "instrument-silent:tls_scan"]
    assert "tls_scan produced nothing" in out.gaps[0] and "vendor_export was not run" in out.gaps[0]


def test_a_collector_the_run_skipped_keeps_its_wording_and_remedy():
    run = RunInfo(collectors=("ike_scan",), skipped={"ike_scan": "no scan was asked for"})
    target = {"asset_classes": [{"name": "Edge firewalls", "collect": "ike_scan"}]}
    out = estate.step(_ctx(target, [], run, {"discovered_vendors": {}}))
    (gap,) = out.gaps
    assert "was not run in this observation, so the class is dark by this run's choice" in gap
    assert coverage.harvest_of(gap) == "Run the observation again with the instrument enabled."


def test_a_plugin_whose_turn_has_not_come_is_still_silent_not_not_run():
    run = RunInfo(plugins={"vendor_export": "pending"})
    target = {"asset_classes": [{"name": "Edge firewalls", "collect": "vendor_export"}]}
    out = estate.step(_ctx(target, [], run, {"discovered_vendors": {}}))
    assert out.records[0].extra["estate_state"] == "instrument-silent"


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


def test_a_declared_plugin_whose_input_file_is_missing_reads_as_not_run_in_an_observation(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = [{"name": "falcon_estate_coverage", "input": "inbox/absent-hosts.csv"},
                         "estate"]
    target["asset_classes"] = [
        {"name": "Sensor fleet", "crypto": ["disk encryption"], "collect": "falcon_estate_coverage"}]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    assert result.summary["plugins"]["falcon_estate_coverage"]["status"] == "not-run"
    (row,) = [a for a in result.assets if a.source == "estate"]
    assert row.extra["estate_state"] == "instrument-not-run"
    assert result.summary["plugins"]["estate"]["summary"]["not_run"] == ["Sensor fleet"]


def test_a_declared_plugin_with_no_input_reads_as_not_run_in_an_observation(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = ["commvault", "estate"]
    target["asset_classes"] = [
        {"name": "Backup appliances", "crypto": ["backup encryption"], "collect": "commvault"}]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    assert result.summary["plugins"]["commvault"]["status"] == "ran"
    assert result.summary["plugins"]["commvault"]["rows"] == 0
    (row,) = [a for a in result.assets if a.source == "estate"]
    assert row.extra["estate_state"] == "instrument-not-run"
    assert result.summary["plugins"]["estate"]["summary"]["not_run"] == ["Backup appliances"]

