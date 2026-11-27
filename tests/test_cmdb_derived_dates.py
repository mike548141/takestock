"""The register dates each row by when its data was collected, else by the observation that read it.

A derived observation (``takestock rerun``) carries most rows from an earlier
one and reads some plug-ins again, so its rows were read on different dates.
These tests build a register from a synthetic derived observation of the
invented Example Widgets Ltd (``cmdbfake``) and check every date it records.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cmdbfake
import pytest

from takestock import cmdb, rerun

HELD = "2030-01-10T0800Z"
REREAD = "2030-01-25T0900Z"
HELD_DAY = "2030-01-10"
REREAD_DAY = "2030-01-25"
PLUGIN = "example_agent_export"


def _rows() -> list[dict[str, Any]]:
    """The synthetic rows, with no row dating itself, and the endpoint agent's
    TLS row and the port scan's SSH row written by the re-read plug-in."""
    rows = cmdbfake.rows()
    for row in rows:
        row.pop("collected_at", None)
        if row["name"] in ("tls app-01", "ssh app-01"):
            row["extra"]["plugin"] = PLUGIN
    return rows


def _write(root: Path, rows: list[dict[str, Any]], record: dict[str, Any] | None,
           stamp: str = REREAD) -> Path:
    obs = root / stamp
    obs.mkdir(parents=True)
    (obs / "assets.json").write_text(json.dumps(rows))
    summary: dict[str, Any] = {"total_assets": len(rows), "observation": {"stamp": stamp}}
    if record is not None:
        summary[cmdb.DERIVED_KEY] = record
    (obs / "summary.json").write_text(json.dumps(summary))
    return obs


def _derived(root: Path, rows: list[dict[str, Any]] | None = None) -> Path:
    return _write(root, _rows() if rows is None else rows,
                  {"from_observation": HELD, "plugins": [PLUGIN]})


def _key(register: cmdb.Cmdb, attribute: str, value: str) -> str:
    return next(a.item for a in register.assertions
                if a.attribute == attribute and a.value == value)


def _recorded(register: cmdb.Cmdb, key: str) -> set[str]:
    return {a.recorded_at for a in register.assertions if a.item == key}


# ── reading the record ─────────────────────────────────────────────────────


def test_the_record_key_is_the_one_rerun_writes():
    assert cmdb.DERIVED_KEY == rerun.SUMMARY_KEY


def test_an_observation_that_is_not_derived_has_no_read_dates():
    assert cmdb.read_dates({"total_assets": 3}, REREAD) is None


def test_a_record_naming_no_dated_observation_is_not_read():
    assert cmdb.read_dates({"rerun": {"from_observation": "copy", "plugins": ["a"]}},
                           REREAD) is None


def test_a_chain_of_derived_observations_is_followed_to_the_full_one():
    # 2030-01-25 re-read a and derived from 2030-01-18, which re-read a and b
    # and was derived from the full observation of 2030-01-10.
    summary = {"rerun": {"from_observation": "2030-01-18T0000Z", "plugins": ["a"],
                         "from_rerun": {"from_observation": HELD, "plugins": ["a", "b"]}}}
    read = cmdb.read_dates(summary, REREAD)
    assert read == cmdb.ReadDates(held=HELD_DAY, reread={"a": REREAD_DAY, "b": "2030-01-18"})
    assert read.of({"extra": {"plugin": "a"}}) == REREAD_DAY
    assert read.of({"extra": {"plugin": "b"}}) == "2030-01-18"
    assert read.of({"extra": {"plugin": "c"}}) == HELD_DAY
    assert read.of({"extra": {}}) == HELD_DAY


# ── the facts ──────────────────────────────────────────────────────────────


def test_each_fact_is_recorded_on_the_date_its_row_was_read(tmp_path):
    register = cmdb.build(_derived(tmp_path))
    app = _key(register, "hostname", "app-01.example.test")
    laptop = _key(register, "hostname", "laptop-01.example.test")
    assert REREAD_DAY in _recorded(register, app)
    assert _recorded(register, laptop) == {HELD_DAY}
    assert {a.recorded_at for a in register.assertions} == {HELD_DAY, REREAD_DAY}
    assert register.recorded_at == HELD_DAY


def test_a_row_without_its_own_date_is_valid_when_it_was_read(tmp_path):
    register = cmdb.build(_derived(tmp_path))
    printer = _key(register, "hostname", "printer-01.example.test")
    assert {a.valid_at for a in register.assertions if a.item == printer} == {HELD_DAY}
    tls = {a.valid_at for a in register.assertions
           if a.attribute == "version" and a.value == "3.0.13"}
    assert tls == {REREAD_DAY}


def test_a_row_that_dates_itself_keeps_its_date(tmp_path):
    rows = _rows()
    for row in rows:
        row["collected_at"] = "2030-01-05"
    register = cmdb.build(_derived(tmp_path, rows))
    assert {a.valid_at for a in register.assertions
            if a.attribute == "hostname" and a.value == "printer-01.example.test"} == {
        "2030-01-05"}
    # Collected before the full observation, so read again it is recorded on
    # the full observation's date, as its carried rows are.
    assert {a.recorded_at for a in register.assertions
            if a.attribute == "version" and a.value == "3.0.13"} == {HELD_DAY}


def test_an_environment_without_a_date_is_valid_when_its_row_was_read(tmp_path):
    rows = _rows()
    tls = next(r for r in rows if r["name"] == "tls app-01")
    del tls["extra"]["environment"]["valid_at"]
    register = cmdb.build(_derived(tmp_path, rows))
    env = [a for a in register.assertions if a.attribute == "environment"]
    assert env and {(a.valid_at, a.recorded_at) for a in env} == {(REREAD_DAY, REREAD_DAY)}


def test_an_os_build_read_again_is_dated_and_recorded_by_when_it_was_collected(tmp_path):
    rows = _rows()
    disk = next(r for r in rows if r["name"] == "disk laptop-01")
    disk["extra"].update({"plugin": PLUGIN, "os_version": "7.2.41",
                          "os_collected_at": "2030-01-20"})
    disk["collected_at"] = "2030-01-04"
    register = cmdb.build(_derived(tmp_path, rows))
    laptop = _key(register, "hostname", "laptop-01.example.test")
    dates = {a.attribute: (a.valid_at, a.recorded_at) for a in register.assertions
             if a.item == laptop and a.attribute in ("hostname", "os_version")}
    # The build was collected after the full observation, so the register
    # learned it no earlier than that; the row's other facts are recorded on
    # the full observation's date, as before.
    assert dates == {"hostname": ("2030-01-04", HELD_DAY),
                     "os_version": ("2030-01-20", "2030-01-20")}


# ── the edges, the keys and the counts ─────────────────────────────────────


def test_edges_drawn_from_a_reread_row_are_dated_by_it(tmp_path):
    register = cmdb.build(_derived(tmp_path))
    ssh = _key(register, "name", "app-01.example.test 22/tcp")
    printer = _key(register, "name", "printer-01.example.test 9100/tcp")
    contains = {e.to_key: e for e in register.edges if e.kind == "contains"}
    by_kind = {e.kind: e for e in register.edges if e.kind in ("installed-on", "release-of")}
    by_kind["contains"] = contains[ssh]
    for kind in ("installed-on", "release-of", "contains"):
        assert (by_kind[kind].valid_at, by_kind[kind].recorded_at) == (
            REREAD_DAY, REREAD_DAY), kind
    assert (contains[printer].valid_at, contains[printer].recorded_at) == (HELD_DAY, HELD_DAY)
    member = [e for e in register.edges if e.kind == "member-of"]
    assert member and {e.recorded_at for e in member} == {HELD_DAY}


def test_edges_drawn_from_carried_rows_are_dated_by_the_full_observation(tmp_path):
    rows = _rows()
    for row in rows:
        row["extra"].pop("plugin", None)
    register = cmdb.build(_derived(tmp_path, rows))
    assert {(e.valid_at, e.recorded_at) for e in register.edges
            if e.kind in ("installed-on", "release-of", "contains")} == {(HELD_DAY, HELD_DAY)}


def test_keys_are_seen_and_merged_when_their_rows_were_read(tmp_path):
    register = cmdb.build(_derived(tmp_path))
    aliases = {a.identifier: a for item in register.items.values() for a in item.aliases}
    assert aliases["printer-01.example.test"].first_seen == HELD_DAY
    assert aliases[cmdbfake.AGENT].last_seen == REREAD_DAY


def test_a_merge_a_reread_row_makes_is_dated_by_it(tmp_path):
    other = "00000000-0000-4000-8000-000000000002"
    rows = [*_rows(),
            cmdbfake._row(name="tls app-02", host="app-02.example.test", port="443",
                          protocol="tls", source="example_scan"),
            cmdbfake._row(name="agent app-02", data_state="at-rest", source="example_agent",
                          extra={"agent_id": other, "host_type": "Server"}),
            cmdbfake._row(name="both app-02", host="app-02.example.test", data_state="at-rest",
                          source="example_agent",
                          extra={"agent_id": other, "host_type": "Server", "plugin": PLUGIN})]
    for row in rows:
        row.pop("collected_at", None)
    register = cmdb.build(_derived(tmp_path, rows))
    assert [m["at"] for m in register.ledger.merges] == [REREAD_DAY]


def test_a_release_a_reread_row_lists_is_dated_by_it(tmp_path):
    rows = [*_rows(),
            cmdbfake._row(name="release list", source="example_agent", data_state="inventory",
                          extra={"plugin": PLUGIN, "releases": [
                              {"product": "Example Server", "versions": ["2.1"]}]})]
    rows[-1].pop("collected_at", None)
    register = cmdb.build(_derived(tmp_path, rows))
    release = _key(register, "name", "Example Server 2.1")
    edge = next(e for e in register.edges if e.kind == "release-of" and e.from_key == release)
    assert (edge.valid_at, edge.recorded_at) == (REREAD_DAY, REREAD_DAY)


def test_what_the_build_infers_after_a_reread_row_is_dated_by_the_full_observation(tmp_path):
    rows = _rows()
    rows.append(rows.pop(next(n for n, r in enumerate(rows) if r["name"] == "tls app-01")))
    register = cmdb.build(_derived(tmp_path, rows))
    member = [e for e in register.edges if e.kind == "member-of"]
    assert member and {(e.valid_at, e.recorded_at) for e in member} == {(HELD_DAY, HELD_DAY)}


def test_counts_of_the_whole_are_dated_by_the_full_observation(tmp_path):
    register = cmdb.build(_derived(tmp_path))
    union = [p for p in register.populations if p.instrument == "every instrument together"]
    assert union and union[0].valid_at == HELD_DAY


# ── what does not change ───────────────────────────────────────────────────


def test_a_recording_date_given_for_the_build_records_every_fact(tmp_path):
    register = cmdb.build(_derived(tmp_path), recorded_at="2030-02-01")
    assert {a.recorded_at for a in register.assertions} == {"2030-02-01"}
    assert {e.recorded_at for e in register.edges} == {"2030-02-01"}
    tls = {a.valid_at for a in register.assertions
           if a.attribute == "version" and a.value == "3.0.13"}
    assert tls == {REREAD_DAY}


def test_an_ordinary_observation_is_dated_by_its_own_stamp(tmp_path):
    register = cmdb.build(_write(tmp_path, _rows(), None))
    assert {a.recorded_at for a in register.assertions} == {REREAD_DAY}
    assert {e.valid_at for e in register.edges
            if e.kind in ("installed-on", "release-of")} == {REREAD_DAY}
    assert register.recorded_at == REREAD_DAY


# ── what the workbook's read-me says of the dates ──────────────────────────


def _readme(register: dict[str, Any], tmp_path: Path) -> list[str]:
    from openpyxl import load_workbook
    cmdb.write_outputs(register, tmp_path / "out")
    sheet = load_workbook(tmp_path / "out" / "cmdb.xlsx")["Read me"]
    return [str(c.value) for c in sheet["A"] if c.value]


def test_the_read_me_says_when_a_derived_observation_was_read(tmp_path):
    register = cmdb.build_register(_derived(tmp_path))
    assert register["register"]["read_on"] == HELD_DAY
    assert register["register"]["read_again"] == {PLUGIN: REREAD_DAY}
    assert register["register"]["read_again_collected"] == {}
    readme = _readme(register, tmp_path)
    assert f"The data was collected between {HELD_DAY} and {REREAD_DAY}." in readme
    assert not any(REREAD in line for line in readme)
    assert [line for line in readme if line.startswith("The data was")] == [
        f"The data was collected between {HELD_DAY} and {REREAD_DAY}."]


def test_the_read_me_gives_one_range_when_sources_were_read_again_on_several_days(tmp_path):
    summary = {"from_observation": "2030-01-18T0000Z", "plugins": [PLUGIN],
               "from_rerun": {"from_observation": HELD, "plugins": [PLUGIN, "example_other"]}}
    register = cmdb.build_register(_write(tmp_path, _rows(), summary))
    assert register["register"]["read_again"] == {PLUGIN: REREAD_DAY,
                                                  "example_other": "2030-01-18"}
    readme = _readme(register, tmp_path)
    assert f"The data was collected between {HELD_DAY} and {REREAD_DAY}." in readme
    assert not any("2030-01-18" in line for line in readme)


def test_the_read_me_dates_an_ordinary_observation_by_its_stamp(tmp_path):
    register = cmdb.build_register(_write(tmp_path, _rows(), None))
    assert register["register"]["read_again"] == {}
    readme = _readme(register, tmp_path)
    assert f"The data was collected on {REREAD_DAY}." in readme
    assert not any(line.startswith("Observation ") for line in readme)


def test_the_read_me_gives_the_span_the_register_carries():
    from takestock.cmdb_export import as_at_line
    reg = {"read_on": HELD_DAY, "recorded_at": "2030-02-01",
           "read_again": {PLUGIN: REREAD_DAY}, "read_again_collected": {}}
    assert as_at_line({**reg, "collected_from": "2030-01-04",
                       "collected_to": "2030-01-04"}) == "The data was collected on 2030-01-04."
    assert as_at_line({**reg, "collected_from": "2030-01-04", "collected_to": HELD_DAY}) == (
        f"The data was collected between 2030-01-04 and {HELD_DAY}.")


def test_a_register_without_the_span_says_when_it_was_read():
    from takestock.cmdb_export import as_at_line
    assert as_at_line({"recorded_at": "2030-02-01"}) == "The data was read on 2030-02-01."
    assert as_at_line({"recorded_at": "2030-02-01", "read_again": {PLUGIN: "2030-02-03"}}) == (
        "The data was read between 2030-02-01 and 2030-02-03.")
    # One written with the newest collection of each plug-in read again, but
    # not the span, still says only when it was read.
    assert as_at_line({"read_on": HELD_DAY, "recorded_at": HELD_DAY,
                       "read_again": {PLUGIN: REREAD_DAY},
                       "read_again_collected": {PLUGIN: "2030-01-04"}}) == (
        f"The data was read between {HELD_DAY} and {REREAD_DAY}.")


def test_a_recording_date_given_for_the_build_leaves_the_read_date_alone(tmp_path):
    register = cmdb.build_register(_write(tmp_path, _rows(), None), recorded_at="2030-02-01")
    assert register["register"]["recorded_at"] == "2030-02-01"
    assert register["register"]["read_on"] == REREAD_DAY
    # A row with no collection date is dated by the observation, not the recording.
    assert register["register"]["collected_to"] == REREAD_DAY
    assert f"The data was collected on {REREAD_DAY}." in _readme(register, tmp_path)


# ── a plug-in read again is dated by when its source was collected ─────────

COLLECTED_DAY = "2030-01-20"


def _collected_rows(day: str) -> list[dict[str, Any]]:
    """The synthetic rows with the re-read plug-in's rows collected on ``day``."""
    rows = _rows()
    for row in rows:
        if (row.get("extra") or {}).get("plugin") == PLUGIN:
            row["collected_at"] = day
    return rows


def test_read_dates_names_the_newest_collection_of_each_plugin_read_again():
    summary = {"rerun": {"from_observation": "2030-01-18T0000Z", "plugins": ["a"],
                         "from_rerun": {"from_observation": HELD, "plugins": ["b"]}}}
    rows = [{"extra": {"plugin": "a"}, "collected_at": "2030-01-03"},
            {"extra": {"plugin": "a"}, "collected_at": COLLECTED_DAY},
            {"extra": {"plugin": "b"}, "collected_at": "2030-01-15T10:00:00Z"},
            {"extra": {"plugin": "c"}, "collected_at": "2030-01-24"},
            {"extra": {}, "collected_at": "2030-01-24"}]
    read = cmdb.read_dates(summary, REREAD, rows)
    assert read is not None
    assert read.reread == {"a": REREAD_DAY, "b": "2030-01-18"}
    assert read.collected == {"a": COLLECTED_DAY, "b": "2030-01-15"}
    # The newest collection describes the source; each row is dated by its own.
    assert read.of({"extra": {"plugin": "a"}, "collected_at": "2030-01-03"}) == "2030-01-03"
    assert read.of({"extra": {"plugin": "a"}}) == REREAD_DAY
    assert read.of({"extra": {"plugin": "b"}}) == "2030-01-18"
    assert read.of({"extra": {"plugin": "c"}}) == HELD_DAY
    assert cmdb.read_dates(summary, REREAD).of({"extra": {"plugin": "a"}}) == REREAD_DAY


def test_a_row_is_dated_by_its_collection_whether_carried_or_read_again():
    read = cmdb.read_dates({"rerun": {"from_observation": HELD, "plugins": ["a"]}}, REREAD,
                           [{"extra": {"plugin": "a"}, "collected_at": "2030-01-02"}])
    assert read is not None and read.collected == {"a": "2030-01-02"}
    # Older than the full observation, read again: dated by its collection,
    # recorded on the full observation's date, which may have held it.
    again = {"extra": {"plugin": "a"}, "collected_at": "2030-01-02"}
    assert (read.of(again), read.recorded(again)) == ("2030-01-02", HELD_DAY)
    carried = {"extra": {"plugin": "c"}, "collected_at": "2030-01-02"}
    assert (read.of(carried), read.recorded(carried)) == ("2030-01-02", HELD_DAY)
    # Newer than the full observation: recorded on the day it was collected.
    newer = {"extra": {"plugin": "a"}, "collected_at": COLLECTED_DAY}
    assert (read.of(newer), read.recorded(newer)) == (COLLECTED_DAY, COLLECTED_DAY)
    # No collection date: dated and recorded by the observation that read it.
    undated = {"extra": {"plugin": "a"}}
    assert (read.of(undated), read.recorded(undated)) == (REREAD_DAY, REREAD_DAY)
    assert (read.of({"extra": {}}), read.recorded({"extra": {}})) == (HELD_DAY, HELD_DAY)


def test_a_row_read_again_is_never_recorded_after_the_day_it_was_read():
    read = cmdb.read_dates({"rerun": {"from_observation": HELD, "plugins": ["a"]}}, REREAD)
    assert read is not None
    assert read.recorded({"extra": {"plugin": "a"}, "collected_at": "2030-02-09"}) == REREAD_DAY


def test_a_collection_never_postdates_the_day_it_was_read_again():
    read = cmdb.read_dates({"rerun": {"from_observation": HELD, "plugins": ["a"]}}, REREAD,
                           [{"extra": {"plugin": "a"}, "collected_at": "2030-02-09"},
                            {"extra": {"plugin": "a"}, "collected_at": "2030-01"}])
    assert read is not None and read.collected == {"a": REREAD_DAY}


def test_facts_and_edges_of_a_plugin_read_again_are_dated_by_its_collection(tmp_path):
    register = cmdb.build(_derived(tmp_path, _collected_rows(COLLECTED_DAY)))
    app = _key(register, "hostname", "app-01.example.test")
    laptop = _key(register, "hostname", "laptop-01.example.test")
    assert COLLECTED_DAY in _recorded(register, app)
    assert _recorded(register, laptop) == {HELD_DAY}
    assert {a.recorded_at for a in register.assertions} == {HELD_DAY, COLLECTED_DAY}
    assert not any(REREAD_DAY in (e.valid_at, e.recorded_at) for e in register.edges)
    by_kind = {e.kind: e for e in register.edges if e.kind in ("installed-on", "release-of")}
    for kind in ("installed-on", "release-of"):
        assert (by_kind[kind].valid_at, by_kind[kind].recorded_at) == (
            COLLECTED_DAY, COLLECTED_DAY), kind
    assert register.recorded_at == HELD_DAY


def test_a_plugin_read_again_from_an_export_the_full_observation_held_moves_no_date(tmp_path):
    carried = cmdb.build(_write(tmp_path / "carried", _collected_rows("2030-01-04"), None,
                                stamp=HELD))
    again = cmdb.build(_derived(tmp_path / "again", _collected_rows("2030-01-04")))

    def dates(register: cmdb.Cmdb) -> set[tuple[str, str, str]]:
        return ({(a.attribute, a.valid_at, a.recorded_at) for a in register.assertions}
                | {(e.kind, e.valid_at, e.recorded_at) for e in register.edges})

    assert dates(again) == dates(carried)


def test_the_read_me_range_ends_at_the_newest_collection(tmp_path):
    register = cmdb.build_register(_derived(tmp_path, _collected_rows(COLLECTED_DAY)))
    assert register["register"]["read_again"] == {PLUGIN: REREAD_DAY}
    assert register["register"]["read_again_collected"] == {PLUGIN: COLLECTED_DAY}
    readme = _readme(register, tmp_path)
    assert f"The data was collected between {HELD_DAY} and {COLLECTED_DAY}." in readme
    assert not any(REREAD_DAY in line for line in readme)


def test_the_read_me_range_starts_at_an_export_collected_before_the_full_observation(tmp_path):
    register = cmdb.build_register(_derived(tmp_path, _collected_rows("2030-01-04")))
    assert register["register"]["read_again_collected"] == {PLUGIN: "2030-01-04"}
    assert (register["register"]["collected_from"],
            register["register"]["collected_to"]) == ("2030-01-04", HELD_DAY)
    readme = _readme(register, tmp_path)
    assert f"The data was collected between 2030-01-04 and {HELD_DAY}." in readme
    assert not any(REREAD_DAY in line for line in readme)


def test_the_read_me_gives_one_date_when_every_row_was_collected_that_day(tmp_path):
    rows = _rows()
    for row in rows:
        row["collected_at"] = "2030-01-04"
    register = cmdb.build_register(_derived(tmp_path, rows))
    assert "The data was collected on 2030-01-04." in _readme(register, tmp_path)


def test_the_read_me_spans_the_collections_of_an_ordinary_observation(tmp_path):
    rows = _rows()
    next(r for r in rows if r["name"] == "tls app-01")["collected_at"] = "2030-01-04"
    register = cmdb.build_register(_write(tmp_path, rows, None))
    assert f"The data was collected between 2030-01-04 and {REREAD_DAY}." in _readme(
        register, tmp_path)


def test_carried_rows_and_edges_are_dated_by_their_collection(tmp_path):
    rows = _rows()
    for row in rows:
        row["extra"].pop("plugin", None)
        row["collected_at"] = "2030-01-04"
    register = cmdb.build(_derived(tmp_path, rows))
    assert {(e.valid_at, e.recorded_at) for e in register.edges
            if e.kind in ("installed-on", "release-of")} == {("2030-01-04", HELD_DAY)}
    assert {a.valid_at for a in register.assertions
            if a.attribute == "version" and a.value == "3.0.13"} == {"2030-01-04"}


def test_an_ordinary_observation_dates_its_edges_by_their_rows_collection(tmp_path):
    rows = _rows()
    for row in rows:
        row["collected_at"] = "2030-01-04"
    register = cmdb.build(_write(tmp_path, rows, None))
    assert {(e.valid_at, e.recorded_at) for e in register.edges
            if e.kind in ("installed-on", "release-of")} == {("2030-01-04", REREAD_DAY)}


# ── a fact collected on its own date counts toward the span ───────────────

_OWN_DATED = [("os_version", "os_collected_at", "7.2.41"),
              ("os", "os_name_collected_at", "Examplix")]


def _own_dated_rows(attribute: str, when_key: str, value: str, day: str) -> list[dict[str, Any]]:
    """The synthetic rows, each collected on 2030-01-04 and one of them holding
    ``attribute`` as collected on ``day``."""
    rows = _rows()
    for row in rows:
        row["collected_at"] = "2030-01-04"
    disk = next(r for r in rows if r["name"] == "disk laptop-01")
    disk["extra"].update({"plugin": PLUGIN, attribute: value, when_key: day})
    return rows


@pytest.mark.parametrize(("attribute", "when_key", "value"), _OWN_DATED)
def test_the_read_me_range_includes_a_fact_collected_after_its_row(tmp_path, attribute,
                                                                  when_key, value):
    rows = _own_dated_rows(attribute, when_key, value, "2030-01-20")
    register = cmdb.build_register(_write(tmp_path, rows, None))
    assert (register["register"]["collected_from"],
            register["register"]["collected_to"]) == ("2030-01-04", "2030-01-20")
    assert "The data was collected between 2030-01-04 and 2030-01-20." in _readme(
        register, tmp_path)


@pytest.mark.parametrize(("attribute", "when_key", "value"), _OWN_DATED)
def test_a_plugin_read_again_is_collected_as_late_as_its_newest_fact(tmp_path, attribute,
                                                                    when_key, value):
    rows = _own_dated_rows(attribute, when_key, value, "2030-01-20")
    register = cmdb.build_register(_derived(tmp_path, rows))
    assert register["register"]["read_again_collected"] == {PLUGIN: "2030-01-20"}
    # Never later than the day it was read again.
    late = _own_dated_rows(attribute, when_key, value, "2030-02-09")
    read = cmdb.read_dates({"rerun": {"from_observation": HELD, "plugins": [PLUGIN]}},
                           REREAD, late)
    assert read is not None and read.collected == {PLUGIN: REREAD_DAY}
