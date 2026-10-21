"""The register dates a derived observation's facts by the observation that read each row.

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
    assert {a.recorded_at for a in register.assertions
            if a.attribute == "version" and a.value == "3.0.13"} == {REREAD_DAY}


def test_an_environment_without_a_date_is_valid_when_its_row_was_read(tmp_path):
    rows = _rows()
    tls = next(r for r in rows if r["name"] == "tls app-01")
    del tls["extra"]["environment"]["valid_at"]
    register = cmdb.build(_derived(tmp_path, rows))
    env = [a for a in register.assertions if a.attribute == "environment"]
    assert env and {(a.valid_at, a.recorded_at) for a in env} == {(REREAD_DAY, REREAD_DAY)}


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
