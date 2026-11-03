"""The CrowdStrike Falcon sign-in and group change event reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (the
sensor's field names, and ``_count``), with made-up machine names, sensor IDs
and account names. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_logon_events as reader
from takestock.readers import library

SIGNIN = ("aid", "ComputerName", "UserName", "LogonType", "_count")
GROUPS = ("#event_simpleName", "aid", "ComputerName", "UserRid", "GroupRid", "_count")


def _export(path: Path, columns: tuple[str, ...], rows: list[dict]) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _s(machine: str, user: str, logon: str, n: int) -> dict:
    return {"aid": f"aid-{machine}", "ComputerName": machine, "UserName": user,
            "LogonType": logon, "_count": str(n)}


def _g(event: str, machine: str, group: str = "", n: int = 1) -> dict:
    return {"#event_simpleName": event, "aid": f"aid-{machine}", "ComputerName": machine,
            "UserRid": "rid-1", "GroupRid": group, "_count": str(n)}


def _run(tmp_path: Path, ok: list[dict] | None, bad: list[dict] | None = None,
         groups: list[dict] | None = None):
    settings: dict = {}
    if bad is not None:
        settings["failures"] = str(_export(tmp_path / "f.csv", SIGNIN, bad))
    if groups is not None:
        settings["group_changes"] = str(_export(tmp_path / "g.csv", GROUPS, groups))
    path = _export(tmp_path / "s.csv", SIGNIN, ok) if ok is not None else None
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["falcon_logon_events"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_nothing_named_gives_two_gaps_in_order():
    out = reader.step(ctx(reader.PLUGIN, None))
    assert out.records == []
    assert [coverage.kind_of(g) for g in out.gaps] == [coverage.NOT_COLLECTED] * 2
    assert "sign-in events" in str(out.gaps[0]) and "group membership" in str(out.gaps[1])
    assert all(coverage.impact_kind_of(g) == coverage.NARROWS_CONFIDENCE for g in out.gaps)


def test_sign_in_rows(tmp_path):
    out = _run(tmp_path,
               [_s("alpha", "alice", "10", 4), _s("ALPHA", "Bob", "RemoteInteractive", 2),
                _s("bravo", "alice", "2", 9), _s("charlie", "carol", "3", 1),
                _s("delta", "dave", "8", 1)],
               [_s("echo", "erin", "8", 3), _s("alpha", "alice", "", 5),
                _s("bravo", "bob", "2", 1)])
    rows = by_name(out.records)
    ri = rows["Machines accepting remote interactive sign-ins"]
    assert ri.verdict == "n/a" and ri.flags == ["remote-interactive-hosts:1"]
    assert ri.extra == {"hosts": "1", "accounts": "2", "events": "6",
                        "hosts_with_any_signin": "4"}
    ct = rows["Machines receiving cleartext sign-ins"]
    assert ct.flags == ["cleartext-logon-receivers:2"]
    assert ct.extra == {"receivers": "2", "succeeded": "1", "failed": "3",
                        "receiving_hosts": "delta, echo"}
    assert "delta, echo" in ct.notes
    scope = rows["Sign-in event scope"]
    assert scope.extra["network_signin_hosts"] == "1"
    assert scope.extra["failures_untyped"] == "5" and scope.extra["failures"] == "9"
    assert scope.extra["logon_type_10"] == "4"
    assert scope.extra["logon_type_RemoteInteractive"] == "2"
    assert all(r.verdict == "n/a" and r.data_state == "identity" for r in out.records)
    # No group export named: its own gap, and no other.
    assert len(out.gaps) == 1 and "group membership" in str(out.gaps[0])


def test_the_cleartext_row_is_written_at_zero(tmp_path):
    out = _run(tmp_path, [_s("alpha", "alice", "2", 1)])
    ct = by_name(out.records)["Machines receiving cleartext sign-ins"]
    assert ct.flags == ["cleartext-logon-receivers:0"]
    assert "receiving_hosts" not in ct.extra and ct.extra["receivers"] == "0"


def test_group_changes_without_the_group_raise_a_low_fidelity_gap(tmp_path):
    out = _run(tmp_path, [_s("alpha", "alice", "2", 1)], None, [
        _g("UserAccountAddedToGroup", "alpha", n=2), _g("UserAccountAddedToGroup", "bravo"),
        _g("UserAccountRemovedFromGroup", "alpha"), _g("UserGroupDeleted", "charlie", n=3)])
    row = by_name(out.records)["Local group membership changes"]
    assert row.flags == ["local-group-changes:3"]
    assert row.extra["UserAccountAddedToGroup_events"] == "3"
    assert row.extra["UserAccountAddedToGroup_hosts"] == "2"
    assert row.extra["group_name_present"] == "no"
    assert row.extra["standard"] == "NZISM v3.9 16.6.10.C.02"
    assert row.extra["rows_with_account"] == "4"
    assert len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.EXTENT_UNKNOWN
    assert coverage.nature_of(out.gaps[0]) == coverage.LOW_FIDELITY


def test_a_named_group_leaves_no_gap(tmp_path):
    out = _run(tmp_path, [_s("alpha", "alice", "2", 1)], None,
               [_g("UserAccountAddedToGroup", "alpha", group="g-1")])
    assert out.gaps == []
    assert by_name(out.records)["Local group membership changes"].extra[
        "group_name_present"] == "yes"


def test_a_machine_without_a_name_is_counted_by_sensor_id(tmp_path):
    rows = [{**_s("alpha", "alice", "10", 1), "ComputerName": ""},
            {**_s("bravo", "bob", "10", 1), "ComputerName": ""}]
    out = _run(tmp_path, rows)
    ri = by_name(out.records)["Machines accepting remote interactive sign-ins"]
    assert ri.extra["hosts"] == "2"
