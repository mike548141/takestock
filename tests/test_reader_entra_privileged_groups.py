"""The Microsoft Entra role-assignable group membership reader in takestock's readers library.

The membership and role exports are composed in each test
(``entra_helpers``), with synthetic group names, people and IDs: one person
holds a role both directly and through a group, one group holds Global
Administrator, one has no membership rows, one holds a nested group and a
guest.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import ROLE_COLUMNS, by_name, ctx, guid, write

from takestock import coverage, plugin_kinds
from takestock.readers import entra_privileged_groups as epg
from takestock.readers import library

MEMBER_COLUMNS = ("group_id", "group_name", "member_id", "member_type", "member_upn",
                  "account_enabled")
USER, GROUP = "#microsoft.graph.user", "#microsoft.graph.group"


def _files(tmp: Path) -> list[str]:
    roles = write(tmp / "roles.csv", ROLE_COLUMNS, [
        {"RoleDisplayName": "Global Administrator", "PrincipalId": guid(11), "PrincipalType": GROUP,
         "PrincipalDisplayName": "Example top admins"},
        {"RoleDisplayName": "Example Administrator", "PrincipalId": guid(12), "PrincipalType": GROUP,
         "PrincipalDisplayName": "Example helpdesk"},
        {"RoleDisplayName": "Example Reader", "PrincipalId": guid(12), "PrincipalType": GROUP},
        {"RoleDisplayName": "Example Reader", "PrincipalId": guid(13), "PrincipalType": GROUP,
         "PrincipalDisplayName": "Example empty group"},
        {"RoleDisplayName": "Global Administrator", "PrincipalId": guid(21), "PrincipalType": USER},
        {"RoleDisplayName": "Global Reader", "PrincipalId": guid(22), "PrincipalType": USER},
    ])
    return [str(roles)]


def _members(path: Path, enabled: str = "true") -> Path:
    rows = [{"group_id": guid(11), "group_name": "Example top admins", "member_id": guid(21),
             "member_type": USER, "member_upn": "member-a@example.test", "account_enabled": enabled},
            {"group_id": guid(11), "group_name": "Example top admins", "member_id": guid(23),
             "member_type": USER, "member_upn": "member-b@example.test", "account_enabled": enabled}]
    rows += [{"group_id": guid(12), "group_name": "Example helpdesk", "member_id": guid(30 + i),
              "member_type": USER, "member_upn": f"h{i}@example.test",
              "account_enabled": enabled} for i in range(3)]
    rows += [{"group_id": guid(12), "group_name": "Example helpdesk", "member_id": guid(40),
              "member_type": USER, "member_upn": "guest_example.org#EXT#@example.test",
              "account_enabled": enabled},
             {"group_id": guid(12), "group_name": "Example helpdesk", "member_id": guid(41),
              "member_type": GROUP, "member_upn": "", "account_enabled": enabled}]
    return write(path, MEMBER_COLUMNS, rows)


def test_the_reader_is_in_the_library():
    assert library()["entra_privileged_groups"] is epg.PLUGIN


def test_people_are_counted_once(tmp_path):
    path = _members(tmp_path / "members.csv")
    result = epg.step(ctx(epg.PLUGIN, path, {"roles": _files(tmp_path)}))
    rows = by_name(result.records)
    pop = rows["Privileged population — everyone who can act with administrative power"]
    x = pop.extra
    assert (x["privileged_people_total"], x["privileged_people_direct"],
            x["privileged_people_via_group"], x["privileged_people_both_routes"]) == (7, 2, 6, 1)
    assert (x["top_role_people_total"], x["top_role_people_both_routes"]) == (2, 1)
    assert (x["nested_groups"], x["external_guests"]) == (1, 1)
    assert (x["groups_with_no_membership_row"], x["max_powers_reached_by_group"]) == (1, 2)
    assert x["membership_export"] == "members.csv"
    assert pop.flags == [] and pop.hosts_count == 7
    assert "Example helpdesk" in x["largest_group"]
    for row in result.records:
        assert row.flags == []
        assert plugin_kinds.check_asset("general", row) == []
    assert [coverage.kind_of(g) for g in result.gaps] == [coverage.EXTENT_UNKNOWN]


def test_group_rows(tmp_path):
    rows = by_name(epg.step(ctx(epg.PLUGIN, _members(tmp_path / "m.csv"),
                                {"roles": _files(tmp_path)})).records)
    top = rows["Example top admins — administrative group membership"]
    assert top.extra["carries_top_role"] == "yes"
    assert (top.hosts_count, top.usage_count) == (2, 1)
    help_desk = rows["Example helpdesk — administrative group membership"]
    assert help_desk.extra["power_names"] == "Example Administrator, Example Reader"
    empty = rows["Example empty group — administrative group with no members listed"]
    assert (empty.hosts_count, empty.extra["membership_row_present"]) == (0, "no")


def test_newest_membership_file_and_account_state(tmp_path):
    _members(tmp_path / "members-2030-01-01.csv")
    _members(tmp_path / "members-2030-02-01.csv", enabled="")
    result = epg.step(ctx(epg.PLUGIN, None, {"members": str(tmp_path / "members-*.csv"),
                                             "roles": _files(tmp_path)}))
    pop = by_name(result.records)[
        "Privileged population — everyone who can act with administrative power"]
    assert pop.extra["membership_export"] == "members-2030-02-01.csv"
    assert pop.extra["rows_with_no_account_state"] == 7
    assert len(result.gaps) == 2


def test_a_page_sized_group(tmp_path):
    rows = [{"group_id": guid(12), "group_name": "Example helpdesk", "member_id": guid(1000 + i),
             "member_type": USER, "account_enabled": "true"} for i in range(100)]
    path = write(tmp_path / "m.csv", MEMBER_COLUMNS, rows)
    result = epg.step(ctx(epg.PLUGIN, path, {"roles": _files(tmp_path)}))
    group = by_name(result.records)["Example helpdesk — administrative group membership"]
    assert group.extra["membership_count_is_page_size"] == "yes"
    assert any("page size" in g for g in result.gaps)


def test_missing_inputs(tmp_path):
    result = epg.step(ctx(epg.PLUGIN, None))
    assert result.records == [] and "none was named" in result.gaps[0]
    result = epg.step(ctx(epg.PLUGIN, _members(tmp_path / "m.csv")))
    assert result.records == [] and "no directory role assignment export" in result.gaps[0]
