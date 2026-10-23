"""Microsoft Entra role-assignable groups: who is inside the groups that hold directory roles.

A directory role can be assigned to a group, and a role assignment export
then names the group, not the people in it. Counting the export's people
gives a floor. This reader joins the role assignments to the groups'
membership, so the number of people who can act with a directory role has a
ceiling too.

**The inputs.**

* The **membership** CSV, the reader's ``input:`` or ``settings: {members:
  ...}`` (a path or a pattern; the last match in name order is read, so a
  date in each file's name picks the newest): one row per member per group,
  in the columns ``group_id``, ``group_name``, ``member_id``,
  ``member_type``, ``member_upn`` and ``account_enabled``.
  ``docs/COLLECTORS.md`` gives a Microsoft Graph PowerShell script that
  writes them.
* The **role assignment** exports, active and eligible, named with
  ``settings: {roles: [...]}``, read for ``PrincipalId``, ``PrincipalType``,
  ``PrincipalDisplayName`` and ``RoleDisplayName`` (the same files the
  ``entra_signins`` reader reads as its roster).

**People are counted once.** A person can hold a role directly and also sit
in a group holding another, so the two counts overlap; every count here is a
set of object IDs, never a sum, and the population row gives the overlap.

**Rows.** One per group holding a role, ``<group> — administrative group
membership`` (or ``… with no members listed`` when the membership export has
no row for it, which fits an empty group and a group the export missed
alike), and the population row. All are ``unknown`` or ``n/a`` and carry no
flags: their counts move whenever someone joins or leaves a group, and a flag
carrying a count would read as a change in posture. The figures are in
``extra``, ``hosts_count`` and ``usage_count``.

**Global Administrator** is the role that can grant every other role
(matched exactly, so Global Reader is not swept in), and the population row
counts who can hold it. A group whose member count is a page size a
directory query stops on (:data:`PAGE_CEILINGS`) may be short. ``#EXT#`` in
a member's user principal name marks a guest account.

**Cannot see.** Whether anyone used a role (membership is not use; the
``entra_audit`` and ``entra_signins`` readers read use); membership changes
after the export was taken; members of a nested group, which are counted as
a gap when the export holds one. No person's name is written.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from ._entra import col

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "entra_privileged_groups"

#: The role that can grant every other role, as Microsoft names it in every tenant.
TOP_ROLE = "global administrator"

#: Member counts a paged directory query stops on; a group with exactly one
#: of these may have more members than the export lists.
PAGE_CEILINGS = (99, 100, 199, 200, 499, 500, 999, 1_000)

#: The marker Microsoft Entra puts in a guest account's user principal name.
GUEST_MARKER = "#EXT#"

MEMBERSHIP_IS_NOT_USE = ("Membership is not use: it says a person can act with the role, "
                         "not that they have; the audit and sign-in logs say that")
POINT_IN_TIME = ("Membership is as it was when the export was taken, and changes since are not "
                 "seen")


def _read_csv(path: Path | None) -> tuple[list[dict], str]:
    if path is None or not path.exists():
        return [], ""
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh)), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


class Roster:
    """Which groups hold which roles, and which people hold one directly."""

    def __init__(self) -> None:
        self.roles_by_group: dict[str, set[str]] = {}
        self.group_names: dict[str, str] = {}
        self.direct_people: set[str] = set()
        self.direct_top_role: set[str] = set()
        self.rows = 0

    def add(self, row: Mapping) -> None:
        self.rows += 1
        principal = col(dict(row), "PrincipalId")
        kind = col(dict(row), "PrincipalType").split(".")[-1].casefold()
        role = col(dict(row), "RoleDisplayName") or "(unnamed power)"
        if not principal:
            return
        if kind == "group":
            self.roles_by_group.setdefault(principal, set()).add(role)
            named = col(dict(row), "PrincipalDisplayName")
            if named:
                self.group_names.setdefault(principal, named)
        elif kind == "user":
            self.direct_people.add(principal)
            if role.casefold() == TOP_ROLE:
                self.direct_top_role.add(principal)

    @property
    def group_assignments(self) -> int:
        return sum(len(r) for r in self.roles_by_group.values())

    def groups_holding_top_role(self) -> set[str]:
        return {g for g, held in self.roles_by_group.items()
                if any(r.casefold() == TOP_ROLE for r in held)}


class Membership:
    """The membership export, by group and by person."""

    def __init__(self) -> None:
        self.members_by_group: dict[str, set[str]] = {}
        self.group_names: dict[str, str] = {}
        self.people: set[str] = set()
        self.nested_groups: set[str] = set()
        self.guests: set[str] = set()
        self.enabled_unrecorded = 0
        self.rows = 0

    def add(self, row: dict) -> None:
        self.rows += 1
        group = col(row, "group_id")
        member = col(row, "member_id")
        if group:
            self.group_names.setdefault(group, col(row, "group_name") or group)
            self.members_by_group.setdefault(group, set())
        if not member:
            return
        if group:
            self.members_by_group[group].add(member)
        if col(row, "member_type").split(".")[-1].casefold() == "group":
            self.nested_groups.add(member)
        else:
            self.people.add(member)
        if GUEST_MARKER.casefold() in col(row, "member_upn").casefold():
            self.guests.add(member)
        if not col(row, "account_enabled"):
            self.enabled_unrecorded += 1


def group_rows(members: Membership, roster: Roster, source_name: str,
               when: str) -> list[CryptoAsset]:
    """One row per group holding a role."""
    out: list[CryptoAsset] = []
    top_groups = roster.groups_holding_top_role()
    for group, held in sorted(roster.roles_by_group.items(),
                              key=lambda kv: (-len(members.members_by_group.get(kv[0], set())),
                                              -len(kv[1]), kv[0])):
        people = members.members_by_group.get(group)
        name = members.group_names.get(group) or roster.group_names.get(group) or group
        listed = ", ".join(sorted(held))
        top = group in top_groups
        if people is None:
            out.append(CryptoAsset(
                name=f"{name} — administrative group with no members listed",
                data_state="identity", protocol="account",
                role=roles.privileged_group(len(held), 0), source=NAME, source_class="private",
                source_name=source_name, collected_at=when, verdict="unknown",
                hosts_count=0, usage_count=len(held),
                notes=(f"This group holds {len(held)} role(s) ({listed}) and the membership "
                       "export has no row for it. That fits a group with no members and a "
                       "group the export did not cover alike. If it is empty, nobody holds "
                       "these roles through it today, but the assignment stays live: adding "
                       f"a member grants the roles. {POINT_IN_TIME}."),
                extra={"group": name, "powers": str(len(held)), "power_names": listed,
                       "members": "0", "membership_row_present": "no",
                       "carries_top_role": "yes" if top else "no"}))
            continue
        paged = len(people) in PAGE_CEILINGS
        notes = (f"{len(people)} person(s) are in this group, and it holds {len(held)} "
                 f"role(s): {listed}. Every member can act with each of them."
                 + (" One of them is Global Administrator, which can grant every other role, "
                    "so membership is equivalent to holding it." if top else "")
                 + (f" The member count is exactly {len(people)}, a page size a directory "
                    "query stops on, so the group may have more members than listed."
                    if paged else "")
                 + f" {MEMBERSHIP_IS_NOT_USE}. {POINT_IN_TIME}.")
        out.append(CryptoAsset(
            name=f"{name} — administrative group membership", data_state="identity",
            protocol="account", role=roles.privileged_group(len(held), len(people)),
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict="unknown", hosts_count=len(people), usage_count=len(held), notes=notes,
            extra={"group": name, "powers": str(len(held)), "power_names": listed,
                   "members": str(len(people)), "membership_row_present": "yes",
                   "membership_count_is_page_size": "yes" if paged else "no",
                   "carries_top_role": "yes" if top else "no"}))
    return out


def population_row(members: Membership, roster: Roster, source_name: str, when: str,
                   path: Path) -> CryptoAsset:
    """Everyone who can act with a directory role, each counted once."""
    via_group = set(members.people)
    direct = set(roster.direct_people)
    total = via_group | direct
    overlap = via_group & direct
    top_via_group: set[str] = set()
    for group in roster.groups_holding_top_role():
        top_via_group |= members.members_by_group.get(group, set())
    top_via_group &= members.people
    top_total = top_via_group | roster.direct_top_role
    top_overlap = top_via_group & roster.direct_top_role
    sized = {g: len(p) for g, p in members.members_by_group.items() if p}
    largest = max(sized, key=lambda g: sized[g]) if sized else ""
    largest_members = sized.get(largest, 0)
    largest_powers = len(roster.roles_by_group.get(largest, set()))
    reach: dict[str, set[str]] = {}
    for group, people in members.members_by_group.items():
        held = roster.roles_by_group.get(group, set())
        if held:
            for person in people:
                reach.setdefault(person, set()).update(held)
    max_reach = max((len(r) for r in reach.values()), default=0)
    at_max = sum(1 for r in reach.values() if len(r) == max_reach) if reach else 0
    no_rows = [g for g in roster.roles_by_group if g not in members.members_by_group]

    notes = (f"{len(total)} person(s) can act with a directory role: {len(direct)} by direct "
             f"assignment and {len(via_group)} through a group, {len(overlap)} of them both "
             f"ways. The two are combined by object ID, not added, which would give "
             f"{len(direct) + len(via_group)}. {len(top_total)} person(s) can act as Global "
             f"Administrator: {len(roster.direct_top_role)} directly and {len(top_via_group)} "
             f"through a group, {len(top_overlap)} both ways. {roster.group_assignments} role "
             f"assignment(s) are held by {len(roster.roles_by_group)} group(s). "
             + (f"The largest group holds {largest_powers} role(s) and has {largest_members} "
                "member(s). " if largest else "")
             + (f"{at_max} person(s) each reach {max_reach} role(s) through groups alone. "
                if max_reach else "")
             + (f"{len(members.nested_groups)} group(s) are nested inside these groups; their "
                "members are counted only if the export was taken transitively (the script "
                "in takestock's docs/COLLECTORS.md does so). " if members.nested_groups else
                "No group is nested inside these groups, so no members are hidden behind "
                "one. ")
             + (f"{len(members.guests)} of the people reached through a group are guest "
                "accounts, whose sign-in is managed by another organisation's directory. "
                if members.guests else
                "None of the people reached through a group is a guest account. ")
             + (f"The export records no account state on {members.enabled_unrecorded} of its "
                f"{members.rows} row(s), so disabled accounts cannot be separated out and "
                "are counted. " if members.enabled_unrecorded else "")
             + (f"{len(no_rows)} group(s) holding a role have no row in the membership "
                "export. " if no_rows else "")
             + f"{MEMBERSHIP_IS_NOT_USE}. {POINT_IN_TIME}.")
    return CryptoAsset(
        name="Privileged population — everyone who can act with administrative power",
        data_state="identity", protocol="account", role=roles.privileged_population(),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a", hosts_count=len(total), usage_count=roster.group_assignments,
        notes=notes,
        extra={"privileged_people_total": len(total),
               "privileged_people_direct": len(direct),
               "privileged_people_via_group": len(via_group),
               "privileged_people_both_routes": len(overlap),
               "top_role_people_total": len(top_total),
               "top_role_people_direct": len(roster.direct_top_role),
               "top_role_people_via_group": len(top_via_group),
               "top_role_people_both_routes": len(top_overlap),
               "group_held_assignments": roster.group_assignments,
               "role_holding_groups": len(roster.roles_by_group),
               "largest_group_members": largest_members,
               "largest_group_powers": largest_powers,
               "largest_group": (members.group_names.get(largest)
                                 or roster.group_names.get(largest) or largest),
               "max_powers_reached_by_group": max_reach,
               "accounts_at_max_reach": at_max,
               "membership_rows": members.rows,
               "nested_groups": len(members.nested_groups),
               "external_guests": len(members.guests),
               "rows_with_no_account_state": members.enabled_unrecorded,
               "groups_with_no_membership_row": len(no_rows),
               "membership_export": path.name})


def step(ctx: Context) -> StepResult:
    """The plug-in's step."""
    path = _entra.primary(ctx, "members")
    member_rows, unreadable = _read_csv(path)
    if not member_rows:
        why = ("none was named, as the reader's input or under settings: members"
               if path is None else
               f"{path.name} could not be read ({unreadable})" if unreadable else
               f"{path.name} does not exist" if not path.exists() else
               f"{path.name} holds no rows")
        return StepResult(gaps=[_no_membership(why)])
    assert path is not None
    members = Membership()
    for row in member_rows:
        members.add(row)
    roster = Roster()
    role_unreadable = ""
    for role_path in _entra.paths(ctx, "roles"):
        rows, problem = _read_csv(role_path)
        role_unreadable = role_unreadable or problem
        for row in rows:
            roster.add(row)
    if not roster.rows:
        return StepResult(gaps=[_no_roster(role_unreadable)])

    when = file_mtime_date(path) or ""
    source_name = ("Microsoft Entra role-assignable group membership export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    assets = group_rows(members, roster, source_name, when)
    assets.append(population_row(members, roster, source_name, when, path))
    gaps: list[str] = []
    if members.enabled_unrecorded:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"whether each person holding a role through a group has an enabled account: the "
            f"membership export records no account state on {members.enabled_unrecorded} of "
            f"its {members.rows} row(s)",
            impact=("Disabled accounts are counted in every figure, so the number of people "
                    "who could act today is at most the number given, by an amount not known."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest="Export the membership again with each member's accountEnabled property."))
    if members.nested_groups:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"the members of {len(members.nested_groups)} group(s) nested inside the groups "
            "holding roles: the membership export lists the nested groups, and unless it was "
            "taken transitively the people in them are not counted",
            impact=("Unless the export was taken transitively, more people can act with a "
                    "directory role than are counted, by an amount not known, and every count "
                    "here is a floor."),
            impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
            harvest="Export the groups' transitive membership, which lists nested members."))
    paged = [g for g, people in members.members_by_group.items() if len(people) in PAGE_CEILINGS]
    if paged:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"the full membership of {len(paged)} group(s) holding roles whose member count "
            "is exactly a page size a directory query stops on, so they may have more members "
            "than the export lists",
            impact=("The count for those groups is a floor, so the number of people with a "
                    "directory role is not shown to be bounded."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest="Export those groups' membership again, following every page."))
    return StepResult(records=assets, gaps=gaps)


def _no_membership(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no membership export of the groups holding directory roles was read: {why}. "
        "Without it, how many people the groups reach, how many can act as Global "
        "Administrator, and how they are spread across the groups are not known",
        impact=("Where roles are assigned to groups, the people holding them are not counted, "
                "so a count of administrators is a floor."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
        harvest=("Run the read-only Microsoft Graph PowerShell script in docs/COLLECTORS.md "
                 "(entra_privileged_groups) and name its CSV as the reader's input."))


def _no_roster(unreadable: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no directory role assignment export was read beside the membership export"
        + (f" (one could not be read: {unreadable})" if unreadable else "")
        + ". Without it, which roles each group holds, and who holds one directly, are not "
          "known, so membership says nothing about privilege",
        impact=("Counted from membership alone, the population leaves out everyone holding a "
                "role by direct assignment."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
        harvest=("Export the active and eligible directory role assignments as CSV and name "
                 "both under settings: roles."))


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Microsoft Entra role-assignable group membership", gap_prefix=False)
