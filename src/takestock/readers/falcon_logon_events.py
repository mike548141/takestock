"""CrowdStrike Falcon: sign-ins and local group changes as the sensor recorded them on each machine.

Three CSV exports, each written by a LogScale (Falcon Next-Gen SIEM) query
that groups the sensor's events and counts them; ``docs/COLLECTORS.md``
gives the queries.

* ``input:``: successful sign-ins (``UserLogon`` events), grouped by
  account, machine and logon type.
* ``settings: failures:``: failed sign-ins (``UserLogonFailed`` and
  ``UserLogonFailed2``), grouped the same way.
* ``settings: group_changes:``: local group membership changes
  (``UserAccountAddedToGroup``, ``UserAccountRemovedFromGroup`` and
  ``UserGroupDeleted``), grouped by event, machine, account and group.

A console's list of sign-ins counts them but need not say where they landed;
these events name the machine. The reader uses them for that alone, and
grades nothing: every row is ``n/a``, so a cleartext sign-in graded by
``falcon_logins`` is not counted twice.

* ``Machines accepting remote interactive sign-ins``: machines that took a
  logon of type 10, RemoteInteractive, with the events and accounts behind
  them (accounts counted, not named).
* ``Machines receiving cleartext sign-ins``: machines that received a logon
  of type 8, NetworkCleartext, succeeded or failed, named, since where the
  setting that accepts it lives is the point. Written at zero too.
* ``Sign-in event scope``: what the exports cover, the logon type mix, how
  many machines recorded a network logon (type 3), and how many failures
  carry no logon type.
* ``Local group membership changes``: on how many machines membership
  changed, by event. When no row names the group, a gap says how many of
  the changes touched an administrators group is unknown.

Logon types are read by Microsoft's number or name (:mod:`._falcon_identity`).
A machine is counted by its name ignoring case, or by its sensor ID where a
row has no name.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi
from ._falcon_traffic import COUNT_HEADING

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_logon_events"

ADDED = "UserAccountAddedToGroup"
REMOVED = "UserAccountRemovedFromGroup"
DELETED = "UserGroupDeleted"

#: NZISM v3.9 16.6.10.C.02 (SHOULD, all classifications): agencies should log, at minimum,
#: "system user and group additions, deletions and modification to permissions".
NZISM_GROUP_LOGGING = "NZISM v3.9 16.6.10.C.02"

_SIGNIN = {"account": "UserName", "machine": "ComputerName", "sensor_id": "aid",
           "logon_type": "LogonType", "count": COUNT_HEADING}
#: Each export's fields and the headings they are read from unless ``settings: columns:`` names others.
HEADINGS: dict[str, dict[str, Any]] = {
    "logons": dict(_SIGNIN),
    "failures": dict(_SIGNIN),
    "group_changes": {"event": "#event_simpleName", "machine": "ComputerName",
                      "sensor_id": "aid", "account": "UserRid", "group": "GroupRid",
                      "count": COUNT_HEADING},
}


def _no_signins_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of sign-in events by machine was read"
        + (f" ({why})" if why else "")
        + ": which machines accept remote interactive sign-ins, and which received a "
        "NetworkCleartext sign-in",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("A list of sign-ins that names no machine cannot say where remote sessions "
                "land, or which machine accepted a password it could read."),
        harvest=("Run the sign-in queries in docs/COLLECTORS.md (falcon_logon_events) and name "
                 "the CSVs with input: and settings: failures:."),
        nature=coverage.NO_DATA)


def _no_groups_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of local group membership changes was read"
        + (f" ({why})" if why else "")
        + ": on which machines membership of local groups changed",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Local groups are where administrative rights on a machine are granted; "
                "without these events nothing says whether, or on how many machines, their "
                "membership changes."),
        harvest=("Run the group change query in docs/COLLECTORS.md (falcon_logon_events) and "
                 "name the CSV with settings: group_changes:."),
        nature=coverage.NO_DATA)


def _no_group_named_gap(machines: int) -> coverage.Gap:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"the group change export records local group membership changes on {machines:,} "
        "machines and names no group, so how many of them touched an administrators group is "
        "unknown",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Which group changed is the privileged-access question: adding an account to "
                "a machine's administrators group gives it control of the machine, and most "
                "other groups do not. Without the group the report can say membership changed, "
                "not whether privilege was granted."),
        harvest=("Re-run the group change query with the group's identifier (GroupRid) among "
                 "the grouped fields, and name its heading with settings: columns:."),
        nature=coverage.LOW_FIDELITY)


def _row(name: str, role: str, flags: list[str], count: int, notes: str,
         extra: dict[str, str], base: Mapping[str, Any]) -> CryptoAsset:
    return CryptoAsset(name=name, role=role, verdict="n/a", flags=flags, hosts_count=count,
                       notes=notes, extra=extra, **base)


def signin_rows(ok: list[dict[str, str]], bad: list[dict[str, str]],
                heads: Mapping[str, Mapping[str, Any]], when: str) -> list[CryptoAsset]:
    """The sign-in rows for the successful and failed exports (either may be empty)."""
    oh, fh = heads["logons"], heads["failures"]
    base = {"data_state": "identity", "protocol": "login", "source": NAME,
            "source_class": "private", "source_name": _fi.source_name("sign-in event", when),
            "collected_at": when}

    def kind(r: dict[str, str], h: Mapping[str, Any]) -> str:
        return _fi.logon_type(_fi.value(r, h["logon_type"]))

    out: list[CryptoAsset] = []
    if ok:
        ri = [r for r in ok if kind(r, oh) == _fi.REMOTE_INTERACTIVE]
        ri_hosts = {_fi.machine(r, oh) for r in ri} - {""}
        ri_users = {_fi.value(r, oh["account"]).casefold() for r in ri} - {""}
        ri_events = sum(_fi.events(_fi.value(r, oh["count"])) for r in ri)
        all_hosts = {_fi.machine(r, oh) for r in ok} - {""}
        out.append(_row(
            "Machines accepting remote interactive sign-ins",
            roles.signin_events_remote(len(ri_hosts)),
            [f"remote-interactive-hosts:{len(ri_hosts)}"], len(ri_hosts),
            (f"{len(ri_hosts):,} of the {len(all_hosts):,} machines with a recorded sign-in "
             f"accepted a remote interactive sign-in (logon type 10): {ri_events:,} events by "
             f"{len(ri_users):,} accounts, counted and not named. Each takes a full remote "
             "desktop session, so a stolen credential that works there gives hands-on control. "
             "These are sign-in events, a different unit from a console's count of sign-ins; "
             "the two are not added together. " + _fi.NO_TIMES_NOTE),
            {"hosts": str(len(ri_hosts)), "accounts": str(len(ri_users)),
             "events": str(ri_events), "hosts_with_any_signin": str(len(all_hosts))}, base))

    ct_ok = [r for r in ok if kind(r, oh) == _fi.NETWORK_CLEARTEXT]
    ct_bad = [r for r in bad if kind(r, fh) == _fi.NETWORK_CLEARTEXT]
    receivers = sorted(({_fi.machine_label(r, oh) for r in ct_ok}
                        | {_fi.machine_label(r, fh) for r in ct_bad}) - {""}, key=str.casefold)
    ok_n = sum(_fi.events(_fi.value(r, oh["count"])) for r in ct_ok)
    bad_n = sum(_fi.events(_fi.value(r, fh["count"])) for r in ct_bad)
    if receivers:
        said = (f"{len(receivers):,} machine(s) received a sign-in of logon type 8, "
                f"NetworkCleartext: {ok_n:,} succeeded and {bad_n:,} failed. Receiving "
                f"machine(s): {', '.join(receivers)}. For this type Microsoft says the password "
                "reached the authentication package unhashed, so the setting that accepts it "
                "lives on the receiving machine; the sender is not in these exports. The "
                "finding is graded once, on falcon_logins' row; this row says where it landed. ")
    else:
        said = ("No machine received a sign-in of logon type 8, NetworkCleartext, succeeded "
                "or failed, in these exports. That holds for machines running the sensor "
                "only. ")
    out.append(_row(
        "Machines receiving cleartext sign-ins", roles.signin_events_cleartext(len(receivers)),
        [f"cleartext-logon-receivers:{len(receivers)}"], len(receivers),
        said + _fi.NO_TIMES_NOTE,
        {"receivers": str(len(receivers)), "succeeded": str(ok_n), "failed": str(bad_n),
         **({"receiving_hosts": ", ".join(receivers)} if receivers else {})}, base))

    types: dict[str, int] = {}
    for r in ok:
        t = _fi.value(r, oh["logon_type"]) or "(not recorded)"
        types[t] = types.get(t, 0) + _fi.events(_fi.value(r, oh["count"]))
    net_hosts = {_fi.machine(r, oh) for r in ok if kind(r, oh) == _fi.NETWORK} - {""}
    failed = sum(_fi.events(_fi.value(r, fh["count"])) for r in bad)
    untyped = sum(_fi.events(_fi.value(r, fh["count"])) for r in bad
                  if not _fi.value(r, fh["logon_type"]))
    out.append(_row(
        "Sign-in event scope", roles.signin_events_scope(), ["scope-observed-not-enumerated"],
        len(ok) + len(bad),
        ("These are the sign-ins the sensor recorded on the machines that run it; a sign-in "
         "to another machine, or to a cloud service, is not here. "
         + (f"A network logon (type 3) was recorded on {len(net_hosts):,} machine(s); compare "
            "that with the machines that take network sign-ins, such as file servers, before "
            "reading a share of network sign-ins from this export. " if ok else "")
         + (f"{untyped:,} of {failed:,} failed sign-ins carry no logon type, so a count of "
            "failures by type is a floor. " if bad else "")
         + "The unit is the sign-in event. " + _fi.NO_TIMES_NOTE),
        {"successful_rows": str(len(ok)), "failed_rows": str(len(bad)),
         "network_signin_hosts": str(len(net_hosts)), "failures_untyped": str(untyped),
         "failures": str(failed), **{f"logon_type_{k}": str(v) for k, v in sorted(types.items())}},
        base))
    return out


def group_rows(rows: list[dict[str, str]], h: Mapping[str, Any],
               when: str) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The group change row, and a gap when no row names the group."""
    base = {"data_state": "identity", "protocol": "login", "source": NAME,
            "source_class": "private",
            "source_name": _fi.source_name("group change event", when), "collected_at": when}
    by_event: dict[str, tuple[int, set[str]]] = {}
    with_account = 0
    for r in rows:
        ev = _fi.value(r, h["event"]) or "(not recorded)"
        n, hosts = by_event.get(ev, (0, set()))
        m = _fi.machine(r, h)
        by_event[ev] = (n + _fi.events(_fi.value(r, h["count"])), hosts | ({m} if m else set()))
        if _fi.value(r, h["account"]):
            with_account += 1
    machines: set[str] = set().union(*(hs for _, hs in by_event.values()))
    named = any(_fi.value(r, h["group"]) for r in rows)

    def part(ev: str, what: str) -> str:
        n, hs = by_event.get(ev, (0, set()))
        return f"{what} {n:,} times on {len(hs):,} machines"

    row = _row(
        "Local group membership changes", roles.signin_events_groups(len(machines)),
        [f"local-group-changes:{len(machines)}"], len(machines),
        (f"Local group membership changed on {len(machines):,} machines: "
         f"{part(ADDED, 'an account was added')}; {part(REMOVED, 'an account was removed')}; "
         f"and {part(DELETED, 'a group was deleted')}. {with_account:,} of {len(rows):,} rows "
         "identify the account. "
         + ("" if named else "No row names the group, so whether a change granted or removed "
                             "administrative rights cannot be said. ")
         + f"Recording these events is the logging {NZISM_GROUP_LOGGING} asks for (user and "
           "group additions, deletions and changes to permissions); whether anyone reviews them "
           "is not in the export. " + _fi.NO_TIMES_NOTE),
        {"hosts": str(len(machines)), "rows": str(len(rows)),
         "rows_with_account": str(with_account), "group_name_present": "yes" if named else "no",
         "standard": NZISM_GROUP_LOGGING,
         **{f"{k}_events": str(v[0]) for k, v in by_event.items()},
         **{f"{k}_hosts": str(len(v[1])) for k, v in by_event.items()}}, base)
    return [row], ([] if named else [_no_group_named_gap(len(machines))])


def read(logons: Path | None, failures: Path | None = None, group_changes: Path | None = None,
         *, headings: Mapping[str, Mapping[str, Any]] | None = None,
         ) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows and gaps for the three exports; each missing part is a gap of its own."""
    heads = headings or HEADINGS
    out: list[CryptoAsset] = []
    gaps: list[coverage.Gap] = []
    ok, ok_why = _fi.rows(logons)
    bad, bad_why = _fi.rows(failures)
    if ok or bad:
        dated = logons if ok else failures
        when = (file_mtime_date(dated) if dated else None) or ""
        out += signin_rows(ok, bad, heads, when)
    else:
        gaps.append(_no_signins_gap(ok_why or bad_why))
    grp, grp_why = _fi.rows(group_changes)
    if grp and group_changes is not None:
        rows, g = group_rows(grp, heads["group_changes"], file_mtime_date(group_changes) or "")
        out += rows
        gaps += g
    else:
        gaps.append(_no_groups_gap(grp_why))
    return out, gaps


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the exports' rows, and a gap for each part not read."""
    assets, gaps = read(ctx.input, _entra.newest(ctx, "failures"),
                        _entra.newest(ctx, "group_changes"),
                        headings=_fi.headings(ctx, HEADINGS))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gaps.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon sign-ins and group changes, per machine",
                gap_prefix=False)
