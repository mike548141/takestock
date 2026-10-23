"""Microsoft Entra interactive sign-ins: who used an administrative role, and how they signed in.

**The input** is the interactive sign-in log the Microsoft Entra admin centre
downloads as CSV (Monitoring & health → Sign-in logs → Interactive user
sign-ins → Download), one row per sign-in. More downloads of the same log,
for overlapping or later periods, are named with ``settings: {also: [...]}``
(paths or patterns) and merged: a sign-in held by two files is counted once
(:func:`row_key`). Beside it, ``settings: {roles: [...]}`` names the role
assignment exports (active and eligible), the roster of who holds which
directory role.

**Why both.** A sign-in log shows who signed in; it cannot show who did not,
because an account that never signs in writes no rows. Only the roster says
who *could* have signed in with a role, so dormancy is measured against it,
and without it the reader says it cannot be measured.

**Rows.**

* One per directory role in the roster with at least one holder that has a
  sign-in name, ``<role> — assignment usage``: how many holders signed in
  successfully (``Status`` ``Success``), how many did not, and how many of
  their successful sign-ins were single-factor, from a device not recorded as
  compliant, or covered by no Conditional Access policy. A failed or
  interrupted attempt is not a sign-in that completed, and is counted apart.
  ``weak`` when any holder's successful sign-in completed on a single factor;
  otherwise ``unknown``, because a holder unseen in the window is not shown
  to be unused. A holder whose name marks an emergency ("break-glass")
  account is counted apart: unused is its intended state.
* One row for the roles held only by groups or service principals, which
  have no sign-in name and so cannot be measured here.
* One per application whose sign-in attempts, successful or not, recorded no
  Conditional Access policy in scope, where that is numerous enough to be a
  scoping decision
  (``settings``: ``policy_gap_min_rows``, ``policy_gap_min_share`` and
  ``policy_gap_share_floor``), ``unknown``: "not applied" means no policy
  covered the sign-in, which is not a policy failing.
* One per legacy authentication flow seen (resource owner password
  credentials, device code), ``weak``.
* One row for accounts named like administrator accounts that hold no role
  in the roster (``settings: {admin_names: ...}``), ``unknown``: a name is a
  habit, never an entitlement, so the row only counts them.
* One row on legacy authentication clients (``Client app``), at zero too.
* A scope row: the period read, whether it is a ceiling, files merged and
  any stretch no file covers.

**The period** is read from the rows, never from the file name. A file whose
row count is a download limit may not cover the whole period it was asked
for. Only the earliest file decides whether the merged record's start is a
ceiling. That rests on an assumption, not on Microsoft's documentation: that a
download cut short is missing its earliest rows, so a later file's missing
rows fall inside a stretch an earlier file covers.

**Cannot see.** Non-interactive, service principal and managed identity
sign-ins are separate logs (the ``entra_workload_signins`` reader); roles
granted outside the directory (Azure resource roles, Intune roles,
per-application administrators); and anything before the first row read.
No account name is written to any row.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from ._entra import col

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "entra_signins"

USED_FLAG = "signin-privileged-used:"
UNUSED_FLAG = "signin-privileged-unused:"
SINGLE_FACTOR_FLAG = "signin-single-factor:"
NONCOMPLIANT_FLAG = "signin-noncompliant-device:"
POLICY_GAP_FLAG = "signin-policy-not-applied:"
LEGACY_FLOW_FLAG = "signin-legacy-flow:"
UNMATCHED_SHAPE_FLAG = "signin-unmatched-admin-shape:"
UNMATCHABLE_FLAG = "signin-principal-unmatchable:"
SCOPE_WINDOW_FLAG = "signin-scope-window:"
SCOPE_CEILING_FLAG = "signin-scope-ceiling:"
SCOPE_SPAN_FLAG = "signin-scope-span:"
BREAK_GLASS_FLAG = "signin-break-glass-unused:"
SCOPE_FILES_FLAG = "signin-scope-files:"
SCOPE_HOLE_FLAG = "signin-scope-hole:"

#: The ``Authentication requirement`` value for a sign-in that asked for one factor. Only a
#: sign-in whose ``Status`` is ``Success`` is counted as completing on one: Microsoft's
#: *Learn about the sign-in log activity details* (learn.microsoft.com) says an attempt
#: whose primary authentication failed records singleFactorAuthentication, because it never
#: reached the check that would ask for a second factor. A failed or interrupted attempt
#: is likewise not counted as a holder using a role.
SINGLE_FACTOR = "single-factor authentication"

#: Authentication flows that cannot carry a second factor or hand the password
#: to the application, by the value the ``Authentication Protocol`` column
#: records, with what each means. Listed, so an unfamiliar value is never
#: assumed legacy.
LEGACY_FLOWS: dict[str, str] = {
    "ropc": ("the application takes the password itself and sends it on, so the sign-in "
             "page and every check attached to it are skipped"),
    "devicecode": ("a code shown on one device is typed into another, which is the step "
                   "device-code phishing relies on"),
}
#: The same flow as the ``Original transfer method`` column records it.
LEGACY_TRANSFERS: dict[str, str] = {"devicecodeflow": "devicecode"}

#: Defaults for when an application's uncovered sign-ins earn a row: at least
#: this many, or at least this share of the application's own sign-ins with
#: at least the floor behind it. Each is a setting.
POLICY_GAP_MIN_ROWS = 20
POLICY_GAP_MIN_SHARE = 0.05
POLICY_GAP_SHARE_FLOOR = 5

#: Default name patterns for an administrator account, matched on the part of
#: the sign-in name before ``@``. Used only to count accounts named like one
#: that hold no role in the roster. ``settings: {admin_names: {prefixes: [...],
#: suffixes: [...], contains: [...]}}`` replaces any of the three lists.
ADMIN_NAMES: dict[str, tuple[str, ...]] = {
    "prefixes": ("admin", "adm-", "adm_", "adm.", "svc-", "svc_", "srv-", "srv_", "sync_"),
    "suffixes": ("-adm", "_adm", "-admin", "_admin"),
    "contains": ("breakglass",),
}

#: Words marking an emergency account, in a role's name or a holder's name.
BREAK_GLASS_HINTS = ("breakglass", "break-glass", "emergency")

EVIDENCE_LIMIT = ("This is the interactive sign-in log only. Non-interactive, service "
                  "principal and managed identity sign-ins are separate logs, so an account "
                  "missing here may still be signing in another way")

NOT_APPLIED_MEANS = ("\"Not applied\" means no Conditional Access policy was in scope for the "
                     "sign-in. It is not a policy failing, and some sign-ins are outside every "
                     "policy's scope by the platform's design")

#: An unbroken run this long reads as a token to a secret scanner. An
#: application name holding one is written with spaces for underscores, its
#: parts kept one per ``extra`` key so the exact name can be rebuilt.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+_-]{32,}")


def _admin_names(ctx: Context) -> dict[str, tuple[str, ...]]:
    given = (ctx.settings or {}).get("admin_names") or {}
    out = dict(ADMIN_NAMES)
    if isinstance(given, dict):
        for key in out:
            if key in given:
                value = given[key]
                values = [value] if isinstance(value, str) else list(value or [])
                out[key] = tuple(str(v).lower() for v in values)
    return out


def admin_shaped(upn: str, names: dict[str, tuple[str, ...]] = ADMIN_NAMES) -> bool:
    """Whether a sign-in name matches the administrator name patterns."""
    local = upn.split("@")[0].lower()
    return (local.startswith(names["prefixes"]) or local.endswith(names["suffixes"])
            or any(t in local for t in names["contains"]))


def break_glass(holders: set[str], role: str = "") -> set[str]:
    """The holders that are emergency accounts: all of them for a role named as one,
    else those whose own name marks one."""
    if any(h in role.lower() for h in BREAK_GLASS_HINTS):
        return set(holders)
    return {u for u in holders if any(h in u.split("@")[0].lower() for h in BREAK_GLASS_HINTS)}


class Roster:
    """Who holds which directory role, from the role assignment exports.

    Columns read: ``RoleDisplayName``, ``PrincipalUserPrincipalName`` and
    ``PrincipalType``. A holder with no user principal name (a group or a
    service principal) is counted per role, since it cannot appear in a
    sign-in log.
    """

    def __init__(self) -> None:
        self.by_role: dict[str, set[str]] = {}
        self.unnamed_by_role: dict[str, int] = {}
        self.unmatchable: dict[str, int] = {}
        self.rows = 0

    def add(self, row: dict) -> None:
        self.rows += 1
        role = col(row, "RoleDisplayName") or "(unnamed role)"
        upn = col(row, "PrincipalUserPrincipalName").lower()
        self.by_role.setdefault(role, set())
        self.unnamed_by_role.setdefault(role, 0)
        if not upn:
            kind = col(row, "PrincipalType").split(".")[-1] or "unknown"
            self.unmatchable[kind] = self.unmatchable.get(kind, 0) + 1
            self.unnamed_by_role[role] += 1
            return
        self.by_role[role].add(upn)

    @property
    def principals(self) -> set[str]:
        return {u for holders in self.by_role.values() for u in holders}


def read_roster(paths: list[Path]) -> tuple[Roster | None, str]:
    """The roster from every existing file; (None, reason) when unreadable, (None, "") when absent."""
    roster = Roster()
    seen = False
    for path in paths:
        if not path.exists():
            continue
        seen = True
        try:
            for row in _entra.stream(path):
                roster.add(row)
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            return None, str(exc)
    return (roster, "") if seen and roster.rows else (None, "")


class Tally:
    """What one pass over the sign-in rows keeps: totals per account, application,
    flow and client type, never the rows themselves."""

    def __init__(self, roster: Roster | None,
                 names: dict[str, tuple[str, ...]] = ADMIN_NAMES) -> None:
        self._holders = roster.principals if roster else set()
        self._names = names
        self.rows = 0
        self.first = ""
        self.last = ""
        self.principals: set[str] = set()
        self.admin_shaped: set[str] = set()
        self.statuses: dict[str, int] = {}
        self.policy_states: dict[str, int] = {}
        self.auth_requirements: dict[str, int] = {}
        self.noncompliant = 0
        self.single_factor_successes = 0
        self.by_principal: dict[str, dict] = {}
        self.by_app: dict[str, dict] = {}
        self.legacy: dict[str, dict] = {}
        self.client_apps: dict[str, dict] = {}
        #: (file name, rows, first, last) for each file read.
        self.files: list[tuple[str, int, str, str]] = []
        self.duplicates = 0

    def _legacy(self, flow: str, column: str, upn: str) -> None:
        slot = self.legacy.setdefault(flow, {"count": 0, "columns": set(), "principals": set()})
        slot["count"] += 1
        slot["columns"].add(column)
        if upn:
            slot["principals"].add(upn)

    def add(self, row: dict) -> None:
        self.rows += 1
        when = col(row, "Date (UTC)")
        if when:
            if not self.first or when < self.first:
                self.first = when
            if when > self.last:
                self.last = when
        upn = col(row, "Username").lower()
        status = col(row, "Status") or "(unrecorded)"
        self.statuses[status] = self.statuses.get(status, 0) + 1
        policy = col(row, "Conditional Access") or "(unrecorded)"
        self.policy_states[policy] = self.policy_states.get(policy, 0) + 1
        requirement = col(row, "Authentication requirement") or "(unrecorded)"
        self.auth_requirements[requirement] = self.auth_requirements.get(requirement, 0) + 1
        succeeded = status.lower() == "success"
        single = requirement.lower() == SINGLE_FACTOR
        not_applied = policy.lower() == "not applied"
        # Only an explicit "true" is compliant; a blank is a device the
        # platform has no verdict on, counted with the not compliant.
        noncompliant = col(row, "Compliant").lower() != "true"
        if noncompliant:
            self.noncompliant += 1
        # A failed or interrupted attempt is not a sign-in that completed:
        # Microsoft records singleFactorAuthentication for an attempt whose
        # primary authentication failed before a second factor could be asked
        # for (see SINGLE_FACTOR).
        if succeeded and single:
            self.single_factor_successes += 1

        protocol = col(row, "Authentication Protocol").lower()
        if protocol in LEGACY_FLOWS:
            self._legacy(protocol, "Authentication Protocol", upn)
        client = col(row, "Client app") or "(unrecorded)"
        cslot = self.client_apps.setdefault(client, {"count": 0, "principals": set()})
        cslot["count"] += 1
        if upn:
            cslot["principals"].add(upn)
        transfer = col(row, "Original transfer method").lower()
        if transfer in LEGACY_TRANSFERS:
            self._legacy(LEGACY_TRANSFERS[transfer], "Original transfer method", upn)

        app = col(row, "Application") or "(unnamed application)"
        aslot = self.by_app.setdefault(app, {"signins": 0, "policy_not_applied": 0,
                                             "noncompliant": 0, "single_factor": 0,
                                             "principals": set()})
        aslot["signins"] += 1
        aslot["policy_not_applied"] += not_applied
        aslot["noncompliant"] += noncompliant
        aslot["single_factor"] += single
        if upn:
            aslot["principals"].add(upn)
        if not upn:
            return
        self.principals.add(upn)
        if upn not in self._holders and admin_shaped(upn, self._names):
            self.admin_shaped.add(upn)
        p = self.by_principal.setdefault(upn, {"attempts": 0, "signins": 0, "single_factor": 0,
                                               "noncompliant": 0, "policy_not_applied": 0,
                                               "last": "", "failures": 0})
        p["attempts"] += 1
        p["failures"] += not succeeded
        if succeeded:
            p["signins"] += 1
            p["single_factor"] += single
            p["noncompliant"] += noncompliant
            p["policy_not_applied"] += not_applied
        if when > p["last"]:
            p["last"] = when


def row_key(row: dict) -> int:
    """A sign-in's identity across two downloads of overlapping periods.

    The request ID alone is not enough: one sign-in can write an interrupted
    and a completed row under the same request, so the time, status, error
    code and correlation ID go with it.
    """
    return hash((col(row, "Request ID"), col(row, "Date (UTC)"), col(row, "Status"),
                 col(row, "Sign-in error code"), col(row, "Correlation ID")))


def read(paths: list[Path], roster: Roster | None,
         names: dict[str, tuple[str, ...]] = ADMIN_NAMES) -> tuple[Tally | None, str]:
    """One tally over every existing file. A row held by an earlier file is counted once;
    a row repeated inside one file is counted as it stands. (None, reason) on a read
    error, since a partial tally would look like an answer."""
    present = [p for p in paths if p.exists()]
    if not present:
        return None, ""
    tally = Tally(roster, names)
    earlier: set[int] = set()
    try:
        for path in present:
            mine: set[int] = set()
            rows, first, last = 0, "", ""
            for row in _entra.stream(path):
                rows += 1
                when = col(row, "Date (UTC)")
                if when and (not first or when < first):
                    first = when
                if when > last:
                    last = when
                key = row_key(row)
                mine.add(key)
                if key in earlier:
                    tally.duplicates += 1
                    continue
                tally.add(row)
            tally.files.append((path.name, rows, first, last))
            earlier |= mine
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return None, str(exc)
    return (tally, "") if tally.rows else (None, "")


def ceiling_rows(tally: Tally) -> int:
    """The row limit the earliest file stopped on, or 0."""
    dated = [f for f in tally.files if f[2]]
    if not dated:
        return tally.rows if _entra.is_ceiling(tally.rows) else 0
    earliest = min(dated, key=lambda f: f[2])
    return earliest[1] if _entra.is_ceiling(earliest[1]) else 0


def holes(tally: Tally) -> list[tuple[str, str]]:
    """Stretches between the merged files that no file covers, as (covered to, covered from)."""
    dated = sorted((f for f in tally.files if f[2]), key=lambda f: f[2])
    out: list[tuple[str, str]] = []
    reach = ""
    for _name, _rows, first, last in dated:
        if reach and first > reach:
            out.append((reach, first))
        reach = max(reach, last)
    return out


def split_long_app_name(name: str) -> list[str] | None:
    """The underscore-separated parts of an application name holding a token-long run, or None."""
    if not _TOKEN_RUN.search(name) or "_" not in name:
        return None
    parts = name.split("_")
    if any(_TOKEN_RUN.search(p) for p in parts) or not all(parts):
        return None
    return parts


class _Out:
    """What every row of one run shares."""

    def __init__(self, source_name: str, when: str, first: str, last: str,
                 ceiling: bool) -> None:
        self.source_name, self.when = source_name, when
        self.first, self.last, self.ceiling = first, last, ceiling
        self.period = _entra.span_days(first, last, ceiling)

    def window(self) -> dict[str, str]:
        return {"window": f"{self.first}..{self.last}",
                "window_is_ceiling": "yes" if self.ceiling else "no"}

    def row(self, **kw: object) -> CryptoAsset:
        return CryptoAsset(data_state="identity", source=NAME, source_class="private",
                           source_name=self.source_name, collected_at=self.when,
                           **kw)  # type: ignore[arg-type]


def role_rows(roster: Roster, tally: Tally, out: _Out) -> list[CryptoAsset]:
    """One row per role with a named holder, and one for the roles with none."""
    rows: list[CryptoAsset] = []
    unmeasurable: list[tuple[str, int]] = []
    for role, holders in sorted(roster.by_role.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        unnamed = roster.unnamed_by_role.get(role, 0)
        if not holders:
            unmeasurable.append((role, unnamed))
            continue
        used = {u for u in holders if tally.by_principal.get(u, {}).get("signins")}
        unused = holders - used
        failed_only = {u for u in unused if u in tally.by_principal}
        failed = sum(tally.by_principal[u]["failures"] for u in holders if u in tally.by_principal)
        single = sum(tally.by_principal[u]["single_factor"] for u in used)
        signins = sum(tally.by_principal[u]["signins"] for u in used)
        noncompliant = sum(tally.by_principal[u]["noncompliant"] for u in used)
        not_applied = sum(tally.by_principal[u]["policy_not_applied"] for u in used)
        emergency = break_glass(unused, role)
        flags = [f"{USED_FLAG}{len(used)}"]
        if unused:
            flags.append(f"{UNUSED_FLAG}{len(unused)}")
        if single:
            flags.append(f"{SINGLE_FACTOR_FLAG}{single}")
        if noncompliant:
            flags.append(f"{NONCOMPLIANT_FLAG}{noncompliant}")
        if emergency:
            flags.append(f"{BREAK_GLASS_FLAG}{len(emergency)}")
        if unnamed:
            flags.append(f"{UNMATCHABLE_FLAG}{unnamed}")
        total = len(holders) + unnamed
        if unused:
            seen = (f"{len(unused)} have no successful sign-in {out.period}"
                    + ("; since the record was cut short, that cannot be told apart from a "
                       "holder who last signed in just before it begins" if out.ceiling else ""))
        else:
            seen = f"every holder with a sign-in name signed in {out.period}"
        notes = (f"{total} account(s) or group(s) hold this role. {len(used)} signed in "
                 f"({signins:,} successful sign-in(s)), and {seen}."
                 + (f" {len(failed_only)} of those only failed or were interrupted when "
                    "signing in, which is not use of the role." if failed_only else "")
                 + (f" Holders' failed or interrupted attempts, not counted as sign-ins: "
                    f"{failed:,}." if failed else "")
                 + (f" {len(emergency)} of the holders with no sign-in are emergency accounts, "
                    "which are meant to stay unused." if emergency else "")
                 + (f" {single:,} of the successful sign-ins completed on a single factor."
                    if single else
                    " Every successful sign-in by a holder asked for a second factor.")
                 + (f" {noncompliant:,} came from a device not recorded as compliant."
                    if noncompliant else "")
                 + (f" {not_applied:,} had no Conditional Access policy in scope."
                    if not_applied else "")
                 + (f" {unnamed} holder(s) are groups or service principals, which have no "
                    "sign-in name, so their use is not measured here." if unnamed else "")
                 + f" {EVIDENCE_LIMIT}.")
        rows.append(out.row(
            name=f"{role} — assignment usage", protocol="account",
            role=roles.signin_assignment_usage(total),
            verdict="weak" if single else "unknown", flags=flags,
            hosts_count=total, usage_count=signins, notes=notes,
            extra={"role": role, "holders": str(total),
                   "holders_with_signin_name": str(len(holders)),
                   "holders_seen": str(len(used)), "holders_not_seen": str(len(unused)),
                   "holders_not_seen_emergency": str(len(emergency)),
                   "holders_without_signin_name": str(unnamed),
                   "signins": str(signins), "single_factor_signins": str(single),
                   "noncompliant_device_signins": str(noncompliant),
                   "policy_not_applied_signins": str(not_applied), **out.window()}))
    if unmeasurable:
        principals = sum(n for _, n in unmeasurable)
        names = ", ".join(r for r, _ in sorted(unmeasurable))
        rows.append(out.row(
            name="Administrative powers whose use cannot be measured here", protocol="account",
            role=roles.signin_unmeasurable(len(unmeasurable)), verdict="unknown",
            flags=[f"{UNMATCHABLE_FLAG}{principals}"], hosts_count=principals,
            notes=(f"{len(unmeasurable)} role(s) are held only by groups or service principals "
                   f"({principals} assignment(s)). None of those holders has a sign-in name, so "
                   "whether the roles are used is not measured here. They share one row so the "
                   "roles that can be measured are not lost among them, and they are listed "
                   f"so none reads as unheld: {names}. {EVIDENCE_LIMIT}."),
            extra={"roles": str(len(unmeasurable)), "assignments": str(principals),
                   "role_names": names, "window": f"{out.first}..{out.last}",
                   "window_is_ceiling": "yes" if out.ceiling else "no"}))
    return rows


def application_rows(tally: Tally, out: _Out, min_rows: float, min_share: float,
                     share_floor: float) -> list[CryptoAsset]:
    """One row per application with enough sign-ins outside every policy."""
    rows: list[CryptoAsset] = []
    total_gap = sum(a["policy_not_applied"] for a in tally.by_app.values())
    for name, slot in sorted(tally.by_app.items(),
                             key=lambda kv: (-kv[1]["policy_not_applied"], kv[0])):
        gap = slot["policy_not_applied"]
        if not gap:
            continue
        share = gap / slot["signins"] if slot["signins"] else 0.0
        if not (gap >= min_rows or (share >= min_share and gap >= share_floor)):
            continue
        of_all = gap / total_gap if total_gap else 0.0
        parts = split_long_app_name(name)
        label = " ".join(parts) if parts else name
        exact = ({f"application_part_{i}": p for i, p in enumerate(parts, 1)}
                 | {"application_joined_by": "_"}) if parts else {"application": name}
        rows.append(out.row(
            name=f"{label} — sign-ins outside access policy", protocol="access-policy",
            role=roles.signin_policy_coverage(gap), software=label, verdict="unknown",
            flags=[f"{POLICY_GAP_FLAG}{gap}"], hosts_count=len(slot["principals"]),
            usage_count=slot["signins"],
            notes=(f"{gap:,} of {slot['signins']:,} sign-in attempt(s) to this application "
                   f"{out.period}, successful or not, had no Conditional Access policy in "
                   f"scope: {share:.1%} of its attempts and {of_all:.1%} of all such attempts "
                   f"read, by {len(slot['principals'])} account(s). {NOT_APPLIED_MEANS}, and "
                   "Microsoft notes that an interrupted attempt can show no policy applied. "
                   "The question it raises is whether the policies should be extended to this "
                   "application."),
            extra={**exact, "signins": str(slot["signins"]), "policy_not_applied": str(gap),
                   "share_of_application": f"{share:.1%}",
                   "share_of_all_uncovered": f"{of_all:.1%}",
                   "accounts": str(len(slot["principals"])),
                   "noncompliant_device_signins": str(slot["noncompliant"]), **out.window()}))
    return rows


def legacy_flow_rows(tally: Tally, out: _Out) -> list[CryptoAsset]:
    """One row per legacy authentication flow seen."""
    rows: list[CryptoAsset] = []
    for flow, slot in sorted(tally.legacy.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        share = slot["count"] / tally.rows if tally.rows else 0.0
        columns = ", ".join(sorted(slot["columns"]))
        rows.append(out.row(
            name=f"{flow} — legacy authentication flow", protocol="authentication-flow",
            role=roles.legacy_signin_flow(slot["count"]), software=flow, verdict="weak",
            flags=[f"{LEGACY_FLOW_FLAG}{flow}:{slot['count']}"],
            hosts_count=len(slot["principals"]), usage_count=slot["count"],
            notes=(f"{slot['count']:,} sign-in(s) {out.period} used this flow ({share:.3%} of "
                   f"those read), by {len(slot['principals'])} account(s). It is weak because "
                   f"{LEGACY_FLOWS[flow]}. A small count is reported too: it shows how little "
                   f"the flow is used. Seen in the {' and '.join(sorted(slot['columns']))} "
                   "column(s)."),
            extra={"flow": flow, "signins": str(slot["count"]),
                   "accounts": str(len(slot["principals"])),
                   "share_of_export": f"{share:.3%}", "columns": columns, **out.window()}))
    return rows


def unmatched_names_row(tally: Tally, out: _Out) -> CryptoAsset | None:
    """The accounts named like administrators that hold no role in the roster, or None."""
    if not tally.admin_shaped:
        return None
    signins = sum(tally.by_principal[u]["attempts"] for u in tally.admin_shaped)
    n = len(tally.admin_shaped)
    return out.row(
        name="Administratively-named accounts with no recorded entitlement", protocol="account",
        role=roles.signin_unmatched_names(n), verdict="unknown",
        flags=[f"{UNMATCHED_SHAPE_FLAG}{n}"], hosts_count=n, usage_count=signins,
        notes=(f"{n} account(s) named like administrator accounts appear in {signins:,} "
               f"sign-in attempt(s) {out.period}, successful or not, and none holds a "
               "directory role in the roster read. "
               "Either they hold roles granted elsewhere (Azure resource roles, Intune roles "
               "and per-application administrator roles are each granted outside the "
               "directory's role list), or they are only named like administrators. This "
               "export cannot tell which. Only counts are given, and nothing here says the "
               "accounts are privileged."),
        extra={"accounts": str(n), "signins": str(signins),
               "window": f"{out.first}..{out.last}",
               "window_is_ceiling": "yes" if out.ceiling else "no"})


def _exports(ctx: Context) -> list[Path]:
    found: list[Path] = [ctx.input] if ctx.input is not None else []
    for p in _entra.paths(ctx, "also"):
        if p not in found:
            found.append(p)
    return found


def step(ctx: Context) -> StepResult:
    """The plug-in's step."""
    exports = _exports(ctx)
    roster, roster_unreadable = read_roster(_entra.paths(ctx, "roles"))
    names = _admin_names(ctx)
    tally, unreadable = read(exports, roster, names)
    if tally is None:
        why = ("no input was given" if not exports else
               f"{exports[0].name} could not be read ({unreadable})" if unreadable else
               "the files named hold no rows")
        return StepResult(gaps=[_no_signins(why)])

    held = [p for p in exports if p.exists()]
    dates = sorted(d for d in (file_mtime_date(p) for p in held) if d)
    when = dates[-1] if dates else ""
    if len(held) > 1:
        source_name = (f"Microsoft Entra interactive sign-in logs, {len(held)} files merged, "
                       f"dated {', '.join(dates) if dates else 'unavailable'}")
    else:
        source_name = ("Microsoft Entra interactive sign-in log, "
                       + (f"file dated {when}" if when else "file date unavailable"))
    first, last = tally.first[:10], tally.last[:10]
    cut = ceiling_rows(tally)
    ceiling = bool(cut)
    gaps_between = holes(tally)
    out = _Out(source_name, when, first, last, ceiling)
    settings = ctx.settings or {}

    assets: list[CryptoAsset] = []
    if roster is not None:
        assets += role_rows(roster, tally, out)
    assets += application_rows(
        tally, out,
        _entra.setting_number(ctx, "policy_gap_min_rows", POLICY_GAP_MIN_ROWS),
        _entra.setting_number(ctx, "policy_gap_min_share", POLICY_GAP_MIN_SHARE),
        _entra.setting_number(ctx, "policy_gap_share_floor", POLICY_GAP_SHARE_FLOOR))
    assets += legacy_flow_rows(tally, out)
    unmatched = unmatched_names_row(tally, out)
    if unmatched is not None:
        assets.append(unmatched)
    assets.append(_entra.legacy_client_row(
        tally.client_apps, tally.rows, source=NAME, source_name=source_name,
        collected_at=when, period=out.period, population="interactive sign-ins",
        limit=EVIDENCE_LIMIT, window=f"{first}..{last}", ceiling=ceiling))
    assets.append(_scope_row(tally, roster, out, cut, gaps_between))

    gaps: list[str] = []
    if roster is None:
        gaps.append(_no_roster(roster_unreadable, bool(settings.get("roles"))))
    if ceiling:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"how long a directory role has gone unused before {first}: the earliest "
            f"sign-in log read holds exactly {cut:,} rows, a download limit, so it may not "
            "reach back as far as the period asked for, and nothing earlier was read",
            impact=("Unused is stated for the period read and no further. A role last used "
                    "just before it began looks the same here as one unused for a year, and "
                    "those call for different decisions."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest=("Download the log in periods short enough to stay under the limit, or "
                     "filtered to the role holders' accounts, and name the files under "
                     "settings: also.")))
    if tally.admin_shaped:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"administrator roles granted outside the directory's role list: "
            f"{len(tally.admin_shaped)} account(s) named like administrator accounts signed "
            "in and hold no directory role in the roster read. Azure resource roles, Intune "
            "roles and per-application administrator roles are granted elsewhere, and none of "
            "them is read here",
            impact=("The number of privileged accounts may be larger than the directory roles "
                    "show, by an amount not known here; a count of directory administrators "
                    "is not a count of all administrators."),
            impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
            harvest=("Export the Azure role assignments at subscription and management group "
                     "scope and the Intune administrator role assignments, and read them "
                     "beside the directory roster.")))
    return StepResult(records=assets, gaps=gaps)


def _scope_row(tally: Tally, roster: Roster | None, out: _Out, cut: int,
               gaps_between: list[tuple[str, str]]) -> CryptoAsset:
    not_applied = tally.policy_states.get("Not Applied", 0)
    single = tally.single_factor_successes
    unmatchable = sum(roster.unmatchable.values()) if roster else 0
    first, last, ceiling = out.first, out.last, out.ceiling
    flags = ([f"{SCOPE_WINDOW_FLAG}{first or '?'}..{last or '?'}",
              f"{SCOPE_CEILING_FLAG}{cut}" if ceiling else f"{SCOPE_SPAN_FLAG}{tally.rows}"]
             + ([f"{SCOPE_FILES_FLAG}{len(tally.files)}"] if len(tally.files) > 1 else [])
             + [f"{SCOPE_HOLE_FLAG}{a[:10]}..{b[:10]}" for a, b in gaps_between]
             + ([f"{UNMATCHABLE_FLAG}{unmatchable}"] if roster and roster.unmatchable else []))
    notes = (f"{tally.rows:,} interactive sign-in(s) by {len(tally.principals)} account(s), "
             f"{out.period}. "
             + (f"{len(tally.files)} files of overlapping periods were merged; "
                f"{tally.duplicates:,} sign-in(s) held by more than one were counted once. "
                if len(tally.files) > 1 else "")
             + "".join(f"No file covers {a[:10]} to {b[:10]}, so nothing here describes that "
                       "stretch. " for a, b in gaps_between)
             + (f"The earliest file holds exactly {cut:,} rows, a download limit: rows before "
                f"{first} were not read, and how far back the period asked for went is not "
                "known. " if ceiling else
                "The row count is not a download limit, so this is the whole period "
                "downloaded. ")
             + f"{not_applied:,} sign-in attempt(s), successful or not, had no Conditional "
               f"Access policy in scope, and {single:,} successful sign-in(s) completed on a "
               "single factor; the application rows above count attempts, and the role rows "
               "successful sign-ins only. "
               f"{tally.noncompliant:,} came from a device not recorded as compliant. "
             + (f"{unmatchable} role holder(s) are groups or service principals, which have no "
                "sign-in name and are not measured here. " if roster and roster.unmatchable
                else "")
             + f"{EVIDENCE_LIMIT}.")
    return CryptoAsset(
        name="Sign-in evidence scope", data_state="discovery", protocol="inventory",
        role=roles.signin_scope(), source=NAME, source_class="private",
        source_name=out.source_name, collected_at=out.when, verdict="n/a", flags=flags,
        hosts_count=len(tally.principals), usage_count=tally.rows, notes=notes,
        extra={"signins": str(tally.rows), "accounts": str(len(tally.principals)),
               "exports_merged": str(len(tally.files)),
               "rows_held_by_two_exports": str(tally.duplicates),
               "uncovered_stretches": "; ".join(
                   f"{a[:10]}..{b[:10]}" for a, b in gaps_between) or "none",
               "window_first": first, "window_last": last,
               "window_is_ceiling": "yes" if ceiling else "no",
               "policy_not_applied": str(not_applied), "single_factor": str(single),
               "noncompliant_device_signins": str(tally.noncompliant),
               "entitlement_roster": "read" if roster else "not supplied",
               "unmatchable_principals": str(unmatchable),
               **{f"status_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in tally.statuses.items()},
               **{f"policy_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in tally.policy_states.items()}})


def _no_signins(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no Microsoft Entra interactive sign-in log was read: {why}. Without it, whether "
        "each directory role assignment was used, whether those sign-ins asked for a second "
        "factor, and which applications were reached with no Conditional Access policy in "
        "scope are not known",
        impact=("Who holds each role can be listed, but not whether anyone uses it, so no "
                "unused assignment can be shown to be safe to remove."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
        harvest=("Download the interactive sign-in log as CSV for the longest period the "
                 "admin centre allows and name it as the reader's input, with the role "
                 "assignment exports under settings: roles."))


def _no_roster(unreadable: str, named: bool) -> str:
    why = (f"a role assignment export could not be read ({unreadable})" if unreadable else
           "the files named under settings: roles hold no rows or do not exist" if named else
           "none was named under settings: roles")
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no directory role assignment export was read beside the sign-in log: {why}. An "
        "account that never signs in writes no sign-in rows, so without the list of who "
        "holds each role, unused assignments cannot be found",
        impact=("Read alone, the sign-in log describes the accounts that did sign in, which "
                "is the opposite of the accounts the question is about."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
        harvest=("Export the active and eligible directory role assignments as CSV and name "
                 "both under settings: roles."))


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Microsoft Entra interactive sign-in log", gap_prefix=False)
