"""Microsoft Entra audit log: how directory roles were granted and removed, and failing jobs.

**The input** is the audit log the Microsoft Entra admin centre downloads as
CSV (Monitoring & health → Audit logs → Download), one row per change, with
the columns the download writes (``Date (UTC)``, ``Category``, ``Service``,
``Activity``, ``Result``, ``ResultReason``, the actor columns, and up to
three targets, each with ``Target<n>Type``, ``Target<n>DisplayName``,
``Target<n>UserPrincipalName`` and its modified properties). A second
download filtered to the ``RoleManagement`` category is named with
``settings: {role_changes: ...}`` (a path or a pattern; the last match in
name order is read).

An unfiltered download can be dominated by routine traffic, such as account
provisioning, so at its row limit (250,000) its role changes may cover only
a short period.
Filtered to role management, the same limit holds a much longer history.
When the filtered download is read it is the only source of role history:
the unfiltered download's role rows are then counted in its totals and not
read again, so no change is counted twice. The unfiltered download still
supplies the failing jobs, which the filter removes.

**Rows.**

* One per directory role that changed, ``<role> — privilege activation
  history``. Each change is read as what happened: a role activated on demand
  through Privileged Identity Management (PIM), granted with no end date,
  granted for a fixed period, made eligible, or removed
  (:data:`ACTIVATION_ACTS`, from Microsoft's audit activity names). The
  directory also records a PIM activation as "Add member to role" written by
  the PIM service; such a row is counted as the activation's other half,
  never as a standing grant. ``weak`` where a role was granted with no end
  date; otherwise ``unknown``.
* One per repeating failure, ``<service> · <activity> — repeating failure``:
  failures grouped by service, activity and the shape of the failure message
  (quoted names, email addresses, identifiers, times and numbers replaced). A
  group earns a row at
  ``settings: {failure_min_rows: ...}`` rows (default
  :data:`FAILURE_MIN_ROWS`). It is ``weak`` when it names the people or
  objects it is holding up, or makes up at least ``failure_material_share``
  of the download (default :data:`FAILURE_MATERIAL_SHARE`); otherwise
  ``unknown``.
* A scope row per download: the period, whether it is a ceiling, and how
  much of it is about roles.

A role is read from either side of the platform: a target of type ``Role``,
or the modified property ``Role.DisplayName``, whose new value is empty on a
removal, so the old value is read too.

**Cannot see.** Changes made through a path the directory does not audit or
before the first row read; whether anyone is alerted on a failing job. The
people affected are counted, and the grouped failure message written in a
row's notes has quoted names and email addresses replaced; a name written in
a message any other way is not replaced.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from ._entra import col

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "entra_audit"

# A failure message can be long; the limit is raised so a long one is read,
# not an error part way through a file.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

ACTIVATION_FLAG = "dirlog-role-activated:"
STANDING_FLAG = "dirlog-role-granted-standing:"
REVOCATION_FLAG = "dirlog-role-revoked:"
ACTORS_FLAG = "dirlog-role-actors:"
AUTOMATION_FAIL_FLAG = "dirlog-automation-failing:"
AUTOMATION_SUBJECTS_FLAG = "dirlog-automation-affected:"
AUTOMATION_ONSET_FLAG = "dirlog-automation-onset-unobserved"
PRIVILEGE_SHARE_FLAG = "dirlog-privilege-share:"
SCOPE_WINDOW_FLAG = "dirlog-scope-window:"
SCOPE_CEILING_FLAG = "dirlog-scope-ceiling:"
SCOPE_SPAN_FLAG = "dirlog-scope-span:"

ROLE_CATEGORY = "rolemanagement"

#: Microsoft's audit activity names for role changes (lower case), and what
#: each records. A name not listed is counted as ``other`` and named in a
#: gap, never guessed into a class. The ``(permanent)`` and ``(timebound)``
#: suffixes are the assignment durations PIM offers: a permanent assignment
#: has no end date, a time-bound one ends at a set time (*Assign Microsoft
#: Entra roles in Privileged Identity Management*, learn.microsoft.com).
#: ``request-step`` marks requests, approvals, cancellations and lapsed
#: requests, counted apart so a request and the change it asked for are not
#: both counted as changes.
ACTIVATION_ACTS: dict[str, str] = {
    "add member to role completed (pim activation)": "activated",
    "add member to role requested (pim activation)": "requested",
    "add member to role": "granted",
    "add eligible member to role": "made-eligible",
    "add permanent eligible role assignment": "made-eligible",
    "remove member from role (pim activation expired)": "expired",
    "remove member from role completed (pim deactivate)": "deactivated",
    "remove member from role requested (pim deactivate)": "deactivate-requested",
    "remove member from role": "revoked",
    "remove eligible member from role": "eligibility-removed",
    "remove permanent eligible role assignment": "eligibility-removed",
    "add member to role in pim completed (permanent)": "granted",
    "add member to role in pim completed (timebound)": "granted-timebound",
    "add eligible member to role in pim completed (permanent)": "made-eligible",
    "add eligible member to role in pim completed (timebound)": "made-eligible",
    "remove member from role in pim completed (permanent)": "revoked",
    "add member to role in pim requested (permanent)": "request-step",
    "add member to role in pim requested (timebound)": "request-step",
    "add eligible member to role in pim requested (permanent)": "request-step",
    "add eligible member to role in pim requested (timebound)": "request-step",
    "remove member from role in pim requested (permanent)": "request-step",
    "add member to role approval requested (pim activation)": "request-step",
    "add member to role request approved (pim activation)": "request-step",
    "add member to role canceled (pim activation)": "request-step",
    "pim activation request expired": "request-step",
}

#: Actor names that mark a row written by the PIM service itself, matched whole and
#: ignoring case: the names the service appears under as an actor (its service principal
#: name, ``MS-PIM``, and display names ``Azure AD PIM`` and ``Privileged Identity
#: Management``). A person whose name merely contains "pim" is not the service.
PIM_ACTOR_NAMES = frozenset({"ms-pim", "azure ad pim", "privileged identity management"})

#: What varies inside one failure message, replaced in this order (the quoted
#: subject first, so the identifier patterns cannot take part of it).
_VARYING: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"'[^']*'"), "'…'"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "…@…"),
    (re.compile(r"(?i)identifier:\s*\S+"), "Identifier: …"),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
     "…"),
    (re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.+Z-]+"), "…"),
    (re.compile(r"\b\d+\b"), "N"),
)
#: Where the platform's own message ends and the far system's error detail
#: begins. The detail differs from one attempt to the next, and can carry the
#: name of the person or object concerned, so it is cut off before grouping.
_FAR_DETAIL = re.compile(r"[;.]?\s*Error:\s.*$", re.DOTALL)
#: How much of a normalised message forms the group.
_FAMILY_CHARS = 160
_SUBJECT = re.compile(r"'([^']+)'|(?i:identifier:)\s*(\S+)")

#: Defaults for a repeating failure: the rows it needs for a row of its own,
#: and the share of the download that makes it ``weak`` without named
#: subjects. Three rows of one shape is a repeat rather than an event and its
#: retry; one row in a hundred is a share of the log nobody would call
#: incidental. Each is a setting.
FAILURE_MIN_ROWS = 3
FAILURE_MATERIAL_SHARE = 0.01

EVIDENCE_LIMIT = ("This is what the directory recorded. A change made through a path the "
                  "directory does not audit, or before the first row read, leaves no row, so "
                  "an absence here is not evidence that nothing happened")


def role_of(row: dict) -> str:
    """The role a row is about: a ``Role`` target's name, else ``Role.DisplayName``'s new
    or old value."""
    for n in ("1", "2", "3"):
        if col(row, f"Target{n}Type") == "Role":
            name = col(row, f"Target{n}DisplayName")
            if name:
                return name
    for n in ("1", "2", "3"):
        for i in range(1, 6):
            if col(row, f"Target{n}ModifiedProperty{i}Name") == "Role.DisplayName":
                for half in ("NewValue", "OldValue"):
                    value = col(row, f"Target{n}ModifiedProperty{i}{half}")
                    if value:
                        return value.strip('"')
    return ""


def _actor(row: dict) -> str:
    return (col(row, "ActorUserPrincipalName") or col(row, "ActorServicePrincipalName")
            or col(row, "ActorDisplayName"))


def is_pim_actor(row: dict) -> bool:
    """Whether the PIM service wrote the row."""
    return any(col(row, c).strip().lower() in PIM_ACTOR_NAMES
               for c in ("ActorDisplayName", "ActorServicePrincipalName"))


def family(service: str, activity: str, reason: str) -> str:
    """The group a failure belongs to: service, activity and the message's shape."""
    text = " ".join((reason or "").split())
    text = _FAR_DETAIL.sub("", text)
    for pattern, replacement in _VARYING:
        text = pattern.sub(replacement, text)
    return f"{service} · {activity} · {text[:_FAMILY_CHARS]}".strip(" ·")


def subject_of(reason: str) -> str:
    """The person or object one failure concerns, for counting; "" when none is named."""
    match = _SUBJECT.search(reason or "")
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").lower().rstrip(";,")


class Tally:
    """The totals one pass over a download keeps."""

    def __init__(self, skip_roles: bool = False) -> None:
        #: When a filtered download is read beside this one, role rows here are
        #: only counted.
        self.skip_roles = skip_roles
        self.rows = 0
        self.first = ""
        self.last = ""
        self.categories: dict[str, int] = {}
        self.services: dict[str, int] = {}
        self.results: dict[str, int] = {}
        self.role_rows = 0
        self.failures = 0
        self.roles: dict[str, dict] = {}
        self.families: dict[str, dict] = {}
        self.unmapped_acts: dict[str, int] = {}

    def add(self, row: dict) -> None:
        self.rows += 1
        when = col(row, "Date (UTC)")
        if when:
            if not self.first or when < self.first:
                self.first = when
            if when > self.last:
                self.last = when
        category = col(row, "Category") or "(unrecorded)"
        self.categories[category] = self.categories.get(category, 0) + 1
        service = col(row, "Service") or "(unrecorded)"
        self.services[service] = self.services.get(service, 0) + 1
        result = col(row, "Result") or "(unrecorded)"
        self.results[result] = self.results.get(result, 0) + 1
        activity = col(row, "Activity")
        if self.skip_roles and category.lower() == ROLE_CATEGORY:
            self.role_rows += 1
            return
        if result.lower() != "success":
            self._failure(row, service, activity, when)
        if category.lower() == ROLE_CATEGORY:
            self._role_change(row, activity, when)

    def _failure(self, row: dict, service: str, activity: str, when: str) -> None:
        self.failures += 1
        key = family(service, activity, col(row, "ResultReason"))
        slot = self.families.setdefault(key, {"rows": 0, "subjects": {}, "first": "",
                                              "last": "", "service": "", "activity": "",
                                              "message": "", "automated": True})
        slot["rows"] += 1
        slot["service"] = service
        slot["activity"] = activity
        # The message's shape, never one instance of it.
        slot["message"] = slot["message"] or key.split(" · ", 2)[-1]
        slot["automated"] = slot["automated"] and col(row, "ActorType").lower() == "application"
        subject = subject_of(col(row, "ResultReason"))
        if subject:
            slot["subjects"][subject] = slot["subjects"].get(subject, 0) + 1
        if not slot["first"] or when < slot["first"]:
            slot["first"] = when
        if when > slot["last"]:
            slot["last"] = when

    def _role_change(self, row: dict, activity: str, when: str) -> None:
        self.role_rows += 1
        role = role_of(row) or "(unnamed administrative power)"
        act = ACTIVATION_ACTS.get(activity.lower(), "")
        if not act:
            self.unmapped_acts[activity] = self.unmapped_acts.get(activity, 0) + 1
            act = "other"
        pim = is_pim_actor(row)
        if act == "granted" and pim:
            act = "activation-recorded-by-directory"
        if act == "revoked" and pim:
            act = "expiry-recorded-by-directory"
        slot = self.roles.setdefault(role, {"acts": {}, "actors": set(), "subjects": set(),
                                            "rows": 0, "first": "", "last": ""})
        slot["rows"] += 1
        slot["acts"][act] = slot["acts"].get(act, 0) + 1
        actor = _actor(row)
        if actor and not pim:
            slot["actors"].add(actor.lower())
        for n in ("1", "2", "3"):
            if col(row, f"Target{n}Type") == "User":
                subject = col(row, f"Target{n}UserPrincipalName") or col(row, f"Target{n}DisplayName")
                if subject:
                    slot["subjects"].add(subject.lower())
        if not slot["first"] or when < slot["first"]:
            slot["first"] = when
        if when > slot["last"]:
            slot["last"] = when


def read(path: Path | None, skip_roles: bool = False) -> tuple[Tally | None, str]:
    """The download's tally; (None, reason) on a read error, (None, "") when absent or empty."""
    if path is None or not path.exists():
        return None, ""
    tally = Tally(skip_roles)
    try:
        for row in _entra.stream(path):
            tally.add(row)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return None, str(exc)
    return (tally, "") if tally.rows else (None, "")


def role_rows(tally: Tally, source_name: str, when: str, first: str, last: str,
              ceiling: bool) -> list[CryptoAsset]:
    """One row per role that changed."""
    out: list[CryptoAsset] = []
    period = _entra.span_days(first, last, ceiling)
    for role, slot in sorted(tally.roles.items(), key=lambda kv: (-kv[1]["rows"], kv[0])):
        acts = slot["acts"]
        activated = acts.get("activated", 0)
        requested = acts.get("requested", 0)
        standing = acts.get("granted", 0)
        eligible = acts.get("made-eligible", 0)
        expired = acts.get("expired", 0)
        removed = acts.get("revoked", 0) + acts.get("eligibility-removed", 0)
        timebound = acts.get("granted-timebound", 0)
        request_steps = acts.get("request-step", 0)
        other = acts.get("other", 0)
        changes = slot["rows"] - request_steps
        flags = [f"{ACTIVATION_FLAG}{activated}", f"{ACTORS_FLAG}{len(slot['actors'])}"]
        if standing:
            flags.append(f"{STANDING_FLAG}{standing}")
        if removed:
            flags.append(f"{REVOCATION_FLAG}{removed}")
        notes = (f"{changes} change(s) to who holds this role {period}, by "
                 f"{len(slot['actors'])} actor(s), to {len(slot['subjects'])} account(s). "
                 + (f"{activated} on-demand activation(s), and {expired} expired on their own"
                    if activated and expired else
                    f"{activated} on-demand activation(s)" if activated else
                    "No on-demand activation")
                 + (f"; {standing} grant(s) with no end date." if standing else
                    "; no grant without an end date.")
                 + (f" {requested} activation request(s)." if requested and requested != activated
                    else "")
                 + (f" {timebound} grant(s) for a fixed period." if timebound else "")
                 + (f" {eligible} account(s) made eligible to activate it." if eligible else "")
                 + (f" {request_steps} request, approval or cancellation step(s), not counted "
                    "as changes." if request_steps else "")
                 + (f" {removed} assignment(s) removed." if removed else "")
                 + (f" {other} change(s) under an activity name not classified here."
                    if other else "")
                 + f" {EVIDENCE_LIMIT}.")
        out.append(CryptoAsset(
            name=f"{role} — privilege activation history", data_state="identity",
            protocol="account", role=roles.privilege_history(activated, standing),
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict="weak" if standing else "unknown", flags=flags,
            hosts_count=len(slot["subjects"]), usage_count=changes, notes=notes,
            extra={"role": role, "changes": str(changes), "activations": str(activated),
                   "activation_requests": str(requested), "standing_grants": str(standing),
                   "timebound_grants": str(timebound), "request_steps": str(request_steps),
                   "made_eligible": str(eligible), "activations_expired": str(expired),
                   "assignments_removed": str(removed), "unclassified_changes": str(other),
                   "actors": str(len(slot["actors"])),
                   "accounts_affected": str(len(slot["subjects"])),
                   "first_change": slot["first"][:19], "last_change": slot["last"][:19],
                   "window": f"{first}..{last}", "window_is_ceiling": "yes" if ceiling else "no"}))
    return out


def failure_rows(tally: Tally, source_name: str, when: str, first: str, last: str,
                 ceiling: bool, min_rows: float, material_share: float) -> list[CryptoAsset]:
    """One row per repeating failure."""
    out: list[CryptoAsset] = []
    period = _entra.span_days(first, last, ceiling)
    for _key, slot in sorted(tally.families.items(), key=lambda kv: (-kv[1]["rows"], kv[0])):
        if slot["rows"] < min_rows:
            continue
        subjects = slot["subjects"]
        counts = sorted(subjects.values())
        median = counts[len(counts) // 2] if counts else 0
        share = slot["rows"] / tally.rows if tally.rows else 0.0
        # A group whose first failure is on the download's first day began
        # before the record, by an unknown amount.
        onset_observed = bool(slot["first"] and first and slot["first"][:10] > first)
        still_failing = bool(slot["last"] and last and slot["last"][:10] >= last)
        flags = [f"{AUTOMATION_FAIL_FLAG}{slot['rows']}"]
        if subjects:
            flags.append(f"{AUTOMATION_SUBJECTS_FLAG}{len(subjects)}")
        if not onset_observed:
            flags.append(AUTOMATION_ONSET_FLAG)
        material = bool(subjects) or share >= material_share
        notes = (f"{slot['rows']:,} failure(s) of the same operation {period}, {share:.1%} of "
                 "the rows read"
                 + (f", for {len(subjects)} person(s) or object(s), each tried a median of "
                    f"{median} time(s)" if subjects else "")
                 + ". "
                 + ("The first of them is on the first day read, so it began before the "
                    "record and how long it has run is not known. " if not onset_observed else
                    f"The first is on {slot['first'][:10]}, inside the period read, so that is "
                    "when it began. ")
                 + ("It was still failing on the last day read. " if still_failing else "")
                 + ("An application is recorded as the actor, so no person is necessarily "
                    "watching it fail. " if slot["automated"] else "")
                 + "Whether anyone is alerted is not in this log. "
                 + (f"The message, with quoted names, email addresses, identifiers and numbers "
                    "replaced: "
                    f"\"{slot['message']}\". " if slot["message"] else "")
                 + f"{EVIDENCE_LIMIT}.")
        out.append(CryptoAsset(
            name=f"{slot['service']} · {slot['activity']} — repeating failure",
            data_state="identity", protocol="provisioning",
            role=roles.failing_automation(len(subjects)), software=slot["service"],
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict="weak" if material else "unknown", flags=flags,
            hosts_count=len(subjects), usage_count=slot["rows"], notes=notes,
            extra={"service": slot["service"], "activity": slot["activity"],
                   "failures": str(slot["rows"]), "subjects_affected": str(len(subjects)),
                   "median_retries_per_subject": str(median), "share_of_export": f"{share:.1%}",
                   "first_failure": slot["first"][:19], "last_failure": slot["last"][:19],
                   "onset_observed": "yes" if onset_observed else "no",
                   "still_failing_at_export": "yes" if still_failing else "no",
                   "actor_is_automated": "yes" if slot["automated"] else "no",
                   "alerting": "not established",
                   "holding_up_named_subjects": "yes" if subjects else "no",
                   "window": f"{first}..{last}", "window_is_ceiling": "yes" if ceiling else "no"}))
    return out


def _source_name(label: str, path: Path) -> tuple[str, str]:
    when = file_mtime_date(path) or ""
    return (f"{label}, " + (f"file dated {when}" if when else "file date unavailable")), when


def role_download_rows(tally: Tally, path: Path) -> list[CryptoAsset]:
    """The role rows and scope row from the download filtered to role management.

    Its failures are assignment requests that did not complete, not a job
    failing, so they are counted on the scope row rather than given rows.
    """
    source_name, when = _source_name(
        "Microsoft Entra audit log, filtered to role management", path)
    first, last = tally.first[:10], tally.last[:10]
    ceiling = _entra.is_ceiling(tally.rows)
    out = role_rows(tally, source_name, when, first, last, ceiling)
    out.append(CryptoAsset(
        name="Role-change record scope", data_state="discovery", protocol="inventory",
        role=roles.audit_scope(), source=NAME, source_class="private", source_name=source_name,
        collected_at=when, verdict="n/a",
        flags=[f"{SCOPE_WINDOW_FLAG}{first or '?'}..{last or '?'}",
               f"{SCOPE_CEILING_FLAG}{tally.rows}" if ceiling else f"{SCOPE_SPAN_FLAG}{tally.rows}",
               f"{PRIVILEGE_SHARE_FLAG}{tally.role_rows}"],
        hosts_count=len(tally.roles), usage_count=tally.rows,
        notes=(f"{tally.rows:,} recorded change(s) to directory role assignments "
               f"{_entra.span_days(first, last, ceiling)}, from a download filtered to role "
               "management. "
               + (f"The row count is exactly {tally.rows:,}, a download limit, so rows before "
                  f"{first} were not read. " if ceiling else
                  "The row count is not a download limit, so this is the whole period "
                  "downloaded, within what the directory retains. ")
               + f"{len(tally.roles)} role(s) changed. {tally.failures:,} row(s) record a "
                 f"failed operation. {EVIDENCE_LIMIT}."),
        extra={"changes": str(tally.rows), "role_changes": str(tally.role_rows),
               "roles_seen": str(len(tally.roles)), "failed_rows": str(tally.failures),
               "window_first": first, "window_last": last,
               "window_is_ceiling": "yes" if ceiling else "no",
               **{f"result_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in tally.results.items()}}))
    return out


def _unmapped_gap(unmapped: dict[str, int]) -> str:
    named = ", ".join(f"{name} ({count})"
                      for name, count in sorted(unmapped.items(), key=lambda kv: -kv[1])[:6])
    return coverage.gap(
        coverage.NOT_MEASURED,
        f"role changes under activity names this reader does not classify: {named}. They are "
        "counted in the totals and left unclassified rather than guessed",
        impact=("The split between roles activated on demand and roles granted with no end "
                "date leaves these changes out, rather than putting them on the wrong side."),
        impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
        harvest=("Find each activity name in Microsoft's audit activity reference and add it "
                 "to ACTIVATION_ACTS in takestock's entra_audit reader."))


def step(ctx: Context) -> StepResult:
    """The plug-in's step."""
    path = ctx.input
    role_path = _entra.newest(ctx, "role_changes")
    min_rows = _entra.setting_number(ctx, "failure_min_rows", FAILURE_MIN_ROWS)
    material = _entra.setting_number(ctx, "failure_material_share", FAILURE_MATERIAL_SHARE)
    assets: list[CryptoAsset] = []
    gaps: list[str] = []

    role_tally, role_unreadable = read(role_path)
    if role_unreadable and role_path is not None:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"the audit log filtered to role management, {role_path.name}, could not be read "
            f"({role_unreadable}); role history comes from the unfiltered download alone",
            impact="The role history covers the unfiltered download's shorter period.",
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest="Download the filtered audit log again and replace the file."))
    tally, unreadable = read(path, skip_roles=role_tally is not None)
    if role_tally is not None:
        assert role_path is not None
        assets += role_download_rows(role_tally, role_path)
    if tally is None:
        why = ("no input was given" if path is None else
               f"{path.name} could not be read ({unreadable})" if unreadable else
               f"{path.name} does not exist" if not path.exists() else
               f"{path.name} holds no rows")
        if role_tally is not None:
            gaps.append(coverage.gap(
                coverage.NOT_COLLECTED,
                f"no unfiltered Microsoft Entra audit log was read ({why}), so whether "
                "automated jobs such as account provisioning are completing is not known; the "
                "download filtered to role management carries none of their rows",
                impact=("A failing joiner, mover and leaver job cannot be seen, so the "
                        "identity lifecycle is described by its role changes alone."),
                impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.NO_DATA,
                harvest=("Download the audit log unfiltered for a recent week and name it as "
                         "the reader's input.")))
            if role_tally.unmapped_acts:
                gaps.append(_unmapped_gap(role_tally.unmapped_acts))
        else:
            gaps.append(coverage.gap(
                coverage.NOT_COLLECTED,
                f"no Microsoft Entra audit log was read: {why}. Without it, which role each "
                "change was to, which account, by whom, and whether a grant had an end date "
                "are not known",
                impact=("Whether roles are activated on demand or granted permanently is not "
                        "known. A list of role holders shows today's state, not how it came "
                        "about, so a grant made last week and one made years ago look the "
                        "same."),
                impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
                harvest=("Download the audit log filtered to the RoleManagement category and "
                         "name it under settings: role_changes, and an unfiltered download as "
                         "the reader's input for failing jobs.")))
        return StepResult(records=assets, gaps=gaps)

    assert path is not None
    source_name, when = _source_name("Microsoft Entra audit log", path)
    first, last = tally.first[:10], tally.last[:10]
    ceiling = _entra.is_ceiling(tally.rows)
    if role_tally is None:
        assets += role_rows(tally, source_name, when, first, last, ceiling)
    assets += failure_rows(tally, source_name, when, first, last, ceiling, min_rows, material)
    assets.append(_scope_row(tally, role_tally is not None, source_name, when, first, last,
                             ceiling))

    share = tally.role_rows / tally.rows if tally.rows else 0.0
    if ceiling and role_tally is None:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"how directory roles were granted before {first}: the audit log read holds "
            f"exactly {tally.rows:,} rows, a download limit, so nothing earlier was read; "
            f"only {share:.2%} of the rows it holds are role changes",
            impact=("The role history covers a short period. A grant with no end date made "
                    "before it began is not seen, so this can show that none was made recently "
                    "and cannot show that none exists."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest=("Download the audit log filtered to the RoleManagement category, which "
                     "holds a much longer history within the same limit, and name it under "
                     "settings: role_changes.")))
    undated = [s for s in tally.families.values()
               if s["rows"] >= min_rows and not (s["first"] and first and s["first"][:10] > first)]
    if undated:
        worst = max(undated, key=lambda s: s["rows"])
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"how long the largest repeating failure has been failing, and whether anyone is "
            f"alerted: its {worst['rows']:,} row(s) begin on the first day read, so it began "
            "before the record, and no alerting configuration is in this log",
            impact=("Whether it is a recent fault or a long-standing one is not known, and "
                    "those call for different responses. A provisioning job that does not "
                    "complete leaves the directory's record of people incomplete."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.NO_DATA,
            harvest=("Read the failing job's own log and its alert settings; the audit log "
                     "records failures, not who was told.")))
    unmapped = dict(tally.unmapped_acts)
    if role_tally is not None:
        for name, count in role_tally.unmapped_acts.items():
            unmapped[name] = unmapped.get(name, 0) + count
    if unmapped:
        gaps.append(_unmapped_gap(unmapped))
    return StepResult(records=assets, gaps=gaps)


def _scope_row(tally: Tally, filtered_read: bool, source_name: str, when: str, first: str,
               last: str, ceiling: bool) -> CryptoAsset:
    share = tally.role_rows / tally.rows if tally.rows else 0.0
    biggest = max(tally.categories.items(), key=lambda kv: kv[1], default=("(none)", 0))
    return CryptoAsset(
        name="Directory change-record scope", data_state="discovery", protocol="inventory",
        role=roles.audit_scope(), source=NAME, source_class="private", source_name=source_name,
        collected_at=when, verdict="n/a",
        flags=[f"{SCOPE_WINDOW_FLAG}{first or '?'}..{last or '?'}",
               f"{SCOPE_CEILING_FLAG}{tally.rows}" if ceiling else f"{SCOPE_SPAN_FLAG}{tally.rows}",
               f"{PRIVILEGE_SHARE_FLAG}{tally.role_rows}"],
        hosts_count=len(tally.roles), usage_count=tally.rows,
        notes=(f"{tally.rows:,} recorded directory change(s) "
               f"{_entra.span_days(first, last, ceiling)}. "
               + (f"The row count is exactly {tally.rows:,}, a download limit, so rows before "
                  f"{first} were not read and how far back the period asked for went is not "
                  "known. " if ceiling else
                  "The row count is not a download limit, so this is the whole period "
                  "downloaded. ")
               + f"{tally.role_rows:,} of the rows ({share:.2%}) are role changes; the largest "
                 f"category is {biggest[0]}, with {biggest[1]:,}. "
               + ("Most of the row limit went on other traffic, so the role history is short; "
                  "a download filtered to role management holds much more of it. "
                  if ceiling and share < 0.5 and not filtered_read else "")
               + ("Role history is read from the download filtered to role management; the "
                  "role rows here are counted in this total and not read again. "
                  if filtered_read else "")
               + f"{tally.failures:,} row(s) record a failed operation. {EVIDENCE_LIMIT}."),
        extra={"changes": str(tally.rows), "role_changes": str(tally.role_rows),
               "role_change_share": f"{share:.2%}", "roles_seen": str(len(tally.roles)),
               "role_history_source": ("role-management export" if filtered_read
                                       else "this export"),
               "failed_rows": str(tally.failures), "window_first": first, "window_last": last,
               "window_is_ceiling": "yes" if ceiling else "no",
               **{f"category_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in tally.categories.items()},
               **{f"result_{k.lower().replace(' ', '_')}": str(v)
                  for k, v in tally.results.items()}})


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step, title="Microsoft Entra audit log",
                gap_prefix=False)
