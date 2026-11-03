"""CrowdStrike Falcon: the accounts the endpoint sensor has seen, by privilege and credential age.

**The input** (``input:``) is a CSV of accounts the sensor observed, one row
per account, such as the Falcon console's account list exported as CSV. No
public description of that export's headings was found, so the reader's
default headings are plain names of its own and ``settings: columns:
{accounts: {<field>: <heading>}}`` names the export's (a list of headings
reads the first holding a value):

==================  =====================  ======================================
field               default heading        what it holds
==================  =====================  ======================================
``account_type``    ``account_type``       ``Local`` or ``Domain``
``last_logon``      ``last_logon_type``    the logon type of its last successful
                                           sign-in (Microsoft's number or name)
``password_set``    ``password_last_set``  when its password was last set
``admin``           ``admin``              whether it holds administrative
                                           privilege (yes, true or 1)
==================  =====================  ======================================

A ``password_set`` value is read as an ISO 8601 date or time, or by
``settings: date_format:`` (a ``strptime`` format). A blank cell, or one the
format cannot read, is an **unknown** age, never an old one.

**One row per population, never per account**: the finding is a
distribution, and names never reach a row.

* ``Privileged accounts``: ``weak`` when more administrative accounts are
  local than domain accounts, since a local account cannot be reviewed,
  time-limited or disabled from a directory.
* ``Privileged account credential age`` and ``Account credential age (all
  observed accounts)``: each account in one bucket by password age, measured
  at the export's file date: within ``settings: fresh_days`` (default 90),
  within ``stale_days`` (default 365), older, or unknown. ``weak`` when any
  is older; the four counts always add up to the population.
* ``Service accounts`` (accounts whose last sign-in was a service logon):
  ``unknown`` when at least half carry no password date, because this export
  cannot tell an account whose password rotates from one whose password
  never changed.
* ``Account inventory scope`` (``n/a``): these are accounts the sensor saw
  sign in, a sample of the directory and not an enumeration of it.

No row is ever ``strong``: these are populations of accounts, not graded
cryptographic primitives.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_accounts"

FRESH_DAYS = 90
STALE_DAYS = 365
SCOPE_FLAG = "scope-observed-not-enumerated"

#: The export's fields and the headings they are read from unless ``settings: columns:`` names others.
HEADINGS: dict[str, dict[str, Any]] = {
    "accounts": {"account_type": "account_type", "last_logon": "last_logon_type",
                 "password_set": "password_last_set", "admin": "admin"},
}


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon account export was read"
        + (f" ({why})" if why else "")
        + ": where administrative privilege sits among the accounts in use, and how old the "
        "passwords protecting them are",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it there is no measured list of accounts: how accounts should be "
                "managed can be described, but not how many hold administrative privilege, "
                "how many of those are local to one machine, or how many passwords have not "
                "changed in years."),
        harvest=("Export the account list from the Falcon console as CSV, name it with input: "
                 "and name its headings with settings: columns:."),
        nature=coverage.NO_DATA)


def parse_date(raw: str, date_format: str = "") -> date | None:
    """The date a password was set, or None when the cell is blank or cannot be read."""
    text = (raw or "").strip()
    if not text:
        return None
    if date_format:
        try:
            return datetime.strptime(text, date_format).date()
        except ValueError:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def ages(rows: list[dict[str, str]], heads: Mapping[str, Any], today: date, *,
         fresh_days: int = FRESH_DAYS, stale_days: int = STALE_DAYS,
         date_format: str = "") -> dict[str, int]:
    """Each account counted in exactly one bucket: ``fresh``, ``within_year``, ``stale``, ``unknown``.

    ``within_year`` holds the accounts older than ``fresh_days`` and no older
    than ``stale_days``; the name is the default's.
    """
    out = {"fresh": 0, "within_year": 0, "stale": 0, "unknown": 0}
    for r in rows:
        d = parse_date(_fi.value(r, heads["password_set"]), date_format)
        if d is None:
            out["unknown"] += 1
            continue
        age = (today - d).days
        if age <= fresh_days:
            out["fresh"] += 1
        elif age <= stale_days:
            out["within_year"] += 1
        else:
            out["stale"] += 1
    return out


def _age_flags(buckets: Mapping[str, int]) -> list[str]:
    return ([f"password-stale:{buckets['stale']}"] if buckets["stale"] else []) + (
        [f"credential-age-unknown:{buckets['unknown']}"] if buckets["unknown"] else [])


def _age_sentence(buckets: Mapping[str, int], fresh_days: int, stale_days: int) -> str:
    return (f"{buckets['fresh']:,} set within {fresh_days} days, {buckets['within_year']:,} "
            f"within {stale_days} days, {buckets['stale']:,} longer ago, and "
            f"{buckets['unknown']:,} with no date")


def read(path: Path | None, *, headings: Mapping[str, Mapping[str, Any]] | None = None,
         fresh_days: int = FRESH_DAYS, stale_days: int = STALE_DAYS, date_format: str = "",
         today: date | None = None) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows for one account export, or one gap when it holds none."""
    h = (headings or HEADINGS)["accounts"]
    rows, why = _fi.rows(path)
    if not rows:
        return [], [_missing_gap(why or ("the file named holds no rows" if path else ""))]
    when = (file_mtime_date(path) if path else None) or ""
    # Ages are measured at the export's own date, so a file read a month later
    # does not age its passwords by a month the evidence never saw.
    as_of = parse_date(when) or today or date.today()
    base: dict[str, Any] = {"data_state": "identity", "protocol": "account", "source": NAME,
                            "source_class": "private",
                            "source_name": _fi.source_name("account", when),
                            "collected_at": when}

    def kind(r: dict[str, str]) -> str:
        return _fi.value(r, h["account_type"]).lower()

    def last(r: dict[str, str]) -> str:
        return _fi.value(r, h["last_logon"])

    total = len(rows)
    admins = [r for r in rows if _fi.is_yes(_fi.value(r, h["admin"]))]
    local_admins = [r for r in admins if kind(r) == "local"]
    domain_admins = [r for r in admins if kind(r) == "domain"]
    remote_admins = [r for r in admins if "remote" in _fi.squash(last(r))
                     or _fi.logon_type(last(r)) == _fi.REMOTE_INTERACTIVE]
    services = [r for r in rows if _fi.logon_type(last(r)) == _fi.SERVICE]
    def bucket(of: list[dict[str, str]]) -> dict[str, int]:
        return ages(of, h, as_of, fresh_days=fresh_days, stale_days=stale_days,
                    date_format=date_format)

    admin_ages, all_ages, service_ages = bucket(admins), bucket(rows), bucket(services)

    def row(name: str, role: str, verdict: str, flags: list[str], count: int, notes: str,
            extra: dict[str, str]) -> CryptoAsset:
        return CryptoAsset(name=name, role=role, verdict=verdict, flags=flags,
                           hosts_count=count, notes=notes,
                           extra={"accounts": str(count), "population": str(total), **extra},
                           **base)

    out: list[CryptoAsset] = []

    # ── where administrative privilege sits ──
    outside = bool(local_admins) and len(local_admins) > len(domain_admins)
    flags = [f"privileged-accounts:{len(admins)}"]
    if outside:
        flags.append(f"privilege-outside-directory:{len(local_admins)}")
    if remote_admins:
        flags.append(f"admin-remote-interactive:{len(remote_admins)}")
    share = (len(local_admins) / len(admins)) if admins else 0.0
    out.append(row(
        "Privileged accounts", roles.account_population("administrative privilege"),
        "weak" if outside else "acceptable", flags, len(admins),
        (f"{len(admins):,} of {total:,} observed accounts hold administrative privilege. "
         f"{len(local_admins):,} of them are local accounts and {len(domain_admins):,} domain "
         "accounts. A local account cannot be reviewed, time-limited or disabled from the "
         "directory, so "
         + ("most administrative privilege here sits outside it. " if outside else
            "the directory holds most administrative privilege here. ")
         + f"{len(remote_admins):,} of them last signed in by a remote interactive logon."),
        {"local": str(len(local_admins)), "domain": str(len(domain_admins)),
         "remote_interactive": str(len(remote_admins)), "local_share": f"{share:.2f}"}))

    # ── password age, administrative accounts, then all ──
    out.append(row(
        "Privileged account credential age",
        roles.account_population("how long ago administrative passwords were set"),
        "weak" if admin_ages["stale"] else "acceptable", _age_flags(admin_ages), len(admins),
        (f"Of {len(admins):,} administrative accounts: "
         + _age_sentence(admin_ages, fresh_days, stale_days)
         + ". No date is not an old password: the export holds no record, and the two are "
           "counted apart."),
        {f"age_{k}": str(v) for k, v in admin_ages.items()}))
    out.append(row(
        "Account credential age (all observed accounts)",
        roles.account_population("how long ago every observed account's password was set"),
        "weak" if all_ages["stale"] else "acceptable", _age_flags(all_ages), total,
        (f"Of all {total:,} observed accounts: "
         + _age_sentence(all_ages, fresh_days, stale_days) + "."),
        {f"age_{k}": str(v) for k, v in all_ages.items()}))

    # ── accounts that sign in as services ──
    if services:
        unknown_share = service_ages["unknown"] / len(services)
        out.append(row(
            "Service accounts", roles.account_population("accounts that sign in as services"),
            "unknown" if unknown_share >= 0.5 else "acceptable",
            [f"service-accounts:{len(services)}"]
            + ([f"credential-age-unknown:{service_ages['unknown']}"]
               if service_ages["unknown"] else []),
            len(services),
            (f"{len(services):,} observed accounts last signed in by a service logon. "
             f"{service_ages['unknown']:,} of them carry no password date, so their password "
             "age is unknown, not old: this export cannot tell an account whose password "
             "rotates automatically from one whose password never changed. The directory or "
             "the secret store can."),
            {f"age_{k}": str(v) for k, v in service_ages.items()}))

    # ── what the export covers ──
    out.append(CryptoAsset(
        name="Account inventory scope", role=roles.account_population_scope(),
        verdict="n/a", flags=[SCOPE_FLAG], hosts_count=total,
        notes=("These are the accounts the endpoint sensor saw sign in on machines that run "
               "it. Domain accounts here are a sample of the directory, not an enumeration of "
               "it: an account that never signed in on such a machine is absent. So this is "
               "not the directory's own list of privileged accounts; an export from the "
               "directory itself is that."),
        extra={"observed_accounts": str(total),
               "domain_rows": str(sum(1 for r in rows if kind(r) == "domain"))},
        **base))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    settings = ctx.settings or {}
    fmt = settings.get("date_format")
    assets, gaps = read(
        ctx.input, headings=_fi.headings(ctx, HEADINGS),
        fresh_days=int(_entra.setting_number(ctx, "fresh_days", FRESH_DAYS)),
        stale_days=int(_entra.setting_number(ctx, "stale_days", STALE_DAYS)),
        date_format=fmt if isinstance(fmt, str) else "",
        today=ctx.ref_time.date())
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon accounts (where privilege sits, password age)",
                gap_prefix=False)
