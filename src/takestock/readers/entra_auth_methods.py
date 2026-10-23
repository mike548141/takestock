"""Microsoft Entra sign-in authentication details: which checks people used to sign in.

**The input** is the interactive sign-in log downloaded "with only the
authentication details included" (Microsoft Entra admin centre, Monitoring &
health → Sign-in logs → Download), one row per authentication step:
``Request ID``, ``Date``, ``Authentication method``, ``Authentication method
detail``, ``Succeeded``, ``Result detail`` and ``Requirement``. A sign-in
that asked for a password and then a phone approval writes two rows under one
request ID. The non-interactive log's details are named with ``settings:
{noninteractive: ...}``. Each file read is one population, and each gets a
row; a file not given or not readable is a coverage gap.

**What it answers.** Whether the second checks people used resist phishing.
NZISM v3.9 asks for phishing-resistant multifactor authentication
(16.7.42.C.06, and for administration accounts 16.7.42.C.05); both are
SHOULD, so the row states the mix and is not graded against them.

**Which methods resist phishing.** Microsoft's built-in "Phishing-resistant
MFA strength" (*Overview of Conditional Access Authentication Strengths*,
learn.microsoft.com) allows Windows Hello for Business or platform
credential, FIDO2 security key, and certificate-based authentication
(multifactor). The same page calls a FIDO2 key a "passkey (FIDO2)", so a
method starting ``passkey`` is counted with them. Push
notifications, one-time codes, text messages and voice calls meet the
ordinary multifactor strength and not that one. A method listed in neither
is counted as unclassified and named, never guessed into either side.

**"Previously satisfied"** steps were met by a claim already in the token,
and say nothing about which method created it, so they are counted apart and
the mix is stated over the steps where a method was used.

**Rows.** One per population, ``n/a``: the mix of methods, counts only. The
method detail column carries masked phone numbers and agent IDs; none is
written. Where an app password stood in for the second check (``Result
detail``: "MFA requirement skipped due to app password"), a second row,
``weak``: NZISM v3.9 16.7.42.C.01 (MUST) requires multifactor authentication
for user accounts on cloud-based services, and an app password is one factor.

**Cannot see.** Which methods each account has registered, and what the
Conditional Access policies require: the rows show how often a method was
used, not that a weaker one is unavailable.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from ._entra import col

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "entra_auth_methods"

MIX_PR_FLAG = "authmethod-phishing-resistant:"
MIX_OTHER_MFA_FLAG = "authmethod-other-second-factor:"
MIX_SCOPE_FLAG = "authmethod-scope-window:"
MIX_CEILING_FLAG = "authmethod-scope-ceiling:"
MIX_SPAN_FLAG = "authmethod-scope-span:"
APP_PASSWORD_FLAG = "authmethod-app-password:"

#: ``Authentication method`` values, matched at the start, lower case.
PHISHING_RESISTANT = ("windows hello for business", "fido2 security key",
                      "certificate-based authentication", "passkey")
OTHER_SECOND_FACTOR = ("mobile app notification", "oath verification code", "text message",
                       "phone call approval", "microsoft authenticator")
FIRST_FACTOR = ("password",)
PREVIOUSLY_SATISFIED = "previously satisfied"
#: The two ordinary second factors that go over the telephone network.
TELEPHONE = ("text message", "phone call approval")

#: ``Result detail`` when an app password stood in for the second factor.
APP_PASSWORD_RESULT = "mfa requirement skipped due to app password"
#: ``Authentication method detail`` for a password checked on premises by a
#: pass-through authentication agent, and for one checked in the cloud.
PASS_THROUGH = "pass-through authentication"
CLOUD_PASSWORD = "password in the cloud"

INTERACTIVE = "interactive sign-ins"
NONINTERACTIVE = "non-interactive sign-ins"

EVIDENCE_LIMIT = ("These are the checks recorded for sign-ins in the period read. They show "
                  "which methods were used, not which each account has registered or what the "
                  "policies require, so they cannot show that a weaker method is unavailable")


def classify(method: str) -> str:
    """The class of an ``Authentication method`` value."""
    m = method.lower()
    if not m:
        return "unrecorded"
    if m == PREVIOUSLY_SATISFIED:
        return "previously-satisfied"
    if m.startswith(PHISHING_RESISTANT):
        return "phishing-resistant"
    if m.startswith(OTHER_SECOND_FACTOR):
        return "other-second-factor"
    if m.startswith(FIRST_FACTOR):
        return "first-factor"
    return "unclassified"


class Tally:
    """The totals one file gives."""

    def __init__(self) -> None:
        self.rows = 0
        self.first = ""
        self.last = ""
        self.requests: set[str] = set()
        self.methods: dict[str, int] = {}
        self.classes: dict[str, int] = {}
        self.failed = 0
        self.app_password = 0
        self.pass_through = 0
        self.cloud_password = 0
        self.agents: set[str] = set()

    def add(self, row: dict) -> None:
        self.rows += 1
        when = col(row, "Date")
        if when:
            if not self.first or when < self.first:
                self.first = when
            if when > self.last:
                self.last = when
        request = col(row, "Request ID")
        if request:
            self.requests.add(request)
        method = col(row, "Authentication method")
        self.methods[method or "(unrecorded)"] = self.methods.get(method or "(unrecorded)", 0) + 1
        kind = classify(method)
        self.classes[kind] = self.classes.get(kind, 0) + 1
        if col(row, "Succeeded").lower() == "false":
            self.failed += 1
        if col(row, "Result detail").lower() == APP_PASSWORD_RESULT:
            self.app_password += 1
        detail = col(row, "Authentication method detail").lower()
        if detail.startswith(PASS_THROUGH):
            self.pass_through += 1
            # The agent ID is counted, never written.
            _, _, agent = detail.partition("agentid:")
            if agent.strip():
                self.agents.add(agent.strip())
        elif detail == CLOUD_PASSWORD:
            self.cloud_password += 1


def read(path: Path) -> tuple[Tally | None, str]:
    """The file's tally, or (None, reason) when it cannot be read, (None, "") when absent or empty."""
    if not path.exists():
        return None, ""
    tally = Tally()
    try:
        for row in _entra.stream(path):
            tally.add(row)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return None, str(exc)
    return (tally, "") if tally.rows else (None, "")


def mix_row(t: Tally, population: str, source_name: str, when: str) -> CryptoAsset:
    """The method mix for one population."""
    ceiling = _entra.is_ceiling(t.rows)
    period = _entra.span_minutes(t.first, t.last, ceiling)
    pr = t.classes.get("phishing-resistant", 0)
    other = t.classes.get("other-second-factor", 0)
    second = pr + other
    telephone = sum(v for k, v in t.methods.items() if k.lower().startswith(TELEPHONE))
    prior = t.classes.get("previously-satisfied", 0)
    unclassified = {k: v for k, v in t.methods.items()
                    if classify(k if k != "(unrecorded)" else "") == "unclassified"}
    mix = ", ".join(f"{k} {v:,}" for k, v in sorted(t.methods.items(), key=lambda kv: -kv[1]))
    notes = (f"{t.rows:,} authentication step(s) in {len(t.requests):,} {population} {period}. "
             + (f"Of the {second:,} step(s) that performed a second check, {pr:,} used a "
                f"phishing-resistant method and {other:,} did not ({pr / second:.0%} "
                f"phishing-resistant); {telephone:,} were a text message or a voice call. "
                if second else "No step performed a new second check. ")
             + f"{prior:,} step(s) were met by a claim already in the token and are counted "
               "apart, since they do not show which method created it. "
             + "NZISM v3.9 16.7.42.C.06, and for administration accounts 16.7.42.C.05, ask "
               "for phishing-resistant multifactor authentication; both are SHOULD, so the mix "
               "is stated and not graded. "
             + (f"{t.pass_through:,} password step(s) were checked on premises by "
                f"{len(t.agents)} pass-through authentication agent(s) and {t.cloud_password:,} "
                "in the cloud, so those sign-ins depend on the agents and the on-premises "
                "directory being reachable. " if t.pass_through else "")
             + (f"{t.app_password:,} step(s) skipped the second check because an app "
                "password stood in for it. " if t.app_password else "")
             + (f"Methods not classified here: "
                f"{', '.join(f'{k} {v:,}' for k, v in unclassified.items())}. "
                if unclassified else "")
             + f"All methods: {mix}. "
             + (f"The row count is exactly {t.rows:,}, a download limit, so it may not cover "
                "the whole period asked for. " if ceiling else "")
             + f"{EVIDENCE_LIMIT}.")
    return CryptoAsset(
        name=f"Authentication methods used — {population}", data_state="identity",
        protocol="authentication-method", role=roles.auth_method_mix(population),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a",
        flags=[f"{MIX_PR_FLAG}{pr}", f"{MIX_OTHER_MFA_FLAG}{other}",
               f"{MIX_SCOPE_FLAG}{_entra.window_days(t.first, t.last)}",
               f"{MIX_CEILING_FLAG}{t.rows}" if ceiling else f"{MIX_SPAN_FLAG}{t.rows}"],
        hosts_count=len(t.requests), usage_count=t.rows, notes=notes,
        extra={"steps": str(t.rows), "signins": str(len(t.requests)),
               "phishing_resistant_steps": str(pr), "other_second_factor_steps": str(other),
               "telephone_steps": str(telephone), "previously_satisfied_steps": str(prior),
               "failed_steps": str(t.failed), "app_password_steps": str(t.app_password),
               "password_pass_through_steps": str(t.pass_through),
               "password_cloud_steps": str(t.cloud_password),
               "pass_through_agents": str(len(t.agents)),
               "window_first": t.first[:19], "window_last": t.last[:19],
               "window_is_ceiling": "yes" if ceiling else "no",
               **{f"method_{k.lower().replace(' ', '_')}": str(v) for k, v in t.methods.items()}})


def app_password_row(t: Tally, population: str, source_name: str, when: str) -> CryptoAsset:
    """The steps where an app password stood in for the second check."""
    ceiling = _entra.is_ceiling(t.rows)
    return CryptoAsset(
        name=f"App passwords standing in for a second check — {population}",
        data_state="identity", protocol="authentication-method",
        role=roles.app_password_signins(t.app_password), source=NAME, source_class="private",
        source_name=source_name, collected_at=when, verdict="weak",
        flags=[f"{APP_PASSWORD_FLAG}{t.app_password}"], usage_count=t.app_password,
        notes=(f"{t.app_password:,} {population} {_entra.span_minutes(t.first, t.last, ceiling)} "
               "met the multifactor requirement with an app password: a fixed password issued "
               "for an older program, which the platform accepts in place of the second "
               "check. NZISM v3.9 16.7.42.C.01 (MUST) requires multifactor authentication for "
               "user accounts on cloud-based services, and an app password is one factor. "
               f"Which accounts hold one is not in this export. {EVIDENCE_LIMIT}."),
        extra={"app_password_steps": str(t.app_password), "window_first": t.first[:19],
               "window_last": t.last[:19], "window_is_ceiling": "yes" if ceiling else "no"})


def _gap(population: str, why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no authentication details of the {population} were read: {why}",
        impact=("Which second checks were used, and so the share that resists phishing, is "
                "not known for these sign-ins."),
        impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.NO_DATA,
        harvest=(f"Download the {population} log with only the authentication details "
                 "included, as CSV, and name it in the profile."))


def step(ctx: Context) -> StepResult:
    """The plug-in's step: a row (or a gap) per population."""
    assets: list[CryptoAsset] = []
    gaps: list[str] = []
    for population, path, how in ((INTERACTIVE, ctx.input, "as the reader's input"),
                                  (NONINTERACTIVE, _entra.newest(ctx, "noninteractive"),
                                   "under settings: noninteractive")):
        tally, unreadable = read(path) if path is not None else (None, "")
        if tally is None:
            why = (f"none was named {how}" if path is None else
                   f"{path.name} could not be read ({unreadable})" if unreadable else
                   f"{path.name} does not exist" if not path.exists() else
                   f"{path.name} holds no rows")
            gaps.append(_gap(population, why))
            continue
        assert path is not None
        when = file_mtime_date(path) or ""
        source_name = (f"Microsoft Entra sign-in authentication details, {population}, "
                       + (f"file dated {when}" if when else "file date unavailable"))
        assets.append(mix_row(tally, population, source_name, when))
        if tally.app_password:
            assets.append(app_password_row(tally, population, source_name, when))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gaps.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Microsoft Entra sign-in authentication details", gap_prefix=False)
