"""Microsoft Entra application, managed identity and non-interactive sign-ins.

Three of the sign-in logs the Microsoft Entra admin centre downloads as CSV
record sign-ins with no person at a sign-in page:

* **Application (service principal) sign-ins**, the reader's ``input:``: an
  application signing in as itself. What matters is what it proves its
  identity with, a certificate or a client secret.
* **Managed identity sign-ins** (``settings: {managed_identities: ...}``):
  identities whose credentials Azure issues and rotates. Counted, not
  graded, since nobody holds a credential to leak or forget.
* **Non-interactive user sign-ins** (``settings: {noninteractive: ...}``):
  a person's session renewed by an application. Read for legacy
  authentication clients, as the interactive log is, and for confidential
  applications that prove their own identity with a client secret.

**Secret or certificate.** A client secret is a shared value both sides
store in full; with a certificate the private key stays with its holder. The
application sign-in log records a ``Credential key ID`` on a credentialed
sign-in and a ``Credential thumbprint`` only for a certificate, so a key ID
with no thumbprint is read as a secret. That is an inference, so where
``settings: {app_credentials: ...}`` names the ``entra_app_credentials``
reader's credential export, each key ID found in both is checked against the
credential type recorded there, and the scope row gives how many agree. The
non-interactive log records the platform's own ``Client credential type``
(``clientSecret``, ``clientAssertion``, ``federatedIdentityCredential``,
``none``), so nothing is inferred there.

**Rows.** One per application seen signing in with a secret, ``unknown`` and
flagged (``workload-signin-secret:<n>``, ``delegated-client-secret:<n>``):
a secret rotated on a sensible cycle is defensible, so the construction
alone is not graded, and the flag lets a move from a certificate to a secret
show as a change. A scope row per log, and the legacy client row for the
non-interactive log. Each log's period is read from its rows.

**Cannot see.** An application that did not sign in during the period; what
each identity is permitted to do; a credential's lifetime (the
``entra_app_credentials`` reader reads that).
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
NAME = "entra_workload_signins"

WORKLOAD_SECRET_FLAG = "workload-signin-secret:"
DELEGATED_SECRET_FLAG = "delegated-client-secret:"
WORKLOAD_CERT_FLAG = "workload-signin-certificate:"
WORKLOAD_SCOPE_FLAG = "workload-scope-window:"
WORKLOAD_CEILING_FLAG = "workload-scope-ceiling:"
WORKLOAD_SPAN_FLAG = "workload-scope-span:"
MANAGED_IDENTITY_FLAG = "workload-managed-identities:"

CERTIFICATE = "certificate"
SECRET = "secret"
NO_CREDENTIAL = "none recorded"

EVIDENCE_LIMIT = ("This is what the platform recorded for sign-ins in the period read. An "
                  "application that did not sign in then is not here, which does not mean it "
                  "holds no credential")
NONINTERACTIVE_LIMIT = (EVIDENCE_LIMIT + ". A non-interactive sign-in renews an existing "
                        "session, so its second factor is normally the one the original "
                        "sign-in performed, not a new check")

#: What each log is called in a sentence.
SERVICE_PRINCIPALS = "application sign-ins"
MANAGED_IDENTITIES = "managed identity sign-ins"
NONINTERACTIVE = "non-interactive user sign-ins"


def _scope_flags(first: str, last: str, rows: int) -> list[str]:
    return [f"{WORKLOAD_SCOPE_FLAG}{_entra.window_days(first, last)}",
            (f"{WORKLOAD_CEILING_FLAG}{rows}" if _entra.is_ceiling(rows)
             else f"{WORKLOAD_SPAN_FLAG}{rows}")]


def _window(win: _Window) -> dict[str, str]:
    return {"window_first": win.first[:19], "window_last": win.last[:19],
            "window_is_ceiling": "yes" if _entra.is_ceiling(win.rows) else "no"}


class _Window:
    """A log's period, row count, failures and Conditional Access states."""

    def __init__(self) -> None:
        self.rows = 0
        self.first = ""
        self.last = ""
        self.failures = 0
        self.policy: dict[str, int] = {}

    def see(self, row: dict) -> None:
        self.rows += 1
        when = col(row, "Date (UTC)")
        if when:
            if not self.first or when < self.first:
                self.first = when
            if when > self.last:
                self.last = when
        if col(row, "Status").lower() != "success":
            self.failures += 1
        policy = col(row, "Conditional Access") or "(unrecorded)"
        self.policy[policy] = self.policy.get(policy, 0) + 1

    @property
    def period(self) -> str:
        return _entra.span_minutes(self.first, self.last, _entra.is_ceiling(self.rows))


def _gap(log: str, why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no Microsoft Entra {log} log was read: {why}",
        impact=(f"What the {log} prove their identity with is not known from use, only from "
                "what is registered."),
        impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.NO_DATA,
        harvest=f"Download the {log} log as CSV from the admin centre and name it in the profile.")


def _why(path: Path | None, unreadable: str = "", how: str = "") -> str:
    if path is None:
        return f"none was named{how}"
    if unreadable:
        return f"{path.name} could not be read ({unreadable})"
    if not path.exists():
        return f"{path.name} does not exist"
    return f"{path.name} holds no rows"


def registered_types(path: Path | None) -> dict[str, str]:
    """Key ID → credential type (lower case) from a credential export, read only to test
    the secret inference; nothing from it is written."""
    if path is None or not path.exists():
        return {}
    try:
        return {col(r, "KeyId").lower(): col(r, "CredentialType").lower()
                for r in _entra.stream(path) if col(r, "KeyId")}
    except (OSError, UnicodeDecodeError, csv.Error):
        return {}


def service_principals(path: Path | None,
                       registered: dict[str, str]) -> tuple[list[CryptoAsset], list[str]]:
    """Rows from the application sign-in log."""
    if path is None or not path.exists():
        return [], [_gap(SERVICE_PRINCIPALS, _why(path, how=" as the reader's input"))]
    win = _Window()
    apps: dict[str, dict] = {}
    agree = disagree = 0
    checked: set[str] = set()
    try:
        for row in _entra.stream(path):
            win.see(row)
            key = col(row, "Service principal ID") or "(unidentified)"
            slot = apps.setdefault(key, {
                "name": (col(row, "Service principal name") or col(row, "Application")
                         or "(unnamed application)"),
                "app_id": col(row, "Application ID"), "kinds": {}, "keys": set(),
                "resources": set(), "signins": 0})
            slot["signins"] += 1
            kid = col(row, "Credential key ID").lower()
            thumb = col(row, "Credential thumbprint")
            kind = CERTIFICATE if thumb else SECRET if kid else NO_CREDENTIAL
            slot["kinds"][kind] = slot["kinds"].get(kind, 0) + 1
            if kid:
                slot["keys"].add(kid)
                if kid in registered and kid not in checked:
                    checked.add(kid)
                    expected = "certificate" if kind == CERTIFICATE else "password"
                    if registered[kid] == expected:
                        agree += 1
                    else:
                        disagree += 1
            resource = col(row, "Resource")
            if resource:
                slot["resources"].add(resource)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [_gap(SERVICE_PRINCIPALS, _why(path, str(exc)))]
    if not win.rows:
        return [], [_gap(SERVICE_PRINCIPALS, _why(path))]

    when = file_mtime_date(path) or ""
    source_name = ("Microsoft Entra application sign-in log, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    out: list[CryptoAsset] = []
    for _key, slot in sorted(apps.items(),
                             key=lambda kv: (-kv[1]["kinds"].get(SECRET, 0), kv[1]["name"])):
        secret = slot["kinds"].get(SECRET, 0)
        if not secret:
            continue
        cert = slot["kinds"].get(CERTIFICATE, 0)
        short_id = slot["app_id"][:8] if slot["app_id"] else "unidentified"
        out.append(CryptoAsset(
            name=f"application signing in with a secret — {slot['name']} [{short_id}]",
            data_state="identity", protocol="oauth-client-credential",
            role=roles.workload_signin_credential("a client secret"), software=slot["name"],
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict="unknown",
            flags=[f"{WORKLOAD_SECRET_FLAG}{secret}"]
            + ([f"{WORKLOAD_CERT_FLAG}{cert}"] if cert else []),
            hosts_count=len(slot["keys"]), usage_count=slot["signins"],
            notes=(f"This application signed in as itself {slot['signins']:,} time(s) "
                   f"{win.period}. {secret:,} of those sign-ins presented a key with no "
                   "certificate thumbprint, which is how a client secret appears in this log"
                   + (f", and {cert:,} a certificate" if cert else "")
                   + f". It used {len(slot['keys'])} credential(s) and reached "
                     f"{len(slot['resources'])} resource(s). A secret is held in full by both "
                     "sides; a certificate's private key stays with the application, and "
                     "the platform offers both. The construction alone is not graded, since "
                     "a secret rotated on a sensible cycle is defensible, and this log does "
                     f"not record the credential's lifetime. {EVIDENCE_LIMIT}."),
            extra={"application": slot["name"], "application_id_prefix": short_id,
                   "signins": str(slot["signins"]), "secret_signins": str(secret),
                   "certificate_signins": str(cert),
                   "credentials_used": str(len(slot["keys"])),
                   "resources": str(len(slot["resources"])), **_window(win)}))

    by_kind = {k: 0 for k in (SECRET, CERTIFICATE, NO_CREDENTIAL)}
    for slot in apps.values():
        for kind in slot["kinds"]:
            by_kind[kind] += 1
    signins = {k: sum(s["kinds"].get(k, 0) for s in apps.values()) for k in by_kind}
    ceiling = _entra.is_ceiling(win.rows)
    out.append(CryptoAsset(
        name="Application sign-in evidence scope", data_state="discovery", protocol="inventory",
        role=roles.workload_signin_scope("applications signing in as themselves"),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a", flags=_scope_flags(win.first, win.last, win.rows),
        hosts_count=len(apps), usage_count=win.rows,
        notes=(f"{win.rows:,} sign-in(s) by {len(apps)} application(s) signing in as "
               f"themselves, {win.period}. {by_kind[SECRET]} presented a key read as a secret "
               f"({signins[SECRET]:,} sign-ins), {by_kind[CERTIFICATE]} a certificate "
               f"({signins[CERTIFICATE]:,}), and {by_kind[NO_CREDENTIAL]} no credential "
               f"({signins[NO_CREDENTIAL]:,}), for which the log does not say how they "
               "authenticated. One application can be in more than one of these. "
               + (f"Key IDs found in the credential export as well: {agree + disagree}; "
                  f"the secret reading agrees on {agree} and disagrees on {disagree}. "
                  if agree + disagree else
                  "No key ID was checked against a credential export, so reading a key "
                  "with no thumbprint as a secret is untested here. ")
               + f"{win.failures:,} sign-in(s) failed. "
               + ("None of these sign-ins had a Conditional Access policy in scope. "
                  if win.policy.get("Not Applied", 0) == win.rows else "")
               + (f"The row count is exactly {win.rows:,}, a download limit, so it may not "
                  "cover the whole period asked for, and an application that signs in rarely "
                  "may be missing. " if ceiling else "")
               + f"{EVIDENCE_LIMIT}."),
        extra={"signins": str(win.rows), "applications": str(len(apps)),
               "applications_secret": str(by_kind[SECRET]),
               "applications_certificate": str(by_kind[CERTIFICATE]),
               "applications_no_credential": str(by_kind[NO_CREDENTIAL]),
               "signins_secret": str(signins[SECRET]),
               "signins_certificate": str(signins[CERTIFICATE]),
               "signins_no_credential": str(signins[NO_CREDENTIAL]),
               "inference_agrees": str(agree), "inference_disagrees": str(disagree),
               "failed": str(win.failures), **_window(win)}))
    return out, []


def managed_identities(path: Path | None) -> tuple[list[CryptoAsset], list[str]]:
    """The scope row from the managed identity sign-in log."""
    how = " under settings: managed_identities"
    if path is None or not path.exists():
        return [], [_gap(MANAGED_IDENTITIES, _why(path, how=how))]
    win = _Window()
    identities: set[str] = set()
    resources: dict[str, int] = {}
    try:
        for row in _entra.stream(path):
            win.see(row)
            identities.add(col(row, "Service principal ID") or col(row, "Service principal name"))
            resource = col(row, "Resource") or "(unrecorded)"
            resources[resource] = resources.get(resource, 0) + 1
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [_gap(MANAGED_IDENTITIES, _why(path, str(exc)))]
    if not win.rows:
        return [], [_gap(MANAGED_IDENTITIES, _why(path))]
    when = file_mtime_date(path) or ""
    top = ", ".join(f"{k} {v:,}" for k, v in sorted(resources.items(), key=lambda kv: -kv[1])[:6])
    return [CryptoAsset(
        name="Managed identity sign-in evidence scope", data_state="discovery",
        protocol="inventory",
        role=roles.workload_signin_scope("identities Azure manages"),
        source=NAME, source_class="private",
        source_name=("Microsoft Entra managed identity sign-in log, "
                     + (f"file dated {when}" if when else "file date unavailable")),
        collected_at=when, verdict="n/a",
        flags=_scope_flags(win.first, win.last, win.rows)
        + [f"{MANAGED_IDENTITY_FLAG}{len(identities)}"],
        hosts_count=len(identities), usage_count=win.rows,
        notes=(f"{win.rows:,} sign-in(s) by {len(identities)} managed identit(ies) "
               f"{win.period}, to {len(resources)} resource(s); the most used are {top}. Azure "
               "issues and rotates a managed identity's credential, and nobody holds a copy, "
               "so there is no secret here to leak or forget to rotate; these are counted, "
               "not graded. What each identity is permitted to do is not in this log. "
               f"{win.failures:,} sign-in(s) failed. "
               + ("The row count is not a download limit, so this is the whole period "
                  "downloaded. " if not _entra.is_ceiling(win.rows) else "")
               + f"{EVIDENCE_LIMIT}."),
        extra={"signins": str(win.rows), "identities": str(len(identities)),
               "resources": str(len(resources)), "failed": str(win.failures),
               **_window(win)})], []


def noninteractive(path: Path | None) -> tuple[list[CryptoAsset], list[str]]:
    """Rows from the non-interactive user sign-in log."""
    how = " under settings: noninteractive"
    if path is None or not path.exists():
        return [], [_gap(NONINTERACTIVE, _why(path, how=how))]
    win = _Window()
    principals: set[str] = set()
    client_apps: dict[str, dict] = {}
    credential_types: dict[str, int] = {}
    secret_apps: dict[str, dict] = {}
    try:
        for row in _entra.stream(path):
            win.see(row)
            upn = col(row, "Username").lower()
            if upn:
                principals.add(upn)
            client = col(row, "Client app") or "(unrecorded)"
            slot = client_apps.setdefault(client, {"count": 0, "principals": set()})
            slot["count"] += 1
            if upn:
                slot["principals"].add(upn)
            ctype = col(row, "Client credential type") or "(unrecorded)"
            credential_types[ctype] = credential_types.get(ctype, 0) + 1
            if ctype.lower() == "clientsecret":
                app = col(row, "Application") or "(unnamed application)"
                a = secret_apps.setdefault(app, {"count": 0, "app_id": col(row, "Application ID"),
                                                 "principals": set()})
                a["count"] += 1
                if upn:
                    a["principals"].add(upn)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [_gap(NONINTERACTIVE, _why(path, str(exc)))]
    if not win.rows:
        return [], [_gap(NONINTERACTIVE, _why(path))]

    when = file_mtime_date(path) or ""
    source_name = ("Microsoft Entra non-interactive sign-in log, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    ceiling = _entra.is_ceiling(win.rows)
    out: list[CryptoAsset] = [_entra.legacy_client_row(
        client_apps, win.rows, source=NAME, source_name=source_name, collected_at=when,
        period=win.period, population="non-interactive sign-ins", limit=NONINTERACTIVE_LIMIT,
        window=f"{win.first[:10]}..{win.last[:10]}", ceiling=ceiling)]
    for app, a in sorted(secret_apps.items(), key=lambda kv: -kv[1]["count"]):
        short_id = a["app_id"][:8] if a["app_id"] else "unidentified"
        out.append(CryptoAsset(
            name=f"application acting for people with a secret — {app} [{short_id}]",
            data_state="identity", protocol="oauth-client-credential",
            role=roles.delegated_signin_credential("a client secret"), software=app,
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict="unknown", flags=[f"{DELEGATED_SECRET_FLAG}{a['count']}"],
            hosts_count=len(a["principals"]), usage_count=a["count"],
            notes=(f"{a['count']:,} session renewal(s) {win.period}, for "
                   f"{len(a['principals'])} account(s), were made by this application proving "
                   "its own identity with a client secret, as the log's credential type "
                   "records. The alternatives the platform offers are a signed assertion from "
                   "a certificate and a federated credential, used by "
                   f"{credential_types.get('clientAssertion', 0):,} and "
                   f"{credential_types.get('federatedIdentityCredential', 0):,} renewals in the "
                   "same period. The construction alone is not graded, as for application "
                   f"credentials. {NONINTERACTIVE_LIMIT}."),
            extra={"application": app, "application_id_prefix": short_id,
                   "secret_signins": str(a["count"]), "accounts": str(len(a["principals"])),
                   **_window(win)}))
    mix = ", ".join(f"{k} {v:,}"
                    for k, v in sorted(credential_types.items(), key=lambda kv: -kv[1]))
    out.append(CryptoAsset(
        name="Non-interactive sign-in evidence scope", data_state="discovery",
        protocol="inventory",
        role=roles.workload_signin_scope("sessions renewed without a sign-in page"),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a", flags=_scope_flags(win.first, win.last, win.rows),
        hosts_count=len(principals), usage_count=win.rows,
        notes=(f"{win.rows:,} non-interactive sign-in(s) by {len(principals)} account(s) "
               f"{win.period}. "
               + (f"The row count is exactly {win.rows:,}, a download limit; this log fills "
                  "quickly, so the period is short and something done rarely may not appear. "
                  if ceiling else "")
               + f"Credential the acting application presented: {mix} (none means it "
                 "presented no credential of its own). "
               + f"{len(secret_apps)} application(s) used a client secret. "
               + f"{win.failures:,} sign-in(s) failed. {NONINTERACTIVE_LIMIT}."),
        extra={"signins": str(win.rows), "accounts": str(len(principals)),
               "secret_applications": str(len(secret_apps)), "failed": str(win.failures),
               **_window(win),
               **{f"credential_{k.lower()}": str(v) for k, v in credential_types.items()}}))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the three logs, each with its rows or its gap."""
    registered = registered_types(_entra.newest(ctx, "app_credentials"))
    assets: list[CryptoAsset] = []
    gaps: list[str] = []
    for rows, found in (service_principals(ctx.input, registered),
                        managed_identities(_entra.newest(ctx, "managed_identities")),
                        noninteractive(_entra.newest(ctx, "noninteractive"))):
        assets += rows
        gaps += found
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gaps.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Microsoft Entra application, managed identity and non-interactive "
                      "sign-in logs", gap_prefix=False)
