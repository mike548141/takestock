"""Microsoft Entra application credentials: the client secrets and certificates applications sign in with.

An application registered in Microsoft Entra ID proves its identity with a
**client secret** (Microsoft Graph credential type ``Password``) or a
**certificate** (type ``Certificate``):

* A client secret is a shared symmetric secret. The directory and every
  system that uses it hold the whole value, which is sent in full on each
  token request (the OAuth 2.0 client credentials grant's ``client_secret``),
  so it is no better protected than the weakest place that stores it.
* A certificate credential is asymmetric. The application signs a client
  assertion with its private key and the directory keeps only the public
  key, so the private key need never leave its holder.

Both are offered on every application registration. A secret is flagged
``credential-shared-secret`` and does not set the verdict: rotated on a
sensible cycle it is defensible, and the flag lets a move from a certificate
to a secret show as a change.

**Lifetime.** The longer a credential stays valid, the longer a copy of it is
worth having. NIST SP 800-57 Part 1 Rev. 5 §5.3.6 recommends cryptoperiods
of up to two years for a symmetric authentication key (a client secret) and
one to three years for a private signature key (a certificate's), so a
credential valid for longer than :data:`PASSWORD_MAX_LIFETIME_DAYS` or
:data:`CERTIFICATE_MAX_LIFETIME_DAYS` is ``weak`` and flagged
``credential-lifetime-excessive:<years>y``; otherwise ``acceptable``. One
valid for a century or more (:data:`PERMANENT_CREDENTIAL_DAYS`) is flagged
``credential-never-expires``: that is the date a tool writes for "never
expires", while a mistyped year stays well within a century. A credential in
use longer than its cryptoperiod is flagged ``credential-unrotated:<years>y``,
and one past its end date ``credential-expired``. A row is never graded
``strong``: the export records no key algorithm, size or storage, so every
credential carries ``credential-key-unknown``.

**The inputs**, CSV files in the columns ``docs/COLLECTORS.md`` lists, which
its Microsoft Graph PowerShell script writes:

* the credentials, the reader's ``input:``: one row per secret or
  certificate (``AppDisplayName``, ``AppId``, ``CredentialType``,
  ``CredentialOwner``, ``CredentialDisplayName``, ``StartDateTimeUtc``,
  ``EndDateTimeUtc``, ``PermissionsOfInterest``);
* the applications, ``settings: {applications: ...}``: one row per
  application (``AppDisplayName``, ``AppId``,
  ``ApplicationCreatedDateUtc``, ``ServicePrincipalCreatedDateUtc``,
  ``PermissionsOfInterest``), so an application with no credential still
  gets a row;
* the permissions, ``settings: {permissions: ...}``: one row per
  application per permission (``AppId``, ``PermissionValue``,
  ``ResourceName``).

Dates are read as ISO 8601 unless ``settings: {date_format: ...}`` gives a
``strptime`` format, and are taken as UTC. A date that does not match is
never guessed: the row is ungraded, flagged ``credential-date-unreadable``,
and a gap counts them, since a day-first date read month-first moves an
expiry by months with no error. ``KeyId`` and ``Hint`` (the first
characters of a secret) are never read.

**Scope.** An export may cover only some applications, such as those
holding directory write permissions. ``settings: {scope: directory-write}``
says so: the scope row is flagged ``scope-directory-write-only`` and the
rows describe the applications as able to change the directory. A
credential holding a permission that can create credentials for other
applications or grant them roles (:data:`CREDENTIAL_MINTING_PERMISSIONS`) is
flagged ``credential-minting-permission:<permission>``.

**Cannot see.** Key algorithm, size and storage; applications outside the
export; and, for an application registered in another tenant (a consented
service principal with no local registration), its credential at all.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "entra_app_credentials"

#: NIST SP 800-57 Part 1 Rev. 5 §5.3.6: a symmetric authentication key, up to
#: two years; a private signature key, one to three years (the upper bound).
PASSWORD_MAX_LIFETIME_DAYS = 730
CERTIFICATE_MAX_LIFETIME_DAYS = 1096
#: A hundred years: past any operational horizon and past any mistyped year.
PERMANENT_CREDENTIAL_DAYS = 36525

#: Microsoft Graph application permissions that let the holder add
#: credentials to other applications or grant them app roles, so one stolen
#: key can become any key in the tenant.
CREDENTIAL_MINTING_PERMISSIONS = ("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All")

#: The ``scope:`` setting for an export limited to applications holding
#: directory write permissions.
DIRECTORY_WRITE = "directory-write"

_PASSWORD = "Password"
_CERTIFICATE = "Certificate"


def _read(path: Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _col(row: dict, *names: str) -> str:
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n.lower():
                return (v or "").strip()
    return ""


def parse_date(value: str, fmt: str = "") -> datetime | None:
    """An export date as an aware UTC datetime, or None when it does not match.

    With ``fmt``, exactly that ``strptime`` format; without, ISO 8601. A date
    with no zone is taken as UTC, and nothing else is tried.
    """
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = (datetime.strptime(value, fmt) if fmt
                  else datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _years(days: int) -> int:
    return round(days / 365.25)


def duration(days: int) -> str:
    """``days`` in days, months or years, whichever reads best."""
    if days < 0:
        return duration(-days)
    if days < 60:
        return f"{days} day(s)"
    if days < 365:
        return f"{round(days / 30.44)} month(s)"
    return f"{_years(days)} year(s)"


def _ceiling(kind: str) -> int:
    return CERTIFICATE_MAX_LIFETIME_DAYS if kind == _CERTIFICATE else PASSWORD_MAX_LIFETIME_DAYS


def _permissions(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(";") if p.strip()]


class _Run:
    """What every row of one run shares."""

    def __init__(self, source_name: str, when: str, now: datetime, fmt: str,
                 directory_write: bool, perms_by_app: dict[str, list[str]]) -> None:
        self.source_name, self.when, self.now, self.fmt = source_name, when, now, fmt
        self.directory_write = directory_write
        self.perms_by_app = perms_by_app

    @property
    def subject(self) -> str:
        return ("an application permitted to change the directory" if self.directory_write
                else "an application")


def credential_row(r: dict, run: _Run) -> tuple[CryptoAsset, dict, int]:
    """One credential's row, what the shared-certificate check needs, and how many of its
    two dates could not be read."""
    app = _col(r, "AppDisplayName") or "(unnamed application)"
    app_id = _col(r, "AppId")
    kind = _col(r, "CredentialType") or "(unstated)"
    label = _col(r, "CredentialDisplayName")
    raw_start, raw_end = _col(r, "StartDateTimeUtc"), _col(r, "EndDateTimeUtc")
    permissions = _permissions(_col(r, "PermissionsOfInterest"))
    start, end = parse_date(raw_start, run.fmt), parse_date(raw_end, run.fmt)
    unreadable = int(start is None) + int(end is None)
    kind_word = ("certificate" if kind == _CERTIFICATE else
                 "secret" if kind == _PASSWORD else kind.lower())
    # The application ID's start keeps rows apart when two applications share a name.
    short_id = app_id[:8] if app_id else "unidentified"
    flags: set[str] = {"credential-key-unknown"}
    lifetime = age = remaining = None
    verdict = "unknown"
    if kind == _PASSWORD:
        flags.add("credential-shared-secret")
    if start is None or end is None:
        flags.add("credential-date-unreadable")
        notes = (f"A {kind_word} credential on {run.subject}. Its validity dates could not be "
                 "read, so its lifetime is not stated and it is not graded.")
    else:
        lifetime, age, remaining = (end - start).days, (run.now - start).days, (end - run.now).days
        ceiling = _ceiling(kind)
        if lifetime > ceiling:
            verdict = "weak"
            flags.add(f"credential-lifetime-excessive:{_years(lifetime)}y")
        else:
            verdict = "acceptable"
        if lifetime >= PERMANENT_CREDENTIAL_DAYS:
            flags.add("credential-never-expires")
        if age > ceiling:
            flags.add(f"credential-unrotated:{_years(age)}y")
        if remaining < 0:
            flags.add("credential-expired")
        notes = _credential_note(kind_word, start, end, lifetime, age, remaining, ceiling,
                                 flags, run)
    for p in permissions:
        if p in CREDENTIAL_MINTING_PERMISSIONS:
            flags.add(f"credential-minting-permission:{p}")
    if permissions:
        notes += f" Permissions held: {'; '.join(permissions)}."
    asset = CryptoAsset(
        name=f"application {kind_word} — {app} [{short_id}]",
        role=roles.application_credential(kind_word, run.directory_write),
        data_state="key-material", protocol="oauth-client-credential", source=NAME,
        source_class="private", source_name=run.source_name, collected_at=run.when,
        verdict=verdict, flags=sorted(flags), notes=notes,
        extra={"app_display_name": app, "app_id": app_id, "credential_type": kind,
               "credential_owner": _col(r, "CredentialOwner"),
               "credential_display_name": label,
               "valid_from": start.isoformat() if start else raw_start,
               "valid_to": end.isoformat() if end else raw_end,
               "lifetime_days": lifetime, "age_days": age, "days_remaining": remaining,
               "permissions": permissions,
               "permission_detail": run.perms_by_app.get(app_id, [])})
    return asset, {"app_id": app_id, "kind": kind, "label": label, "from": raw_start,
                   "to": raw_end, "asset": asset}, unreadable


def _credential_note(kind_word: str, start: datetime, end: datetime, lifetime: int, age: int,
                     remaining: int, ceiling: int, flags: set[str], run: _Run) -> str:
    window = (f"Valid {start:%Y-%m-%d} to {end:%Y-%m-%d} ({lifetime} days, "
              f"about {duration(lifetime)}), in use for {duration(age)} so far")
    if remaining < 0:
        window += f", and expired {-remaining} days ago"
    if "credential-never-expires" in flags:
        lead = (f"This credential is valid for about {_years(lifetime)} years, the date a tool "
                "writes for a credential set never to expire, so no rotation will replace "
                "it. ")
    elif f"credential-lifetime-excessive:{_years(lifetime)}y" in flags:
        lead = (f"Valid for about {_years(lifetime)} years, against a recommended cryptoperiod "
                f"of {ceiling} days for this kind of key (NIST SP 800-57 Part 1 Rev. 5). ")
    else:
        lead = ""
    body = f"A {kind_word} credential on {run.subject}. {window}."
    if kind_word == "secret":
        body += (" A client secret is held in full by every system that uses it, so it is no "
                 "better protected than the weakest of them; a certificate credential would "
                 "keep the private key with the application.")
    else:
        body += (" A certificate credential is asymmetric, so the private key need never leave "
                 "the application; it is the stronger of the two kinds Microsoft Entra offers.")
    body += (" The export records no key algorithm, size or storage, so the key's strength is "
             "not assessed.")
    return lead + body


def flag_shared_certificates(built: list[tuple[CryptoAsset, dict]]) -> None:
    """Flag certificates whose name and validity, to the second, appear on several applications.

    The export holds no thumbprint, so this cannot prove one certificate;
    the same subject and the same issue and expiry times to the second is
    strong evidence of one uploaded several times. ``shared-credential:<n>``
    is a fact about how credentials are arranged, not a grade.
    """
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for _asset, d in built:
        if d["kind"] == _CERTIFICATE and d["label"]:
            groups.setdefault((d["label"], d["from"], d["to"]), []).append(d)
    for details in groups.values():
        app_ids = sorted({d["app_id"] for d in details if d["app_id"]})
        if len(app_ids) < 2:
            continue
        for d in details:
            a: CryptoAsset = d["asset"]
            a.flags = sorted(set(a.flags) | {f"shared-credential:{len(app_ids)}"})
            a.extra["shared_credential_apps"] = [i for i in app_ids if i != d["app_id"]]
            a.notes += (f" A certificate with the same name and the same validity, to the "
                        f"second, is on {len(app_ids)} applications, which strongly suggests "
                        "one certificate uploaded to all of them (the export holds no "
                        f"thumbprint to prove it). If so, one stolen key reaches all "
                        f"{len(app_ids)}, and removing it from one leaves the others working.")


def no_credential_row(r: dict, run: _Run) -> CryptoAsset:
    """An application listed with no credential in the export."""
    app = _col(r, "AppDisplayName") or "(unnamed application)"
    app_id = _col(r, "AppId")
    short_id = app_id[:8] if app_id else "unidentified"
    permissions = _permissions(_col(r, "PermissionsOfInterest"))
    app_created = _col(r, "ApplicationCreatedDateUtc")
    sp_created = _col(r, "ServicePrincipalCreatedDateUtc")
    if not app_created and sp_created:
        # A service principal with no local registration: an application
        # registered in another tenant and consented to here.
        flags = ["credential-held-by-publisher"]
        notes = ("This tenant holds no registration for this application, only a consented "
                 "service principal, so the credential it signs in with is held by its "
                 "publisher. Its type, age and strength cannot be seen here, and it cannot be "
                 "rotated or revoked from here.")
    else:
        flags = ["credentials-not-visible"]
        notes = ("A registration in this tenant with no secret and no certificate in the "
                 "export. Either it signs in with a federated credential, which stores no key, "
                 "or it is unused and its permissions are consent nothing exercises. The "
                 "export cannot tell which, so it is not graded.")
    for p in permissions:
        if p in CREDENTIAL_MINTING_PERMISSIONS:
            flags.append(f"credential-minting-permission:{p}")
    if permissions:
        notes += f" Permissions held: {'; '.join(permissions)}."
    return CryptoAsset(
        name=f"application with no visible credential — {app} [{short_id}]",
        role=roles.application_credential_absent(run.directory_write),
        data_state="key-material", protocol="oauth-client-credential", source=NAME,
        source_class="private", source_name=run.source_name, collected_at=run.when,
        verdict="unknown", flags=sorted(set(flags)), notes=notes,
        extra={"app_display_name": app, "app_id": app_id, "permissions": permissions,
               "permission_detail": run.perms_by_app.get(app_id, []),
               "application_created": app_created, "service_principal_created": sp_created})


def scope_row(cred_rows: list[dict], app_rows: list[dict], run: _Run) -> CryptoAsset:
    """What the export covers."""
    passwords = sum(1 for r in cred_rows if _col(r, "CredentialType") == _PASSWORD)
    certificates = sum(1 for r in cred_rows if _col(r, "CredentialType") == _CERTIFICATE)
    apps = len({_col(r, "AppId") for r in app_rows if _col(r, "AppId")}
               | {_col(r, "AppId") for r in cred_rows if _col(r, "AppId")})
    scope = ("The export covers only applications holding directory write permissions, so it "
             "is not a list of every application's credentials: an application without them "
             "is not here, which does not mean it holds none. " if run.directory_write else
             "An application not in the export is not here, which does not mean it holds no "
             "credential. ")
    return CryptoAsset(
        name="Application credential scope", role=roles.application_credential_scope(),
        data_state="key-material", protocol="oauth-client-credential", source=NAME,
        source_class="private", source_name=run.source_name, collected_at=run.when,
        verdict="n/a", flags=["scope-directory-write-only"] if run.directory_write else [],
        hosts_count=apps,
        notes=(f"{apps} application(s) and {len(cred_rows)} credential(s): {passwords} client "
               f"secret(s) and {certificates} certificate(s). {scope}The export records no key "
               "algorithm, size or storage, so no row is graded above acceptable and none is "
               "assessed for post-quantum exposure."),
        extra={"applications": str(apps), "credentials": str(len(cred_rows)),
               "passwords": str(passwords), "certificates": str(certificates)})


def step(ctx: Context) -> StepResult:
    """The plug-in's step."""
    settings = ctx.settings or {}
    creds_path = ctx.input
    apps_path = _entra.newest(ctx, "applications")
    cred_rows = _read(creds_path)
    app_rows = _read(apps_path)
    perm_rows = _read(_entra.newest(ctx, "permissions"))
    if not cred_rows and not app_rows:
        why = ("no input was given" if creds_path is None and apps_path is None else
               "the files named hold no rows or do not exist")
        return StepResult(gaps=[coverage.gap(
            coverage.NOT_COLLECTED,
            f"no Microsoft Entra application credential export was read: {why}. Without it, "
            "which applications hold secrets or certificates, and how long each stays valid, "
            "are not known",
            impact=("Whether any application credential has expired, will never expire, or "
                    "is valid far longer than recommended is not known, and the applications "
                    "that sign in without a person are left out of the account picture."),
            impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
            harvest=("Run the read-only Microsoft Graph PowerShell script in docs/COLLECTORS.md "
                     "(entra_app_credentials) and name its credentials CSV as the reader's "
                     "input."))])

    fmt = str(settings.get("date_format") or "")
    when = (file_mtime_date(creds_path) if creds_path is not None else None) or (
        file_mtime_date(apps_path) if apps_path is not None else None) or ""
    source_name = ("Microsoft Entra application credential export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    perms_by_app: dict[str, list[str]] = {}
    for r in perm_rows:
        aid, value, resource = _col(r, "AppId"), _col(r, "PermissionValue"), _col(r, "ResourceName")
        if not aid or not value:
            continue
        entry = f"{value} on {resource}" if resource else value
        if entry not in perms_by_app.setdefault(aid, []):
            perms_by_app[aid].append(entry)
    run = _Run(source_name, when, ctx.ref_time,
               fmt, str(settings.get("scope") or "").strip().lower() == DIRECTORY_WRITE,
               perms_by_app)

    assets: list[CryptoAsset] = []
    built: list[tuple[CryptoAsset, dict]] = []
    unreadable = 0
    for r in cred_rows:
        asset, detail, bad = credential_row(r, run)
        unreadable += bad
        built.append((asset, detail))
        assets.append(asset)
    flag_shared_certificates(built)
    seen = {_col(r, "AppId") for r in cred_rows}
    for r in app_rows:
        aid = _col(r, "AppId")
        if not aid or aid in seen:
            continue
        assets.append(no_credential_row(r, run))
        seen.add(aid)
    assets.append(scope_row(cred_rows, app_rows, run))

    gaps = [coverage.gap(
        coverage.COULD_NOT_TEST,
        "application credential key strength: the export gives each credential's type and "
        "validity dates but no key algorithm, key size or key storage, so no credential is "
        "graded above acceptable and none is assessed for post-quantum exposure",
        impact=("Each credential is graded on its type and dates alone, so its grade is a "
                "ceiling: it can only fall once the key is seen. Post-quantum exposure is not "
                "assessed for any application credential."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.LOW_FIDELITY,
        harvest="Export each certificate credential's public key, or its thumbprint, as well.")]
    if unreadable:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            f"{unreadable} application credential date(s) could not be read as "
            + (f"the format {fmt!r} set for this reader" if fmt else "ISO 8601")
            + "; those credentials are listed ungraded and flagged credential-date-unreadable",
            impact=("Those credentials are listed, but not placed on the expiry timeline, so "
                    "any count of credentials expiring in a period is short by that many."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest=("Export the dates in ISO 8601, or set settings: date_format to the "
                     "export's format.")))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Microsoft Entra application credential export", gap_prefix=False)
