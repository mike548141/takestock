"""WinRM configuration: does a Windows host *require* encrypted remote administration?

Windows Remote Management (WinRM) listens on 5985 (HTTP) and 5986 (HTTPS).
A listener on 5985 proves neither an exposure nor its absence: with the
default Negotiate authentication (Kerberos, or NTLM where Kerberos is not
available) WinRM encrypts each message itself, so the session is protected
even though the HTTP transport is plain. Two service settings switch that
protection off, and only the configuration shows them. This collector reads
that configuration from a supplied export.

**The export** is a CSV, by default ``inbox/winrm-config.csv`` (set
``winrm_inbox.export`` in the target profile to move it), one row per host.
Columns, matched case-blind:

* ``hostname`` (or ``computername``, ``host``, ``name``), and optionally a
  stable ``host_id`` (or ``device_id``, ``asset_id``) that survives a rename;
* ``allow_unencrypted_service`` and ``basic_service``: the two settings that
  decide the verdict;
* ``allow_unencrypted_client``, ``basic_client``, ``credssp_service`` and
  ``https_listener``: context.

Each setting reads ``true``/``false`` (also ``1``/``0``, ``yes``/``no``,
``on``/``off``, ``enabled``/``disabled``). PowerShell produces them with
``Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted`` and its siblings
under ``Service\\Auth`` and ``Client``.

**Grading**:

* ``weak``: the service accepts unencrypted messages, Basic authentication is
  enabled on the service, or the host as a client will send unencrypted
  messages. None of these is a default.
* ``acceptable``: both deciding service settings were read and both are
  protective. Never ``strong``: these are on/off settings, not graded
  algorithms.
* ``unknown``: a deciding setting is blank or unreadable. A blank cell is a
  setting nobody collected, never a setting that is off.

Basic authentication on the **client** is enabled by default on Windows, so
it is recorded and explained but never flagged. CredSSP on the service is
flagged (it hands the caller's credentials on to the host) but does not move
the verdict, which is about encryption. An HTTPS listener is recorded as a
mitigating fact and moves nothing: it does not close the plain-HTTP path.

The port table's ``opportunistic`` reading of 5985 is not applied here:
these rows read the setting the table can only guess at.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from .. import coverage
from ..config import display_path, inbox_path
from ..model import CryptoAsset, register_informational_prefixes
from ..util import file_mtime_date

SOURCE = "winrm_config"
DEFAULT_EXPORT = "inbox/winrm-config.csv"
#: The plain-HTTP listener port the service settings govern.
HTTP_PORT = "5985"
ROLE = ("Remote administration service on this computer — whether it requires the "
        "instructions administrators send it, and the passwords used to send them, to be "
        "encrypted on the way")

ALLOW_UNENCRYPTED_SERVICE = "allow_unencrypted_service"
BASIC_SERVICE = "basic_service"
ALLOW_UNENCRYPTED_CLIENT = "allow_unencrypted_client"
BASIC_CLIENT = "basic_client"
CREDSSP_SERVICE = "credssp_service"
HTTPS_LISTENER = "https_listener"

DECIDING = (ALLOW_UNENCRYPTED_SERVICE, BASIC_SERVICE)
SETTINGS = (ALLOW_UNENCRYPTED_SERVICE, BASIC_SERVICE, ALLOW_UNENCRYPTED_CLIENT,
            BASIC_CLIENT, CREDSSP_SERVICE, HTTPS_LISTENER)

# Findings: a protection somebody turned off.
ALLOWS_UNENCRYPTED = "winrm-allows-unencrypted"
BASIC_ON_SERVICE = "winrm-basic-auth-service"
CLIENT_ALLOWS_UNENCRYPTED = "winrm-client-allows-unencrypted"
# A finding about credential delegation; it does not move the verdict.
CREDSSP_ON_SERVICE = "winrm-credssp-service"
# Facts and measurement limits.
HTTPS_LISTENER_FLAG = "winrm-https-listener"
NOT_ASSESSED = "not-assessed:"
UNREADABLE_VALUE = "unreadable-assessment:"

register_informational_prefixes(HTTPS_LISTENER_FLAG, NOT_ASSESSED, UNREADABLE_VALUE)

#: The two non-values a cell can hold, kept apart from True and False.
BLANK = "blank"
UNREADABLE = "unreadable"

_TRUE = {"true", "1", "yes", "on", "enabled"}
_FALSE = {"false", "0", "no", "off", "disabled"}

_HOST_COLUMNS = ("hostname", "computername", "host", "name")
_ID_COLUMNS = ("host_id", "device_id", "asset_id")


def _read(path: Path) -> tuple[list[dict], str]:
    """(rows, error); never raises, so an unreadable file is a gap, not a crash."""
    if not path.exists():
        return [], ""
    try:
        with path.open(newline="") as f:
            return list(csv.DictReader(f)), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def _col(row: dict, *names: str) -> str:
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n:
                return (v or "").strip()
    return ""


def setting(raw: str) -> bool | str:
    """One cell as True, False, :data:`BLANK` or :data:`UNREADABLE`."""
    text = (raw or "").strip().lower()
    if not text:
        return BLANK
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return UNREADABLE


def posture(values: dict[str, bool | str]) -> tuple[str, set[str], dict[str, int]]:
    """(verdict, flags, counts) for one host's settings."""
    flags: set[str] = set()
    counts = {"permissive": 0, "blank": 0, "unreadable": 0}
    for name in SETTINGS:
        value = values.get(name, BLANK)
        if value == BLANK:
            counts["blank"] += 1
            flags.add(f"{NOT_ASSESSED}{name}")
        elif value == UNREADABLE:
            counts["unreadable"] += 1
            flags.add(f"{UNREADABLE_VALUE}{name}")
    for name, flag in ((ALLOW_UNENCRYPTED_SERVICE, ALLOWS_UNENCRYPTED),
                       (BASIC_SERVICE, BASIC_ON_SERVICE),
                       (ALLOW_UNENCRYPTED_CLIENT, CLIENT_ALLOWS_UNENCRYPTED)):
        if values.get(name) is True:
            flags.add(flag)
            counts["permissive"] += 1
    if values.get(CREDSSP_SERVICE) is True:
        flags.add(CREDSSP_ON_SERVICE)
    if values.get(HTTPS_LISTENER) is True:
        flags.add(HTTPS_LISTENER_FLAG)
    # basic_client is deliberately not tested: it is on by default everywhere.
    if counts["permissive"]:
        verdict = "weak"
    elif all(isinstance(values.get(f), bool) for f in DECIDING):
        verdict = "acceptable"
    else:
        verdict = "unknown"
    return verdict, flags, counts


def notes_for(values: dict[str, bool | str], verdict: str, counts: dict[str, int]) -> str:
    """The row's own account, readable without the flag vocabulary."""
    parts: list[str] = []
    if values.get(ALLOW_UNENCRYPTED_SERVICE) is True:
        parts.append("the service accepts UNENCRYPTED messages — the protection that makes a "
                     "plain-HTTP WinRM session safe is turned off here")
    if values.get(BASIC_SERVICE) is True:
        parts.append("Basic authentication is enabled ON THE SERVICE, which carries the "
                     "password itself in a reversible form")
    if values.get(ALLOW_UNENCRYPTED_CLIENT) is True:
        parts.append("as a client, this host will send unencrypted messages to other hosts")
    if verdict == "acceptable":
        parts.append("the service requires encrypted messages and refuses Basic "
                     "authentication, both at their Windows defaults")
    if verdict == "unknown":
        missing = [f for f in DECIDING if not isinstance(values.get(f), bool)]
        parts.append("NOT READ — the export carries no usable value for "
                     + " or ".join(missing)
                     + ", so this host's posture is unmeasured rather than good")
    if values.get(CREDSSP_SERVICE) is True:
        parts.append("CredSSP is enabled on the service, which lets a caller's credentials "
                     "be passed on to further systems")
    if values.get(HTTPS_LISTENER) is True:
        parts.append("an HTTPS listener (5986) is also configured; it protects the outer "
                     "request but does not close the plain-HTTP path or change the settings "
                     "above")
    if values.get(BASIC_CLIENT) is True:
        parts.append("Basic authentication is enabled on the CLIENT, which is the Windows "
                     "default and not a finding on its own")
    if counts["unreadable"]:
        parts.append(f"{counts['unreadable']} setting(s) carried a value this build cannot read")
    if verdict == "weak":
        parts[0] = "PROTECTION DISABLED — " + parts[0]
    return "; ".join(parts)


def identity(row: dict) -> tuple[str, str, str]:
    """(hostname, host_id, join_basis) for one exported row."""
    hostname = _col(row, *_HOST_COLUMNS)
    host_id = _col(row, *_ID_COLUMNS)
    return hostname, host_id, "host_id" if host_id else ("hostname" if hostname else "")


def unread_listeners(other_assets: Iterable[CryptoAsset], covered: set[str]) -> list[str]:
    """Hosts another collector saw listening on 5985 that the export says nothing about."""
    out: dict[str, str] = {}
    for a in other_assets:
        if a.source == SOURCE or str(a.port) != HTTP_PORT:
            continue
        name = a.host or a.ip
        if name and name.casefold() not in covered:
            out.setdefault(name.casefold(), name)
    return sorted(out.values())


def _missing_export_gap(shown: str, fatal: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"{shown} (WinRM client and service configuration) — whether Windows hosts "
        "REQUIRE encrypted remote-administration messages or merely default to it; a "
        "listener on 5985 proves neither"
        + (f"; the file is present but could not be read ({fatal})" if fatal else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Windows servers are administered remotely, and nothing here says whether "
                "they require that session to be encrypted. A server that accepts an "
                "unencrypted administrative session exposes administrator credentials on "
                "the internal network."),
        harvest=("One configuration export with the columns this collector's documentation "
                 "names, one row per host."),
        nature=coverage.NO_DATA)


def collect(target: dict, root: Path | None = None,
            other_assets: Iterable[CryptoAsset] = ()) -> tuple[list[CryptoAsset], list[str]]:
    """Read the WinRM configuration export; return (assets, coverage gaps).

    ``other_assets`` are the run's other rows; any on port 5985 whose host the
    export does not cover is reported as a gap.
    """
    inbox = target.get("winrm_inbox") or {}
    path = inbox_path(inbox.get("export", DEFAULT_EXPORT), root)
    shown = display_path(path, root)
    rows, fatal = _read(path)
    if not rows:
        return [], [_missing_export_gap(shown, fatal)]

    mtime = file_mtime_date(path)
    source_name = (f"WinRM configuration export (file dated {mtime})" if mtime
                   else "WinRM configuration export (file date unavailable)")
    assets: list[CryptoAsset] = []
    gaps: list[str] = []
    covered: set[str] = set()
    unnamed = duplicates = incomplete = 0

    for row in rows:
        hostname, host_id, join_basis = identity(row)
        if not join_basis:
            unnamed += 1
            continue
        key = host_id.casefold() if host_id else hostname.casefold()
        if key in covered:
            duplicates += 1
            continue
        covered.add(key)
        if hostname:
            covered.add(hostname.casefold())
        values: dict[str, bool | str] = {f: setting(_col(row, f)) for f in SETTINGS}
        verdict, flags, counts = posture(values)
        if verdict == "unknown":
            incomplete += 1
        assets.append(CryptoAsset(
            name=f"WinRM configuration — {hostname or host_id}",
            role=ROLE if hostname else "",
            data_state="in-transit", protocol="winrm", port=HTTP_PORT, host=hostname,
            software="Windows Remote Management", source=SOURCE, source_class="private",
            source_name=source_name, collected_at=mtime or "",
            verdict=verdict, flags=sorted(flags), notes=notes_for(values, verdict, counts),
            extra={"host_id": host_id, "join_basis": join_basis,
                   **{f: values[f] for f in SETTINGS}}))

    if unnamed or duplicates:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{unnamed + duplicates} of {len(rows)} row(s) in {shown} produced no asset: "
            f"{unnamed} named no host and {duplicates} repeated a host already read (the "
            "first row for a host wins)",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("Some rows of the configuration export could not be tied to a machine, "
                    "so those machines are counted nowhere. The result for every machine "
                    "that was read stands."),
            harvest="A re-export with a hostname or host_id on every row.",
            nature=coverage.NO_DATA))

    if incomplete:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{incomplete} of {len(assets)} host(s) in {shown} have no usable value for "
            f"`{ALLOW_UNENCRYPTED_SERVICE}` or `{BASIC_SERVICE}`, the two settings that "
            "decide, so each is graded unknown rather than passed",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("For these hosts the settings that decide whether remote administration "
                    "must be encrypted came back empty. They are shown as unknown, not "
                    "compliant, and some of them may be the ones at risk."),
            harvest="A re-export with those two settings included.",
            nature=coverage.LOW_FIDELITY))

    unread = unread_listeners(other_assets, covered)
    if unread:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{len(unread)} host(s) seen with a listener on {HTTP_PORT} have no row in "
            f"{shown}, so whether they require encryption is unread: {', '.join(unread)}",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("These hosts are known to accept remote administration and their "
                    "settings were not exported, so the report cannot say whether they "
                    "insist on encrypting it."),
            harvest="A re-export covering the hosts named.",
            nature=coverage.LOW_FIDELITY))
    return assets, gaps
