"""Shared reading for the CrowdStrike Falcon identity and endpoint-event readers.

``falcon_logins``, ``falcon_accounts``, ``falcon_logon_events`` and
``falcon_endpoint_events`` each read one or more CSV exports in which a
field may sit under a heading of the exporter's choosing. Each reader keeps
a table per export of the fields it reads and their default headings;
``settings: columns: {<export>: {<field>: <heading>}}`` names another
heading, or a list of headings of which the first holding a value is read.
Headings match ignoring case, spaces and hyphens (:mod:`._table`).

Windows logon types are read by Microsoft's numbers or names, as Microsoft
lists them for security event 4624 (*4624(S) An account was successfully
logged on*, learn.microsoft.com): 0 ``System``, 2 ``Interactive``,
3 ``Network``, 4 ``Batch``, 5 ``Service``, 7 ``Unlock``, 8 ``NetworkCleartext``,
9 ``NewCredentials``, 10 ``RemoteInteractive``, 11 ``CachedInteractive``,
12 ``CachedRemoteInteractive``, 13 ``CachedUnlock``.
A name is compared with case, spaces, hyphens and underscores ignored, so
``Remote interactive`` and ``RemoteInteractive`` are the same type.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..plugins import Context
from . import _table

#: Microsoft's logon type numbers and names (event 4624's logon type table).
LOGON_TYPES: dict[str, str] = {
    "0": "System", "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive",
    "11": "CachedInteractive", "12": "CachedRemoteInteractive", "13": "CachedUnlock",
}

INTERACTIVE = "2"
NETWORK = "3"
SERVICE = "5"
NETWORK_CLEARTEXT = "8"
REMOTE_INTERACTIVE = "10"

_SQUASH = re.compile(r"[\s_\-]+")

#: Said of an event export, which holds counts but no time stamps.
NO_TIMES_NOTE = ("The export holds counts and no time stamps, so the period it covers is the "
                 "search period of the query that wrote it, which the file does not record.")


def squash(text: str) -> str:
    """``text`` lower-cased with spaces, hyphens and underscores removed."""
    return _SQUASH.sub("", (text or "").strip().lower())


def logon_type(raw: str) -> str:
    """A logon type as Microsoft's number ("" when blank; the text itself when unknown).

    A number is kept as it is; a name is matched to Microsoft's list ignoring
    case, spaces, hyphens and underscores.
    """
    text = (raw or "").strip()
    if not text or text.isdigit():
        return text
    want = squash(text)
    for number, name in LOGON_TYPES.items():
        if squash(name) == want:
            return number
    return text


def headings(ctx: Context, tables: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Each export's field-to-heading map, with ``settings: columns:`` applied."""
    named = (ctx.settings or {}).get("columns") or {}
    out = {table: dict(heads) for table, heads in tables.items()}
    if not isinstance(named, Mapping):
        return out
    for table, fields in named.items():
        if table not in out or not isinstance(fields, Mapping):
            continue
        for field, heading in fields.items():
            if field not in out[table]:
                continue
            if isinstance(heading, str) and heading.strip():
                out[table][field] = heading
            elif isinstance(heading, list) and all(isinstance(h, str) for h in heading):
                out[table][field] = [h for h in heading if h.strip()]
    return out


def value(row: Mapping[str, str], heading: Any) -> str:
    """The field's value: under its heading, or the first of its headings holding one.

    ``--``, which a console writes for an empty cell, is read as blank.
    """
    names = heading if isinstance(heading, list) else [str(heading or "")]
    for h in names:
        if not h:
            continue
        v = _table.value(row, h).strip()
        if v and v != "--":
            return v
    return ""


def rows(path: Path | None) -> tuple[list[dict[str, str]], str]:
    """The file's rows and, when it could not be read, why ("" when read, or when not named)."""
    if path is None:
        return [], ""
    if not path.exists():
        return [], f"{path.name} was named and not found"
    try:
        return _table.read(path), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], f"{path.name} could not be read ({exc})"


def number(raw: str) -> int:
    """A count; blank or unreadable is 0."""
    try:
        return int((raw or "").strip() or 0)
    except ValueError:
        return 0


def events(raw: str) -> int:
    """A grouped row's event count; blank or unreadable is read as 1, since the row is at least one."""
    try:
        return int((raw or "").strip())
    except ValueError:
        return 1


def machine(row: Mapping[str, str], heads: Mapping[str, Any]) -> str:
    """The machine a row is about, for counting: its name ignoring case, else its sensor ID."""
    name = value(row, heads.get("machine", ""))
    if name:
        return name.casefold()
    return value(row, heads.get("sensor_id", ""))


def machine_label(row: Mapping[str, str], heads: Mapping[str, Any]) -> str:
    """The machine a row is about, for naming: its name as written, else its sensor ID."""
    return value(row, heads.get("machine", "")) or value(row, heads.get("sensor_id", ""))


def is_yes(text: str) -> bool:
    """Whether a cell reads as yes (``yes``, ``true`` or ``1``, ignoring case)."""
    return (text or "").strip().lower() in ("yes", "true", "1")


def source_name(label: str, when: str | None) -> str:
    """``CrowdStrike Falcon <label> export, file dated <date>``."""
    return (f"CrowdStrike Falcon {label} export, "
            + (f"file dated {when}" if when else "file date unavailable"))
