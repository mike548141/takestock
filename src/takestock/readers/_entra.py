"""What the Microsoft Entra readers share: reading the admin centre's CSV downloads.

The Microsoft Entra admin centre downloads its activity logs (sign-ins and
audit) as CSV files, one row per event, with times in UTC. Microsoft's page
*How to download logs in Microsoft Entra ID* (learn.microsoft.com) sets a
limit per file: up to 100,000 sign-in records and up to 250,000 audit
records. The readers find that a file stopped at a limit from its row count
alone (:func:`is_ceiling`). Microsoft does not document which rows a
download over the limit leaves out. The readers state only that such a file
may not cover the whole period asked for, and that nothing before its first
row was read; where one has to assume which end is missing, it assumes the
earliest, and says so.

Three things shape the helpers:

* **Headings are matched with surrounding spaces ignored** (:func:`col`), so
  a heading written with a trailing space is still found.
* **A file is read one row at a time** (:func:`stream`), because a download
  at its limit is tens of megabytes and a reader needs only its totals.
* **A file may carry a byte-order mark**, which ``utf-8-sig`` removes.

The readers name their exports in ``input:`` and in ``settings:``. A setting
naming a file may be a single path, a list of paths, or a pattern
(``*``, ``?`` or ``[`` in the file name), resolved as a target profile's
paths are (:func:`paths`, :func:`newest`).
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..model import CryptoAsset
from ..plugins import Context

#: Row counts a download stops on rather than a number of events: Microsoft's
#: two documented limits per file, and the other round numbers an export, a
#: filter or a paging script commonly stops on. A file holding exactly one of
#: these is read as having hit a limit.
EXPORT_CEILINGS = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
                   1_000_000)

#: The two client types Microsoft's Conditional Access *client apps* condition
#: counts as modern authentication ("Browser" and "Mobile apps and desktop
#: clients", on *How to Use Conditions in Conditional Access Policies*,
#: learn.microsoft.com). Every other value it lists (Exchange ActiveSync and
#: "Other clients": IMAP, POP, authenticated SMTP and the like) is legacy
#: authentication, which that page says does not support multifactor
#: authentication. Legacy is read as anything outside this pair, so a value
#: never seen before is reported rather than assumed modern.
MODERN_CLIENT_APPS = frozenset({"browser", "mobile apps and desktop clients"})
#: The client type the platform records when it does not know; counted apart.
UNKNOWN_CLIENT_APP = "unknown"

LEGACY_CLIENT_FLAG = "signin-legacy-client:"
LEGACY_CLIENT_NONE_FLAG = "signin-legacy-client-none"


def col(row: dict, name: str) -> str:
    """The value under heading ``name``, ignoring spaces around the heading; "" when absent."""
    if name in row:
        return str(row.get(name) or "").strip()
    for key, value in row.items():
        if key and key.strip() == name:
            return str(value or "").strip()
    return ""


def stream(path: Path) -> Iterator[dict]:
    """The file's rows, one at a time."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        yield from csv.DictReader(fh)


def is_ceiling(rows: int) -> bool:
    """Whether a file's row count is a limit it stopped on (:data:`EXPORT_CEILINGS`)."""
    return rows in EXPORT_CEILINGS


def _expand(ctx: Context, value: str) -> list[Path]:
    path = ctx.inbox_path(value)
    if any(ch in path.name for ch in "*?["):
        return sorted(path.parent.glob(path.name)) if path.parent.is_dir() else []
    return [path]


def paths(ctx: Context, key: str) -> list[Path]:
    """Every file the setting ``key`` names: a path, a pattern, or a list of either.

    A pattern is expanded in name order. A path that does not exist is
    returned as it is, so the reader can say it was named and not found.
    """
    value: Any = (ctx.settings or {}).get(key)
    if not value:
        return []
    values = [value] if isinstance(value, str) else list(value)
    out: list[Path] = []
    for v in values:
        for p in _expand(ctx, str(v)):
            if p not in out:
                out.append(p)
    return out


def newest(ctx: Context, key: str) -> Path | None:
    """The one file the setting ``key`` names: for a pattern or a list, the last in name order.

    A date written into each file's name (``members-2030-01-31.csv``) makes
    the last in name order the newest.
    """
    found = paths(ctx, key)
    return found[-1] if found else None


def primary(ctx: Context, key: str) -> Path | None:
    """A reader's main export: ``input:``, else the setting ``key``."""
    return ctx.input if ctx.input is not None else newest(ctx, key)


def setting_number(ctx: Context, key: str, default: float) -> float:
    """A numeric setting, or ``default`` when it is absent or not a number."""
    value = (ctx.settings or {}).get(key)
    if isinstance(value, bool) or value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


#: Said after a period read from a file that stopped at a download limit.
CUT_SHORT = (" (the download stopped at its row limit, so it may not cover the whole period "
             "asked for)")


def window_days(first: str, last: str) -> str:
    """``first..last`` as dates, with ``?`` for an end that is not recorded."""
    return f"{first[:10] or '?'}..{last[:10] or '?'}"


def span_minutes(first: str, last: str, ceiling: bool) -> str:
    """The period a file covers, to the minute, for a sentence."""
    if not first or not last:
        return "over an unrecorded period"
    text = f"over {first[:16].replace('T', ' ')} to {last[:16].replace('T', ' ')} UTC"
    if ceiling:
        text += CUT_SHORT
    return text


def span_days(first: str, last: str, ceiling: bool) -> str:
    """The period a file covers, by day, for a sentence."""
    if not first or not last:
        return "over an unrecorded period"
    text = f"over {first} to {last}"
    if ceiling:
        text += CUT_SHORT
    return text


def legacy_client_row(client_apps: dict[str, dict], total: int, *, source: str,
                      source_name: str, collected_at: str, period: str, population: str,
                      limit: str, window: str, ceiling: bool) -> CryptoAsset:
    """One row saying whether any sign-in came from a legacy authentication client.

    ``client_apps`` maps each ``Client app`` value to its sign-in count
    (``count``) and the accounts that used it (``principals``). The row is
    written at zero too, since "none seen" is an answer: ``n/a`` then, never a
    pass, because none seen in a window is not a setting that blocks them.
    Any legacy sign-in makes it ``weak``. NZISM v3.9 16.7.42.C.01 (MUST) requires
    multifactor authentication for all user accounts on cloud-based services, and these
    clients cannot ask for it.
    """
    from .. import roles

    legacy = {k: v for k, v in client_apps.items()
              if k.lower() not in MODERN_CLIENT_APPS and k.lower() != UNKNOWN_CLIENT_APP}
    unknown = sum(v["count"] for k, v in client_apps.items() if k.lower() == UNKNOWN_CLIENT_APP)
    count = sum(v["count"] for v in legacy.values())
    accounts = len({u for v in legacy.values() for u in v["principals"]})
    flags = ([f"{LEGACY_CLIENT_FLAG}{k}:{v['count']}" for k, v in sorted(legacy.items())]
             or [LEGACY_CLIENT_NONE_FLAG])
    mix = ", ".join(f"{k} {v['count']:,}"
                    for k, v in sorted(client_apps.items(), key=lambda kv: -kv[1]["count"]))
    if count:
        seen = (f"{count:,} of {total:,} {population} {period} came from a legacy "
                f"authentication client, by {accounts} account(s): "
                + ", ".join(f"{k} {v['count']:,}" for k, v in sorted(legacy.items())) + ". ")
    else:
        seen = (f"None of {total:,} {population} {period} came from a legacy authentication "
                "client (Exchange ActiveSync, or the older mail protocols Microsoft groups as "
                "other clients: IMAP, POP, authenticated SMTP and the like). ")
    notes = (seen
             + "A legacy client cannot ask for a second sign-in check, which NZISM v3.9 "
               "16.7.42.C.01 (MUST) requires for user accounts on cloud-based services. "
             + (f"{unknown:,} sign-in(s) record the client type as unknown; they are counted "
                "apart rather than assumed either way. " if unknown else "")
             + f"All client types: {mix}. "
             + ("No legacy sign-in in this period does not show that a policy blocks legacy "
                "clients; the policies are not in this export. " if not count else "")
             + f"{limit}.")
    return CryptoAsset(
        name=f"Legacy mail and client protocols — {population}",
        data_state="identity", protocol="authentication-flow",
        role=roles.legacy_client_signins(count),
        source=source, source_class="private", source_name=source_name,
        collected_at=collected_at, verdict="weak" if count else "n/a",
        flags=flags, hosts_count=accounts, usage_count=count, notes=notes,
        extra={"window": window, "window_is_ceiling": "yes" if ceiling else "no",
               "legacy_client_signins": str(count),
               "legacy_client_accounts": str(accounts),
               "unknown_client_signins": str(unknown),
               "signins": str(total),
               **{f"client_{k.lower().replace(' ', '_')}": str(v["count"])
                  for k, v in client_apps.items()}})
