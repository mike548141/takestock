"""Shared reading for the CrowdStrike Falcon traffic readers.

``falcon_connections``, ``falcon_http`` and ``falcon_tls_clienthello`` each
read a CSV written by a CrowdStrike LogScale (Falcon Next-Gen SIEM) query
that groups the endpoint sensor's network events and counts them.
``docs/COLLECTORS.md`` gives each query. The grouped columns carry the
sensor's own field names (``aid``, ``RemotePort`` and so on); the count
column is whatever the query names it, ``_count`` when ``count()`` is given
no name. A reader's ``settings: columns:`` names other headings for any field,
so an export written by another query is read without editing it.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping
from pathlib import Path

from ..plugins import Context
from . import _table

#: The heading ``count()`` writes when the query gives it no name.
COUNT_HEADING = "_count"


def headings(ctx: Context, defaults: Mapping[str, str]) -> dict[str, str]:
    """Each field's column heading: the reader's default, unless ``settings: columns:`` names another."""
    named = (ctx.settings or {}).get("columns") or {}
    out = dict(defaults)
    if isinstance(named, Mapping):
        for field, heading in named.items():
            if field in out and isinstance(heading, str) and heading.strip():
                out[field] = heading
    return out


def load(path: Path | None) -> tuple[list[dict[str, str]], str]:
    """A CSV's rows (headings normalised), or ([], why) when it cannot be read; ([], "") when absent."""
    if path is None or not path.exists():
        return [], ""
    try:
        return _table.read(path), ""
    except (OSError, UnicodeDecodeError, csv.Error, ValueError) as exc:
        return [], str(exc)


def cell(row: Mapping[str, str], heading: str) -> str:
    """The value under ``heading`` ("" when the export has no such column)."""
    return _table.value(row, heading).strip()


def count(raw: str) -> int:
    """A row's event count; blank or unreadable is read as 1, since a grouped row is at least one event."""
    try:
        return int(raw.strip())
    except ValueError:
        return 1


def program(image: str) -> str:
    """The file name at the end of a program's path, with either kind of slash."""
    return image.replace("\\", "/").rsplit("/", 1)[-1].strip()


def top(counter: Mapping[str, int], n: int = 3) -> str:
    """The ``n`` largest entries as ``name (count)``, largest first, ties by name; blank names are dropped."""
    ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return "; ".join(f"{k} ({v:,})" for k, v in ranked if k)


def share(n: int, of: int) -> str:
    """``n`` as a percentage of ``of``, to one decimal place; ``unknown`` when ``of`` is 0."""
    return f"{n * 100 / of:.1f}%" if of else "unknown"


def plural(n: int, word: str) -> str:
    """``1 machine``, ``2 machines``."""
    return f"{n:,} {word}{'' if n == 1 else 's'}"
