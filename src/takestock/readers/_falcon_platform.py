"""Shared reading for the CrowdStrike Falcon platform and software readers.

``falcon_software``, ``falcon_vulnerabilities``, ``falcon_system_resources``,
``falcon_windows_os_security`` and ``falcon_sha1_signed_modules`` each read a
CSV whose headings depend on where it was exported from: a LogScale query
names its own columns, an API record flattened to CSV carries the API's field
names, and the Falcon console writes headings of its own. Each reader
therefore names every field it reads, with a default heading, and
``settings: columns:`` names another heading, or a list of headings tried in
order, for any field.

Headings are matched as :mod:`takestock.readers._table` matches them:
ignoring case, and with spaces and hyphens read as ``_``.
"""

from __future__ import annotations

import csv
import dataclasses
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..plugins import Context
from . import _entra, _table


def columns(ctx: Context, defaults: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    """Each field's headings, in the order tried: the default, unless ``settings: columns:`` names others."""
    named = (ctx.settings or {}).get("columns") or {}
    out: dict[str, tuple[str, ...]] = {field: (heading,) for field, heading in defaults.items()}
    if isinstance(named, Mapping):
        for field, heading in named.items():
            if field not in out:
                continue
            if isinstance(heading, str) and heading.strip():
                out[field] = (heading,)
            elif isinstance(heading, (list, tuple)):
                listed = tuple(str(h) for h in heading if str(h).strip())
                if listed:
                    out[field] = listed
    return out


def first(row: Mapping[str, str], headings: Sequence[str]) -> str:
    """The first non-blank value under any of ``headings`` ("" when none)."""
    for h in headings:
        v = _table.value(row, h).strip()
        if v:
            return v
    return ""


def has_column(header: Iterable[str], headings: Iterable[str]) -> bool:
    """Whether the export's header holds any of ``headings``."""
    keys = {_table.heading(h) for h in header}
    return any(_table.heading(h) in keys for h in headings)


def load(path: Path | None) -> tuple[list[dict[str, str]], list[str], str]:
    """A CSV's rows (headings normalised) and its header as written.

    ``([], [], why)`` when the file cannot be read; ``([], [], "")`` when it
    is absent.
    """
    if path is None or not path.exists():
        return [], [], ""
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            header = next(csv.reader(fh), [])
        return _table.read(path), [h for h in header if h], ""
    except (OSError, UnicodeDecodeError, csv.Error, ValueError) as exc:
        return [], [], str(exc)


def stream(path: Path, wanted: Mapping[str, Sequence[str]]) -> Iterator[dict[str, str]]:
    """The rows of a large CSV one at a time, holding only the ``wanted`` fields.

    Each row is a mapping of field name to value, the value taken from the
    first of the field's headings the header holds. The whole file is never
    held in memory. A field can hold a large block of text with line breaks
    inside it (a JSON document, say), so the file is read by the ``csv``
    module, never line by line, and the module's field size limit is raised
    for the read and put back after it. Raises ``OSError``,
    ``UnicodeDecodeError`` or ``csv.Error`` for a file that cannot be read.
    """
    old = csv.field_size_limit()
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            header = [_table.heading(h) for h in next(reader, [])]
            index: dict[str, int] = {}
            for field, headings in wanted.items():
                for h in headings:
                    key = _table.heading(h)
                    if key in header:
                        index[field] = header.index(key)
                        break
            for raw in reader:
                if not any(c.strip() for c in raw):
                    continue
                yield {f: (raw[i].strip() if i < len(raw) else "") for f, i in index.items()}
    finally:
        csv.field_size_limit(old)


def header_of(path: Path) -> list[str]:
    """The header row of a CSV as written ([] when it has none)."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return [h for h in next(csv.reader(fh), []) if h]


def words(raw: Any, default: Sequence[str]) -> tuple[str, ...]:
    """A setting holding one word or a list, lower-cased; ``default`` when it is not set."""
    if raw is None:
        return tuple(w.lower() for w in default)
    values = [raw] if isinstance(raw, str) else list(raw)
    return tuple(str(v).strip().lower() for v in values)


def file_setting(ctx: Context, conf: Mapping[str, Any], key: str = "file") -> Path | None:
    """The file a nested setting names (a path, a pattern or a list), resolved as a top-level one is."""
    if not conf.get(key):
        return None
    return _entra.newest(dataclasses.replace(ctx, settings={key: conf[key]}), key)


def nested(ctx: Context, name: str) -> dict[str, Any]:
    """A setting that is either a mapping or, as a shorthand, the file it names."""
    conf = (ctx.settings or {}).get(name) or {}
    if isinstance(conf, str):
        return {"file": conf}
    return dict(conf) if isinstance(conf, Mapping) else {}


def heading_list(raw: Any, default: Sequence[str]) -> tuple[str, ...]:
    """A heading setting given as one heading or a list; ``default`` when it is not set."""
    if not raw:
        return tuple(default)
    return (str(raw),) if isinstance(raw, str) else tuple(str(v) for v in raw)


def plural(n: int, word: str) -> str:
    """``1 machine``, ``2 machines``."""
    return f"{n:,} {word}{'' if n == 1 else 's'}"
