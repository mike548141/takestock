"""Reading a CSV export whose column names vary: shared by the library's CSV readers.

An administrator's export is often saved by hand, so its headings vary in
case and in how words are joined (``DB_NAME``, ``db name``, ``Db-Name``).
:func:`read` returns each data row with its headings normalised, and
:func:`value` looks a field up under any of the names it may carry.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Mapping
from pathlib import Path

_JOIN = re.compile(r"[\s\-]+")


def heading(name: str) -> str:
    """A column heading in the form lookups use: lower case, words joined by ``_``."""
    return _JOIN.sub("_", (name or "").strip().lower())


def read(path: Path) -> list[dict[str, str]]:
    """The data rows of a CSV file, keyed by normalised heading.

    A byte-order mark is ignored, as are rows with no value at all. When two
    headings normalise to the same name, the first one's value is kept.
    Raises ``OSError``, ``UnicodeDecodeError`` or ``csv.Error`` for a file
    that cannot be read as CSV.
    """
    with path.open(newline="", encoding="utf-8-sig") as f:
        rows = []
        for raw in csv.DictReader(f):
            row: dict[str, str] = {}
            for k, v in raw.items():
                if k is None:
                    continue  # values beyond the last heading
                key = heading(k)
                if key not in row:
                    row[key] = "" if v is None else str(v).strip()
            if any(row.values()):
                rows.append(row)
        return rows


def value(row: Mapping[str, str], *names: str) -> str:
    """The value under the first of ``names`` the row has a column for ("" if none).

    The first name present wins even when its value is empty, so a column
    left blank is read as blank rather than filled from a later synonym.
    """
    for name in names:
        key = heading(name)
        if key in row:
            return row[key]
    return ""
