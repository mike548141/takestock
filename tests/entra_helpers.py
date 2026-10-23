"""Shared pieces for the Microsoft Entra reader tests.

Every CSV these tests read is composed by hand in the test that uses it, in
the columns the reader reads: the Microsoft Entra admin centre's sign-in and
audit log downloads, and the CSV formats ``docs/COLLECTORS.md`` gives for the
role, membership and credential exports. Every name, ID and date is
synthetic (``example.test`` accounts, ``00000000-0000-4000-8000-…`` IDs,
dates in 2030), so they test the readers' behaviour, not any real export's
format; nothing here was captured.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

from takestock import config
from takestock.plugins import Context, Plugin
from takestock.policy import Policy

REF_TIME = datetime(2030, 6, 30, tzinfo=UTC)

#: The interactive and non-interactive sign-in download's columns these readers read.
SIGNIN_COLUMNS = ("Date (UTC)", "Request ID", "Correlation ID", "Username", "Application",
                  "Application ID ", "Resource", "Status", "Sign-in error code",
                  "Client app", "Authentication Protocol", "Original transfer method",
                  "Client credential type", "Compliant", "Authentication requirement",
                  "Conditional Access")
#: The application and managed identity sign-in download's columns these readers read.
SERVICE_COLUMNS = ("Date (UTC)", "Request ID", "Service principal ID", "Service principal name",
                   "Application ID", "Resource", "Status", "Credential key ID",
                   "Credential thumbprint", "Conditional Access")
ROLE_COLUMNS = ("RoleDisplayName", "PrincipalId", "PrincipalDisplayName",
                "PrincipalUserPrincipalName", "PrincipalType")


def guid(n: int) -> str:
    """A synthetic GUID ending in ``n``."""
    return f"00000000-0000-4000-8000-{n:012d}"


def write(path: Path, columns: tuple[str, ...] | list[str], rows: list[dict]) -> Path:
    """Write ``rows`` (missing columns blank) under ``columns`` and return the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="raise")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c.strip(), r.get(c, "")) for c in columns})
    return path


def ctx(plugin: Plugin, path: Path | None, settings: dict | None = None) -> Context:
    """A context for ``plugin`` with ``path`` as its input."""
    return Context(plugin=plugin, target={}, settings=settings or {}, input=path,
                   ref_time=REF_TIME, raw_dir=Path("."),
                   policy=Policy(config.load_baseline()), baseline={}, dictionary={},
                   port_table={}, collected_on="2030-06-30")


def by_name(rows: list) -> dict:
    """Rows keyed by name."""
    return {a.name: a for a in rows}
