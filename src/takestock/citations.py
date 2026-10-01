"""Resolve the baseline's citations into text a reader can check.

``data/baseline.yaml`` grades every algorithm token. Its ``authorities:``
block lists the documents those grades rest on (title, publisher, version,
date, link), its ``compliance_levels:`` block records what a cited control
obliges (MUST, SHOULD and so on, with the control text), and its
``citations:`` block says which document and control backs each table and
each individual row.

Assets carry only citation keys (``"<table>/<token>"``); this module turns
the keys into full citations once per report.
"""

from __future__ import annotations

from typing import Any

#: A document's status, as recorded in the authorities block.
STATUSES = frozenset({"final", "initial-public-draft", "unverified"})

#: What a reader is told about each status.
STATUS_NOTE = {
    "final": "",
    "initial-public-draft": "This is a draft, not a final standard.",
    "unverified": "This document's version and date have not been checked "
                  "against the document itself.",
}

# A control's compliance level, in the standard's own words.
MUST = "must"
SHOULD = "should"
MUST_NOT = "must-not"
SHOULD_NOT = "should-not"
LEVELS = frozenset({MUST, SHOULD, MUST_NOT, SHOULD_NOT})

#: Levels that oblige rather than recommend.
BINDING_LEVELS = frozenset({MUST, MUST_NOT})


class UnknownAuthority(KeyError):
    """A citation names a document that is not in the authorities block."""


class UnknownComplianceLevel(ValueError):
    """A compliance level is not one of :data:`LEVELS`."""


class UnreasonedBreach(ValueError):
    """A citation marks a row as breaching a control without saying how solid that is."""


def calibration_years(baseline: dict) -> dict[str, int]:
    """The baseline's ``deadlines:`` block as {name: year}.

    These are other bodies' transition years, recorded as the calibration the
    grades were set against. Non-integer values are ignored.
    """
    raw = baseline.get("deadlines")
    if not isinstance(raw, dict):
        return {}
    return {str(k): int(v) for k, v in raw.items()
            if isinstance(v, int) and not isinstance(v, bool)}


def compliance_index(baseline: dict) -> dict[tuple[str, str], dict]:
    """Index ``compliance_levels:`` by (authority, control).

    Each value carries ``level``, ``classifications``, ``condition`` and
    ``text`` (whitespace collapsed). A control absent from the index has no
    recorded level, which callers must treat as unknown, never as ``should``.

    Raises :class:`UnknownComplianceLevel` for a level outside :data:`LEVELS`.
    """
    out: dict[tuple[str, str], dict] = {}
    for authority, controls in (baseline.get("compliance_levels") or {}).items():
        if not isinstance(controls, dict):
            continue
        for control, entry in controls.items():
            if not isinstance(entry, dict):
                continue
            level = str(entry.get("level", "")).strip().lower()
            if level not in LEVELS:
                raise UnknownComplianceLevel(
                    f"compliance_levels.{authority}.{control} records level "
                    f"{level!r}, which is not one of {sorted(LEVELS)}")
            out[(str(authority).strip(), str(control).strip())] = {
                "level": level,
                "classifications": str(entry.get("classifications", "")).strip(),
                "condition": " ".join(str(entry.get("condition", "")).split()),
                "text": " ".join(str(entry.get("text", "")).split()),
            }
    return out


def authority_line(entry: dict) -> str:
    """One line naming a document: title, then version (if not in the title), then date."""
    out = str(entry.get("title", "")).strip()
    version = str(entry.get("version", "")).strip()
    date = str(entry.get("date", "")).strip()
    if version and version.lower() not in out.lower():
        out += f" — {version}"
    if date:
        out += f" ({date})"
    return out


def _cite(raw: dict, registry: dict, where: str,
          levels: dict[tuple[str, str], dict] | None = None) -> dict:
    """Resolve one ``cites:`` entry against the registry and the compliance index."""
    ident = str(raw.get("authority", "")).strip()
    entry = registry.get(ident)
    if entry is None:
        raise UnknownAuthority(
            f"{where} cites authority {ident!r}, which is not in the "
            f"`authorities:` block of the baseline")
    control = str(raw.get("control", "")).strip()
    lvl = (levels or {}).get((ident, control)) or {}
    breaches = bool(raw.get("breaches"))
    commentary = " ".join(str(raw.get("commentary", "")).split())
    # A row marked against a control must say how settled that reading is;
    # a bare control number would imply the standard decides it outright.
    if breaches and not commentary:
        raise UnreasonedBreach(
            f"{where} marks {control!r} as breached and carries no "
            f"`commentary:`. A row marked against a control ships the control "
            f"id to a reader; without the commentary it also ships the claim "
            f"that the reading is settled. Say how solid it is.")
    return {
        "authority": ident,
        "control": control,
        "note": str(raw.get("note", "")).strip(),
        "document": authority_line(entry),
        "publisher": str(entry.get("publisher", "")).strip(),
        "status": str(entry.get("status", "")).strip(),
        "index": str(entry.get("index", "")).strip(),
        "checked": str(entry.get("checked", "")).strip(),
        "compliance": lvl.get("level", ""),
        "classifications": lvl.get("classifications", ""),
        "control_text": lvl.get("text", ""),
        "condition": lvl.get("condition", ""),
        "breaches": breaches,
        "commentary": commentary,
    }


def resolve(baseline: dict) -> dict[str, list[dict]]:
    """Every graded row's citations, keyed ``"<table>/<token>"``.

    A row with its own ``tokens:`` entry uses that; any other row in a cited
    table inherits the table's ``cites:``. Raises :class:`UnknownAuthority`
    or :class:`UnreasonedBreach` for a malformed citation.
    """
    registry = baseline.get("authorities") or {}
    levels = compliance_index(baseline)
    out: dict[str, list[dict]] = {}
    for table, block in (baseline.get("citations") or {}).items():
        if not isinstance(block, dict):
            continue
        rows = baseline.get(table) or {}
        table_cites = [_cite(c, registry, f"citations.{table}", levels)
                       for c in block.get("cites") or []]
        tokens = block.get("tokens") or {}
        for token in rows:
            key = f"{table}/{token}"
            own = tokens.get(token)
            if own:
                out[key] = [_cite(c, registry, f"citations.{table}.tokens.{token}",
                                  levels)
                            for c in own]
            elif table_cites:
                out[key] = list(table_cites)
    return out


def payload(baseline: dict, used: set[str]) -> dict[str, Any]:
    """The citation block a report ships: the cited keys, the registry, status notes.

    ``used`` is the set of citation keys that appear on some asset; only those
    are resolved into the payload.
    """
    resolved = resolve(baseline)
    registry = baseline.get("authorities") or {}
    return {
        "cites": {k: v for k, v in resolved.items() if k in used},
        "authorities": {name: {f: str(v) for f, v in entry.items()}
                        for name, entry in registry.items()},
        "status_notes": dict(STATUS_NOTE),
    }
