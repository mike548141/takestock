"""Write a configuration register as JSON, CSV and a workbook.

Every writer takes the plain dict :func:`takestock.cmdb.build_register`
returns, so the three views are always of the same register:

* ``cmdb.json``: the whole register, schema first, then the data;
* ``csv/<class>.csv``: one file per declared class, every attribute the
  class carries as a column, header-only when the class is empty, plus
  ``csv/relationships.csv``;
* ``cmdb.xlsx``: a read-me, one sheet per populated class, the
  relationships, what is not in the register, disagreements, population
  counts, the per-fact provenance and the data dictionary;
* ``keys.jsonl``: the key ledger, for the next build to keep its keys.

A missing value is written as its reason in brackets (``[not measured]``),
never as an empty cell. Styling is deliberately plain: bold headers on light
grey, absences in grey italics, contested values in one accent colour.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

JSON_NAME = "cmdb.json"
XLSX_NAME = "cmdb.xlsx"
CSV_DIR = "csv"
KEYS_NAME = "keys.jsonl"

_HEADER_FILL = "D9D9D9"
_ABSENT_INK = "767676"
_ACCENT = "C00000"

_ABSENT_WORDS = {
    "not-collected": "not collected",
    "not-measured": "not measured",
    "not-applicable": "not applicable",
    "could-not-test": "could not test",
    "extent-unknown": "extent unknown",
    "asked-unknown": "asked, unknown",
    "asked-declined": "asked, declined",
    "temp-unknown": "not known yet",
    "masked": "withheld",
    "unsupported": "source cannot hold it",
}


def absent_words(code: str) -> str:
    """An absence code as plain words."""
    return _ABSENT_WORDS.get(code, code.replace("-", " "))


def cell_text(cell: Mapping[str, Any] | None) -> Any:
    """What a spreadsheet or CSV shows for one attribute cell."""
    if cell is None:
        return ""
    if cell.get("absent"):
        return f"[{absent_words(str(cell['absent']))}]"
    value = cell.get("value")
    if isinstance(value, bool):
        return "yes" if value else "no"
    return value


def slug(name: str) -> str:
    """A class name as a file name: ``Software Release`` becomes ``software-release``."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _compact(node: Any) -> Any:
    # Drop empty strings, nulls and false contest markers; keep every real
    # value, including 0 and False.
    if isinstance(node, dict):
        return {k: _compact(v) for k, v in node.items()
                if not (v == "" or v is None or (v is False and k in ("contested", "tie")))}
    if isinstance(node, list):
        return [_compact(v) for v in node]
    return node


def write_json(register: Mapping[str, Any], path: Path) -> Path:
    """The whole register as one JSON document, the schema beside the data."""
    body = {k: v for k, v in register.items() if k != "key_ledger"}
    path.write_text(json.dumps(_compact(body), indent=1, default=str, ensure_ascii=False) + "\n")
    return path


def write_keys(register: Mapping[str, Any], path: Path) -> Path:
    """The key ledger, one JSON record per line."""
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                            for r in register.get("key_ledger") or []))
    return path


def _class_columns(register: Mapping[str, Any], name: str) -> list[str]:
    for spec in register["schema"]["classes"]:
        if spec["name"] == name:
            return [a for a in spec["attributes"] if a != "lifecycle_state"]
    return []


_ITEM_FIXED = ["key", "name", "lifecycle_state", "identifiers", "contested"]


def _item_row(item: Mapping[str, Any], columns: list[str]) -> list[Any]:
    cells = item["attributes"]
    contested = sorted(a for a, c in cells.items() if c.get("contested"))
    identifiers = "; ".join(f"{a['kind']}={a['identifier']}" for a in item["aliases"])
    return ([item["key"], item["name"], item["lifecycle_state"], identifiers,
             ", ".join(contested)] + [cell_text(cells.get(a)) for a in columns])


_RELATIONSHIP_COLUMNS = ["from", "from_name", "type", "to", "to_name", "count", "unit",
                         "evidence_strength", "valid_at", "qualifier"]


def write_csv(register: Mapping[str, Any], directory: Path) -> list[Path]:
    """One CSV per declared class, and one for the relationships."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for spec in register["schema"]["classes"]:
        columns = _class_columns(register, spec["name"])
        path = directory / f"{slug(spec['name'])}.csv"
        with path.open("w", newline="") as fh:
            out = csv.writer(fh)
            out.writerow(_ITEM_FIXED + columns)
            for item in register["items"]:
                if item["class"] == spec["name"]:
                    out.writerow(_item_row(item, columns))
        written.append(path)
    path = directory / "relationships.csv"
    with path.open("w", newline="") as fh:
        out = csv.writer(fh)
        out.writerow(_RELATIONSHIP_COLUMNS)
        for edge in register["relationships"]:
            out.writerow([edge.get(c, "") for c in _RELATIONSHIP_COLUMNS])
    written.append(path)
    return written


def write_xlsx(register: Mapping[str, Any], path: Path) -> Path:
    """The register as a workbook, plainly styled."""
    # openpyxl ships without type information.
    from openpyxl import Workbook  # type: ignore[import-untyped]
    from openpyxl.styles import Alignment, Font, PatternFill  # type: ignore[import-untyped]
    from openpyxl.utils import get_column_letter  # type: ignore[import-untyped]

    wrap = Alignment(vertical="top", wrap_text=True)
    absent_font = Font(color=_ABSENT_INK, italic=True)
    accent_font = Font(color=_ACCENT, bold=True)

    def table(ws: Any, names: list[str], rows: list[list[Any]], *, start: int = 1,
              widths: Mapping[str, int] | None = None) -> None:
        for col, name in enumerate(names, start=1):
            cell = ws.cell(row=start, column=col, value=name)
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor=_HEADER_FILL)
            cell.alignment = wrap
            ws.column_dimensions[get_column_letter(col)].width = (widths or {}).get(name, 20)
        for r, values in enumerate(rows, start=start + 1):
            for col, value in enumerate(values, start=1):
                cell = ws.cell(row=r, column=col, value=value)
                if isinstance(value, str) and value.startswith("[") and value.endswith("]"):
                    cell.font = absent_font
        ws.freeze_panes = f"A{start + 1}"
        ws.auto_filter.ref = f"A{start}:{get_column_letter(len(names))}{start + len(rows)}"

    reg = register["register"]
    counts = reg["counts"]
    wb = Workbook()
    ws = wb.active
    assert ws is not None
    ws.title = "Read me"
    lines: list[tuple[str, Font | None]] = [
        (str(reg["title"]), Font(bold=True, size=16)),
        (f"Observation {reg['observation']}, recorded {reg['recorded_at']}. "
         f"Schema {reg['schema_version']} ({reg['schema_maturity']}).", None),
        ("", None),
        (f"{counts['configuration_items']} configuration items, {counts['recorded_facts']} "
         f"recorded facts, {counts['relationships']} relationships. "
         f"{counts['classes_populated']} of {counts['classes_declared']} declared classes "
         f"hold items; the 'Not in here' sheet says why each other one is empty. "
         f"{counts['contested_attributes']} values are contested.", Font(bold=True)),
    ]
    unassigned = reg["governance"].get("unassigned") or []
    if unassigned:
        lines.append(("No one is named for: " + ", ".join(unassigned) + ".", accent_font))
    lines.append(("", None))
    for entry in register["how_to_read"]:
        lines += [(entry["heading"], Font(bold=True)), (entry["body"], None), ("", None)]
    for r, (text, font) in enumerate(lines, start=1):
        cell = ws.cell(row=r, column=1, value=text or None)
        cell.alignment = wrap
        if font is not None:
            cell.font = font
    ws.column_dimensions["A"].width = 110

    populated = [c["class"] for c in register["census"] if c["items"]]
    for name in populated:
        columns = _class_columns(register, name)
        sheet = wb.create_sheet(name[:31])
        members = [i for i in register["items"] if i["class"] == name]
        table(sheet, _ITEM_FIXED + columns, [_item_row(i, columns) for i in members],
              widths={"key": 12, "name": 34, "identifiers": 40, "contested": 18})
        for r, item in enumerate(members, start=2):
            for col, attribute in enumerate(columns, start=len(_ITEM_FIXED) + 1):
                if item["attributes"].get(attribute, {}).get("contested"):
                    sheet.cell(row=r, column=col).font = accent_font

    table(wb.create_sheet("Relationships"), _RELATIONSHIP_COLUMNS,
          [[e.get(c, "") for c in _RELATIONSHIP_COLUMNS] for e in register["relationships"]],
          widths={"from_name": 34, "to_name": 34, "unit": 30, "qualifier": 60})

    gaps = wb.create_sheet("Not in here")
    table(gaps, ["class", "family", "items", "answers", "built_from", "empty_because"],
          [[c["class"], c["family"], c["items"], c["answers"], c["source"], c["empty_because"]]
           for c in register["census"]],
          widths={"class": 24, "answers": 50, "built_from": 40, "empty_because": 70})
    start = len(register["census"]) + 3
    table(gaps, ["relationship not drawn", "why"],
          [[r["relationship"], r["reason"]] for r in register["relationships_not_drawn"]],
          start=start, widths={"relationship not drawn": 24, "why": 50})
    gaps.freeze_panes = "A2"
    gaps.auto_filter.ref = f"A1:F{len(register['census']) + 1}"

    vocab = register["schema"]["vocabularies"].get("absence_reason", {})
    recorded = register["absence"]["recorded_by_reason"]
    table(wb.create_sheet("Absence counted"), ["absence", "values", "meaning"],
          [[absent_words(code), n, str(vocab.get(code, {}).get("definition", ""))]
           for code, n in sorted(recorded.items())]
          + [["declared and unasserted", register["absence"]["attributes_declared_and_unasserted"],
              "Attributes a class declares that no row stated. Counted apart from the rows "
              "above and never added to them."]],
          widths={"absence": 26, "values": 10, "meaning": 90})

    def said(value: Any) -> str:
        if isinstance(value, Mapping) and "absent" in value:
            return f"[{absent_words(str(value['absent']))}]"
        return "" if value is None else str(value)

    table(wb.create_sheet("Disagreements"),
          ["key", "attribute", "published value", "evidence_strength", "valid_at",
           "asserted_by", "tie", "what each source said"],
          [[c["item"], c["attribute"], said(c["value"]), c["evidence_strength"], c["valid_at"],
            c["actor"], "yes" if c["tie"] else "",
            " | ".join(f"{said(a['value'])} ({a['evidence_strength']}, {a['valid_at']}, "
                       f"{a['actor']})" for a in c["assertions"])]
           for c in register["conflicts"]],
          widths={"published value": 30, "asserted_by": 30, "what each source said": 90})

    table(wb.create_sheet("Populations"),
          ["population", "instrument", "count", "unit", "valid_at", "evidence_strength", "note"],
          [[p["population"], p["instrument"], p["count"], p["unit"], p["valid_at"],
            p["evidence_strength"], p["note"]] for p in register["populations"]],
          widths={"instrument": 40, "note": 70})

    fact_columns = ["key", "class", "name", "attribute", "value", "evidence_strength",
                    "valid_at", "recorded_at", "asserted_by", "source_artefact", "basis",
                    "contested"]
    table(wb.create_sheet("Facts"), fact_columns,
          [[f["key"], f["class"], f["name"], f["attribute"],
            f"[{absent_words(f['absent'])}]" if f["absent"] else cell_text(f),
            f["evidence_strength"], f["valid_at"], f["recorded_at"], f["asserted_by"],
            f["source_artefact"], f["basis"], "yes" if f["contested"] else ""]
           for f in register["facts"]],
          widths={"name": 30, "value": 34, "asserted_by": 30, "source_artefact": 30})

    dictionary = wb.create_sheet("Data dictionary")
    table(dictionary, ["attribute", "expected_strength", "refresh_interval_days",
                       "carried_by", "note"],
          [[a["name"], a["expected_strength"], a["refresh_interval_days"],
            ", ".join(a["carried_by"]), a["note"]] for a in register["schema"]["attributes"]],
          widths={"attribute": 26, "carried_by": 50, "note": 90})

    wb.save(path)
    return path


def write_all(register: Mapping[str, Any], out_dir: Path) -> list[Path]:
    """Write every view of ``register`` into ``out_dir``; return the paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return ([write_json(register, out_dir / JSON_NAME)]
            + write_csv(register, out_dir / CSV_DIR)
            + [write_xlsx(register, out_dir / XLSX_NAME), write_keys(register, out_dir / KEYS_NAME)])
