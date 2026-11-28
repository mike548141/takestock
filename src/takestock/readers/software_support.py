"""Software releases that carry a decision: vendor support dates and exploited defects.

A ``general`` plug-in (``docs/PLUGINS.md``). It reads the files a software
census produced and writes the rows takestock's configuration register
(``takestock cmdb``) turns into **Software Release** items, so a release
reaches the register with its vendor's support date and any known-exploited
defect open against it. The register never opens a census file itself: this
reader is the one door in, so the register keeps a single, checked input
path.

**The inputs** are four CSV files and a manifest that names them. The manifest
is ``<profile stem>.software-census.yaml``, beside the target profile (found
by convention, so a profile cannot point at another organisation's census)::

    output: census.csv                  # one row per source, product and version
    support:
      output: census-support.csv        # each census row graded against a vendor lifecycle
      as_of: 2030-03-01                 # the date every band is read on
      superseded_by_measurement:        # optional, see below
        - {line: wdg-os-3, declared_source: portfolio, measured_sources: [agent-hosts],
           measured_product: Widget OS}
      declaration_notes:                # optional: one sentence for a lifecycle line
        - {line: wdg-os-3, note: "Support extended by contract."}
    vulnerabilities:
      products_output: vuln-products.csv   # exploit counts per product and version
      kev_output: vuln-catalogue.csv       # one row per catalogued defect
      dated: 2030-02-10                    # the date of the vulnerability export

Every path is relative to the manifest. The columns this reader uses are named
in :data:`CENSUS_COLUMNS`, :data:`SUPPORT_COLUMNS`, :data:`PRODUCT_COLUMNS` and
:data:`CATALOGUE_COLUMNS`; others are ignored. The support file is what
:func:`takestock.lifecycle.derive_census_support` writes for a census. Where
the products file lists exploited defects it does so in the form
``CVE-2099-1 (added 2030-01-02, due 2030-01-23)``, the catalogue's own dates.

**The lifecycle table** the support bands were read from is also needed, for
the vendor's own line names and end dates. By default it is takestock's
(``data/software-lifecycle.yaml``, or a workspace copy). ``settings:
lifecycle:`` names another file, relative to the workspace, when the census was
graded against one.

**Which releases are written.** A software release is written only where a
decision hangs on it (:func:`promotion_reasons`), which is one of two things:

* *the support band is past its date*: on the manifest's fixed ``as_of``, the
  vendor band is end-of-support or end-of-life, or it is security-only only
  under a paid condition (an extension nobody has shown), which means the
  unconditional date has passed;
* *an exploited defect is open*: the vulnerability export names at least one
  catalogued identifier open against this product and version.

Every other spelling stays a counted population on the scope row, never an
item.

**A release is keyed on the vendor's own version line.** Every spelling the
lifecycle table maps to one line ("Widget OS 3 (x64)" and "Widget OS 3.2",
or many patch builds of one release) becomes one release carrying
those spellings and their counts, and the line is named by the vendor: the
table's own variant names, never a pattern matched over the spellings. A
spelling the table maps to no line, or to more than one, stays its own release
and carries the reason on the row.

**A count carries its unit and is never summed across sources.** Each version
string a release covers carries one population per census source, each in the
unit that source counts in (hosts, devices, virtual machines, systems,
installs, documents). Exploited-defect identifiers are unioned across the
spellings of one line, never added, because one defect is routinely open against
several.

**Whose attribution a defect's product is.** The export's. The join matches on
the defect identifier alone: product and identifier come from one export row,
and the catalogue's own vendor and product are carried beside it, never
matched on. Where the export attributes an identifier to a product the
catalogue files under a different vendor, that is a fact about the export's
data and not about the product, so every row that carries a count says so
(:data:`ATTRIBUTION_NOTE`).

**Superseded declarations.** A release a hand-kept source declares is
superseded where the named measuring sources have census rows for the measured
product and none of their support rows grades to the declared line: the
measurement says a different version, so a support finding drawn from the
declaration alone would be untrue. The declaration's rows stay in the census
as the record of what it says; they only stop carrying a support finding.

**Excluded.** Census rows whose source is an earlier observation
(``observation-…``) are not promoted and add no population: they restate rows
already in the run.

**Failure is cheap.** A missing manifest or output file is a ``not-collected``
gap and no rows: the observation completes, and the register's software
releases read *not collected* for support exactly as without this reader. A
malformed number is read as zero rather than raised on, so the population it
would have carried is visibly absent from the row.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from .. import config, coverage
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult

#: The plug-in's name, and the ``source`` of every row it writes.
NAME = "software_support"
SOURCE = "software_support"
SOURCE_NAME = "Software census, vendor support bands and exploited-defect join"
#: The manifest's name beside the profile: ``<profile stem>`` plus this.
MANIFEST_SUFFIX = ".software-census.yaml"
#: ``settings:`` key naming a lifecycle table other than takestock's.
LIFECYCLE_SETTING = "lifecycle"

#: The ``extra`` keys the rows carry: one per release, and one for the scope.
RELEASE_KEY = "software_release"
SCOPE_KEY = "software_support_scope"
#: The release in the shape the register reads (``docs/CMDB.md``, *Releases a row
#: lists*). Written beside :data:`RELEASE_KEY`, never instead of it: the
#: populations, the "why it is here" note and the catalogue's attribution have
#: no slot in that shape.
RELEASES_KEY = "releases"

#: The columns read from each file. Others are ignored.
CENSUS_COLUMNS = ("source", "source_date", "kind", "vendor", "product", "version", "population",
                  "population_unit", "installs", "seen_within_90_days")
SUPPORT_COLUMNS = ("source", "kind", "product", "version", "line", "matched_by", "as_of",
                   "band_at_as_of", "condition_at_as_of", "holds_until", "vendor_sources")
PRODUCT_COLUMNS = ("product", "version", "hosts_open", "cves_open", "kev_listed_cves",
                   "kev_detail")
CATALOGUE_COLUMNS = ("cve", "catalogue_vendor", "catalogue_product", "known_ransomware_use",
                     "hosts_open")

#: Vendor bands that mean the support date has passed.
PAST_BANDS = frozenset({"end-of-support", "end-of-life"})
#: Why a release is written.
SUPPORT_PAST = "support-past-date"
EXPLOITED_OPEN = "exploited-defect-open"
REASONS = (SUPPORT_PAST, EXPLOITED_OPEN)

ATTRIBUTION_NOTE = (
    "Which product a defect identifier is attributed to is the vulnerability export's own "
    "attribution: the join matches on the identifier alone and carries the catalogue's own "
    "vendor and product beside it. Where the two name different products that is evidence "
    "about the export's data, not about this product")

_FROM_OBSERVATION = re.compile(r"^observation-")
_CATALOGUE_DETAIL = re.compile(
    r"(CVE-\d{4}-\d+) \(added (\d{4}-\d{2}-\d{2}), due (\d{4}-\d{2}-\d{2})\)")

Table = list[dict[str, str]]
Record = dict[str, Any]


# ── small readers ──

def _fold(value: object) -> str:
    return " ".join(str(value or "").split()).casefold()


def _tidy(value: object) -> str:
    return " ".join(str(value or "").split())


def _int(value: object) -> int:
    try:
        return int(str(value or "").strip() or 0)
    except ValueError:
        return 0


def spelling_key(product: str, version: str) -> tuple[str, str]:
    """The identity of one release spelling: product and version as written, folded."""
    return _fold(product), _fold(version)


def _read_csv(path: Path) -> Table:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def manifest_path_for_target(target: Mapping[str, Any]) -> Path | None:
    """``<stem>.software-census.yaml`` beside the loaded profile, or None."""
    given = target.get("_path")
    if not given:
        return None
    path = Path(str(given))
    if not path.suffix:
        return None
    candidate = path.with_name(path.name[: -len(path.suffix)] + MANIFEST_SUFFIX)
    return candidate if candidate.exists() else None


# ── the vendor's dates for a line ──

def _variant_ends(variant: Mapping[str, Any]) -> tuple[str, str]:
    """``(end of support, end of life)`` one vendor variant prints, ``""`` for none.

    End of support is the ``until`` of the last phase that holds without a
    condition: after it, fixes stop unless somebody pays for an extension. End
    of life is that same date, but only where the variant's own ``after`` band
    is end-of-life and no paid phase follows.
    """
    phases = list(variant.get("phases") or [])
    free = [p for p in phases if not p.get("condition")]
    if not free:
        return "", ""
    end = str(free[-1]["until"])
    paid_tail = bool(phases and phases[-1].get("condition"))
    life = end if str(variant.get("after") or "") == "end-of-life" and not paid_tail else ""
    return end, life


def line_end_dates(line: Mapping[str, Any]) -> dict[str, str]:
    """The line's vendor end dates, or the reason one cannot be stated.

    Returns ``end_of_support`` and ``end_of_life`` (a date as the vendor
    prints it, ``YYYY-MM`` where only a month is printed) and, for each,
    ``<field>_reason`` and ``<field>_absent``. A date the vendor never printed
    is ``not-measured``; a date the table cannot choose between because the
    variants disagree is ``could-not-test``, with the disagreement spelled out.
    """
    variants = list(line.get("variants") or [])
    any_support = any(_variant_ends(v)[0] for v in variants)
    out: dict[str, str] = {}
    for position, key in enumerate(("end_of_support", "end_of_life")):
        by_name = {str(v.get("name")): _variant_ends(v)[position] for v in variants}
        distinct = set(by_name.values())
        out[key], out[f"{key}_reason"], out[f"{key}_absent"] = "", "", "not-measured"
        if len(distinct) == 1 and "" not in distinct:
            out[key], out[f"{key}_absent"] = distinct.pop(), ""
        elif not variants or not any_support:
            out[f"{key}_reason"] = "the vendor publishes a status for this line and no date"
        elif distinct == {""}:
            out[f"{key}_reason"] = ("the vendor publishes an end of support and no separate "
                                    "end-of-life date")
        else:
            out[f"{key}_absent"] = "could-not-test"
            out[f"{key}_reason"] = (
                "the source cannot tell these vendor products apart and their dates differ: "
                + "; ".join(f"{n}={d or 'none printed'}" for n, d in sorted(by_name.items())))
    return out


def line_label(line: Mapping[str, Any]) -> str:
    """What to call a vendor version line: the vendor's own product names.

    Never derived from a census spelling. The table's variant names are
    transcribed from the vendor's lifecycle page, so they are the only names
    here with a source behind them; a label built by pattern-matching build
    strings would be this tool naming the vendor's products for it. Where a
    line covers several products the table cannot tell apart, every one is
    named, because that ambiguity is the fact the reader needs.
    """
    names = [_tidy(v.get("name")) for v in line.get("variants") or []
             if str(v.get("name") or "").strip()]
    return " or ".join(names)


# ── why a release is written ──

def support_past_date(row: Mapping[str, str]) -> bool:
    """True where the graded band on the fixed ``as_of`` is past its vendor date."""
    if not str(row.get("line") or ""):
        return False
    return (str(row.get("band_at_as_of") or "") in PAST_BANDS
            or bool(str(row.get("condition_at_as_of") or "").strip()))


def exploited_open(row: Mapping[str, str]) -> bool:
    """True where the export names a catalogued defect open on at least one host."""
    return _int(row.get("kev_listed_cves")) > 0 and _int(row.get("hosts_open")) > 0


def promotion_reasons(support_rows: Iterable[Mapping[str, str]],
                      vulnerability_row: Mapping[str, str] | None) -> list[str]:
    """Why a decision hangs on this spelling; empty means none does."""
    reasons: list[str] = []
    if any(support_past_date(r) for r in support_rows):
        reasons.append(SUPPORT_PAST)
    if vulnerability_row is not None and exploited_open(vulnerability_row):
        reasons.append(EXPLOITED_OPEN)
    return reasons


# ── blocks the rows carry ──

def _support_block(row: Mapping[str, str], lines: Mapping[str, Mapping[str, Any]],
                   sources: Mapping[str, Any]) -> dict[str, str]:
    line = lines.get(str(row.get("line") or ""), {})
    variants = line.get("variants") or [] if line else []
    reads = sorted({str((sources.get(v.get("source")) or {}).get("read") or "")
                    for v in variants} - {""})
    return {
        "line": str(row.get("line") or ""),
        "line_names": "; ".join(str(v.get("name")) for v in variants),
        "band": str(row.get("band_at_as_of") or ""),
        "condition": str(row.get("condition_at_as_of") or ""),
        "as_of": str(row.get("as_of") or ""),
        "holds_until": str(row.get("holds_until") or ""),
        "vendor_sources": str(row.get("vendor_sources") or ""),
        "vendor_read": ", ".join(reads),
        "matched_by": str(row.get("matched_by") or ""),
        **(line_end_dates(line) if line else {}),
    }


def catalogue_attribution(catalogue: Mapping[str, Mapping[str, str]],
                          ids: Iterable[str]) -> dict[str, str]:
    """The catalogue's own vendor and product for each identifier it names.

    Carried so a row shows both attributions, never to match on: the reader is
    owed the export's view and the catalogue's view side by side.
    """
    out: dict[str, str] = {}
    for cve in ids:
        row = catalogue.get(cve) or {}
        named = " — ".join(p for p in (_tidy(row.get("catalogue_vendor")),
                                       _tidy(row.get("catalogue_product"))) if p)
        if named:
            out[cve] = named
    return out


def _ransomware(catalogue: Mapping[str, Mapping[str, str]], ids: Iterable[str]) -> int:
    return sum(1 for c in ids
               if _fold((catalogue.get(c) or {}).get("known_ransomware_use")) == "known")


def _exploited_block(row: Mapping[str, str], catalogue: Mapping[str, Mapping[str, str]],
                     export_date: str) -> Record:
    due: dict[str, str] = {}
    for cve, _added, due_date in _CATALOGUE_DETAIL.findall(str(row.get("kev_detail") or "")):
        due[cve] = due_date
    ids = sorted(due)
    return {
        "open": _int(row.get("kev_listed_cves")),
        "identifiers": ids,
        "due_by_id": due,
        "catalogue_attribution": catalogue_attribution(catalogue, ids),
        "past_due_at_export": sum(1 for c in ids if export_date and due[c] < export_date),
        "known_ransomware_use": _ransomware(catalogue, ids),
        "export_date": export_date,
        "hosts_with_any_open_defect": _int(row.get("hosts_open")),
        "defects_open": _int(row.get("cves_open")),
    }


def _merge_exploited(blocks: list[Record], catalogue: Mapping[str, Mapping[str, str]],
                     export_date: str) -> Record | None:
    """One exploited-defect summary for the spellings of one release.

    Identifiers are unioned, never added: one defect is routinely open against
    several spellings of a line, and summing would report it once per
    spelling. Host counts are not merged at all; each spelling keeps its own,
    in its own unit, on its own entry.
    """
    if not blocks:
        return None
    due: dict[str, str] = {}
    for block in blocks:
        due.update(block["due_by_id"])
    ids = sorted(due)
    return {
        "open": len(ids),
        "identifiers": ids,
        "catalogue_attribution": catalogue_attribution(catalogue, ids),
        "past_due_at_export": sum(1 for c in ids if export_date and due[c] and due[c] < export_date),
        "known_ransomware_use": _ransomware(catalogue, ids),
        "export_date": export_date,
    }


def _population(row: Mapping[str, str]) -> Record | None:
    """One census row's count, in its own unit; installs where no host is named."""
    count, unit = _int(row.get("population")), str(row.get("population_unit") or "").strip()
    if not count and _int(row.get("installs")):
        count, unit = _int(row.get("installs")), "installs"
    if not count or not unit:
        return None
    recent = str(row.get("seen_within_90_days") or "").strip()
    return {"source": str(row.get("source") or ""), "valid_at": str(row.get("source_date") or ""),
            "count": count, "unit": unit,
            "note": f"{recent} seen within 90 days of the export date" if recent else ""}


# ── declarations a measurement supersedes ──

def superseded_declarations(census: Table, support: Table,
                            entries: Iterable[Mapping[str, Any]]) -> list[Record]:
    """Declared releases the measuring sources contradict (see the module docstring)."""
    out: list[Record] = []
    for entry in entries or []:
        line = str(entry.get("line") or "")
        declared = str(entry.get("declared_source") or "")
        measuring = {str(s) for s in entry.get("measured_sources") or []}
        product = _fold(entry.get("measured_product"))
        measured = [r for r in census
                    if str(r.get("source") or "") in measuring and _fold(r.get("product")) == product]
        if not line or not declared or not measured:
            continue
        if any(str(r.get("source") or "") in measuring and str(r.get("line") or "") == line
               for r in support):
            continue
        versions: dict[str, tuple[int, str]] = {}
        for r in measured:
            n, unit = _int(r.get("population")), str(r.get("population_unit") or "")
            held, _ = versions.get(r.get("version") or "", (0, unit))
            versions[str(r.get("version") or "")] = (held + n, unit)
        declared_rows = [r for r in support
                         if str(r.get("source") or "") == declared and str(r.get("line") or "") == line]
        out.append({
            "line": line,
            "declared_source": declared,
            "declared": "; ".join(sorted({f"{r['product']} {r.get('version') or ''}".strip()
                                          for r in declared_rows})),
            "measured": "; ".join(f"{entry.get('measured_product')} {v} on {n} {u}".replace("  ", " ")
                                  for v, (n, u) in sorted(versions.items())),
            "measured_sources": ", ".join(sorted(measuring)),
        })
    return out


# ── the fold ──

def fold(census: Table, support: Table, vulnerabilities: Table, catalogue: Table,
         dataset: Mapping[str, Any], *, as_of: str, export_date: str,
         supersede: Iterable[Mapping[str, Any]] = (),
         declaration_notes: Iterable[Mapping[str, Any]] = ()) -> tuple[list[Record], Record]:
    """``(one record per release written, the scope record)``.

    Pure: no file is read here. ``supersede`` and ``declaration_notes`` are the
    manifest's entries of those names.
    """
    def own(row: Mapping[str, str]) -> bool:
        return not _FROM_OBSERVATION.match(str(row.get("source") or ""))

    census = [r for r in census if own(r)]
    support = [r for r in support if own(r)]
    superseded = superseded_declarations(census, support, supersede)
    dropped = {(s["declared_source"], s["line"]) for s in superseded}
    note_for = {str(n.get("line") or ""): str(n.get("note") or "") for n in declaration_notes or []}
    lines = {str(ln["id"]): ln for ln in dataset.get("lines") or []}
    sources = dataset.get("sources") or {}
    catalogue_by_id = {str(r.get("cve") or ""): r for r in catalogue}

    graded_by: dict[tuple[str, str], Table] = {}
    for r in support:
        graded_by.setdefault(spelling_key(r["product"], r["version"]), []).append(r)
    export_by = {spelling_key(r["product"], r["version"]): r for r in vulnerabilities}
    census_by: dict[tuple[str, str], Table] = {}
    for r in census:
        census_by.setdefault(spelling_key(r["product"], r["version"]), []).append(r)

    spelled: dict[tuple[str, str], tuple[str, str]] = {}
    for r in [*support, *vulnerabilities]:
        spelled.setdefault(spelling_key(r["product"], r["version"]),
                           (_tidy(r["product"]), _tidy(r["version"])))

    # The vendor line each spelling belongs to. A spelling graded under two
    # lines belongs to neither, and says so.
    line_of: dict[tuple[str, str], str] = {}
    why_unmapped: dict[tuple[str, str], str] = {}
    for key, rows in graded_by.items():
        found = sorted({str(r.get("line") or "") for r in rows} - {""})
        if len(found) == 1:
            line_of[key] = found[0]
        elif len(found) > 1:
            why_unmapped[key] = (f"the census grades this spelling under {len(found)} vendor "
                                 f"lifecycle lines ({', '.join(found)}), so it belongs to no "
                                 "single version line and is kept on its own")

    groups: dict[str, Record] = {}
    for key in sorted(set(graded_by) | set(export_by)):
        live = [r for r in graded_by.get(key, [])
                if (str(r.get("source") or ""), str(r.get("line") or "")) not in dropped]
        reasons = promotion_reasons(live, export_by.get(key))
        if not reasons:
            continue
        product, version = spelled[key]
        line = line_of.get(key, "")
        export_row = export_by.get(key)
        covered = {
            "product": product,
            "version": version,
            "populations": sorted((p for p in (_population(r) for r in census_by.get(key, [])) if p),
                                  key=lambda p: (p["source"], p["unit"])),
            "exploited": (_exploited_block(export_row, catalogue_by_id, export_date)
                          if export_row is not None and exploited_open(export_row) else None),
        }
        group = groups.setdefault(f"line:{line}" if line else f"spelling:{product}\x00{version}", {
            "keyed_on": "vendor-line" if line else "spelling",
            "line": line,
            # The table's own identifier is the fallback where a line's variants
            # carry no product name: still the table's word, never an invented one.
            "label": (line_label(lines.get(line, {})) or line) if line else "",
            "promoted_because": [],
            "support": None,
            "covered": [],
            "declaration_note": note_for.get(line, "") if line else "",
            "unmapped_reason": "" if line else why_unmapped.get(
                key, "no vendor lifecycle line the table holds covers this spelling exactly, "
                     "so it is kept as its own release rather than filed under a line that "
                     "cannot be named"),
        })
        for reason in reasons:
            if reason not in group["promoted_because"]:
                group["promoted_because"].append(reason)
        graded = [r for r in graded_by.get(key, []) if r.get("line")]
        if group["support"] is None and graded:
            group["support"] = _support_block(graded[0], lines, sources)
        group["covered"].append(covered)

    releases: list[Record] = []
    for gid in sorted(groups):
        group = groups[gid]
        group["covered"].sort(key=lambda c: (c["product"].casefold(), c["version"]))
        group["promoted_because"].sort(key=REASONS.index)
        group["exploited"] = _merge_exploited(
            [c["exploited"] for c in group["covered"] if c["exploited"]], catalogue_by_id,
            export_date)
        products = {c["product"] for c in group["covered"]}
        if group["keyed_on"] == "spelling":
            one = group["covered"][0]
            group["label"] = f"{one['product']} {one['version']}".strip()
            group["product"] = one["product"]
        else:
            # The product a line belongs to, only where every spelling under it
            # names the same one; otherwise the vendor's line name, because
            # picking one of several spellings would be a guess.
            group["product"] = products.pop() if len(products) == 1 else group["label"]
        releases.append(group)

    # Product-level support, for the register's name join onto releases it already
    # holds. A product qualifies only where every graded row naming it resolves to
    # the same single line; anything else is recorded with its reason.
    by_product: dict[str, Table] = {}
    for r in support:
        by_product.setdefault(_fold(r["product"]), []).append(r)
    products_out: dict[str, dict[str, str]] = {}
    ambiguous: dict[str, str] = {}
    for name, rows in sorted(by_product.items()):
        line_ids = {str(r.get("line") or "") for r in rows}
        if line_ids == {""}:
            continue
        if len(line_ids) == 1:
            products_out[name] = {"product": _tidy(rows[0]["product"]),
                                  **_support_block(rows[0], lines, sources)}
        else:
            named = sorted(line_ids - {""})
            ambiguous[name] = (
                "the census names this product under "
                + (f"{len(named)} vendor lifecycle lines ({', '.join(named)})" if len(named) > 1
                   else f"the line {named[0]}")
                + (" and in rows no line matches (no build or version to grade)" if "" in line_ids
                   else "")
                + ", so no single support date belongs to the product name")

    spellings = {spelling_key(r["product"], r["version"]) for r in census}
    in_releases = {spelling_key(c["product"], c["version"]) for r in releases for c in r["covered"]}
    scope: Record = {
        "as_of": as_of,
        "export_date": export_date,
        "census_rows": len(census),
        "census_spellings": len(spellings),
        "graded_rows": sum(1 for r in support if r.get("line")),
        "graded_spellings": len({spelling_key(r["product"], r["version"])
                                 for r in support if r.get("line")}),
        "promoted": len(releases),
        "promoted_vendor_lines": sum(1 for r in releases if r["keyed_on"] == "vendor-line"),
        "promoted_unmapped_spellings": sum(1 for r in releases if r["keyed_on"] == "spelling"),
        "promoted_covered_spellings": sum(len(r["covered"]) for r in releases),
        "promoted_support_past_date": sum(1 for r in releases if SUPPORT_PAST in r["promoted_because"]),
        "promoted_exploited_open": sum(1 for r in releases if EXPLOITED_OPEN in r["promoted_because"]),
        "not_promoted_spellings": len(spellings - in_releases),
        "exploited_identifiers_open": sum(1 for r in catalogue if _int(r.get("hosts_open")) > 0),
        "products": products_out,
        "ambiguous_products": ambiguous,
        "superseded_declarations": superseded,
    }
    return releases, scope


# ── rows ──

def _release_role(reasons: Iterable[str]) -> str:
    why = []
    if SUPPORT_PAST in reasons:
        why.append("its vendor support date has passed")
    if EXPLOITED_OPEN in reasons:
        why.append("a defect known to be exploited is open against it")
    return ("A software version in use where " + " and ".join(why)) if why \
        else "A software version in use"


_SCOPE_ROLE = ("How many software versions the exports name, how many carry a support or "
               "exploited-defect decision, and the units each is counted in")


def _release_note(rec: Mapping[str, Any]) -> str:
    parts: list[str] = []
    support = rec.get("support")
    if support:
        band = support["band"] + (f", only with {support['condition']}" if support["condition"] else "")
        parts.append(f"Vendor band on {support['as_of']}: {band}"
                     + (f"; support ends {support['end_of_support']}"
                        if support.get("end_of_support") else ""))
    exploited = rec.get("exploited")
    if exploited:
        parts.append(f"{exploited['open']} catalogued exploited defect(s) open on the "
                     f"{exploited['export_date']} export, {exploited['past_due_at_export']} past "
                     "the catalogue's due date on that date")
        named = "; ".join(f"{c} ({a})" for c, a in
                          sorted((exploited.get("catalogue_attribution") or {}).items()))
        parts.append(ATTRIBUTION_NOTE + (f" — the catalogue names {named}" if named else ""))
    covered = rec.get("covered") or []
    if rec.get("keyed_on") == "vendor-line":
        parts.append(f"Covers {len(covered)} version string(s) the exports name, each counted "
                     "separately in its own unit")
    elif rec.get("unmapped_reason"):
        parts.append(str(rec["unmapped_reason"]))
    if rec.get("declaration_note"):
        parts.append(str(rec["declaration_note"]).rstrip("."))
    return ". ".join(parts) + ("." if parts else "")


def register_release(rec: Mapping[str, Any]) -> Record:
    """One release as an entry of ``extra.releases`` (``docs/CMDB.md``).

    A release keyed on the vendor's line carries the line and every version
    string it covers, spelled as the exports spell them. Any other release
    carries its one version, or none. The support band and its condition travel
    as one status ("band, only with condition"); the exploited defects travel
    as their identifiers, the count past the catalogue's due date, and the
    export date.
    """
    by_line = rec.get("keyed_on") == "vendor-line"
    covered = [c for c in rec.get("covered") or [] if isinstance(c, Mapping)]
    if by_line:
        versions = [f"{c.get('product') or ''} {c.get('version') or ''}".strip() for c in covered]
    else:
        one = str(covered[0].get("version") or "") if covered else ""
        versions = [one] if one else []
    entry: Record = {
        "product": str(rec.get("product") or ""),
        "label": str(rec.get("label") or rec.get("product") or ""),
        "line": str(rec.get("line") or "") if by_line else "",
        "versions": [v for v in versions if v],
    }
    support = rec.get("support")
    if isinstance(support, Mapping):
        band, condition = str(support.get("band") or ""), str(support.get("condition") or "")
        entry["support"] = {
            "status": band + (f", only with {condition}" if band and condition else ""),
            "end_of_support": str(support.get("end_of_support") or ""),
            "end_of_life": str(support.get("end_of_life") or ""),
            "as_of": str(support.get("as_of") or ""),
        }
    exploited = rec.get("exploited")
    if isinstance(exploited, Mapping):
        entry["exploited"] = {
            "identifiers": [str(i) for i in exploited.get("identifiers") or []],
            "past_due": _int(exploited.get("past_due_at_export")),
            "as_of": str(exploited.get("export_date") or ""),
        }
    return entry


def rows(releases: list[Record], scope: Record, *, collected_at: str) -> list[CryptoAsset]:
    """The release rows, then the scope row."""
    out: list[CryptoAsset] = []
    for rec in releases:
        out.append(CryptoAsset(
            name=str(rec["label"]), data_state="discovery", protocol="software-lifecycle",
            role=_release_role(rec["promoted_because"]),
            software=str(rec["product"]),
            version="" if rec["keyed_on"] == "vendor-line" else str(rec["covered"][0]["version"]),
            source=SOURCE, source_class="private", source_name=SOURCE_NAME,
            collected_at=collected_at, verdict="n/a", notes=_release_note(rec),
            extra={RELEASE_KEY: rec, RELEASES_KEY: [register_release(rec)]}))
    superseded = "".join(
        f" Measurement supersedes declaration: {s['declared_source']} declares {s['declared']} "
        f"(line {s['line']}), while {s['measured_sources']} measure {s['measured']}, so the "
        "declared release carries no support finding; the declaration stays in the census as "
        "the record of what it says."
        for s in scope.get("superseded_declarations") or [])
    out.append(CryptoAsset(
        name="Software census support and exploited-defect fold — scope",
        data_state="discovery", protocol="software-lifecycle", role=_SCOPE_ROLE,
        source=SOURCE, source_class="private", source_name=SOURCE_NAME,
        collected_at=collected_at, verdict="n/a",
        notes=(f"{scope['census_rows']} census rows naming {scope['census_spellings']} "
               f"product-and-version spellings. {scope['promoted_covered_spellings']} of them "
               f"carry a decision (a vendor support date passed on {scope['as_of']}, or an "
               f"exploited defect open on the {scope['export_date']} export) and are carried "
               f"as {scope['promoted']} releases: {scope['promoted_vendor_lines']} vendor "
               f"version lines, and {scope['promoted_unmapped_spellings']} spellings no line "
               f"covers. The other {scope['not_promoted_spellings']} stay a counted "
               "population. Counts are in each source's own unit and never summed. "
               + ATTRIBUTION_NOTE + "." + superseded),
        extra={SCOPE_KEY: scope}))
    return out


# ── reading the census ──

_IMPACT = ("The configuration register cannot say which software versions are past their "
           "vendor support date or carry an exploited defect, so no release carries a "
           "support date or an exploited-defect count.")


def _gap(text: str, harvest: str):
    return coverage.gap(coverage.NOT_COLLECTED, text, impact=_IMPACT,
                        impact_kind=coverage.NARROWS_CONFIDENCE, harvest=harvest,
                        nature=coverage.NO_DATA)


def collect(target: Mapping[str, Any], dataset: Mapping[str, Any]) -> tuple[list[CryptoAsset], list]:
    """The census's rows and gaps: ``([], [gap])`` where an input is missing or unreadable."""
    manifest_path = manifest_path_for_target(target)
    if manifest_path is None:
        return [], [_gap(
            f"software census manifest (<profile>{MANIFEST_SUFFIX}): no vendor support band "
            "or exploited-defect count can reach the configuration register's software "
            "releases",
            "Write the census manifest and run the census, support and vulnerability "
            "analyses it names.")]
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        base = manifest_path.parent
        support_spec = manifest.get("support") or {}
        vulnerability_spec = manifest.get("vulnerabilities") or {}
        census = _read_csv(base / str(manifest["output"]))
        support = _read_csv(base / str(support_spec["output"]))
        vulnerabilities = _read_csv(base / str(vulnerability_spec["products_output"]))
        catalogue = _read_csv(base / str(vulnerability_spec["kev_output"]))
    except (OSError, KeyError, TypeError, AttributeError, csv.Error, yaml.YAMLError) as exc:
        return [], [_gap(
            f"software census outputs named by {manifest_path.name} could not be read "
            f"({type(exc).__name__}: {exc}): no vendor support band or exploited-defect "
            "count reaches the configuration register",
            "Re-run the census, support and vulnerability analyses the manifest names.")]
    as_of = str(support_spec.get("as_of") or "")
    releases, scope = fold(
        census, support, vulnerabilities, catalogue, dataset, as_of=as_of,
        export_date=str(vulnerability_spec.get("dated") or ""),
        supersede=support_spec.get("superseded_by_measurement") or [],
        declaration_notes=support_spec.get("declaration_notes") or [])
    return rows(releases, scope, collected_at=as_of), []


def _dataset(settings: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    """``(the lifecycle table, "")``, or ``({}, why not)``."""
    named = settings.get(LIFECYCLE_SETTING)
    if not named:
        return config.load_software_lifecycle() or {}, ""
    path = config.inbox_path(str(named))
    try:
        loaded = config.load_yaml_strict(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {}, f"{named} could not be read ({type(exc).__name__}: {exc})"
    if not isinstance(loaded, Mapping):
        return {}, f"{named} does not hold a lifecycle table (it must be a mapping with `lines:`)"
    return loaded, ""


def step(ctx: Context) -> StepResult:
    dataset, why = _dataset(ctx.settings)
    if why:
        return StepResult(gaps=[coverage.gap(
            coverage.COULD_NOT_TEST,
            f"software census support was not read: the lifecycle table named by "
            f"`software_support`'s `settings: lifecycle:` {why}",
            impact=_IMPACT, impact_kind=coverage.NARROWS_CONFIDENCE,
            harvest="Correct the lifecycle path in the target profile.",
            nature=coverage.NO_DATA)])
    found, gaps = collect(ctx.target, dataset)
    return StepResult(records=list(found), gaps=list(gaps))


#: The declaration. It names no default input: the manifest sits beside the profile.
PLUGIN = Plugin(name=NAME, kind="general", step=step, gap_prefix=False,
                title="census support bands and exploited defects")
