"""What is planned for a system, and whether its vendor still supports it.

Two axes, both recorded beside the verdict and neither changing it: a weak
cipher on an unsupported system is exactly as weak. What they change is what a
remediation plan can honestly propose.

**Migration strategy** (``migration_strategy``) is one of the "6 R's" of
application migration: rehost, replatform, repurchase, refactor, retire,
retain. It is always declared by a person in the target profile; a word that
covers two of them (such as "migrate", which covers rehost and replatform) is
refused, because the difference is whether the move fixes a finding or merely
carries it across.

**Support status** (``support_status``, ``support_end``) is a band rather than
a yes or no, because vendor support degrades in steps:

* ``supported``: patches and new features still ship;
* ``security-only``: security fixes ship but new protocols and ciphers do not,
  so a patched system may still be unable to reach the baseline;
* ``end-of-support``: no security fixes; a finding cannot be patched away;
* ``end-of-life``: the vendor has withdrawn the product entirely.

A blank status reads as ``unknown``. It may be declared in the target profile,
and a declaration always wins. Otherwise it is derived only where the evidence
identifies a product line exactly:

* Windows devices, from the OS build and edition, against
  ``data/windows-lifecycle.yaml`` (:func:`derive_windows_support`);
* software inventory rows, from product name and version, against
  ``data/software-lifecycle.yaml`` (:func:`derive_census_support`).

Derived bands are computed as of the date the evidence was collected, never
today's date, so the same observation always gives the same answer. A near
match is left unmatched rather than guessed.

**Plan marks** (``replaced_by``, ``retiring_by``) are two further lists of
patterns, also declared by a person. A match sets ``extra[<key>] = True`` on
the row, which two disposition rules read:

* ``replaced_by``: a planned replacement will remove this control;
* ``retiring_by``: the system is being migrated off or retired.

No collector can know either fact, so neither is ever derived. The marks
never change a verdict, and the rules that read them claim only rows that are
not weak (see ``docs/DISPOSITIONS.md``).
"""

from __future__ import annotations

import re
from datetime import date

from .model import CryptoAsset

REHOST = "rehost"
REPLATFORM = "replatform"
REPURCHASE = "repurchase"
REFACTOR = "refactor"
RETIRE = "retire"
RETAIN = "retain"
MIGRATION_STRATEGIES = (REHOST, REPLATFORM, REPURCHASE, REFACTOR, RETIRE, RETAIN)

SUPPORTED = "supported"
SECURITY_ONLY = "security-only"
END_OF_SUPPORT = "end-of-support"
END_OF_LIFE = "end-of-life"
SUPPORT_STATUSES = (SUPPORTED, SECURITY_ONLY, END_OF_SUPPORT, END_OF_LIFE)
# The absence of a value; never written as a declared status.
UNKNOWN_SUPPORT = "unknown"

#: Statuses under which no security update is coming.
UNPATCHABLE = frozenset({END_OF_SUPPORT, END_OF_LIFE})


class LifecycleError(ValueError):
    """A target profile's lifecycle block says something that cannot be applied."""


def _match(rx: re.Pattern[str], a: CryptoAsset) -> bool:
    return bool(rx.search(a.host or "") or rx.search(a.name or ""))


def apply_migration_strategy(assets: list[CryptoAsset], block: dict) -> list[CryptoAsset]:
    """Tag assets from a ``migration_strategy:`` block of ``{strategy: [host or name regex]}``."""
    for strategy, patterns in (block or {}).items():
        if strategy not in MIGRATION_STRATEGIES:
            raise LifecycleError(
                f"migration_strategy: {strategy!r} is not one of {list(MIGRATION_STRATEGIES)}. "
                f"A word covering two of them (such as 'migrate') has to be split by a "
                f"person into one of them")
        for pattern in patterns or []:
            rx = re.compile(pattern)
            for a in assets:
                if _match(rx, a):
                    a.migration_strategy = strategy
    return assets


def apply_support_status(assets: list[CryptoAsset], block: dict) -> list[CryptoAsset]:
    """Tag assets from a ``support_status:`` block.

    Each status lists entries that are either a regex, or ``{match: regex,
    ends: date}`` to record when support ends.
    """
    for status, entries in (block or {}).items():
        if status not in SUPPORT_STATUSES:
            raise LifecycleError(
                f"support_status: {status!r} is not one of {list(SUPPORT_STATUSES)}. "
                f"{UNKNOWN_SUPPORT!r} is the absence of a value, so leave the asset out "
                f"instead of declaring it")
        for entry in entries or []:
            pattern = entry if isinstance(entry, str) else entry.get("match", "")
            ends = "" if isinstance(entry, str) else str(entry.get("ends", "") or "")
            rx = re.compile(pattern)
            for a in assets:
                if _match(rx, a):
                    a.support_status = status
                    if ends:
                        a.support_end = ends
    return assets


REPLACED_BY = "replaced_by"
RETIRING_BY = "retiring_by"
#: Keys of the lifecycle block that are flat pattern lists setting ``extra[<key>] = True``.
PLAN_MARKS = (REPLACED_BY, RETIRING_BY)


def _mark_patterns(block: dict, key: str) -> list[str]:
    patterns = (block or {}).get(key) or []
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        raise LifecycleError(f"{key}: expected a list of regular expressions, got {patterns!r}")
    return patterns


def apply_plan_marks(assets: list[CryptoAsset], block: dict) -> list[CryptoAsset]:
    """Set ``extra[key] = True`` on every asset a ``replaced_by`` or ``retiring_by`` pattern matches."""
    for key in PLAN_MARKS:
        for pattern in _mark_patterns(block, key):
            rx = re.compile(pattern)
            for a in assets:
                if _match(rx, a):
                    a.extra[key] = True
    return assets


def unmatched_patterns(assets: list[CryptoAsset], block: dict | list, key: str) -> list[str]:
    """Patterns in a lifecycle block that match no asset: a typo, or a host since gone.

    ``block`` is either a mapping of value to entries, or a flat list of
    patterns (a plan mark), reported under ``key`` alone.
    """
    groups = {"": block} if isinstance(block, list) else (block or {})
    out = []
    for value, entries in groups.items():
        label = f"{key}.{value}" if value else key
        for entry in entries or []:
            pattern = entry if isinstance(entry, str) else entry.get("match", "")
            rx = re.compile(pattern)
            if not any(_match(rx, a) for a in assets):
                out.append(f"{label}: /{pattern}/ matched no asset")
    return out


# ── Windows: build and edition against the Microsoft lifecycle tables ──

#: ``extra`` key set to :data:`DERIVED` on every asset whose status was derived here.
SUPPORT_STATUS_BASIS_KEY = "support_status_basis"
DERIVED = "derived"
#: ``extra`` key for what a derived band depends on, such as a paid extension.
SUPPORT_CONDITION_KEY = "support_condition"

#: ``extra`` keys a collector fills for a Windows device: the dotted version
#: string (``10.0.<build>.<revision>``), the edition as the inventory reports
#: it, and the product name.
OS_VERSION_KEY = "os_version"
OS_EDITION_KEY = "sku_family"
OS_NAME_KEY = "os"

_WINDOWS_BUILD = re.compile(r"^10\.0\.(\d{5})(?:\.\d+)?$")

# Windows 11 builds start here; anything lower on 10.0 is Windows 10.
_WINDOWS_11_FIRST_BUILD = 22000

# Editions served by the Home and Pro tables, as the data file's header names
# them (written without spaces), and as Windows itself reports its edition.
HOME_PRO_EDITIONS = frozenset({
    "Home", "Pro", "ProEducation", "ProForWorkstations",
    "Core", "Professional", "ProfessionalEducation", "ProfessionalWorkstation",
})

_ESU_CONDITION = "paid Extended Security Updates"


def _as_of(a: CryptoAsset) -> date | None:
    try:
        return date.fromisoformat((a.collected_at or "")[:10])
    except ValueError:
        return None


def _fold(s: object) -> str:
    return " ".join(str(s or "").split()).casefold()


def _product_row(dataset: dict, name: str) -> dict | None:
    """The LTSC or Server row whose product name begins ``name`` at a word boundary; longest wins."""
    folded = _fold(name)
    if not folded:
        return None
    best: dict | None = None
    for table in ("windows_server", "windows_ltsc"):
        for row in dataset.get(table) or []:
            product = _fold(row.get("product"))
            if product and (folded == product or folded.startswith(product + " ")):
                if best is None or len(product) > len(_fold(best.get("product"))):
                    best = row
    return best


def _product_band(row: dict, as_of: date) -> tuple[str, str, str]:
    """(band, condition, last day without a paid extension) for an LTSC or Server row."""
    mainstream = date.fromisoformat(str(row["mainstream_end"]))
    extended = date.fromisoformat(str(row["extended_end"])) if row.get("extended_end") else None
    esu = date.fromisoformat(str(row["esu_end"])) if row.get("esu_end") else None
    last_free = str(row.get("extended_end") or row["mainstream_end"])
    if as_of <= mainstream:
        return SUPPORTED, "", last_free
    if extended is not None and as_of <= extended:
        return SECURITY_ONLY, "", last_free
    if esu is not None and as_of <= esu:
        return SECURITY_ONLY, _ESU_CONDITION, last_free
    return END_OF_SUPPORT, "", last_free


def _ga_table(dataset: dict, build: int, edition: str) -> dict | None:
    """The General Availability table for this build and edition, or None if the edition is not covered."""
    release = "windows_11" if build >= _WINDOWS_11_FIRST_BUILD else "windows_10"
    if edition in set(dataset.get("editions_covered") or []):
        return dataset.get(f"{release}_enterprise_education") or {}
    if edition in HOME_PRO_EDITIONS:
        return dataset.get(f"{release}_home_pro") or {}
    return None


def derive_windows_support(assets: list[CryptoAsset], dataset: dict) -> dict:
    """Fill ``support_status`` and ``support_end`` on Windows devices from ``dataset``.

    ``dataset`` is ``data/windows-lifecycle.yaml``. An asset already carrying
    a status is skipped, so call this after :func:`apply_support_status`.

    A device whose product name (``extra["os"]``) names an LTSC or Server
    release is graded against that release's row, and the row's build must
    agree with the device's where both are known. Any other device needs a
    ``10.0.<build>`` version, a build in a General Availability table and an
    edition that table covers;
    a build alone is never enough, because editions of the same build have
    different end dates. Returns counts of what was matched and why the rest
    was not.
    """
    counts = {"matched": 0, "wrong_or_missing_edition": 0, "unrecognised_build": 0,
              "unrecognised_product": 0, "uncollected_date": 0}
    for a in assets:
        if a.support_status:
            continue
        m = _WINDOWS_BUILD.match(str(a.extra.get(OS_VERSION_KEY) or "").strip())
        build = m.group(1) if m else ""
        name = str(a.extra.get(OS_NAME_KEY) or "")
        row = _product_row(dataset, name)
        if row is None:
            if not build:
                continue
            if re.search(r"\b(server|ltsc|ltsb)\b", name, re.IGNORECASE):
                counts["unrecognised_product"] += 1
                continue
        elif build and row.get("build") and str(row["build"]) != build:
            counts["unrecognised_product"] += 1
            continue
        as_of = _as_of(a)
        if row is not None:
            if as_of is None:
                counts["uncollected_date"] += 1
                continue
            band, condition, end = _product_band(row, as_of)
        else:
            table = _ga_table(dataset, int(build), str(a.extra.get(OS_EDITION_KEY) or "").strip())
            if table is None:
                counts["wrong_or_missing_edition"] += 1
                continue
            ga = table.get(build)
            if ga is None:
                counts["unrecognised_build"] += 1
                continue
            if as_of is None:
                counts["uncollected_date"] += 1
                continue
            end = str(ga["end"])
            band = SUPPORTED if as_of <= date.fromisoformat(end) else END_OF_SUPPORT
            condition = ""
        a.support_status = band
        a.support_end = end
        a.extra[SUPPORT_STATUS_BASIS_KEY] = DERIVED
        if condition:
            a.extra[SUPPORT_CONDITION_KEY] = condition
        counts["matched"] += 1
    return counts


def is_unpatchable(asset: CryptoAsset) -> bool:
    """True when no security update is coming for this system."""
    return asset.support_status in UNPATCHABLE


def lifecycle_summary(assets: list[CryptoAsset]) -> dict:
    """Counts on each axis, including how much is unknown and how much was derived."""
    total = len(assets)
    by_strategy: dict[str, int] = {}
    by_support: dict[str, int] = {}
    for a in assets:
        if a.migration_strategy:
            by_strategy[a.migration_strategy] = by_strategy.get(a.migration_strategy, 0) + 1
        key = a.support_status or UNKNOWN_SUPPORT
        by_support[key] = by_support.get(key, 0) + 1
    known = total - by_support.get(UNKNOWN_SUPPORT, 0)
    derived = sum(1 for a in assets if a.extra.get(SUPPORT_STATUS_BASIS_KEY) == DERIVED)
    return {
        "by_migration_strategy": by_strategy,
        "by_support_status": by_support,
        "unpatchable": sum(1 for a in assets if is_unpatchable(a)),
        "strategy_declared": sum(by_strategy.values()),
        "support_declared": known - derived,
        "support_derived": derived,
        "declared_share": round(known / total, 3) if total else 0.0,
    }


# ── Software inventory rows against data/software-lifecycle.yaml ──

_MONTH = re.compile(r"^(\d{4})-(\d{2})$")

#: Row kinds for which "no line matches" is itself worth reporting: an
#: operating system or hypervisor with no known lifecycle is a gap, while most
#: applications are simply outside the table.
REPORT_UNMATCHED_KINDS = ("os", "hypervisor")


def _bounds(until: str) -> tuple[date, date]:
    """(first, last) day an ``until`` value can mean: one day, or a whole month."""
    m = _MONTH.match(until)
    if not m:
        d = date.fromisoformat(until)
        return d, d
    y, mo = int(m.group(1)), int(m.group(2))
    first = date(y, mo, 1)
    nxt = date(y + (mo == 12), 1 if mo == 12 else mo + 1, 1)
    return first, date.fromordinal(nxt.toordinal() - 1)


def variant_band(variant: dict, as_of: date) -> tuple[str | None, str, str]:
    """(band or None, condition, the ``until`` it holds to) for one variant on ``as_of``.

    Each phase holds up to and including its ``until``. Inside a month-only
    boundary, before ``known_from``, or after a line whose ``after`` is
    ``unknown``, the band is undetermined (None).
    """
    known_from = str(variant.get("known_from") or "")
    if known_from and as_of < date.fromisoformat(known_from):
        return None, "", ""
    for phase in variant.get("phases") or []:
        until = str(phase["until"])
        first, last = _bounds(until)
        if first == last:
            if as_of <= last:
                return str(phase["band"]), str(phase.get("condition") or ""), until
            continue
        if as_of < first:
            return str(phase["band"]), str(phase.get("condition") or ""), until
        if as_of <= last:
            return None, "", until
    after = str(variant.get("after") or UNKNOWN_SUPPORT)
    return (None if after == UNKNOWN_SUPPORT else after), "", ""


def match_lines(dataset: dict, kind: str, product: str, version: str) -> list[dict]:
    """Every line whose ``match`` rules accept this row: same kind, whole-string matches only."""
    hits = []
    for line in dataset.get("lines") or []:
        for m in line.get("match") or []:
            if str(m.get("kind") or "") != kind:
                continue
            if "product" in m and _fold(m["product"]) != _fold(product):
                continue
            if "product_pattern" in m and not re.fullmatch(str(m["product_pattern"]), product.strip(),
                                                           re.IGNORECASE):
                continue
            if "version_pattern" in m and not re.fullmatch(str(m["version_pattern"]), version.strip()):
                continue
            hits.append(line)
            break
    return hits


def line_support(line: dict, as_of: date) -> dict:
    """The line's band on ``as_of``; ``unknown`` with a reason when the variants cannot settle it."""
    results = [(v, *variant_band(v, as_of)) for v in line.get("variants") or []]
    if not results:
        return {"band": UNKNOWN_SUPPORT, "condition": "", "holds_until": "",
                "reason": "line has no variants"}
    undetermined = [str(v.get("name")) for v, band, _c, _u in results if band is None]
    if undetermined:
        return {"band": UNKNOWN_SUPPORT, "condition": "", "holds_until": "",
                "reason": "undetermined on this date for: " + "; ".join(undetermined)}
    outcomes = {(band, cond) for _v, band, cond, _u in results}
    if len(outcomes) > 1:
        detail = "; ".join(f"{v.get('name')}={band}{' (' + cond + ')' if cond else ''}"
                           for v, band, cond, _u in results)
        return {"band": UNKNOWN_SUPPORT, "condition": "", "holds_until": "",
                "reason": "the variants disagree: " + detail}
    (band, cond), = outcomes
    untils = {u for _v, _b, _c, u in results}
    return {"band": band, "condition": cond,
            "holds_until": untils.pop() if len(untils) == 1 else "",
            "reason": "" if len(untils) <= 1 else "the band agrees; the date it holds to differs by variant"}


def derive_census_support(rows: list[dict], dataset: dict, as_of: str,
                          aliases: list[dict] | None = None) -> tuple[list[dict], dict]:
    """Grade software inventory rows against ``dataset`` (``data/software-lifecycle.yaml``).

    Each row needs ``source``, ``kind``, ``product`` and optionally
    ``version`` and ``source_date``. The band is read twice: on the row's own
    ``source_date``, and on ``as_of``. ``aliases`` (``{source, product,
    version, line}``) map a product string an export spells unusually to a
    line id. A row matching two lines is reported as ambiguous, never graded.
    Unmatched rows are returned only for :data:`REPORT_UNMATCHED_KINDS`.
    Returns the graded records and counts of matched, ambiguous and unmatched.
    """
    by_id = {str(line["id"]): line for line in dataset.get("lines") or []}
    sources = dataset.get("sources") or {}
    as_of_date = date.fromisoformat(as_of)
    alias_index: dict[tuple[str, str, str], str] = {}
    for al in aliases or []:
        if str(al["line"]) not in by_id:
            raise LifecycleError(f"alias names unknown lifecycle line {al['line']!r}")
        alias_index[(str(al["source"]), _fold(al["product"]), _fold(al.get("version") or ""))] = \
            str(al["line"])
    out: list[dict] = []
    counts = {"matched": 0, "ambiguous": 0, "unmatched": 0}
    for r in rows:
        alias = alias_index.get((str(r["source"]), _fold(r["product"]), _fold(r.get("version") or "")))
        hits = [by_id[alias]] if alias else match_lines(dataset, str(r["kind"]), str(r["product"]),
                                                       str(r.get("version") or ""))
        rec = {k: r.get(k, "") for k in ("source", "source_date", "kind", "vendor", "product", "version",
                                         "population", "population_unit", "declared_support_end")}
        if len(hits) > 1:
            counts["ambiguous"] += 1
            rec.update(line="", band_at_source_date=UNKNOWN_SUPPORT, band_at_as_of=UNKNOWN_SUPPORT,
                       reason="ambiguous: matches " + ", ".join(str(h["id"]) for h in hits))
            out.append(rec)
            continue
        if not hits:
            counts["unmatched"] += 1
            if str(r["kind"]) in REPORT_UNMATCHED_KINDS:
                rec.update(line="", band_at_source_date=UNKNOWN_SUPPORT, band_at_as_of=UNKNOWN_SUPPORT,
                           reason="no lifecycle line matches this product exactly")
                out.append(rec)
            continue
        counts["matched"] += 1
        line = hits[0]
        at_as_of = line_support(line, as_of_date)
        src_date = str(r.get("source_date") or "")
        at_source = (line_support(line, date.fromisoformat(src_date[:10])) if src_date else
                     {"band": UNKNOWN_SUPPORT, "condition": "", "holds_until": "",
                      "reason": "the export states no date"})
        urls = sorted({str((sources.get(v.get("source")) or {}).get("url") or "")
                       for v in line.get("variants") or []} - {""})
        rec.update(
            line=line["id"], matched_by="alias" if alias else "dataset",
            band_at_source_date=at_source["band"], condition_at_source_date=at_source["condition"],
            band_at_as_of=at_as_of["band"], condition_at_as_of=at_as_of["condition"],
            as_of=as_of, holds_until=at_as_of["holds_until"],
            reason="; ".join(x for x in (at_source["reason"] and f"at source date: {at_source['reason']}",
                                         at_as_of["reason"] and f"at {as_of}: {at_as_of['reason']}") if x),
            vendor_sources=" ".join(urls),
        )
        out.append(rec)
    return out, counts
