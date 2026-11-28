"""CrowdStrike Falcon: the outside organisations an estate's machines look names up for.

**The input** (``input:``) is a CSV of DNS names the Falcon sensor saw its
machines ask for, one row per name with a count of lookups, such as the
LogScale query in ``docs/COLLECTORS.md`` writes. The default headings are that
query's; ``settings: columns:`` names an export's own (a heading, or a list
tried in order):

* ``name`` (``DomainName``): the name looked up;
* ``lookups`` (``_count``): how many times. A blank or unreadable count is
  read as 0 lookups; the name is still counted.

**What a name is.** Each name is trimmed, lower-cased and stripped of a
trailing dot (:func:`takestock.dnsnames.normalise`), then put in one of three
places:

* *not public*: a single label, or a name ending in one of
  :data:`takestock.dnsnames.NON_PUBLIC_SUFFIXES` or in an ending
  ``settings: non_public_suffixes:`` adds. It cannot belong to anybody
  outside the organisation, so it is counted on the scope row and nothing
  more;
* *the organisation's own*: a name equal to, or under, one of the profile's
  ``discovery.domains`` or ``discovery.email_domains``. Counted, never a row;
* *external*: everything else.

**Who is behind an external name.** The profile's own declarations win: a
domain listed under ``domains:`` on a ``third_party:``, ``infrastructure:``
or ``scan_targets`` (``saas_443``, ``smtp_25``) entry names that declared
supplier (:func:`takestock.dnsnames.declared_vendors`). Otherwise the vendor
table does: takestock's bundled ``vendor-domains.csv``, or the CSV
``settings: vendor_domains:`` names, which replaces it (same columns:
``domain``, ``vendor``, ``category``, ``notes``). Both are matched by the
longest listed suffix of the name (:func:`takestock.dnsnames.suffix_lookup`).
A name neither places is *unattributed*, and is grouped under a best guess at
its registered domain (:func:`takestock.dnsnames.registrable`, which
``settings: second_level_labels:`` extends). That guess is used only for
grouping, never for attributing.

**A dependency, or incidental.** Each name an organisation is looked up under
gives it a category: the vendor table's for that name, or
:data:`DECLARED_CATEGORY` for a name only the profile's ``domains:`` place.
The organisation is a dependency when one of those categories is in
``settings: dependency_categories:`` (default :data:`DEPENDENCY_CATEGORIES`:
every category of the bundled table except ``cdn``, a shared content network)
or is :data:`DECLARED_CATEGORY`. The table's category wins over a declaration:
a declared supplier whose every name the table files under a category that
does not count is incidental, and its declaration still counts as seen. The
rest are *incidental*: collapsed onto one row and named there, so a reader who
disagrees with the table can see what it set aside.

**Declared or not.** A dependency is matched to the profile's declarations by
whole words (:func:`takestock.dnsnames.declared_matches`): every identifying
word of the vendor's name must be a whole word of a declared name, so a vendor
is never absorbed into a declared supplier whose name merely contains one of
its words. Every declaration it accounts for counts as seen, not only the
first. A dependency no declaration accounts for is *undeclared*.

**Post-quantum positions.** Beside each dependency the reader puts what it
knows about the supplier's post-quantum plans: the declaration's own
``pq_roadmap:`` when it has one, else a published position from
:mod:`takestock.pqc_positions` (the bundled file and the profile's
``<stem>.pqc-positions.yaml``). Neither means no position is *on record
here*, which is never read as *silent*, and the row is flagged
``pq-roadmap-unrecorded``. A position past its re-check date on the day the
reader runs is still shown; its sentence says it is due for re-checking, its
payload says ``stale: true``, and a gap lists every such position shown on a
row. The run date, not the export's, decides this, because the question is
whether the supplier's stated position is still current, not how old the
export is.

**Rows** (all ``third-party``, protocol ``dependency``):

* ``Third-party dependency: <vendor>``, one per dependency:
  ``third-party-observed:<vendor>`` (declared, ``n/a``) or
  ``third-party-undeclared:<vendor>`` (``unknown``), plus
  ``pq-roadmap-unrecorded`` when there is no position. Its ``extra`` holds
  ``vendor``, ``lookups``, ``names``, ``registrable_domains`` (at most 40),
  ``categories``, ``declared_as``, ``declared``, ``pq_roadmap`` (the
  sentence, or ``unrecorded``), ``pq_position`` (the published position's
  payload, empty when the roadmap is the profile's own or absent) and
  ``evidence``;
* the same name for a ``third_party:`` supplier declared and never seen:
  ``third-party-not-observed:<vendor>`` (``n/a``: absence of a lookup is not
  evidence a supplier is unused);
* ``Names resolved that are not organisational dependencies``
  (``third-party-incidental``, ``n/a``);
* ``Unattributed external domain: <domain>`` (``dns-name-unattributed:<domain>``,
  ``unknown``), for each group holding at least ``settings:
  unattributed_share:`` of the external lookups (default 0.001, 0.1%); the
  smaller groups are counted on the scope row;
* ``Third-party dependency scope`` (``scope-dns-evidence-only``, ``n/a``):
  the counts, the shares, and what a lookup cannot prove.

**Gaps.** The undeclared organisations, by name; the dependencies with no
post-quantum position; the stale positions shown. :func:`summarise` gives the
``summary.json`` block, and :func:`attribution` returns the tables the reader
attributes with, so another module can attribute names exactly as these rows
were.

A DNS lookup proves only that something asked for a name: not that a
connection was made, that data flowed, or that anything was encrypted.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config, coverage, dnsnames, pqc_positions, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_dns"
#: The data state of every row.
DATA_STATE = "third-party"
#: The protocol of every row.
PROTOCOL = "dependency"

OBSERVED_FLAG = "third-party-observed:"
UNDECLARED_FLAG = "third-party-undeclared:"
NOT_OBSERVED_FLAG = "third-party-not-observed:"
INCIDENTAL_FLAG = "third-party-incidental"
UNATTRIBUTED_FLAG = "dns-name-unattributed:"
NO_ROADMAP_FLAG = "pq-roadmap-unrecorded"
SCOPE_FLAG = "scope-dns-evidence-only"

# These say what the supplier record does and does not know. A supplier nobody
# wrote down is not a weaker supplier, so none of them is a finding about the
# estate getting worse; the undeclared and unpositioned ones are gaps instead.
register_informational_prefixes(OBSERVED_FLAG, UNDECLARED_FLAG, NOT_OBSERVED_FLAG,
                                INCIDENTAL_FLAG, UNATTRIBUTED_FLAG, NO_ROADMAP_FLAG,
                                SCOPE_FLAG)

#: Each field and its default heading, unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {"name": "DomainName", "lookups": "_count"}

#: The vendor table categories that make an organisation a dependency, unless
#: ``settings: dependency_categories:`` names others.
DEPENDENCY_CATEGORIES: frozenset[str] = frozenset({
    "cloud", "saas", "collaboration", "identity", "security", "pki", "devtools",
    "infrastructure"})
#: The category given to a name the profile's own ``domains:`` place when the
#: vendor table has no category for it. It always counts as a dependency.
DECLARED_CATEGORY = "declared"
#: The share of external lookups an unattributed group needs for a row of its own.
UNATTRIBUTED_SHARE = 0.001
#: How many registered domains a dependency row lists.
DOMAINS_LISTED = 40
#: How many incidental organisations the incidental row names.
INCIDENTAL_NAMED = 60
#: How many undeclared organisations the gap names.
UNDECLARED_NAMED = 25

DNS_SCOPE = (
    "A DNS lookup proves only that something asked for a name. It is not evidence "
    "that a connection was made, that data flowed, that anything was encrypted, or "
    "that the organisation has any relationship with whoever owns the name. Where the "
    "sensored machines include people's workstations, ordinary web browsing is mixed "
    "in with the organisation's own dependencies, and lookup counts cannot tell the "
    "two apart")


@dataclass(frozen=True)
class Attribution:
    """Everything the reader attributes names with, as one profile and its settings give it.

    ``entries`` and ``declared_domains`` are
    :func:`takestock.dnsnames.declared_vendors`'s two results;
    ``vendor_table`` is keyed by domain; ``own_suffixes`` are the profile's
    own domains; ``positions`` are the post-quantum positions.
    """

    vendor_table: Mapping[str, Mapping[str, str]]
    entries: Mapping[str, dnsnames.DeclaredVendor]
    declared_domains: Mapping[str, str]
    own_suffixes: tuple[str, ...]
    positions: pqc_positions.Positions
    non_public: tuple[str, ...] = dnsnames.NON_PUBLIC_SUFFIXES
    second_level: frozenset[str] = dnsnames.SECOND_LEVEL_LABELS
    dependency_categories: frozenset[str] = DEPENDENCY_CATEGORIES
    unattributed_share: float = UNATTRIBUTED_SHARE
    #: The vendor table file read, or "" for the bundled one.
    vendor_table_file: str = ""
    #: Each setting that was not used, with why; its default was used instead.
    setting_problems: tuple[tuple[str, str], ...] = ()


def own_suffixes(target: Mapping) -> tuple[str, ...]:
    """The organisation's own domains: ``discovery.domains`` and ``discovery.email_domains``."""
    discovery = target.get("discovery") or {}
    if not isinstance(discovery, Mapping):
        return ()
    names = [dnsnames.normalise(d) for d in _listed(discovery.get("domains"))]
    names += [dnsnames.normalise(d) for d in _listed(discovery.get("email_domains"))]
    return tuple(sorted({n for n in names if n}))


def _listed(raw: Any) -> list:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    return list(raw) if isinstance(raw, Iterable) else []


def _words(raw: Any, default: Iterable[str]) -> frozenset[str]:
    if raw is None:
        return frozenset(default)
    return frozenset(str(v).strip().lower() for v in _listed(raw) if str(v).strip())


def _share(raw: Any) -> tuple[float, str]:
    """The ``unattributed_share`` setting, and "" or why it was not used."""
    if raw is None:
        return UNATTRIBUTED_SHARE, ""
    if isinstance(raw, bool):
        value = None
    else:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = None
    if value is None or not 0 <= value < 1:
        return UNATTRIBUTED_SHARE, f"is {raw!r}, not a share from 0 up to (not including) 1"
    return value, ""


def attribution(target: Mapping, settings: Mapping | None = None) -> Attribution:
    """The tables :data:`PLUGIN` attributes with, for ``target`` and the plug-in's ``settings``.

    Built exactly as the step builds them, so a caller attributing other
    names (a host it reached, say) uses the same table as the rows. Raises
    ``OSError`` when ``settings: vendor_domains:`` names a file that cannot be
    read, and ``ValueError`` when a positions file is malformed.
    """
    s = settings or {}
    named = s.get("vendor_domains")
    table_path = config.inbox_path(str(named)) if named else None
    table = config.load_vendor_domains(table_path)
    entries, domains = dnsnames.declared_vendors(target)
    share, share_problem = _share(s.get("unattributed_share"))
    return Attribution(
        vendor_table=table, entries=entries, declared_domains=domains,
        own_suffixes=own_suffixes(target), positions=pqc_positions.load(target),
        non_public=dnsnames.non_public_suffixes(_listed(s.get("non_public_suffixes"))),
        second_level=dnsnames.second_level_labels(_listed(s.get("second_level_labels"))),
        dependency_categories=_words(s.get("dependency_categories"), DEPENDENCY_CATEGORIES),
        unattributed_share=share,
        vendor_table_file=str(table_path) if table_path else "",
        setting_problems=(("unattributed_share", share_problem),) if share_problem else ())


def attribute(name: str, att: Attribution) -> tuple[str, str]:
    """The organisation behind an external name and its category, or ``("", "")``.

    The profile's ``domains:`` win over the vendor table; an organisation they
    name takes the table's category for the name when it has one, else
    :data:`DECLARED_CATEGORY`.
    """
    by_profile = dnsnames.suffix_lookup(name, att.declared_domains)
    found = dnsnames.suffix_lookup(name, att.vendor_table)
    row: Mapping = found if isinstance(found, Mapping) else {}
    if by_profile:
        return str(by_profile), str(row.get("category", "")) or DECLARED_CATEGORY
    return str(row.get("vendor", "")), str(row.get("category", ""))


@dataclass
class _Tally:
    rows: int = 0
    names_nonpublic: int = 0
    lookups_nonpublic: int = 0
    names_own: int = 0
    lookups_own: int = 0
    names_external: int = 0
    lookups_external: int = 0
    names_attributed: int = 0
    lookups_attributed: int = 0
    vendors: dict[str, dict] = field(default_factory=dict)
    unattributed: dict[str, dict] = field(default_factory=dict)

    @property
    def lookups_unattributed(self) -> int:
        return sum(v["lookups"] for v in self.unattributed.values())

    def threshold(self, share: float) -> int:
        return int(self.lookups_external * share)


def _tally(rows: Iterable[Mapping[str, str]], att: Attribution) -> _Tally:
    t = _Tally()
    for r in rows:
        t.rows += 1
        name = dnsnames.normalise(r.get("name"))
        count = _lookups(r.get("lookups", ""))
        if not dnsnames.is_public(name, att.non_public):
            t.names_nonpublic += 1
            t.lookups_nonpublic += count
            continue
        if any(name == o or name.endswith("." + o) for o in att.own_suffixes):
            t.names_own += 1
            t.lookups_own += count
            continue
        t.names_external += 1
        t.lookups_external += count
        vendor, category = attribute(name, att)
        if not vendor:
            grp = t.unattributed.setdefault(
                dnsnames.registrable(name, att.second_level), {"lookups": 0, "names": 0})
            grp["lookups"] += count
            grp["names"] += 1
            continue
        t.names_attributed += 1
        t.lookups_attributed += count
        agg = t.vendors.setdefault(vendor, {"lookups": 0, "names": 0, "domains": set(),
                                            "categories": set()})
        agg["lookups"] += count
        agg["names"] += 1
        agg["domains"].add(dnsnames.registrable(name, att.second_level))
        if category:
            agg["categories"].add(category)
    return t


def _lookups(raw: object) -> int:
    try:
        return int(str(raw or "").strip() or 0)
    except ValueError:
        return 0


def _base(source_name: str, collected_at: str) -> dict[str, Any]:
    return {"data_state": DATA_STATE, "protocol": PROTOCOL, "source": NAME,
            "source_class": "private", "source_name": source_name,
            "collected_at": collected_at}


def _roadmap_sentence(roadmap: str, published: Mapping) -> str:
    if published:
        return f"Its published post-quantum position: {roadmap}."
    if roadmap:
        return f"The profile records its post-quantum roadmap as: {roadmap}."
    return ("No post-quantum position is on record here for it, in the profile or in the "
            "positions files. That is not the same as a supplier that has published "
            "nothing: no entry says only that none is recorded. Whether its key exchange "
            "will resist a quantum computer is not known here.")


def _vendor_asset(vendor: str, agg: Mapping, entry: Mapping, declared: str,
                  att: Attribution, base: Mapping[str, Any]) -> CryptoAsset:
    lookups, names = agg["lookups"], agg["names"]
    domains = sorted(agg["domains"])
    roadmap, published = pqc_positions.resolve(att.positions, declared or vendor,
                                               str(entry.get("pq_roadmap") or ""))
    flags = [f"{OBSERVED_FLAG}{dnsnames.slug(vendor)}" if declared
             else f"{UNDECLARED_FLAG}{dnsnames.slug(vendor)}"]
    if not roadmap:
        flags.append(NO_ROADMAP_FLAG)
    seen = f"the organisation's machines looked up {len(domains)} of its domains {lookups:,} times"
    if declared:
        opening = f"An outside organisation the profile declares ({declared}); {seen}"
        verdict = "n/a"
    else:
        opening = f"An outside organisation no declaration in the profile accounts for; {seen}"
        verdict = "unknown"
    return CryptoAsset(
        name=f"Third-party dependency: {vendor}",
        role=roles.third_party_vendor(vendor, len(domains), bool(declared)),
        verdict=verdict, flags=sorted(flags), hosts_count=None,
        notes=(f"{opening}. A lookup count shows that a name was asked for, never that a "
               f"connection was made, that data flowed or that anything was encrypted. "
               f"{_roadmap_sentence(roadmap, published)}"),
        extra={"vendor": vendor, "lookups": str(lookups), "names": str(names),
               "registrable_domains": domains[:DOMAINS_LISTED],
               "categories": sorted(agg["categories"]), "declared_as": declared,
               "declared": bool(declared), "pq_roadmap": roadmap or "unrecorded",
               "pq_position": published, "evidence": "dns-resolution-only"},
        **base)


def _not_observed_asset(name: str, entry: Mapping, att: Attribution,
                        base: Mapping[str, Any]) -> CryptoAsset:
    roadmap, published = pqc_positions.resolve(att.positions, name,
                                               str(entry.get("pq_roadmap") or ""))
    flags = [f"{NOT_OBSERVED_FLAG}{dnsnames.slug(name)}"]
    if not roadmap:
        flags.append(NO_ROADMAP_FLAG)
    return CryptoAsset(
        name=f"Third-party dependency: {name}",
        role=roles.third_party_vendor(name, 0, True),
        verdict="n/a", flags=sorted(flags),
        notes=("Declared in the profile as a third party, and not seen in this export. That "
               "is not evidence it is unused: it may be reached by address, under a name "
               "nothing here maps, from a machine without the sensor, or outside the "
               f"export's period. {_roadmap_sentence(roadmap, published)}"),
        extra={"vendor": name, "lookups": "0", "declared_as": name, "declared": True,
               "pq_roadmap": roadmap or "unrecorded", "pq_position": published,
               "evidence": "declaration-only"},
        **base)


def _incidental_asset(incidental: Sequence[tuple[str, dict]], t: _Tally,
                      base: Mapping[str, Any]) -> CryptoAsset:
    ordered = sorted(incidental, key=lambda kv: -kv[1]["lookups"])
    lookups = sum(a["lookups"] for _, a in ordered)
    share = f"{lookups * 100 // t.lookups_external}%" if t.lookups_external else "unknown"
    return CryptoAsset(
        name="Names resolved that are not organisational dependencies",
        role=roles.third_party_incidental(len(ordered)), verdict="n/a",
        flags=[INCIDENTAL_FLAG],
        notes=(f"{len(ordered)} organisations, {lookups:,} lookups ({share} of external "
               f"lookups), whose every name the vendor table files under a category that "
               f"is not a dependency, such as a shared content network a web page pulls "
               f"in. They are named here rather than dropped, because the category is the "
               f"table's judgement and a reader may disagree with it."),
        extra={"organisations": str(len(ordered)), "lookups": str(lookups),
               "share_of_external_lookups": share,
               "named": [v for v, _ in ordered[:INCIDENTAL_NAMED]],
               "basis": "vendor-dictionary-category", "evidence": "dns-resolution-only"},
        **base)


def _unattributed_assets(t: _Tally, att: Attribution,
                         base: Mapping[str, Any]) -> list[CryptoAsset]:
    threshold = t.threshold(att.unattributed_share)
    out: list[CryptoAsset] = []
    for domain, agg in sorted(t.unattributed.items(), key=lambda kv: -kv[1]["lookups"]):
        if agg["lookups"] < threshold:
            continue
        share = (f"{agg['lookups'] * 100 / t.lookups_external:.1f}%"
                 if t.lookups_external else "unknown")
        out.append(CryptoAsset(
            name=f"Unattributed external domain: {domain}",
            role=roles.unattributed_domain(), verdict="unknown",
            flags=[f"{UNATTRIBUTED_FLAG}{domain}"],
            notes=(f"{agg['lookups']:,} lookups ({share} of external lookups) across "
                   f"{agg['names']} name(s), and neither the vendor table nor any "
                   f"declaration in the profile says whose domain this is, so nothing here "
                   f"knows which organisation is behind it. A lookup count shows only that "
                   f"a name was asked for."),
            extra={"registrable_domain": domain, "lookups": str(agg["lookups"]),
                   "names": str(agg["names"]), "share_of_external_lookups": share,
                   "evidence": "dns-resolution-only"},
            **base))
    return out


def _percent(share: float) -> str:
    return f"{share * 100:g}%"


def _scope_asset(t: _Tally, att: Attribution, base: Mapping[str, Any]) -> CryptoAsset:
    threshold = t.threshold(att.unattributed_share)
    below = {d: a for d, a in t.unattributed.items() if a["lookups"] < threshold}
    below_lookups = sum(a["lookups"] for a in below.values())
    attributed_share = (f"{t.lookups_attributed * 100 / t.lookups_external:.1f}%"
                        if t.lookups_external else "unknown")
    below_share = (f"{below_lookups * 100 / t.lookups_external:.1f}%"
                   if t.lookups_external else "unknown")
    return CryptoAsset(
        name="Third-party dependency scope", role=roles.third_party_scope(),
        verdict="n/a", flags=[SCOPE_FLAG],
        notes=(f"{DNS_SCOPE}. The export held {t.rows:,} rows: {t.names_own:,} names under "
               f"the organisation's own domains, {t.names_nonpublic:,} that cannot belong to "
               f"anyone outside it (single labels and private or reserved endings), and "
               f"{t.names_external:,} external names carrying {t.lookups_external:,} "
               f"lookups. {attributed_share} of those lookups were put to "
               f"{len(t.vendors)} organisations by the vendor table or the profile's own "
               f"declarations; {len(below):,} registered domains carrying "
               f"{below_lookups:,} lookups ({below_share}) fell below the "
               f"{_percent(att.unattributed_share)} needed for a row of their own and are "
               f"counted here. The vendor table is a lookup, not a measurement: an "
               f"unattributed name is one the table does not know, never one that does "
               f"not matter. Unattributed names are grouped by a best guess at their "
               f"registered domain, which can split or merge a domain under a public "
               f"suffix the guess does not know."),
        extra={"rows": str(t.rows), "names_external": str(t.names_external),
               "names_own_domains": str(t.names_own),
               "names_non_public": str(t.names_nonpublic),
               "lookups_external": str(t.lookups_external),
               "lookups_own_domains": str(t.lookups_own),
               "lookups_attributed": str(t.lookups_attributed),
               "attributed_share": attributed_share, "organisations": str(len(t.vendors)),
               "unattributed_domains": str(len(t.unattributed)),
               "unattributed_lookups": str(t.lookups_unattributed),
               "unattributed_below_threshold": str(len(below)),
               "threshold_share": _percent(att.unattributed_share),
               "evidence": "dns-resolution-only"},
        **base)


def rows_for(export_rows: Iterable[Mapping[str, str]], att: Attribution, source_name: str,
             collected_at: str) -> list[CryptoAsset]:
    """The rows for an export's ``{"name", "lookups"}`` rows, attributed with ``att``."""
    t = _tally(export_rows, att)
    base = _base(source_name, collected_at)
    assets: list[CryptoAsset] = []
    matched: set[str] = set()
    incidental: list[tuple[str, dict]] = []
    for vendor, agg in sorted(t.vendors.items(), key=lambda kv: -kv[1]["lookups"]):
        hits = dnsnames.declared_matches(vendor, att.entries)
        if vendor in att.entries and vendor not in hits:
            # The vendor is a declared name word matching cannot reproduce
            # (a slash, a bracket): the profile's own domains named it.
            hits.insert(0, vendor)
        declared = vendor if vendor in att.entries else (hits[0] if hits else "")
        matched.update(hits)
        cats = agg["categories"]
        if not (cats & att.dependency_categories or DECLARED_CATEGORY in cats):
            incidental.append((vendor, agg))
            continue
        entry: Mapping = att.entries.get(declared) or {}
        assets.append(_vendor_asset(vendor, agg, entry, declared, att, base))
    if incidental:
        assets.append(_incidental_asset(incidental, t, base))
    for name, entry in sorted(att.entries.items()):
        if name in matched or entry["kind"] != "third-party":
            continue
        assets.append(_not_observed_asset(name, entry, att, base))
    assets += _unattributed_assets(t, att, base)
    assets.append(_scope_asset(t, att, base))
    return assets


def gaps_for(assets: Sequence[CryptoAsset], att: Attribution) -> list:
    """The gaps the rows call for: undeclared organisations, no position, stale positions."""
    gaps: list = []
    undeclared = sorted(
        ((str(a.extra.get("vendor", "")), _lookups(a.extra.get("lookups"))) for a in assets
         if any(f.startswith(UNDECLARED_FLAG) for f in a.flags)),
        key=lambda kv: -kv[1])
    if undeclared:
        named = ", ".join(f"{v} ({n:,})" for v, n in undeclared[:UNDECLARED_NAMED])
        more = (f", and {len(undeclared) - UNDECLARED_NAMED} more"
                if len(undeclared) > UNDECLARED_NAMED else "")
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{len(undeclared)} outside organisation(s) the machines look names up for are in "
            f"no declaration in the profile (no third party, declared asset class or scan "
            f"target names them): {named}{more}. Each may be a supplier whose cryptography "
            f"the organisation does not control and whose post-quantum plans nobody has "
            f"looked up. The count is a floor: the vendor table does not know every "
            f"domain, and a lookup shows only that a name was asked for",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("The organisation's machines are reaching outside parties that no list "
                    "anybody keeps names. Until each is added to the supplier record or "
                    "set aside as incidental, the record cannot be called complete, and "
                    "nobody has weighed how these parties protect what they carry."),
            harvest=("Go through the names with whoever keeps the supplier record: add each "
                     "as a third_party: entry, or record it as incidental."),
            nature=coverage.NO_DATA))
    without = {str(a.extra.get("vendor", "")) for a in assets if NO_ROADMAP_FLAG in a.flags}
    have = {str(a.extra.get("vendor", "")) for a in assets
            if a.data_state == DATA_STATE and a.extra.get("pq_position")}
    if without:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"No post-quantum position is on record for {len(without)} of the outside "
            f"organisations depended on"
            + (f", against {len(have)} whose own published position has been read and cited"
               if have else "")
            + ". Until each is read, how exposed the traffic these suppliers carry is to "
              "recording now and decrypting later is not known",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("For these suppliers nothing here says whether they plan for the change "
                    "of encryption that quantum computing forces, so a post-quantum "
                    "readiness statement covers the organisation's own systems and the "
                    "suppliers with a position read, and not these."),
            harvest=("Read what each supplier publishes on post-quantum cryptography and "
                     "record it in the profile's <stem>.pqc-positions.yaml: the state, the "
                     "release, the source, who published it and when, and the date read."),
            nature=coverage.LOW_FIDELITY))
    shown = {str((a.extra.get("pq_position") or {}).get("key", "")) for a in assets
             if a.data_state == DATA_STATE and (a.extra.get("pq_position") or {}).get("stale")}
    stale = [s for s in att.positions.stale if s.key in shown]
    if stale:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"{len(stale)} post-quantum position(s) shown beside a supplier are past their "
            f"re-check date: " + "; ".join(s.message for s in stale),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("A supplier's published plans can move on after they were read, so "
                    "these positions may no longer say what the supplier says now."),
            harvest=("Read each supplier's material again and update its entry's read date, "
                     "and its recheck_by where it gives one."),
            nature=coverage.LOW_FIDELITY))
    return gaps


def summarise(assets: Sequence[CryptoAsset]) -> dict:
    """The ``summary.json`` block, from the reader's own rows; ``{}`` when there are none."""
    rows = [a for a in assets if a.data_state == DATA_STATE]
    if not rows:
        return {}

    def vendor(a: CryptoAsset) -> str:
        return str(a.extra.get("vendor", a.name))

    def named(prefix: str) -> list[str]:
        return sorted(vendor(a) for a in rows if any(f.startswith(prefix) for f in a.flags))

    def state_of(a: CryptoAsset) -> object:
        return (a.extra.get("pq_position") or {}).get("state")

    undeclared = named(UNDECLARED_FLAG)
    scope = next((a for a in rows if SCOPE_FLAG in a.flags), None)
    return {
        "dependencies": len(named(OBSERVED_FLAG)) + len(undeclared),
        "declared_and_observed": named(OBSERVED_FLAG),
        "undeclared": undeclared,
        "undeclared_count": len(undeclared),
        "declared_not_observed": named(NOT_OBSERVED_FLAG),
        "without_pq_roadmap": sorted(vendor(a) for a in rows if NO_ROADMAP_FLAG in a.flags),
        "with_pq_position": sorted(vendor(a) for a in rows if a.extra.get("pq_position")),
        "pq_position_states": {
            state: sorted(vendor(a) for a in rows if state_of(a) == state)
            for state in pqc_positions.STATES if any(state_of(a) == state for a in rows)},
        "unattributed_domains": sorted(
            str(a.extra.get("registrable_domain", "")) for a in rows
            if any(f.startswith(UNATTRIBUTED_FLAG) for f in a.flags)),
        "attributed_share": scope.extra.get("attributed_share", "") if scope else "",
    }


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of DNS names looked up was read"
        + (f" ({why})" if why else "")
        + ": which outside organisations the machines depend on, and so which suppliers' "
          "post-quantum plans matter (name it with `input:`)",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it the list of outside organisations depended on is only what was "
                "written down, and which suppliers' encryption the organisation relies on "
                "has no measured answer."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_dns) and name its CSV "
                 "with input:; name its headings with settings: columns:."),
        nature=coverage.NO_DATA)


def _setting_gap(key: str, why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"`settings: {key}:` for `{NAME}` {why}, so it was ignored and the built-in "
        f"default ({_percent(UNATTRIBUTED_SHARE)}) was used",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Which unattributed domains have a row of their own, and which are only "
                "counted on the scope row, follow the default rather than the share the "
                "profile meant to set."),
        harvest="Correct the setting in the target profile.",
        nature=coverage.NO_DATA)


def read(path: Path, heads: Mapping[str, Sequence[str]],
         att: Attribution) -> tuple[list[CryptoAsset], list]:
    """The rows and gaps for one export, or no rows and a gap when it cannot be read."""
    try:
        header = _fp.header_of(path)
        missing = [f"`{heads[f][0]}`" for f in ("name", "lookups")
                   if not _fp.has_column(header, heads[f])]
        if missing:
            return [], [_missing_gap(f"{path.name} has no {' or '.join(missing)} column")]
        export = list(_fp.stream(path, heads))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [_missing_gap(f"{path.name} could not be read: {exc}")]
    if not export:
        return [], [_missing_gap(f"{path.name} holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = (f"CrowdStrike Falcon DNS lookup export, file dated {when}" if when
                   else "CrowdStrike Falcon DNS lookup export, file date unavailable")
    assets = rows_for(export, att, source_name, when)
    return assets, gaps_for(assets, att)


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    try:
        att = attribution(ctx.target, ctx.settings)
    except OSError as exc:
        return StepResult(gaps=[_missing_gap(f"the vendor table named could not be read: {exc}")])
    except ValueError as exc:
        return StepResult(gaps=[_missing_gap(f"a post-quantum positions file is malformed: {exc}")])
    heads = _fp.columns(ctx, HEADINGS)
    assets, gaps = read(ctx.input, heads, att)
    return StepResult(records=assets, gaps=gaps + [_setting_gap(k, why)
                                                   for k, why in att.setting_problems])


def _summary(_ctx: Context, rows: list[CryptoAsset]) -> dict:
    return summarise(rows)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon DNS lookups", summarise=_summary,
                gap_prefix=False)

