"""Software inventory: which cryptographic providers are installed, and at which versions.

The probes measure what a service negotiates. This collector reads what a
service negotiates *with*: the TLS libraries, language runtimes and other
cryptographic providers installed on each machine, from a software inventory
someone supplied. Any inventory tool, or a spreadsheet, can produce one.

**The export** is a CSV, by default ``inbox/software-inventory.csv`` (set
``software_inbox.export`` in the target profile to move it), one row per
product installed on one machine. Header names are matched ignoring case,
spaces, hyphens and underscores; the first spelling present wins:

* ``host`` (or ``hostname``, ``computer name``, ``machine``, ``device``,
  ``server``): the machine, by name or address;
* ``product`` (or ``product name``, ``name``, ``software``, ``application``,
  ``display name``, ``package``): the product as the inventory spells it;
* ``version`` (or ``product version``, ``software version``,
  ``display version``, ``package version``);
* optionally ``vendor`` (or ``publisher``, ``manufacturer``) and ``path`` (or
  ``install path``, ``install location``, ``location``, ``file path``).

**Matching** reads ``data/crypto-software.csv``. A product belongs to the
first entry whose ``match`` expression matches the start of its name, ignoring
case. A product no entry matches is counted on the scope row and named in its
``software_products`` list, and otherwise not graded. Within a product, an
entry with a ``branch`` describes one release line. It applies to a version
that equals the branch, or continues it with something other than a digit
(branch ``1.0`` takes ``1.0.2`` but not ``1.01``), once any packaging epoch
such as ``1:`` is set aside. The longest
matching branch wins. Its ``max_tls`` is the highest TLS version that line can
negotiate, and its ``citation`` says where that is documented.

**Rows.** One per product and version, with the number of machines carrying it
in ``hosts_count`` and their names in ``extra["hosts"]``, and again as a list
in ``extra["installed_on"]``, which the configuration register reads.
Machines are named by the rule in :mod:`takestock.identity`: an address the
target profile pairs with a host name is reported by that name, so a machine
listed both ways is counted once.

* A release line whose ``max_tls`` is below TLS 1.3, or below the lowest
  version the baseline grades better than weak (the floor), is flagged
  ``capability-ceiling:<max_tls>``. The row is weak when the baseline grades
  the ceiling itself weak, since nothing that line negotiates can reach the
  floor. Otherwise it stays unknown: an installed version says the most a
  service using it can do, not the least it will accept.
* A version with no release line on record stays unknown, flagged
  ``ungraded:crypto-software:<product> <version>``.
* A product found at two or more versions gets one more row,
  ``<product> version spread``, flagged ``version-spread:<n>``.

:mod:`takestock.agility` reads those two flags: a ceiling places a row in
``replacement``, a spread in ``library``.

The **scope row** names every product the export lists, cryptographic or not,
in ``extra["software_products"]``: a provider by its register name, any other
product as the export first spells it. Only the name of a product outside the
register is kept, not its versions or machines.

**Lifecycle.** Each product and version is passed to
:func:`takestock.lifecycle.derive_census_support`, as a library and as an
application, under the canonical product name and each spelling the export
used, on the export file's date. Exactly one matching lifecycle line sets
``support_status`` and ``support_end``; none, or more than one, leaves them
blank. A status declared in the profile's ``lifecycle:`` block still wins.

**Cannot see** a provider the register does not list, a library compiled into
another program (an inventory lists installed packages, not what a binary
contains), or what any service using an installed provider negotiates. A
missing or unreadable export is a coverage gap, never a clean result.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .. import binding, coverage, identity, lifecycle
from ..agility import CEILING_FLAG, SPREAD_FLAG
from ..config import (
    display_path,
    inbox_path,
    load_baseline,
    load_crypto_software,
    load_software_lifecycle,
)
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..policy import Policy
from ..util import file_mtime_date, scan_address

SOURCE = "software_inventory"
DEFAULT_EXPORT = "inbox/software-inventory.csv"
#: The row kind: an installed piece of software that provides cryptography.
DATA_STATE = "software"
#: The table named in ``ungraded:`` flags for a version with no release line.
REGISTER_TABLE = "crypto-software"
SCOPE_NAME = "Software inventory scope"

#: A provider row whose version the export left blank.
VERSION_UNRECORDED = "version-unrecorded"

register_informational_prefixes(SPREAD_FLAG, VERSION_UNRECORDED)
binding.register_binding(binding.SOFTWARE, data_states=(DATA_STATE,))

TLS_ORDER = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_NEWEST_TLS = "TLSv1.3"

#: The kinds a product is tried as in the software lifecycle data.
LIFECYCLE_KINDS = ("library", "application")

_PROVIDES = {
    "tls": "TLS and general cryptography",
    "crypto": "cryptographic functions",
    "ssh": "secure shell",
    "signing": "signing and encryption of files and packages",
}

SCOPE_ROLE = ("What the software inventory covers: how many rows and machines it lists, "
              "and how many name a cryptographic provider this build recognises")

_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("host", "hostname", "computername", "computer", "machine", "machinename",
             "device", "devicename", "server", "servername"),
    "product": ("product", "productname", "name", "software", "softwarename", "application",
                "applicationname", "displayname", "package", "packagename"),
    "version": ("version", "productversion", "softwareversion", "applicationversion",
                "displayversion", "packageversion"),
    "vendor": ("vendor", "publisher", "manufacturer"),
    "path": ("path", "installpath", "installlocation", "location", "filepath"),
}

_EPOCH = re.compile(r"^\d+:")


# ── reading the export ──

def _fold_header(cell: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (cell or "").lower())


def columns(header: list[str]) -> dict[str, str]:
    """The header cell read for each field (``host``, ``product`` ...); absent fields are left out."""
    folded: dict[str, str] = {}
    for cell in header:
        folded.setdefault(_fold_header(cell), cell)
    out: dict[str, str] = {}
    for name, spellings in _COLUMNS.items():
        for s in spellings:
            if s in folded:
                out[name] = folded[s]
                break
    return out


def _read(path: Path) -> tuple[list[dict], list[str], str]:
    """(rows, header, error); never raises, so an unreadable file is a gap, not a crash."""
    if not path.exists():
        return [], [], ""
    try:
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            return rows, list(reader.fieldnames or []), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [], str(exc)


# ── matching against the register ──

def provider_for(register: list[dict], product: str) -> dict | None:
    """The first register entry whose ``match`` accepts ``product``, or None."""
    name = product.strip()
    for entry in register:
        pattern = entry.get("match") or ""
        if pattern and re.match(pattern, name, re.IGNORECASE):
            return entry
    return None


def upstream(version: str) -> str:
    """``version`` without a packaging epoch (``1:3.0.0`` gives ``3.0.0``)."""
    return _EPOCH.sub("", (version or "").strip())


def branch_matches(branch: str, version: str) -> bool:
    """True when ``version`` is on release line ``branch``: equal, or continued by a non-digit."""
    v = upstream(version)
    if not branch or not v.startswith(branch):
        return False
    rest = v[len(branch):]
    return not rest or not rest[0].isdigit()


def release_line(register: list[dict], product: str, version: str) -> dict | None:
    """The register entry for ``product``'s release line holding ``version``; the longest branch wins."""
    lines = [e for e in register
             if e.get("product") == product and e.get("branch") and e.get("max_tls")
             and branch_matches(e["branch"], version)]
    return max(lines, key=lambda e: len(e["branch"]), default=None)


def tls_rank(version: str) -> int:
    """The position of a TLS or SSL version in :data:`TLS_ORDER`; -1 when unrecognised."""
    v = Policy.normalise_tls_version(version.strip())
    return TLS_ORDER.index(v) if v in TLS_ORDER else -1


def tls_floor(baseline: Mapping) -> str:
    """The lowest TLS version the baseline grades better than weak."""
    table = baseline.get("tls_versions") or {}
    for v in TLS_ORDER:
        if table.get(v) not in (None, "weak"):
            return v
    return _NEWEST_TLS


def has_ceiling(max_tls: str, floor: str) -> bool:
    """True when a line capped at ``max_tls`` cannot reach TLS 1.3 or the floor."""
    rank = tls_rank(max_tls)
    if rank < 0:
        return False
    return rank < TLS_ORDER.index(_NEWEST_TLS) or rank < tls_rank(floor)


# ── lifecycle ──

def lifecycle_reading(dataset: dict, spellings: list[str], version: str,
                      as_of: str) -> dict | None:
    """The lifecycle record for one product and version, or None when no line matches.

    Every spelling is tried as each of :data:`LIFECYCLE_KINDS`. One line
    matched gives that line's record; two or more give a record with no
    ``line`` and the reason.
    """
    if not dataset.get("lines") or not as_of or not version:
        return None
    rows = [{"source": SOURCE, "kind": kind, "product": s, "version": version,
             "source_date": as_of} for kind in LIFECYCLE_KINDS for s in spellings if s]
    records, _counts = lifecycle.derive_census_support(rows, dataset, as_of)
    matched = {str(r["line"]): r for r in records if r.get("line")}
    ambiguous = [r for r in records if not r.get("line")]
    if len(matched) == 1 and not ambiguous:
        return next(iter(matched.values()))
    if not matched and not ambiguous:
        return None
    reason = (str(ambiguous[0].get("reason")) if ambiguous
              else "the spellings match different lines: " + ", ".join(sorted(matched)))
    return {"line": "", "band_at_source_date": lifecycle.UNKNOWN_SUPPORT, "reason": reason}


def _apply_lifecycle(asset: CryptoAsset, record: dict | None) -> None:
    if record is None:
        return
    line = str(record.get("line") or "")
    band = str(record.get("band_at_source_date") or lifecycle.UNKNOWN_SUPPORT)
    asset.extra[lifecycle.LIFECYCLE_LINE_KEY] = line
    if line and band != lifecycle.UNKNOWN_SUPPORT:
        asset.support_status = band
        asset.support_end = str(record.get("holds_until") or "")
        asset.extra[lifecycle.SUPPORT_STATUS_BASIS_KEY] = lifecycle.DERIVED
        condition = str(record.get("condition_at_source_date") or "")
        if condition:
            asset.extra[lifecycle.SUPPORT_CONDITION_KEY] = condition
        asset.extra["lifecycle_sources"] = str(record.get("vendor_sources") or "")
    else:
        asset.extra["lifecycle_reason"] = str(record.get("reason") or "")


# ── rows ──

@dataclass
class _Group:
    """One product at one version, across every machine that carries it."""

    product: str
    entry: dict
    version: str
    hosts: dict[str, str] = field(default_factory=dict)
    spellings: set[str] = field(default_factory=set)
    vendors: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    rows: int = 0


def machine_name(raw: str, names: Mapping[str, str]) -> str:
    """The name a machine is reported by: the profile's host name for a paired address, else as given."""
    named = names.get(scan_address(raw).lower(), "")
    host, _ip = identity.row_identity(named, raw)
    return host


def _role(provides: str) -> str:
    return (f"Installed software that provides {_PROVIDES.get(provides, 'cryptography')} "
            "to the machines carrying it")


def _version_row(g: _Group, register: list[dict], baseline_tls: Mapping, floor: str,
                 source_name: str, mtime: str, source: str = SOURCE) -> CryptoAsset:
    n = len(g.hosts)
    flags: list[str] = []
    verdict = "unknown"
    extra: dict = {"provides": g.entry.get("provides", ""), "hosts": ", ".join(sorted(g.hosts.values())),
                   "installed_on": sorted(g.hosts.values()),
                   "inventory_rows": g.rows, "spellings": ", ".join(sorted(g.spellings)),
                   "vendors": ", ".join(sorted(g.vendors)), "paths": ", ".join(sorted(g.paths))}
    line = release_line(register, g.product, g.version) if g.version else None
    carry = f"{n} machine(s) carry {g.product}"
    if not g.version:
        flags.append(VERSION_UNRECORDED)
        note = f"{carry} with no version recorded, so its release line cannot be read."
    elif line is None:
        flags.append(f"ungraded:{REGISTER_TABLE}:{g.product} {g.version}")
        note = (f"{carry} {g.version}. No release line covering this version is on record, "
                "so the most it can negotiate is not stated here.")
    else:
        max_tls, branch = line["max_tls"], line["branch"]
        extra.update(release_line=branch, max_tls=max_tls,
                     capability_citation=line.get("citation", ""))
        detail = line.get("note", "").rstrip(".")
        if has_ceiling(max_tls, floor):
            flags.append(f"{CEILING_FLAG}{max_tls}")
            below_floor = baseline_tls.get(Policy.normalise_tls_version(max_tls)) == "weak"
            if below_floor:
                verdict = "weak"
            note = (f"{carry} {g.version}, on the {branch} release line, which cannot negotiate "
                    f"above {max_tls}. No setting changes that: the component is upgraded or "
                    "replaced first."
                    + (f" That ceiling is below the baseline's floor of {floor}, so nothing this "
                       "version negotiates can meet it." if below_floor else ""))
        else:
            note = f"{carry} {g.version}, on the {branch} release line, which can negotiate up to {max_tls}."
        note += (f" {detail}." if detail else "") + f" Source: {line.get('citation', '')}."
    note += (" An installed version says the most a service using it can do; what any service "
             "actually negotiates is measured by the probes, not here.")
    return CryptoAsset(
        name=f"{g.product} {g.version or '(version not recorded)'}",
        data_state=DATA_STATE, role=_role(g.entry.get("provides", "")),
        software=g.product, version=g.version, source=source, source_class="private",
        source_name=source_name, collected_at=mtime, verdict=verdict, flags=sorted(flags),
        hosts_count=n, notes=note, extra=extra)


def _spread_row(product: str, entry: dict, groups: list[_Group], source_name: str,
                mtime: str, source: str = SOURCE) -> CryptoAsset | None:
    versions: dict[str, str] = {}
    for g in groups:
        if g.version:
            versions.setdefault(upstream(g.version).casefold(), g.version)
    if len(versions) < 2:
        return None
    hosts = {k: v for g in groups for k, v in g.hosts.items()}
    shown = ", ".join(sorted(versions.values()))
    return CryptoAsset(
        name=f"{product} version spread", data_state=DATA_STATE,
        role=_role(entry.get("provides", "")), software=product, source=source,
        source_class="private", source_name=source_name, collected_at=mtime,
        verdict=NA_VERDICT, flags=[f"{SPREAD_FLAG}{len(versions)}"], hosts_count=len(hosts),
        notes=(f"{len(hosts)} machine(s) carry {len(versions)} distinct versions of {product}: "
               f"{shown}. A change delivered as an upgrade of this provider has to reach every "
               "one of them. This counts versions in service; it is not a weakness in any one "
               "machine."),
        extra={"provides": entry.get("provides", ""), "versions": shown,
               "version_count": len(versions), "hosts": ", ".join(sorted(hosts.values()))})


# ── gaps ──

def _missing_gap(shown: str, fatal: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"{shown} (software inventory): which cryptographic providers are installed, at which "
        "versions, and which machines carry a version that cannot negotiate a current protocol"
        + (f"; the file is present but could not be read ({fatal})" if fatal else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Nothing here names the libraries and runtimes behind the services that were "
                "measured, so no installed version that caps below TLS 1.3 can be found, and "
                "the number of versions of each provider in service is not known."),
        harvest=("One software inventory export with the columns this collector's "
                 "documentation names, one row per product on each machine."),
        nature=coverage.NO_DATA)


def _scope_row(shown: str, source_name: str, mtime: str, rows: int, machines: int,
               matched_rows: int, products: list[str], unmatched_rows: int,
               unmatched_products: int, source: str = SOURCE,
               scope_name: str = SCOPE_NAME,
               every_product: list[str] | None = None) -> CryptoAsset:
    return CryptoAsset(
        name=scope_name, data_state=DATA_STATE, role=SCOPE_ROLE, source=source,
        source_class="private", source_name=source_name, collected_at=mtime, verdict=NA_VERDICT,
        notes=(f"{rows} row(s) read from {shown}, naming {machines} machine(s). {matched_rows} "
               f"row(s) name a cryptographic provider in the register: "
               f"{', '.join(products) or 'none'}. The other {unmatched_rows} row(s), "
               f"{unmatched_products} distinct product name(s), are named in this row's "
               "product list and not graded: the register's list is the limit of what is "
               "graded. Nothing here says "
               "how many machines the organisation runs, so this is a count of what was "
               "exported, not a share of the estate."),
        extra={"rows": rows, "machines": machines, "matched_rows": matched_rows,
               "providers": products, "unmatched_rows": unmatched_rows,
               "unmatched_products": unmatched_products,
               "software_products": list(every_product or products)})


def collect(target: Mapping, root: Path | None = None) -> tuple[list[CryptoAsset], list]:
    """Read the software inventory export; return (assets, coverage gaps)."""
    inbox = target.get("software_inbox") or {}
    path = inbox_path(str(inbox.get("export") or DEFAULT_EXPORT), root)
    shown = display_path(path, root)
    rows, header, fatal = _read(path)
    cols = columns(header)
    if path.exists() and not fatal:
        if "host" not in cols or "product" not in cols:
            fatal = "no host or no product column in its header"
        elif not rows:
            fatal = "no data rows"
    if fatal or not rows:
        return [], [_missing_gap(shown, fatal)]

    mtime = file_mtime_date(path) or ""
    source_name = (f"Software inventory export (file dated {mtime})" if mtime
                   else "Software inventory export (file date unavailable)")

    def cell(row: dict, name: str) -> str:
        return str(row.get(cols[name]) or "").strip() if name in cols else ""

    records = [{name: cell(row, name) for name in _COLUMNS} for row in rows]
    return assess(target, records, shown=shown, source_name=source_name, mtime=mtime)


def assess(target: Mapping, records: list[dict], *, shown: str, source_name: str, mtime: str,
           source: str = SOURCE, scope_name: str = SCOPE_NAME) -> tuple[list[CryptoAsset], list]:
    """Match inventory records against the register; return (assets, coverage gaps).

    Each record is a mapping with ``host`` and ``product``, and optionally
    ``version``, ``vendor`` and ``path``. ``shown`` names the input in gap
    sentences; ``source`` and ``scope_name`` let another reader of the same
    kind of evidence keep its rows apart from this collector's.
    """
    register = load_crypto_software()
    baseline = load_baseline()
    floor = tls_floor(baseline)
    names = identity.names_by_address(target)

    def cell(row: dict, name: str) -> str:
        return str(row.get(name) or "").strip()

    rows = records
    groups: dict[tuple[str, str], _Group] = {}
    machines: set[str] = set()
    unusable = matched = 0
    unmatched: dict[str, str] = {}
    unmatched_rows = 0
    for row in rows:
        raw_host, product = cell(row, "host"), cell(row, "product")
        if not raw_host or not product:
            unusable += 1
            continue
        host = machine_name(raw_host, names)
        machines.add(host.casefold())
        entry = provider_for(register, product)
        if entry is None:
            unmatched_rows += 1
            unmatched.setdefault(product.casefold(), product)
            continue
        matched += 1
        version = cell(row, "version")
        key = (entry["product"], version.casefold())
        g = groups.setdefault(key, _Group(entry["product"], entry, version))
        g.hosts.setdefault(host.casefold(), host)
        g.spellings.add(product)
        g.rows += 1
        for name, bucket in (("vendor", g.vendors), ("path", g.paths)):
            value = cell(row, name)
            if value:
                bucket.add(value)

    dataset = load_software_lifecycle()
    assets: list[CryptoAsset] = []
    by_product: dict[str, list[_Group]] = {}
    for key in sorted(groups, key=lambda k: (k[0].casefold(), k[1])):
        g = groups[key]
        by_product.setdefault(g.product, []).append(g)
        a = _version_row(g, register, baseline.get("tls_versions") or {}, floor, source_name, mtime,
                         source)
        _apply_lifecycle(a, lifecycle_reading(dataset, [g.product, *sorted(g.spellings)],
                                              g.version, mtime))
        assets.append(a)
    for product, product_groups in by_product.items():
        spread = _spread_row(product, product_groups[0].entry, product_groups, source_name, mtime,
                             source)
        if spread is not None:
            assets.append(spread)

    gaps: list = []
    if unusable:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{unusable} of {len(rows)} row(s) in {shown} name no machine or no product, so "
            "they are neither counted nor matched",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("Some inventory rows could not be tied to a machine or a product, so any "
                    "cryptographic provider they describe is missing from these counts. "
                    "Every row that was read stands."),
            harvest="A re-export with the host and product columns filled on every row.",
            nature=coverage.NO_DATA))
    unversioned = sum(g.rows for g in groups.values() if not g.version)
    if unversioned:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{unversioned} row(s) in {shown} name a cryptographic provider and no version, so "
            "their release line, capability ceiling and support status are not read",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("These installs are counted as present, but whether any of them caps below "
                    "TLS 1.3 or is out of support cannot be said."),
            harvest="A re-export with the version column filled.",
            nature=coverage.LOW_FIDELITY))
    every_product = sorted({*by_product, *unmatched.values()}, key=str.casefold)
    assets.append(_scope_row(shown, source_name, mtime, len(rows), len(machines), matched,
                             sorted(by_product), unmatched_rows, len(unmatched), source,
                             scope_name, every_product))
    return assets, gaps
