"""DNS zone files: every record the organisation configures, and where each points.

Lookups only find names somebody thinks to ask for. A zone file lists every
record configured, so this collector reads the zone files supplied in
``inbox/dns-zones/`` (``<zone>.zone``, plus ``private/<zone>.json`` for a
private zone's record-set export and an optional ``_exported-at-utc.txt``
stamp) and reports:

* **dangling records**: an alias, mail or service record whose target name
  no longer exists, confirmed by two or more resolvers answering NXDOMAIN.
  Where the target sits in a namespace a cloud provider documents as
  claimable by another customer (``takeover_namespaces`` in
  ``data/dns-services.yaml``), the row says so;
* **undelegated zones**: a zone held for a sub-domain whose parent zone has
  no NS record pointing to it, so none of its records is ever served;
* **names nobody measured**: published names no other row of the run
  covers, and, if supplied, no endpoint's resolved-name export mentions;
* **outside services**: services named by ownership-proof TXT records or as
  the target of a pointer, mapped to their operator where the target profile
  or ``data/vendor-domains.csv`` knows it;
* a **scope row** with record-set counts, duplicate SPF records, and whether
  the files' apex CAA agrees with the public CAA reading.

Target-profile settings, all optional, under ``dns_zones:``:
``resolved_names`` (a CSV of names endpoints resolved), ``resolved_names_column``
(default ``name``), ``proof_prefixes`` (TXT key -> service name), and
``second_level_labels`` (further labels that sit directly under a country
code as part of a public suffix, ``gen`` in ``example.gen.zz`` say, added to
the generic set).
"""

from __future__ import annotations

import concurrent.futures as futures
import csv
import shutil
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .. import coverage, dnsevidence, roles, zonefile
from ..config import inbox_path, load_vendor_domains
from ..coverage import Gap
from ..digresponse import norm, parse, query
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..util import now_date

SOURCE = "dns_zones"
DIRECTORY = "inbox/dns-zones"
STAMP_FILE = "_exported-at-utc.txt"

#: The target-profile key holding this collector's settings.
TARGET_KEY = "dns_zones"

SCOPE_FLAG = "dns-zone-scope"
DANGLING = "dns-zone-dangling-target"
CLAIMABLE_FLAG = "dns-zone-takeover-claimable"
NOT_LISTED = "dns-zone-target-not-listed-claimable"
NOT_DELEGATED = "dns-zone-not-delegated"
DUPLICATE_SPF = "dns-zone-duplicate-spf"
UNMEASURED = "dns-zone-names-unmeasured:"
SERVICES = "dns-zone-third-party-services:"
UNVERIFIED = "dns-zone-targets-unverified:"
CAA_DIFFERS = "dns-zone-caa-differs-from-public"

# Statements about the reading or its population, not adverse findings. A
# dangling target outside the listed namespaces keeps its adverse sibling
# DANGLING on the same row.
register_informational_prefixes(
    SCOPE_FLAG, NOT_LISTED, NOT_DELEGATED, UNMEASURED, SERVICES, UNVERIFIED, CAA_DIFFERS,
)

#: Top-level labels reserved from the public DNS (RFC 2606, RFC 6761, RFC 6762).
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost", "local"})

# Second-level labels that, directly under a two-letter country code, form part
# of a public suffix (``co`` or ``com`` before the country code). A profile may
# add its own.
SECOND_LEVEL_LABELS = frozenset({"co", "com", "net", "org", "ac", "gov"})

#: Reads (name, resolver) and returns dig's text for an A query.
Reader = Callable[[str, str], str]


def _live_reader(name: str, resolver: str) -> str:
    return query(name, "A", resolver)


@dataclass
class Held:
    """The zone material supplied: public zones, private exports, export time, failures."""

    zones: list[zonefile.ZoneFile]
    private: list[tuple[str, list[zonefile.PrivateRecordSet], str]]
    exported_at: str
    unreadable: list[str]


def load(directory: Path) -> Held:
    """Read every ``*.zone`` file and ``private/*.json`` export in ``directory``."""
    zones, unreadable = [], []
    for p in sorted(directory.glob("*.zone")):
        try:
            zones.append(zonefile.read(p))
        except (OSError, ValueError) as exc:
            unreadable.append(f"{p.name}: {exc}")
    private = [zonefile.read_private(p) for p in sorted((directory / "private").glob("*.json"))]
    stamp = ""
    try:
        stamp = (directory / STAMP_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return Held(zones, private, stamp, unreadable)


def reserved(origin: str) -> bool:
    """True for a zone under a top-level label reserved from the public DNS."""
    return origin.rsplit(".", 1)[-1] in RESERVED_TLDS


def delegation(zones: list[zonefile.ZoneFile]) -> dict[str, str]:
    """Held zones whose nearest held parent has no NS record for them: {child: parent}."""
    by_origin = {z.origin: z for z in zones}
    out = {}
    for z in zones:
        labels = z.origin.split(".")
        for i in range(1, len(labels) - 1):
            parent = by_origin.get(".".join(labels[i:]))
            if parent is None:
                continue
            if not any(r.rtype == "NS" and r.owner == z.origin for r in parent.records):
                out[z.origin] = parent.origin
            break
    return out


def claimable(target: str, namespaces: Mapping[str, str]) -> str:
    """The service whose claimable namespace ``target`` falls in, or ""."""
    for suffix, service in namespaces.items():
        if target == suffix or target.endswith("." + suffix):
            return str(service)
    return ""


def pointer_records(zone: zonefile.ZoneFile) -> list[zonefile.Record]:
    """Records that point at another name: CNAME, MX and SRV."""
    return [r for r in zone.records if r.rtype in ("CNAME", "MX", "SRV") and r.target()]


def resolve(targets: Iterable[str], reader: Reader,
            resolvers: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Each target's response code from each resolver: {target: {resolver: status}}."""
    names = sorted(set(targets))

    def one(name: str) -> dict[str, str]:
        out = {}
        for r in resolvers:
            resp = parse(reader(name, r))
            out[dnsevidence.resolver_label(r)] = resp.status or f"error: {resp.error}"
        return out

    with futures.ThreadPoolExecutor(dnsevidence.SWEEP_WORKERS) as pool:
        return dict(zip(names, pool.map(one, names), strict=True))


def verdict_of(readings: Mapping[str, str]) -> str:
    """``nxdomain`` when two or more resolvers agree the name does not exist; else exists/unverified."""
    answered = [s for s in readings.values() if not s.startswith("error")]
    if len(answered) >= 2 and all(s == "NXDOMAIN" for s in answered):
        return "nxdomain"
    if "NOERROR" in answered:
        return "exists"
    return "unverified"


def spf_per_name(zone: zonefile.ZoneFile) -> Counter[str]:
    """How many ``v=spf1`` TXT records each owner name carries."""
    return Counter(r.owner for r in zone.by_type("TXT")
                   if r.text.strip().lower().startswith("v=spf1"))


def proof_service(text: str, prefixes: Mapping[str, str] | None = None) -> str:
    """The service an ownership-proof TXT record names, or "" for anything else.

    A record ``<key>=<token>`` or ``<key>:<token>`` counts when ``prefixes``
    maps its key to a service, or when the key itself says it is a
    verification. The token is never kept.
    """
    head = text.strip()
    for sep in ("=", ":"):
        if sep in head:
            key = head.split(sep, 1)[0].strip().lower()
            if key == "v":
                return ""
            if prefixes and key in prefixes:
                return str(prefixes[key])
            if "verif" in key:
                return key
            return ""
    return ""


def registrable(name: str, second_level: Iterable[str] = SECOND_LEVEL_LABELS) -> str:
    """A best guess at the registered domain: the last two labels, or three under a public suffix."""
    parts = name.split(".")
    tail = 3 if (len(parts) >= 3 and parts[-2] in set(second_level)
                 and len(parts[-1]) == 2) else 2
    return ".".join(parts[-tail:])


def _hosts(assets: Iterable[CryptoAsset]) -> set[str]:
    return {norm(a.host).removeprefix("*.") for a in assets if a.host}


def _settings(target: Mapping) -> dict:
    own = target.get(TARGET_KEY) or {}
    return own if isinstance(own, dict) else {}


def _resolved_names(target: Mapping, root: Path | None) -> tuple[set[str], bool]:
    """Names in the endpoint resolved-name export, and whether one was read."""
    settings = _settings(target)
    rel = settings.get("resolved_names")
    if not rel:
        return set(), False
    column = str(settings.get("resolved_names_column") or "name")
    path = inbox_path(str(rel), root)
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            return {norm(str(r.get(column) or "")) for r in csv.DictReader(fh)} - {""}, True
    except (OSError, UnicodeDecodeError, csv.Error):
        return set(), False


def declared_vendor_domains(target: Mapping) -> dict[str, str]:
    """Vendor domains the profile declares: {domain: vendor name}.

    Read from ``third_party`` and ``infrastructure`` entries (``name`` and
    ``domains``) and from ``scan_targets.saas_443`` / ``smtp_25`` entries
    (``vendor`` and ``domains``).
    """
    out: dict[str, str] = {}

    def add(name: object, entry: Mapping) -> None:
        vendor = str(name or "").strip()
        if not vendor:
            return
        for d in entry.get("domains") or []:
            dom = norm(str(d or ""))
            if dom:
                out[dom] = vendor

    for key in ("third_party", "infrastructure"):
        for e in target.get(key) or []:
            if isinstance(e, Mapping):
                add(e.get("name"), e)
    scan = target.get("scan_targets") or {}
    for key in ("saas_443", "smtp_25"):
        for e in scan.get(key) or []:
            if isinstance(e, Mapping):
                add(e.get("vendor"), e)
    return out


def suffix_lookup(name: str, table: Mapping[str, object]) -> object | None:
    """The value for ``name`` or its nearest listed parent in ``table``."""
    parts = name.split(".")
    for i in range(len(parts) - 1):
        value = table.get(".".join(parts[i:]))
        if value:
            return value
    return None


def no_zones_gap(unreadable: int) -> Gap:
    """The gap recorded when no zone file was supplied or readable."""
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"{DIRECTORY}/ (the organisation's DNS zones exported as files) — every record "
        "configured, not only the names a lookup happens to ask for"
        + (f"; {unreadable} file(s) could not be read" if unreadable else ""),
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Without the zone files, forgotten names and records pointing "
                "at resources that no longer exist are found only if some "
                "other lookup happens to ask for them."),
        harvest=f"A zone export from the DNS host, placed in {DIRECTORY}/.",
        nature=coverage.NO_DATA)


def internal_zone_gap() -> Gap:
    """An internal zone held on directory DNS servers, which a public export never holds."""
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "Any internal DNS zone held on the directory's own DNS servers — including, "
        "where the directory domain shares its name with a public zone (split "
        "horizon), the internal copy of that zone. Such a zone holds names the "
        "organisation's own machines resolve inside, which the public zone export "
        "cannot show",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Internal names, and any records pointing at retired internal "
                "services, are not in this reading; an endpoint resolved-name export "
                "shows the names that were asked for, not every record configured."),
        harvest="A zone export from a directory DNS server by a directory administrator.",
        nature=coverage.NO_DATA)


def collect(target: Mapping, root: Path | None, population: Iterable[CryptoAsset],
            ref_time: datetime | None = None, reader: Reader | None = None,
            resolvers: tuple[str, ...] | None = None,
            ) -> tuple[list[CryptoAsset], list[Gap]]:
    """Read the supplied zones against the rest of the run (``population``)."""
    population = list(population)
    directory = inbox_path(DIRECTORY, root)
    held = load(directory) if directory.is_dir() else Held([], [], "", [])
    gaps: list[Gap] = [internal_zone_gap()]
    if not held.zones:
        gaps.insert(0, no_zones_gap(len(held.unreadable)))
        return [], gaps
    if reader is None and shutil.which("dig"):
        reader = _live_reader
    if reader is None:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            "dns_zones: dig is not on PATH, so no record's target was looked up "
            "and no dangling record could be found",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="The zone files were read, but whether their pointers lead anywhere was not.",
            harvest="Re-run with dig on PATH.",
            nature=coverage.LOW_FIDELITY))
    if resolvers is None:
        resolvers = dnsevidence.resolvers(dict(target))
    services_cfg = dnsevidence.services(dict(target))
    namespaces = dict(services_cfg.get("takeover_namespaces") or {})
    settings = _settings(target)
    second_level = SECOND_LEVEL_LABELS | {str(x) for x in settings.get("second_level_labels") or []}
    proof_prefixes = {str(k).lower(): str(v)
                      for k, v in (settings.get("proof_prefixes") or {}).items()}

    now = ref_time or datetime.now(UTC)
    read_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    exported = held.exported_at or "an unrecorded time"
    content_date = held.exported_at[:10] if held.exported_at else ""
    source_name = f"DNS zone files, exported from the DNS host at {exported}"

    undelegated = delegation(held.zones)
    served = [z for z in held.zones if not reserved(z.origin) and z.origin not in undelegated]
    own = tuple(z.origin for z in held.zones)

    pointers = [(z, r) for z in served for r in pointer_records(z)]
    readings: dict[str, dict[str, str]] = {}
    if reader is not None:
        readings = resolve((r.target() for _, r in pointers), reader, resolvers)

    assets: list[CryptoAsset] = []
    dangling = 0
    for z, r in pointers:
        t = r.target()
        if verdict_of(readings.get(t, {})) != "nxdomain":
            continue
        dangling += 1
        service = claimable(t, namespaces)
        flags = [DANGLING, CLAIMABLE_FLAG if service else NOT_LISTED]
        notes = (f"The {r.rtype} record at {r.owner} points to {t}, and "
                 f"{len(readings[t])} resolvers answered that the name does "
                 f"not exist (looked up {read_at}). Nothing reaches a service "
                 f"through this record today. ")
        if service:
            notes += (f"The target is a {service} name, which its provider documents "
                      "as one another customer can provision once the original is "
                      "deleted — whoever does receives the traffic sent to this name.")
        else:
            notes += ("The target's namespace is not on the list of namespaces known "
                      "to be claimable by another customer; this reading does not "
                      "establish that nobody can claim it.")
        assets.append(CryptoAsset(
            name=f"DNS {r.rtype} {r.owner} → {t}", data_state="discovery", protocol="dns",
            role=roles.dns_zone_dangling_record(r.owner, t), host=r.owner,
            internet_facing=True, source=SOURCE, source_class="private",
            source_name=source_name, collected_at=now_date(now), verdict=NA_VERDICT,
            flags=flags, notes=notes,
            extra={"zone": z.origin, "record_type": r.rtype, "target": t,
                   "target_lookups": readings[t], "looked_up_at": read_at,
                   "claimable_namespace": service, "zone_exported_at": held.exported_at}))

    for child, parent in sorted(undelegated.items()):
        zone = next(z for z in held.zones if z.origin == child)
        live = {}
        if reader is not None:
            live = {dnsevidence.resolver_label(rv): (parse(reader(child, rv)).status or "error")
                    for rv in resolvers}
        kinds = Counter(r.rtype for r in zone.records if r.rtype not in ("SOA", "NS"))
        what = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "no records"
        assets.append(CryptoAsset(
            name=f"DNS zone {child} (not delegated)", data_state="discovery", protocol="dns",
            role=roles.dns_zone_not_delegated(child), host=child, source=SOURCE,
            source_class="private", source_name=source_name,
            collected_at=content_date, verdict=NA_VERDICT, flags=[NOT_DELEGATED],
            notes=(f"A zone is held for {child} carrying {what} beyond its own "
                   f"SOA and NS, but the {parent} zone has no NS record sending "
                   f"resolvers to it, so none of its records is served. "
                   + (f"Resolvers answered {', '.join(sorted(set(live.values())))} "
                      f"for the name ({read_at}). " if live else "")
                   + "Whether anything was meant to use it is not recorded in the zone."),
            extra={"parent_zone": parent, "record_types": dict(kinds),
                   "live_lookups": live, "looked_up_at": read_at if live else ""}))

    names: dict[str, str] = {}
    for z in served:
        for r in z.records:
            if r.rtype not in ("A", "AAAA", "CNAME") or "_" in r.owner:
                continue
            names.setdefault(r.owner, f"{r.rtype} {r.rdata[0] if r.rtype != 'CNAME' else r.target()}")
    measured = _hosts(population)
    resolved, resolved_read = _resolved_names(target, root)
    unmeasured = sorted(n for n in names if n not in measured and n not in resolved)
    resolved_only = sorted(n for n in names if n not in measured and n in resolved)
    assets.append(CryptoAsset(
        name="DNS names nobody measured", data_state="discovery", protocol="dns",
        role=roles.dns_zone_unmeasured_names(len(unmeasured)), source=SOURCE,
        source_class="private", source_name=source_name, collected_at=content_date,
        verdict=NA_VERDICT, flags=[f"{UNMEASURED}{len(unmeasured)}"],
        usage_count=len(unmeasured),
        notes=(f"{len(names)} names carry an address or alias in the served zones. "
               f"{len(names) - len(unmeasured) - len(resolved_only)} are named by "
               f"another row of this run (certificates, scans, headers); "
               f"{len(resolved_only)} more appear only in the endpoints' "
               f"resolved-name export"
               + ("" if resolved_read else " (none was read this run)")
               + f"; {len(unmeasured)} appear in neither. A name here was not "
               "tested by anything else in this run, which is not the same as "
               "being unused or unsafe."),
        extra={"published_names": len(names), "unmeasured": [
            {"name": n, "record": names[n]} for n in unmeasured],
            "resolved_by_endpoints_only": resolved_only}))

    vendor_table = load_vendor_domains()
    declared = declared_vendor_domains(target)
    services: dict[str, set[str]] = {}
    for z in served:
        for r in z.by_type("TXT"):
            svc = proof_service(r.text, proof_prefixes)
            if svc:
                services.setdefault(svc, set()).add(f"ownership proof at {r.owner}")
        for r in pointer_records(z):
            t = r.target()
            if any(t == o or t.endswith("." + o) for o in own):
                continue
            hit = suffix_lookup(t, declared) or suffix_lookup(t, vendor_table)
            vendor = (hit.get("vendor") if isinstance(hit, dict) else hit) or \
                registrable(t, second_level)
            services.setdefault(str(vendor), set()).add(f"{r.rtype} {r.owner}")
    assets.append(CryptoAsset(
        name="Outside services the DNS records name", data_state="discovery",
        protocol="dns", role=roles.dns_zone_services(len(services)), source=SOURCE,
        source_class="private", source_name=source_name, collected_at=content_date,
        verdict=NA_VERDICT, flags=[f"{SERVICES}{len(services)}"],
        usage_count=len(services),
        notes=("Services named by an ownership-proof TXT record (by its prefix — "
               "the token itself is not kept) or as the target of an alias, mail "
               "or service record. A proof shows the service was once verified "
               "for the name; it does not show the service is still in use."),
        extra={"services": {k: sorted(v) for k, v in sorted(services.items())}}))

    flags = [SCOPE_FLAG]
    duplicate_spf = {n: c for z in served for n, c in spf_per_name(z).items() if c > 1}
    if duplicate_spf:
        flags.append(DUPLICATE_SPF)
    unverified = sorted(t for t in readings if verdict_of(readings[t]) == "unverified")
    if unverified:
        flags.append(f"{UNVERIFIED}{len(unverified)}")
    caa_note, caa_differs = _caa_compare(served, population)
    if caa_differs:
        flags.append(CAA_DIFFERS)
    reserved_zones = [z.origin for z in held.zones if reserved(z.origin)]
    sets = {z.origin: len(z.record_sets()) for z in held.zones}
    unparsed = sum(len(z.unparsed) for z in held.zones)
    priv_sets = sum(len(s) for _, s, _ in held.private)
    empty_private = [n for n, s, _ in held.private if all(x.rtype == "SOA" for x in s)]
    notes = (
        f"{len(held.zones)} zone file(s) exported at {exported}: "
        + ", ".join(f"{o} {n}" for o, n in sets.items())
        + " record sets"
        + (f"; {unparsed} line(s) the reader could not place" if unparsed else "")
        + f". {len(served)} are served publicly; "
        + (f"{', '.join(reserved_zones)} sits under a name reserved from the public "
           "DNS; " if reserved_zones else "")
        + (f"{', '.join(sorted(undelegated))} is not delegated; " if undelegated else "")
        + f"{len(pointers)} alias, mail and service records were looked up at "
          f"{read_at}: {dangling} point at a name that does not exist"
        + (f", {len(unverified)} could not be settled" if unverified else "")
        + ". "
        + ("No name carries more than one SPF record. " if not duplicate_spf else
           f"{len(duplicate_spf)} name(s) carry more than one SPF record, which "
           "RFC 7208 § 3.2 makes a permanent error for every receiver. ")
        + caa_note
        + " Zone files carry no DS record (the parent holds it) and an export may "
          "omit keys, so signing is read from outside by the DNSSEC row, not here. "
        + f"{len(held.private)} private zone(s), {priv_sets} record sets"
        + (f"; {len(empty_private)} hold nothing but their SOA "
           f"({', '.join(empty_private)})" if empty_private else "")
        + ". Not held: any internal zone kept on the directory's own DNS servers, "
          "such as the internal copy of a zone where the directory domain shares its "
          "name with a public one.")
    assets.insert(0, CryptoAsset(
        name="DNS zone files — scope", data_state="discovery", protocol="dns",
        role=roles.dns_zone_scope(len(held.zones)), source=SOURCE, source_class="private",
        source_name=source_name, collected_at=content_date, verdict=NA_VERDICT,
        flags=flags, notes=notes,
        extra={"exported_at": held.exported_at, "record_sets": sets,
               "served_zones": [z.origin for z in served],
               "reserved_zones": reserved_zones, "undelegated": undelegated,
               "pointers_looked_up": len(pointers), "looked_up_at": read_at,
               "dangling": dangling, "unverified_targets": unverified,
               "duplicate_spf": duplicate_spf, "unparsed_lines": unparsed,
               "private_zones": {n: len(s) for n, s, _ in held.private},
               "private_errors": {n: e for n, _, e in held.private if e},
               "unreadable_files": held.unreadable}))
    return assets, gaps


def _caa_compare(served: list[zonefile.ZoneFile],
                 population: Iterable[CryptoAsset]) -> tuple[str, bool]:
    """Compare each served zone's apex CAA with the public CAA row; (note, any differ)."""
    public = {norm(a.host): sorted((int(p["flags"]), str(p["tag"]).lower(), str(p["value"]))
                                   for p in (a.extra or {}).get("records", []))
              for a in population if a.source == "caa" and a.host}
    agree, differ, unread = [], [], []
    for z in served:
        mine = sorted((int(r.rdata[0]), r.rdata[1].lower(), "".join(
            p.strip('"') for p in r.rdata[2:])) for r in z.by_type("CAA") if r.owner == z.origin
            and len(r.rdata) >= 3)
        if z.origin not in public:
            unread.append(z.origin)
        elif public[z.origin] == mine:
            agree.append(z.origin)
        else:
            differ.append(z.origin)
    note = (f"Apex CAA in the files matches the public reading on {len(agree)} of "
            f"{len(agree) + len(differ)} domain(s) the CAA row covers"
            + (f"; differs on {', '.join(differ)}" if differ else "")
            + (f"; {len(unread)} served zone(s) have no CAA row this run" if unread else "")
            + ".")
    return note, bool(differ)
