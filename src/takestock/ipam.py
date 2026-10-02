"""The IP address plan: sites, subnets, and every address the evidence places in them.

An engineer's first questions about a network are *which ranges are ours,
where does each one live, what is on it, and how sure are we*. No single export
answers all of them, so the plan joins two kinds of input:

* a **plan file**, ``targets/<stem>.ipam.yaml``, holding what no export states:
  the sites, what each subnet is for, which sources to read and how;
* **sources**: exports (CSV files, DNS zone files, saved internet-registry
  lookups, or anything a plugged-in reader understands) and dated documents.

Every address found is placed in the most specific subnet that holds it, with
the source that reported it and the date of that source.

**The plan file never asserts an address on its own authority.** A subnet entry
cannot list addresses. An address enters the plan only from a source, or from a
``documented_addresses`` entry that names a document source with its own date,
so every address in the output can be traced to something outside the plan
file.

**A roaming source cannot found a subnet.** A source marked ``roams: true``
(a laptop's check-in log, say) reports addresses the machine held anywhere:
home networks, hotspots, its own container bridges. Such a source can only
place an address inside a subnet the plan already holds; everything else it
reports is counted and set aside. A site may also name an
``authoritative_for`` source, and inside that site a roaming source is accepted
only where the authoritative source holds the same address. A subnet can narrow
who may populate it with ``only_sources``.

**Readers.** Three ship with the package: ``csv`` (any CSV, with the column
mapping declared in the plan file), ``dns-zones`` (zone files and private-zone
record-set exports, read with :mod:`takestock.zonefile`) and ``asn-lookups``
(saved internet-registry answers, see :func:`lookup_asn`). An organisation can
add its own reader without changing the package, with :func:`register_reader`
or through the ``takestock.ipam_readers`` entry-point group.

**What it cannot see.** It knows what the sources saw, on the dates they were
taken. It holds no DHCP server configuration, so it knows addresses that were
in use, not ranges that are handed out.

Run as ``python -m takestock.ipam <plan.ipam.yaml> <out_dir> [--exports DIR]``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import socket
import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from importlib import metadata
from pathlib import Path
from typing import Any

from . import config, htmlpage, util, zonefile
from .exits import EXIT_CLEAN, EXIT_ERROR, guarded

SCHEMA_VERSION = 1

#: The plan file's suffix; it sits beside a target profile and is not one
#: (:mod:`takestock.config` lists it as an overlay).
PLAN_SUFFIX = config.IPAM_PLAN_SUFFIX

#: Source kinds that are dated documents rather than files to read.
DOCUMENT_KINDS = frozenset({"document", "record"})

#: What a sighting's name identifies: a machine, another name for the address
#: (a DNS record), or a description (a role, a note).
NAME_IS = ("machine", "alias", "label")

#: How far a source's sightings go: ``observed`` means seen in use, ``named``
#: means a name was configured for the address (DNS, say) without showing it is
#: in use, ``documented`` means a document says so.
EVIDENCE_CLASSES = ("observed", "named", "documented")

#: ``addressing`` values for subnets whose addresses change hands, where two
#: machine names on one address are expected rather than a conflict.
SHARED_ADDRESSING = frozenset({"dynamic", "pool", "overlay"})

#: Site id given to a subnet an export declared that no site's ranges hold.
NO_SITE = "unassigned"

ENTRY_POINT_GROUP = "takestock.ipam_readers"


class IpamError(ValueError):
    """The plan file or a source cannot be read as declared."""


@dataclass
class Sighting:
    """One source saying one address was associated with one name."""

    ip: str
    name: str
    source: str
    seen: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    name_is: str = "machine"


@dataclass
class Segment:
    """A layer-2 network a source reports: a VLAN, a switch port group or the like."""

    source: str
    site: str
    name: str
    vlan: int | None = None
    subnet: str | None = None
    switch: str = ""


@dataclass
class Harvest:
    """Everything the readers found, before it is placed in the plan."""

    sightings: list[Sighting] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    #: Subnets a source states exist: cidr -> {"source", "name", optional "site"}.
    declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    #: Internet-registry facts by address, from :func:`read_asn_lookups`.
    registry: dict[str, dict[str, Any]] = field(default_factory=dict)


Reader = Callable[[dict, list[Path], Harvest], None]


@dataclass(frozen=True)
class ReaderSpec:
    """A registered reader: the function, and how its sightings count."""

    fn: Reader
    #: When true, a missing input becomes a note rather than an error.
    optional: bool = False
    #: The evidence class its sightings carry unless a source overrides it.
    evidence: str = "observed"


READERS: dict[str, ReaderSpec] = {}
_entry_points_loaded = False


def register_reader(kind: str, fn: Reader, *, optional: bool = False,
                    evidence: str = "observed", replace: bool = False) -> None:
    """Make ``fn`` the reader for sources of ``kind``.

    ``fn(source, paths, harvest)`` receives the source's plan-file entry, its
    resolved input paths (all of which exist), and the :class:`Harvest` to add
    sightings, segments or declared subnets to.
    """
    if kind in DOCUMENT_KINDS:
        raise ValueError(f"{kind!r} is a document kind and has no reader")
    if evidence not in EVIDENCE_CLASSES:
        raise ValueError(f"evidence must be one of {', '.join(EVIDENCE_CLASSES)}")
    if kind in READERS and not replace:
        raise ValueError(f"a reader for {kind!r} is already registered")
    READERS[kind] = ReaderSpec(fn, optional, evidence)


def _load_entry_points() -> None:
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        if ep.name not in READERS:
            register_reader(ep.name, ep.load())


def reader_for(kind: str) -> ReaderSpec | None:
    """The reader registered for ``kind``, looking in installed entry points if needed."""
    if kind not in READERS:
        _load_entry_points()
    return READERS.get(kind)


# --- small parsers -----------------------------------------------------------

_IP_SPLIT = re.compile(r"[\s;,|]+")


def _ips(raw: str) -> tuple[list[str], int]:
    """The addresses in a cell that may hold several, and how many tokens were not addresses."""
    out: list[str] = []
    rejected = 0
    for token in _IP_SPLIT.split(raw or ""):
        token = token.strip().strip("[]")
        if not token:
            continue
        try:
            out.append(str(ipaddress.ip_address(token)))
        except ValueError:
            rejected += 1
    return out, rejected


def _day(value: Any) -> str:
    """The ``YYYY-MM-DD`` a timestamp starts with, or ""."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})", str(value or "").strip())
    return m.group(1) if m else ""


def _net(cidr: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(str(cidr), strict=False)


def _non_routed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Why an address describes no network, or ""."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (self-assigned)"
    if ip.is_unspecified or (ip.version == 4 and ip.packed[0] == 0):
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    return ""


def _short(name: str) -> str:
    """A machine name reduced for comparison: lower case, first label, no trailing notes."""
    n = str(name or "").strip().lower()
    n = re.split(r"[\s(\[]", n, maxsplit=1)[0]
    return n if re.fullmatch(r"[\d.:]+", n) else n.split(".", 1)[0]


def _usable(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if net.version == 4 and net.prefixlen <= 30:
        return net.num_addresses - 2
    return net.num_addresses


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# --- readers -----------------------------------------------------------------

CSV_COLUMN_KEYS = ("ip", "name", "date", "mac", "site", "kind")
# A mapped column's key in a sighting's detail, where it differs from the key.
_CSV_DETAIL_KEY = {"site": "site_stated", "kind": "device_kind"}


def read_csv(src: dict, paths: list[Path], h: Harvest) -> None:
    """Read addresses from CSV files using the source's ``columns:`` mapping.

    ``columns`` maps the plan's field names to the file's header names; ``ip``
    is required and ``name``, ``date``, ``mac``, ``site`` and ``kind`` are
    optional. An address cell may hold several addresses separated by spaces,
    commas, semicolons or bars. ``delimiter`` sets the field separator
    (default ``,``) and ``name_is`` says what the name column identifies
    (default ``machine``).
    """
    sid = src["id"]
    cols = src.get("columns") or {}
    if not isinstance(cols, dict) or "ip" not in cols:
        raise IpamError(f"source {sid}: a csv source needs `columns:` with at least `ip`")
    unknown = sorted(set(cols) - set(CSV_COLUMN_KEYS))
    if unknown:
        raise IpamError(f"source {sid}: unknown column keys {', '.join(unknown)}; "
                        f"known: {', '.join(CSV_COLUMN_KEYS)}")
    delimiter = str(src.get("delimiter") or ",")
    name_is = str(src.get("name_is") or "machine")
    rejected = rows = 0
    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            header = list(reader.fieldnames or [])
            missing = [str(c) for c in cols.values() if str(c) not in header]
            if missing:
                raise IpamError(f"source {sid}: {path.name} has no column "
                                + ", ".join(repr(c) for c in missing))
            for row in reader:
                rows += 1
                def cell(key: str, r: dict = row) -> str:
                    return str(r.get(str(cols[key])) or "").strip() if key in cols else ""
                detail = {_CSV_DETAIL_KEY.get(k, k): cell(k) for k in ("mac", "site", "kind")
                          if cell(k)}
                if len(paths) > 1:
                    detail["file"] = path.name
                ips, bad = _ips(cell("ip"))
                rejected += bad
                for ip in ips:
                    h.sightings.append(Sighting(ip, cell("name"), sid, _day(cell("date")),
                                                detail, name_is))
    h.notes[sid].append(f"{_plural(rows, 'row')} read")
    if rejected:
        h.notes[sid].append(f"{_plural(rejected, 'value')} in the address column "
                            f"{'was' if rejected == 1 else 'were'} not an address and "
                            f"{'was' if rejected == 1 else 'were'} skipped")


def read_dns_zones(src: dict, paths: list[Path], h: Harvest) -> None:
    """Read A and AAAA records, and single-address SPF mechanisms, from DNS exports.

    Each path may be a zone file (``<origin>.zone``), a private-zone record-set
    export (``<zone>.json``), or a directory holding ``*.zone`` files and an
    optional ``private/`` directory of ``*.json`` exports.
    """
    sid = src["id"]
    zones: list[Path] = []
    private: list[Path] = []
    for p in paths:
        if p.is_dir():
            zones += sorted(p.glob("*.zone"))
            private += sorted((p / "private").glob("*.json"))
        elif p.suffix == ".json":
            private.append(p)
        else:
            zones.append(p)
    for path in zones:
        zf = zonefile.read(path)
        for r in zf.records:
            if r.rtype in ("A", "AAAA") and r.rdata:
                h.sightings.append(Sighting(r.rdata[-1], r.owner, sid, "",
                                            {"record": r.rtype, "zone": zf.origin}, "alias"))
            elif r.rtype == "TXT" and r.text.lower().startswith("v=spf1"):
                for mech in re.findall(r"\bip[46]:(\S+)", r.text):
                    try:
                        net = _net(mech)
                    except ValueError:
                        continue
                    if net.num_addresses == 1:
                        h.sightings.append(Sighting(
                            str(net.network_address), f"authorised mail sender for {r.owner}",
                            sid, "", {"record": "SPF", "zone": zf.origin}, "label"))
    for path in private:
        zone, sets, err = zonefile.read_private(path)
        if err:
            h.notes[sid].append(f"{path.name}: {err}")
        for rs in sets:
            if rs.rtype not in ("A", "AAAA"):
                continue
            for rec in rs.records:
                if rec and rec[0]:
                    h.sightings.append(Sighting(rec[0], rs.fqdn, sid, "",
                                                {"record": rs.rtype, "zone": zone,
                                                 "private_zone": True}, "alias"))
    h.notes[sid].append(f"{_plural(len(zones), 'zone file')} and "
                        f"{_plural(len(private), 'private-zone export')} read")


# --- internet registry lookups -----------------------------------------------
#
# Two public services answer "who announces and who holds this address":
#
# * Team Cymru's IP-to-ASN mapping service, which takes bulk queries over the
#   whois protocol (TCP port 43) and returns the origin AS number, the
#   announced prefix, the regional registry and the AS name. No host is
#   shipped as a default: the plan file names it as ``asn_lookup.whois_host``
#   after reading the service's own documentation.
# * RDAP (RFC 9083), the registries' structured replacement for whois. The
#   right registry for an address is found from IANA's bootstrap registry
#   (RFC 9224), so no regional registry's address is written here.
#
# Lookups only run when asked for (``--lookup-asn``). They send the plan's
# public addresses to those services, and the raw replies are saved so a
# later build reads them without asking again.

RDAP_BOOTSTRAP = {4: "https://data.iana.org/rdap/ipv4.json",
                  6: "https://data.iana.org/rdap/ipv6.json"}


def whois_bulk(host: str, ips: list[str], port: int = 43, timeout: float = 30.0) -> str:
    """Send one bulk verbose query for ``ips`` to a whois-protocol IP-to-ASN service."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(("begin\nverbose\n" + "\n".join(ips) + "\nend\n").encode())
        chunks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", "replace")


def parse_cymru(text: str) -> dict[str, dict[str, str]]:
    """Bulk verbose replies (``AS | IP | prefix | CC | registry | allocated | AS name``) by address.

    An address announced by nobody comes back with AS ``NA`` and is kept,
    because that is a fact about it too.
    """
    out: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7 or not parts[1] or parts[0] == "AS":
            continue
        try:
            ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        out[parts[1]] = {"asn": parts[0], "announced_prefix": parts[2], "country": parts[3],
                         "registry": parts[4], "allocated": parts[5],
                         "as_name": "|".join(parts[6:]).strip()}
    return out


def parse_rdap(doc: dict) -> dict[str, Any]:
    """The fields of an RDAP IP-network object an engineer reads."""
    registrant = ""
    for e in doc.get("entities") or []:
        if "registrant" in (e.get("roles") or []):
            vcard = (e.get("vcardArray") or [None, []])[1]
            registrant = next((x[3] for x in vcard if x and x[0] == "fn"), "") or e.get("handle", "")
            break
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
             for c in doc.get("cidr0_cidrs") or [] if c.get("length") is not None]
    return {k: v for k, v in (
        ("registered_range", f"{doc.get('startAddress')} – {doc.get('endAddress')}"
         if doc.get("startAddress") else ""),
        ("registered_cidrs", cidrs), ("network_name", doc.get("name") or ""),
        ("handle", doc.get("handle") or ""), ("registrant", registrant),
        ("registered_country", doc.get("country") or "")) if v}


def rdap_base(ip: str, bootstrap: dict) -> str:
    """The RDAP base URL an IANA bootstrap file gives for ``ip`` (longest match), or ""."""
    addr = ipaddress.ip_address(ip)
    best, best_len = "", -1
    for service in bootstrap.get("services") or []:
        if len(service) < 2 or not service[1]:
            continue
        for prefix in service[0]:
            try:
                net = _net(prefix)
            except ValueError:
                continue
            if net.version == addr.version and addr in net and net.prefixlen > best_len:
                urls = [u for u in service[1] if str(u).startswith("https://")] or service[1]
                best, best_len = str(urls[0]), net.prefixlen
    return best if not best or best.endswith("/") else best + "/"


def lookup_asn(ips: list[str], folder: Path, today: str, *, whois_host: str = "",
               query: Callable[[str, list[str]], str] = whois_bulk,
               fetch: Callable[[str], Any] = util.http_json) -> int:
    """Look up every address not already answered and save the raw replies in ``folder``.

    Returns how many addresses were looked up. ``query`` and ``fetch`` are the
    network calls, replaceable for testing.
    """
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "rdap").mkdir(exist_ok=True)
    index_path = folder / "_index.json"
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else {}
    todo = sorted({ip for ip in ips if ip not in index}, key=ipaddress.ip_address)
    if not todo:
        return 0
    whois_file = ""
    if whois_host:
        raw = query(whois_host, todo)
        whois_file = f"cymru-{today}.txt"
        with (folder / whois_file).open("a", encoding="utf-8") as f:
            f.write(raw if raw.endswith("\n") else raw + "\n")
    bootstraps: dict[int, dict] = {}
    for ip in todo:
        version = ipaddress.ip_address(ip).version
        if version not in bootstraps:
            got = fetch(RDAP_BOOTSTRAP[version])
            bootstraps[version] = got if isinstance(got, dict) else {}
        rdap_file = ""
        base = rdap_base(ip, bootstraps[version])
        if base:
            doc = fetch(base + "ip/" + ip)
            if isinstance(doc, dict) and doc.get("objectClassName") == "ip network":
                rdap_file = f"rdap/{ip.replace(':', '_')}.json"
                (folder / rdap_file).write_text(json.dumps(doc, indent=1), encoding="utf-8")
        index[ip] = {"looked_up": today, "cymru_file": whois_file, "rdap_file": rdap_file}
    index_path.write_text(json.dumps(index, indent=1, sort_keys=True), encoding="utf-8")
    return len(todo)


def read_asn_lookups(src: dict, paths: list[Path], h: Harvest) -> None:
    """Read the replies :func:`lookup_asn` saved into the folder this source names."""
    folder = paths[0]
    index_path = folder / "_index.json"
    if not index_path.is_file():
        h.notes[src["id"]].append("no lookups saved yet: run with --lookup-asn")
        return
    index = json.loads(index_path.read_text(encoding="utf-8"))
    cymru: dict[str, dict[str, str]] = {}
    for f in sorted(folder.glob("cymru-*.txt")):
        cymru.update(parse_cymru(f.read_text(encoding="utf-8")))
    for ip, meta in index.items():
        rec: dict[str, Any] = dict(cymru.get(ip, {}))
        rdap = folder / str(meta.get("rdap_file") or "")
        if meta.get("rdap_file") and rdap.is_file():
            rec.update(parse_rdap(json.loads(rdap.read_text(encoding="utf-8"))))
        rec["looked_up"] = meta.get("looked_up", "")
        rec["source"] = src["id"]
        h.registry[ip] = rec


register_reader("csv", read_csv)
register_reader("dns-zones", read_dns_zones, evidence="named")
register_reader("asn-lookups", read_asn_lookups, optional=True, evidence="named")


# --- reading the plan file ---------------------------------------------------

def _source_paths(src: dict, exports_dir: Path) -> list[Path]:
    raw = src.get("paths") or ([src["path"]] if src.get("path") else [])
    if not raw:
        raise IpamError(f"source {src['id']}: needs `path:` or `paths:`")
    out = []
    for p in raw:
        q = Path(str(p)).expanduser()
        out.append(q if q.is_absolute() else exports_dir / q)
    return out


def _sources(cfg: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for s in cfg.get("sources") or []:
        sid = str(s.get("id") or "")
        if not sid:
            raise IpamError("every source needs an `id:`")
        if sid in out:
            raise IpamError(f"source {sid} is declared twice")
        kind = str(s.get("kind") or "")
        if not kind:
            raise IpamError(f"source {sid}: needs a `kind:`")
        if s.get("name_is", "machine") not in NAME_IS:
            raise IpamError(f"source {sid}: name_is must be one of {', '.join(NAME_IS)}")
        if s.get("evidence") and s["evidence"] not in ("observed", "named"):
            raise IpamError(f"source {sid}: evidence must be observed or named")
        out[sid] = {**s, "id": sid, "kind": kind, "label": str(s.get("label") or sid),
                    "as_of": str(s.get("as_of") or ""),
                    "as_of_basis": str(s.get("as_of_basis") or "dated")}
    for sid, s in out.items():
        for other in list(s.get("supersedes") or []):
            if other not in out:
                raise IpamError(f"source {sid}: supersedes unknown source {other!r}")
    return out


def _evidence_class(src: dict) -> str:
    if src["kind"] in DOCUMENT_KINDS:
        return "documented"
    if src.get("evidence"):
        return str(src["evidence"])
    spec = reader_for(src["kind"])
    return spec.evidence if spec else "observed"


def harvest(cfg: dict, exports_dir: Path) -> Harvest:
    """Run every source's reader and collect what they found.

    A declared source whose input is missing is an error, not a silent gap: a
    plan built from fewer exports than it names would read as complete and not
    be.
    """
    h = Harvest()
    sources = _sources(cfg)
    for sid, src in sources.items():
        kind = src["kind"]
        if kind in DOCUMENT_KINDS:
            continue
        spec = reader_for(kind)
        if spec is None:
            raise IpamError(f"source {sid}: no reader for kind {kind!r}; registered: "
                            f"{', '.join(sorted(READERS))}")
        paths = _source_paths(src, exports_dir)
        missing = [p for p in paths if not p.exists()]
        if missing and spec.optional:
            h.notes[sid].append("nothing saved yet at " + ", ".join(p.name for p in missing))
            continue
        if missing:
            raise IpamError(f"source {sid}: missing {', '.join(str(p) for p in missing)}")
        spec.fn(src, paths, h)
    for d in cfg.get("documented_addresses") or []:
        sid = str(d.get("source") or "")
        if sources.get(sid, {}).get("kind") not in DOCUMENT_KINDS:
            raise IpamError(f"documented address {d.get('ip')}: source {sid!r} must be a "
                            f"declared source of kind {' or '.join(sorted(DOCUMENT_KINDS))}")
        h.sightings.append(Sighting(str(d["ip"]), str(d.get("name") or ""), sid, "",
                                    {"note": str(d["note"])} if d.get("note") else {}, "label"))
    return h


# --- building the plan -------------------------------------------------------

def _sites(cfg: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for s in cfg.get("sites") or []:
        sid = str(s.get("id") or "")
        if not sid or sid in out:
            raise IpamError(f"site {sid!r}: every site needs a unique `id:`")
        out[sid] = {**s, "id": sid, "name": str(s.get("name") or sid),
                    "kind": str(s.get("kind") or ""), "status": str(s.get("status") or "in use"),
                    "ranges": [str(_net(r)) for r in s.get("ranges") or []]}
    return out


def _curated_subnets(cfg: dict, sites: dict, sources: dict) -> dict[str, dict]:
    subnets: dict[str, dict] = {}
    for s in cfg.get("subnets") or []:
        key = str(_net(s["cidr"]))
        if key in subnets:
            raise IpamError(f"subnet {key} is listed twice in the plan file")
        if "addresses" in s:
            raise IpamError(f"subnet {key}: the plan file cannot list addresses; they come "
                            "from sources and from documented_addresses")
        if s.get("site") not in sites:
            raise IpamError(f"subnet {key}: unknown site {s.get('site')!r}")
        for ev in list(s.get("evidence") or []) + list(s.get("only_sources") or []):
            if ev not in sources:
                raise IpamError(f"subnet {key}: unknown source {ev!r}")
        if s.get("scope") not in (None, "public", "private"):
            raise IpamError(f"subnet {key}: scope must be public or private")
        if s.get("vlan") is not None and not isinstance(s["vlan"], int):
            raise IpamError(f"subnet {key}: vlan must be a number")
        subnets[key] = {**s, "cidr": key, "origin": "plan file",
                        "evidence": list(s.get("evidence") or [])}
    return subnets


def _mirror(m: dict, subnets: dict[str, dict], sites: dict) -> dict:
    """Pair the subnets at the same position inside two equally sized prefixes."""
    sides = {}
    for side in ("left", "right"):
        spec = m.get(side) or {}
        if not spec.get("prefix"):
            raise IpamError(f"mirror {m.get('name')!r}: {side} needs a prefix")
        net = _net(spec["prefix"])
        site = str(spec.get("site") or "")
        label = str(spec.get("label") or sites.get(site, {}).get("name") or net)
        sides[side] = (net, {"site": site, "prefix": str(net), "label": label})
    (ln, _), (rn, _) = sides["left"], sides["right"]
    if ln.version != rn.version or ln.prefixlen != rn.prefixlen:
        raise IpamError(f"mirror {m.get('name')!r}: the two prefixes must be the same size")
    slots: dict[tuple[int, int], dict[str, str | None]] = defaultdict(
        lambda: {"left": None, "right": None})
    for side, (outer, _) in sides.items():
        for c in subnets:
            n = _net(c)
            if n.version == outer.version and n != outer and n.subnet_of(outer):  # type: ignore[arg-type]
                offset = int(n.network_address) - int(outer.network_address)
                slots[(offset, n.prefixlen)][side] = c
    rows = [{"position": f"+{off} /{plen}", **pair} for (off, plen), pair in sorted(slots.items())]
    return {"name": str(m.get("name") or "Mirror"), "left": sides["left"][1],
            "right": sides["right"][1], "rows": rows,
            "both": sum(1 for r in rows if r["left"] and r["right"]),
            "left_only": sum(1 for r in rows if r["left"] and not r["right"]),
            "right_only": sum(1 for r in rows if r["right"] and not r["left"])}


def build(cfg: dict, h: Harvest, *, plan_sha256: str = "", built_on: str = "",
          stem: str = "", organisation: str = "") -> dict:
    """The whole plan: sites, subnets with their addresses, segments, mirrors and checks."""
    sources = _sources(cfg)
    sites = _sites(cfg)
    subnets = _curated_subnets(cfg, sites, sources)

    def site_for(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
        best, best_len = NO_SITE, -1
        for sid, site in sites.items():
            for r in site["ranges"]:
                rn = _net(r)
                if net.version == rn.version and net.subnet_of(rn) and rn.prefixlen > best_len:  # type: ignore[arg-type]
                    best, best_len = sid, rn.prefixlen
        return best

    for cidr, d in h.declared.items():
        key = str(_net(cidr))
        if key in subnets:
            subnets[key]["evidence"] = sorted(set(subnets[key]["evidence"]) | {d["source"]})
            subnets[key].setdefault("declared_as", d.get("name", ""))
            continue
        name = str(d.get("name") or "")
        subnets[key] = {"cidr": key, "site": d.get("site") or site_for(_net(key)),
                        "purpose": name[:1].upper() + name[1:], "confidence": "declared",
                        "origin": "declared by a source", "evidence": [d["source"]],
                        "declared_as": name}

    # Segments: one row per (site, name), from the newest source that reports it.
    def as_of(sid: str) -> str:
        return str(sources.get(sid, {}).get("as_of") or "")

    by_name: dict[tuple[str, str], list[Segment]] = defaultdict(list)
    for seg in h.segments:
        by_name[(seg.site, seg.name)].append(seg)
    segments: list[dict] = []
    by_subnet_seg: dict[str, list[dict]] = defaultdict(list)
    for group in by_name.values():
        group.sort(key=lambda g: as_of(g.source), reverse=True)
        seg = group[0]
        subnet = str(_net(seg.subnet)) if seg.subnet else None
        row: dict[str, Any] = {"site": seg.site, "name": seg.name, "vlan": seg.vlan,
                               "subnet": subnet, "switch": seg.switch, "source": seg.source}
        older = sorted({g.source for g in group[1:]} - {seg.source})
        if older:
            row["also_in"] = older
        segments.append(row)
        if subnet is None:
            continue
        by_subnet_seg[subnet].append(row)
        if subnet not in subnets:
            subnets[subnet] = {"cidr": subnet, "site": seg.site or site_for(_net(subnet)),
                               "purpose": f"Network segment {seg.name}", "confidence": "declared",
                               "origin": "declared by a source", "evidence": []}
        if seg.source not in subnets[subnet]["evidence"]:
            subnets[subnet]["evidence"].append(seg.source)

    # Placement: every sighting goes to the most specific subnet holding it, or is set aside.
    nets = sorted(((_net(c), c) for c in subnets), key=lambda x: -x[0].prefixlen)
    authority = {site_id: s["id"] for s in sources.values()
                 for site_id in s.get("authoritative_for") or []}
    roaming = {sid for sid, s in sources.items() if s.get("roams")}
    superseded = {sid: list(s.get("supersedes") or []) for sid, s in sources.items()}
    newer_of = {old: new for new, olds in superseded.items() for old in olds}
    inside = [(_net(r["cidr"]), f"inside a machine: {r.get('reason') or 'no reason given'}")
              for r in cfg.get("host_internal_ranges") or []]
    ips_by_source: dict[str, set[str]] = defaultdict(set)
    for sg in h.sightings:
        ips_by_source[sg.source].add(sg.ip)

    placed: dict[str, list[Sighting]] = defaultdict(list)
    set_aside: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for sg in h.sightings:
        try:
            ip = ipaddress.ip_address(sg.ip)
        except ValueError:
            set_aside[sg.source]["not an address"] += 1
            continue
        sg.ip = str(ip)
        reason = _non_routed(ip) or next(
            (r for n, r in inside if ip.version == n.version and ip in n), "")
        if reason:
            set_aside[sg.source][reason] += 1
            continue
        home = next((c for n, c in nets if ip.version == n.version and ip in n), None)
        if home is None:
            set_aside[sg.source]["outside every subnet in the plan"
                                 + (" (a roaming source)" if sg.source in roaming else "")] += 1
            continue
        sub = subnets[home]
        only = sub.get("only_sources")
        if only and sg.source not in only:
            allowed = ", ".join(sources[o]["label"] for o in only)
            set_aside[sg.source][f"inside {home}, which only {allowed} may populate"] += 1
            continue
        auth = authority.get(sub["site"])
        if auth and sg.source in roaming and sg.source != auth and sg.ip not in ips_by_source[auth]:
            set_aside[sg.source][f"inside {sites[sub['site']]['name']}, but not an address "
                                 f"{sources[auth]['label']} holds"] += 1
            continue
        placed[home].append(sg)

    classes = {sid: _evidence_class(s) for sid, s in sources.items()}
    for cidr, sub in subnets.items():
        net = _net(cidr)
        sub["addresses"] = _addresses(placed.get(cidr, []), sub, sources, sites, classes,
                                      authority, superseded, newer_of)
        sub["address_count"] = len(sub["addresses"])
        sub["usable"] = _usable(net)
        sub["ip_version"] = net.version
        sub["scope"] = sub.get("scope") or ("public" if net.is_global
                                            else "private" if net.is_private else "other")
        if sub["scope"] == "public":
            for a in sub["addresses"]:
                if a["ip"] in h.registry:
                    a["internet_registry"] = h.registry[a["ip"]]
            rec = h.registry.get(str(net.network_address))
            if rec:
                sub["internet_registry"] = rec
        sub["segments"] = by_subnet_seg.get(cidr, [])
        vlans = {f"{p['site'] or '?'}:{p['vlan']}" for p in sub["segments"] if p["vlan"] is not None}
        if sub.get("vlan") is not None:
            vlans.add(f"{sub['site']}:{sub['vlan']}")
        sub["vlans"] = sorted(vlans)
        ev = set(sub["evidence"]) | {sg.source for sg in placed.get(cidr, [])}
        sub["evidence"] = sorted(sorted(ev), key=as_of, reverse=True)
        dates = [as_of(s) for s in ev if as_of(s)]
        sub["oldest_evidence"] = min(dates, default="")
        dates += [a["last_observed"] for a in sub["addresses"] if a["last_observed"]]
        sub["newest_evidence"] = max(dates, default="")
        sub["action_ids"] = [str(a["id"]) for a in cfg.get("actions") or []
                             if cidr in [str(_net(x)) for x in a.get("subnets") or []]]

    ordered = sorted(subnets, key=lambda c: (_net(c).version, _net(c).network_address,
                                             _net(c).prefixlen))
    for c in ordered:
        n = _net(c)
        parents = [p for p in subnets if p != c and _net(p).version == n.version
                   and n.subnet_of(_net(p))]  # type: ignore[arg-type]
        subnets[c]["parent"] = max(parents, key=lambda p: _net(p).prefixlen) if parents else ""

    mirrors = [_mirror(m, subnets, sites) for m in cfg.get("mirrors") or []]
    source_rows = [{**s, "evidence_class": classes[sid],
                    "notes": list(h.notes.get(sid, []))} for sid, s in sources.items()]
    return {
        "schema": SCHEMA_VERSION,
        "stem": stem,
        "organisation": organisation,
        "title": str(cfg.get("title") or "IP address plan"),
        "subtitle": str(cfg.get("subtitle") or ""),
        "summary": [str(p) for p in cfg.get("summary") or []],
        "built_on": built_on or date.today().isoformat(),
        "plan_sha256": plan_sha256,
        "sources": source_rows,
        "sites": list(sites.values()),
        "subnets": [subnets[c] for c in ordered],
        "segments": sorted(segments, key=lambda e: (e["site"], e["vlan"] or 0, e["name"])),
        "mirrors": mirrors,
        "actions": list(cfg.get("actions") or []),
        "checks": _checks(subnets, segments, sources),
        "counts": _counts(subnets, segments, sites, classes),
        "set_aside": {s: dict(v) for s, v in set_aside.items()},
    }


def _addresses(sightings: list[Sighting], sub: dict, sources: dict, sites: dict,
               classes: dict[str, str], authority: dict[str, str],
               superseded: dict[str, list[str]], newer_of: dict[str, str]) -> list[dict]:
    per_ip: dict[str, list[Sighting]] = defaultdict(list)
    for sg in sightings:
        per_ip[sg.ip].append(sg)
    auth = authority.get(sub["site"])
    site = sites.get(sub["site"], {})
    out: list[dict] = []
    for addr in sorted(per_ip, key=ipaddress.ip_address):
        sgs = per_ip[addr]
        names: list[str] = []
        for sg in sgs:
            if sg.name and sg.name not in names:
                names.append(sg.name)
        here = {sg.source for sg in sgs}
        replaced = {old for s in here for old in superseded.get(s, ()) if old in here}
        machines = [sg for sg in sgs if sg.name and sg.name_is == "machine"]
        current = sorted({_short(sg.name) for sg in machines if sg.source not in replaced})
        previous = sorted({_short(sg.name) for sg in machines if sg.source in replaced}
                          - set(current))

        def dated(cls: tuple[str, ...], group: list[Sighting] = sgs) -> list[str]:
            return [d for d in (sg.seen or sources.get(sg.source, {}).get("as_of", "")
                                for sg in group if classes.get(sg.source) in cls) if d]

        seen, named = dated(("observed",)), dated(("named", "documented"))
        entry: dict[str, Any] = {
            "ip": addr, "names": names, "sources": sorted(here),
            "evidence": sorted({classes.get(s, "observed") for s in here},
                               key=EVIDENCE_CLASSES.index),
            "first_observed": min(seen, default=""), "last_observed": max(seen, default=""),
            "last_documented": max(named, default=""),
            "machine_names": current,
            "sightings": [{"source": sg.source, "name": sg.name, "name_is": sg.name_is,
                           "observed": sg.seen or sources.get(sg.source, {}).get("as_of", ""),
                           **sg.detail} for sg in sgs],
        }
        if len(current) > 1:
            entry["name_conflict"] = current
        if previous:
            entry["previous_names"] = previous
        if auth and auth not in here and not sub.get("only_sources"):
            entry["not_in_authoritative_source"] = sources[auth]["label"]
        observed = {s for s in here if classes.get(s) == "observed"}
        if observed and all(s in newer_of for s in observed):
            entry["only_in_superseded"] = sources[newer_of[sorted(observed)[0]]]["label"]
        stated = sorted({str(sg.detail["site_stated"]) for sg in sgs if sg.detail.get("site_stated")})
        known = {str(sub["site"]).lower(), str(site.get("name") or "").lower()}
        wrong = [s for s in stated if s.lower() not in known]
        if wrong:
            entry["site_stated"] = wrong
        out.append(entry)
    return out


def _counts(subnets: dict[str, dict], segments: list[dict], sites: dict,
            classes: dict[str, str]) -> dict:
    single = sum(1 for c in subnets if _net(c).num_addresses == 1)
    seen = named = documented = 0
    for s in subnets.values():
        for a in s["addresses"]:
            ev = set(a["evidence"])
            if "observed" in ev:
                seen += 1
            elif "named" in ev:
                named += 1
            else:
                documented += 1
    by_kind: dict[str, int] = defaultdict(int)
    for site in sites.values():
        by_kind[site["kind"] or "unspecified"] += 1
    vlans = {(s["site"], s["vlan"]) for s in segments if s["vlan"] not in (None, 0)}
    vlans |= {(s["site"], s["vlan"]) for s in subnets.values() if s.get("vlan") not in (None, 0)}
    return {
        "blocks": len(subnets), "subnets": len(subnets) - single, "single_addresses": single,
        "addresses": seen + named + documented, "addresses_seen_in_use": seen,
        "addresses_named_only": named, "addresses_documented_only": documented,
        "segments": len(segments), "vlans": len(vlans),
        "sites": len(sites), "sites_by_kind": dict(sorted(by_kind.items())),
        "sites_planned": sum(1 for x in sites.values() if x["status"] == "planned"),
        "sites_with_subnets": len({s["site"] for s in subnets.values()} & set(sites)),
    }


def _checks(subnets: dict[str, dict], segments: list[dict], sources: dict) -> dict:
    """What a reviewer should look at, each item found in the data."""
    def every(flag: str) -> list[dict]:
        return [{"subnet": c, "ip": a["ip"], "names": a["names"], "sources": a["sources"],
                 flag: a[flag]} for c, s in subnets.items() for a in s["addresses"] if a.get(flag)]

    name_conflicts = [r for r in every("name_conflict")
                      if subnets[r["subnet"]].get("addressing") not in SHARED_ADDRESSING]
    # One IPv4 and one IPv6 subnet on a VLAN is ordinary dual-stack; two of
    # the same version is the conflict.
    on_vlan: dict[tuple[str, int, int], set[str]] = defaultdict(set)
    for e in segments:
        if e["vlan"] not in (None, 0) and e["subnet"]:
            on_vlan[(e["site"], e["vlan"], _net(e["subnet"]).version)].add(e["subnet"])
    for c, s in subnets.items():
        if s.get("vlan") not in (None, 0):
            on_vlan[(s["site"], s["vlan"], _net(c).version)].add(c)
    vlan_conflicts = [{"site": site, "vlan": vlan, "subnets": sorted(subs, key=_net)}
                      for (site, vlan, _v), subs in sorted(on_vlan.items()) if len(subs) > 1]
    empty = [c for c, s in subnets.items()
             if not s["addresses"] and not s["segments"] and _net(c).num_addresses > 1]
    documented_only = [c for c, s in subnets.items() if s["evidence"]
                       and all(sources.get(e, {}).get("kind") in DOCUMENT_KINDS
                               for e in s["evidence"])
                       and not s["addresses"] and not s["segments"]]
    return {"name_conflicts": name_conflicts, "vlan_conflicts": vlan_conflicts,
            "site_disagreements": every("site_stated"),
            "not_in_authoritative_source": every("not_in_authoritative_source"),
            "only_in_superseded": every("only_in_superseded"),
            "no_addresses_found": empty, "documented_only": documented_only}


# --- writing -----------------------------------------------------------------

CSV_FIELDS = ["subnet", "parent", "ip_version", "scope", "site", "site_name", "site_kind",
              "location", "environment", "purpose", "vlans", "segments", "addressing",
              "addresses_found", "usable_addresses", "confidence", "origin",
              "last_observed_in_use", "newest_evidence", "oldest_evidence", "evidence", "asn",
              "as_name", "announced_prefix", "registered_range", "registrant", "action_ids",
              "notes"]


def csv_rows(plan: dict) -> list[dict]:
    """One row per subnet, flattened for a spreadsheet."""
    sources = {s["id"]: s for s in plan["sources"]}
    sites = {s["id"]: s for s in plan["sites"]}
    out = []
    for s in plan["subnets"]:
        site = sites.get(s["site"], {})
        reg = s.get("internet_registry") or {}
        out.append({
            "subnet": s["cidr"], "parent": s.get("parent", ""), "ip_version": s["ip_version"],
            "scope": s["scope"], "site": s["site"], "site_name": site.get("name", ""),
            "site_kind": site.get("kind", ""), "location": site.get("location", ""),
            "environment": s.get("environment", ""), "purpose": s.get("purpose", ""),
            "vlans": "; ".join(s["vlans"]),
            "segments": "; ".join(sorted({p["name"] for p in s["segments"]})),
            "addressing": s.get("addressing", ""),
            "addresses_found": s["address_count"], "usable_addresses": s["usable"],
            "confidence": s.get("confidence", ""), "origin": s.get("origin", ""),
            "last_observed_in_use": max((a["last_observed"] for a in s["addresses"]
                                         if a.get("last_observed")), default=""),
            "newest_evidence": s.get("newest_evidence", ""),
            "oldest_evidence": s.get("oldest_evidence", ""),
            "evidence": "; ".join(
                f"{sources[e]['label']} ({sources[e]['as_of_basis']} {sources[e]['as_of']})"
                if e in sources else e for e in s["evidence"]),
            "asn": reg.get("asn", ""), "as_name": reg.get("as_name", ""),
            "announced_prefix": reg.get("announced_prefix", ""),
            "registered_range": reg.get("registered_range", ""),
            "registrant": reg.get("registrant", ""),
            "action_ids": "; ".join(s.get("action_ids") or []),
            "notes": s.get("notes", ""),
        })
    return out


_CREDENTIAL_SHAPES = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|"
    r"\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S{6,}",
    re.IGNORECASE)
# Keys never written out: local file locations of the inputs.
_LOCAL_KEYS = frozenset({"path", "paths"})


def for_writing(value: Any, key: str = "") -> Any:
    """``value`` as it is written: local input paths removed, and a refusal on
    anything shaped like a credential (an export that carries one is a finding,
    not something to copy into a plan)."""
    if isinstance(value, dict):
        return {k: for_writing(v, str(k)) for k, v in value.items() if k not in _LOCAL_KEYS}
    if isinstance(value, list):
        return [for_writing(v, key) for v in value]
    if isinstance(value, str) and _CREDENTIAL_SHAPES.search(value):
        raise IpamError(f"a value under {key!r} is shaped like a credential; nothing was "
                        "written. Find it in the export and treat it as a finding.")
    return value


def write_outputs(plan: dict, out_dir: str | Path, *,
                  theme: htmlpage.Theme | None = None) -> dict[str, Path]:
    """Write ``<stem>.json``, ``<stem>.csv`` and ``<stem>.html`` to ``out_dir``; return their paths."""
    from . import ipam_view

    clean = for_writing(plan)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = str(clean.get("stem") or "ipam")
    paths = {"json": out / f"{stem}.json", "csv": out / f"{stem}.csv",
             "html": out / f"{stem}.html"}
    paths["json"].write_text(json.dumps(clean, indent=1, ensure_ascii=False, default=str) + "\n",
                             encoding="utf-8")
    with paths["csv"].open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(csv_rows(clean))
    paths["html"].write_text(ipam_view.render(clean, theme=theme), encoding="utf-8")
    return paths


# --- entry points ------------------------------------------------------------

def plan_stem(plan_path: Path) -> str:
    """``example`` for ``example.ipam.yaml``."""
    return plan_path.name.removesuffix(PLAN_SUFFIX).removesuffix(".yaml")


def profile_for(plan_path: Path) -> dict:
    """The target profile beside the plan file (``<stem>.yaml``) if there is one, else the plan file.

    Branding and the organisation's name are read from whichever this returns.
    """
    sibling = plan_path.with_name(plan_stem(plan_path) + ".yaml")
    path = sibling if sibling.is_file() else plan_path
    doc = config.load_yaml_strict(path)
    doc["_path"] = str(path)
    return doc


def _exports(exports_dir: str | Path | None) -> Path:
    return Path(exports_dir).expanduser() if exports_dir is not None else config.inbox_dir()


def build_plan(target_path: str | Path, exports_dir: str | Path | None = None, *,
               built_on: str = "") -> dict:
    """Build the plan from a ``.ipam.yaml`` file.

    Source paths in the plan file are read relative to ``exports_dir``, which
    defaults to the workspace's inbox (:func:`takestock.config.inbox_dir`).
    """
    path = Path(target_path)
    if not path.is_file():
        raise IpamError(f"no IP address plan at {path}")
    cfg = config.load_yaml_strict(path)
    return build(cfg, harvest(cfg, _exports(exports_dir)),
                 plan_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                 built_on=built_on, stem=plan_stem(path),
                 organisation=htmlpage.organisation_name(profile_for(path), default=""))


def public_addresses(plan: dict) -> list[str]:
    """Every public address the plan holds, plus the first address of every public subnet."""
    out: set[str] = set()
    for s in plan["subnets"]:
        if s.get("scope") != "public":
            continue
        out.add(str(_net(s["cidr"]).network_address))
        out.update(a["ip"] for a in s["addresses"])
    return sorted(out, key=ipaddress.ip_address)


def refresh_asn(target_path: str | Path, exports_dir: str | Path | None = None,
                today: str = "") -> int:
    """Look up the plan's public addresses and save the replies where its ``asn-lookups`` source reads."""
    path = Path(target_path)
    cfg = config.load_yaml_strict(path)
    exports = _exports(exports_dir)
    src = next((s for s in cfg.get("sources") or [] if s.get("kind") == "asn-lookups"), None)
    if src is None:
        raise IpamError("--lookup-asn needs a source of kind asn-lookups in the plan file")
    folder = _source_paths({**src, "id": str(src.get("id"))}, exports)[0]
    host = str((cfg.get("asn_lookup") or {}).get("whois_host") or "")
    plan = build(cfg, harvest(cfg, exports))
    return lookup_asn(public_addresses(plan), folder, today or date.today().isoformat(),
                      whois_host=host)


def main(argv: list[str] | None = None) -> int:
    """Build an IP address plan and write its JSON, CSV and HTML.

    Exits 0 when the plan is written, and 2 for wrong arguments or an
    unreadable input (see :mod:`takestock.exits`).
    """
    return guarded("takestock.ipam", _main, argv)


def _main(argv: list[str] | None) -> int:
    ap = argparse.ArgumentParser(prog="takestock.ipam",
                                 description="Build an IP address plan from a .ipam.yaml file.")
    ap.add_argument("plan", help="the plan file, <stem>.ipam.yaml")
    ap.add_argument("out_dir", help="directory to write <stem>.json, .csv and .html into")
    ap.add_argument("--exports", help="directory the plan's source paths are relative to "
                                      "(default: the workspace inbox)")
    ap.add_argument("--lookup-asn", action="store_true",
                    help="first look up the plan's public addresses with the internet "
                         "registries (sends them over the network)")
    args = ap.parse_args(argv)
    try:
        if args.lookup_asn:
            n = refresh_asn(args.plan, args.exports)
            print(f"looked up {_plural(n, 'address', 'addresses')}", file=sys.stderr)
        plan = build_plan(args.plan, args.exports)
        theme = htmlpage.theme_from_target(profile_for(Path(args.plan)))
        for problem in theme.contrast_failures():
            print(f"warning: branding contrast: {problem}", file=sys.stderr)
        paths = write_outputs(plan, args.out_dir, theme=theme)
    except IpamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for p in paths.values():
        print(p)
    return EXIT_CLEAN


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
