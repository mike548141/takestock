"""Read DNS zone files and private-zone record-set exports.

A zone file (RFC 1035 master-file format) lists every record an
organisation configures, not only the names somebody happens to look up.
:func:`parse` reads the common subset: ``$ORIGIN`` and ``$TTL``, relative and
absolute owner names, ``@``, a blank owner meaning "same as the line before",
parenthesised multi-line records, quoted strings and ``;`` comments. Lines it
cannot place are kept in ``ZoneFile.unparsed`` rather than dropped, so a
reader can see what was not understood.

:func:`read_private` reads the JSON a cloud provider's command-line tool
writes when it lists the record sets of a private DNS zone (one object per
record set, with ``aRecords``, ``cnameRecord`` and similar fields).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

#: Record types the parser recognises; a line naming any other type is unparsed.
TYPES = frozenset({"A", "AAAA", "CAA", "CNAME", "DS", "MX", "NS", "PTR", "SOA",
                   "SRV", "TLSA", "TXT", "NAPTR"})

# Header comment keys some DNS hosts write at the top of an exported zone.
_HEADER_KEYS = ("Zone name", "Resource Group Name", "Date and time (UTC)")


@dataclass(frozen=True)
class Record:
    """One record: owner (absolute, lower case), TTL, type, and its data fields."""

    owner: str
    ttl: int
    rtype: str
    rdata: tuple[str, ...]

    @property
    def text(self) -> str:
        """The data joined with quotes removed: a TXT record's full string."""
        return "".join(_unquote(p) for p in self.rdata)

    def target(self) -> str:
        """The name a pointer record leads to (its last field), normalised."""
        if not self.rdata:
            return ""
        return _fqdn(self.rdata[-1])


@dataclass
class ZoneFile:
    """A parsed zone: its origin, records, lines not understood, and any export header."""

    origin: str
    records: list[Record] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    header: dict[str, str] = field(default_factory=dict)

    def record_sets(self) -> dict[tuple[str, str], list[Record]]:
        """Records grouped by (owner, type)."""
        out: dict[tuple[str, str], list[Record]] = {}
        for r in self.records:
            out.setdefault((r.owner, r.rtype), []).append(r)
        return out

    def by_type(self, rtype: str) -> list[Record]:
        """Every record of one type."""
        return [r for r in self.records if r.rtype == rtype]


def _fqdn(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _unquote(s: str) -> str:
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s


def _tokens(line: str) -> list[str]:
    """Split one physical line into fields, keeping quoted strings whole."""
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            i += 1
        elif c == ";":
            break
        elif c in "()":
            out.append(c)
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                j += 2 if line[j] == "\\" else 1
            out.append(line[i:j + 1])
            i = j + 1
        else:
            j = i
            while j < n and line[j] not in ' \t;()"':
                j += 1
            out.append(line[i:j])
            i = j
    return out


def _logical_lines(text: str) -> list[tuple[bool, list[str], str]]:
    """Join parenthesised continuations into (starts-blank, fields, raw text) entries."""
    out: list[tuple[bool, list[str], str]] = []
    pending: list[str] | None = None
    blank = False
    raw_acc = ""
    for raw in text.splitlines():
        toks = _tokens(raw)
        if pending is None:
            if not toks:
                continue
            blank = raw[:1] in (" ", "\t")
            pending, raw_acc = [], raw
        else:
            raw_acc += "\n" + raw
        pending += toks
        if pending.count("(") <= pending.count(")"):
            out.append((blank, [t for t in pending if t not in "()"], raw_acc))
            pending = None
    if pending:
        out.append((blank, [t for t in pending if t not in "()"], raw_acc))
    return out


def parse(text: str, origin: str = "") -> ZoneFile:
    """Parse zone-file text; ``origin`` applies until a ``$ORIGIN`` line changes it."""
    zone = ZoneFile(origin=_fqdn(origin))
    for line in text.splitlines()[:12]:
        stripped = line.strip().lstrip(";").strip()
        if ":" in stripped and not stripped.startswith("$"):
            k, v = stripped.split(":", 1)
            if k.strip() in _HEADER_KEYS:
                zone.header[k.strip()] = v.strip()
    default_ttl = 3600
    previous = zone.origin
    for blank, toks, raw in _logical_lines(text):
        if toks[0].upper() == "$ORIGIN" and len(toks) > 1:
            zone.origin = _fqdn(toks[1])
            previous = zone.origin
            continue
        if toks[0].upper() == "$TTL" and len(toks) > 1:
            default_ttl = int(toks[1]) if toks[1].isdigit() else default_ttl
            continue
        if toks[0].startswith("$"):
            zone.unparsed.append(raw)
            continue
        rest = toks
        owner = previous
        if not blank:
            name, rest = toks[0], toks[1:]
            if name == "@":
                owner = zone.origin
            elif name.endswith("."):
                owner = _fqdn(name)
            else:
                owner = f"{name.lower()}.{zone.origin}" if zone.origin else name.lower()
        ttl = default_ttl
        # Between the owner and the type sit an optional TTL and class, in either order.
        while rest and rest[0].upper() not in TYPES:
            head = rest[0]
            if head.isdigit():
                ttl = int(head)
            elif head.upper() not in ("IN",):
                break
            rest = rest[1:]
        if not rest or rest[0].upper() not in TYPES:
            zone.unparsed.append(raw)
            continue
        zone.records.append(Record(owner=owner, ttl=ttl, rtype=rest[0].upper(),
                                   rdata=tuple(rest[1:])))
        previous = owner
    return zone


def read(path: Path) -> ZoneFile:
    """Read ``<origin>.zone`` from disk; the file name supplies the starting origin."""
    origin = path.name.removesuffix(".zone")
    return parse(path.read_text(encoding="utf-8", errors="replace"), origin)


# For each record type, the field that holds its records in a private-zone
# export and how to turn one entry into data fields like a zone file's.
_PRIVATE_FIELDS: dict[str, tuple[str, Callable[[dict], tuple[str, ...]]]] = {
    "A": ("aRecords", lambda r: (r.get("ipv4Address", ""),)),
    "AAAA": ("aaaaRecords", lambda r: (r.get("ipv6Address", ""),)),
    "CNAME": ("cnameRecord", lambda r: (r.get("cname", ""),)),
    "MX": ("mxRecords", lambda r: (str(r.get("preference", "")), r.get("exchange", ""))),
    "PTR": ("ptrRecords", lambda r: (r.get("ptrdname", ""),)),
    "SRV": ("srvRecords", lambda r: (str(r.get("priority", "")), str(r.get("weight", "")),
                                     str(r.get("port", "")), r.get("target", ""))),
    "TXT": ("txtRecords", lambda r: tuple(f'"{v}"' for v in r.get("value", []))),
    "SOA": ("soaRecord", lambda r: (r.get("host", ""), r.get("email", ""))),
}


@dataclass
class PrivateRecordSet:
    """One record set from a private-zone export."""

    fqdn: str
    rtype: str
    ttl: int
    auto_registered: bool
    records: list[tuple[str, ...]]


def read_private(path: Path) -> tuple[str, list[PrivateRecordSet], str]:
    """Read ``<zone>.json``; returns (zone, record sets, error text or "")."""
    zone = path.name.removesuffix(".json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return zone, [], str(exc)
    if not isinstance(data, list):
        return zone, [], "not a JSON list of record sets"
    out: list[PrivateRecordSet] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rtype = str(item.get("type", "")).rsplit("/", 1)[-1].upper()
        entry = _PRIVATE_FIELDS.get(rtype)
        records: list[tuple[str, ...]] = []
        if entry is not None:
            key, fn = entry
            raw = item.get(key)
            rows = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
            records = [fn(r) for r in rows if isinstance(r, dict)]
        out.append(PrivateRecordSet(
            fqdn=_fqdn(str(item.get("fqdn", ""))), rtype=rtype,
            ttl=int(item.get("ttl") or 0),
            auto_registered=bool(item.get("isAutoRegistered")),
            records=records))
    return zone, out, ""
