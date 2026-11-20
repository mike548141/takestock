"""Recognise the mail system behind a host name, header or registry name.

The catalogue is ``data/mail-systems.yaml``; an overlay of the same shape adds
an organisation's own hosts and partners and replaces a bundled entry of the
same name. Matching is by evidence, strongest first: a host-name suffix, a
host-name pattern, an address range, a Message-ID suffix, a header that only one system writes,
a mailer string, and last the IP registry's organisation name, which says who
owns an address, not which service sent from it.

A host nobody recognises is named by its registrable domain, so two unknown
relays in the same domain still read as one system, and an internal host (a
private address, or a name with no public suffix) is named as internal.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..config import BUNDLED_DATA_DIR

CATALOGUE = BUNDLED_DATA_DIR / "mail-systems.yaml"

INTERNAL = "internal host"
UNKNOWN = "unidentified"

# Second-level labels under which registrations sit one level deeper
# (a name registered under a country's "co" or "com" label). Enough to name a registrable domain without
# the public suffix list; a miss only makes a name one label longer.
_SECOND_LEVEL = {"co", "com", "net", "org", "govt", "gov", "ac", "edu", "school",
                 "mil", "iwi", "geek", "gen", "kiwi", "maori", "health", "parliament", "cri"}

_INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".localdomain",
                      ".intranet", ".private", ".localhost")


@dataclass
class System:
    """One recognisable mail system."""

    name: str
    kind: str = "relay"
    host_suffixes: list[str] = field(default_factory=list)
    host_regex: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    message_id_suffixes: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    mailer_regex: list[str] = field(default_factory=list)
    received_regex: list[str] = field(default_factory=list)
    asn_orgs: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)      # CIDR ranges


def _entry(raw: dict) -> System:
    known = set(System.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"mail system {raw.get('name')!r}: unknown key(s) {sorted(unknown)}")
    if not raw.get("name"):
        raise ValueError("a mail system entry needs a name")
    fields: dict[str, Any] = {k: (list(v) if isinstance(v, list) else v) for k, v in raw.items()}
    return System(**fields)


def load(overlays: list[Path] | None = None) -> Catalogue:
    """The bundled catalogue with any overlays applied in order."""
    entries: dict[str, System] = {}
    for path in [CATALOGUE, *(overlays or [])]:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for raw in doc.get("systems") or []:
            s = _entry(raw)
            entries.pop(s.name, None)
            entries[s.name] = s
    # Overlay entries are more specific than bundled ones, so they are tried first.
    return Catalogue(list(reversed(list(entries.values()))))


def is_internal_address(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def is_internal_name(host: str) -> bool:
    h = host.lower().rstrip(".")
    if not h or h.startswith("["):
        return False
    if "." not in h:
        return not _looks_like_ip(h)
    return h.endswith(_INTERNAL_SUFFIXES)


def _looks_like_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


def registrable(host: str) -> str:
    """The registered name a host sits under (two labels, or three under a
    country's "co"-style label); the host itself if it is too short."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _suffix_match(host: str, suffixes: list[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in (x.lower() for x in suffixes))


class Catalogue:
    """Lookups over a list of systems, tried in order."""

    def __init__(self, systems: list[System]):
        self.systems = systems
        self._re = {s.name: [re.compile(p, re.I) for p in s.host_regex] for s in systems}
        self._mailer = {s.name: [re.compile(p, re.I) for p in s.mailer_regex] for s in systems}
        self._recv = {s.name: [re.compile(p, re.I) for p in s.received_regex] for s in systems}
        self._nets = {s.name: [ipaddress.ip_network(c, strict=False) for c in s.addresses]
                      for s in systems}

    def kind_of(self, name: str) -> str:
        for s in self.systems:
            if s.name == name:
                return s.kind
        return "internal" if name.startswith(INTERNAL) else "unknown"

    def by_host(self, *hosts: str) -> str | None:
        """The system a host name belongs to, or None."""
        for h in hosts:
            if not h:
                continue
            for s in self.systems:
                if _suffix_match(h, s.host_suffixes) or any(r.search(h) for r in self._re[s.name]):
                    return s.name
        return None

    def by_address(self, ip: str) -> str | None:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return None
        for s in self.systems:
            if any(a.version == n.version and a in n for n in self._nets[s.name]):
                return s.name
        return None

    def by_spf_include(self, include: str) -> str | None:
        for s in self.systems:
            if _suffix_match(include, s.spf_includes) or _suffix_match(include, s.host_suffixes):
                return s.name
        return None

    def by_message_id(self, right_hand: str) -> str | None:
        for s in self.systems:
            if _suffix_match(right_hand, s.message_id_suffixes):
                return s.name
        return None

    def by_headers(self, present: set[str]) -> list[str]:
        low = {h.lower() for h in present}
        return [s.name for s in self.systems if any(h.lower() in low for h in s.headers)]

    def by_mailer(self, text: str) -> str | None:
        for s in self.systems:
            if any(r.search(text) for r in self._mailer[s.name]):
                return s.name
        return None

    def by_received_text(self, text: str) -> str | None:
        for s in self.systems:
            if any(r.search(text) for r in self._recv[s.name]):
                return s.name
        return None

    def by_asn_org(self, org: str) -> str | None:
        o = org.lower().strip()
        for s in self.systems:
            if any(o == a.lower() for a in s.asn_orgs):
                return s.name
        return None

    def name_host(self, host: str = "", rdns: str = "", ip: str = "", received: str = "") -> str:
        """A station name for a hop's host: a catalogued system, internal, or its domain."""
        known = self.by_host(rdns, host) or (self.by_address(ip) if ip else None)
        if known:
            return known
        if (ip and is_internal_address(ip)) or is_internal_name(host) or is_internal_name(rdns):
            label = next((h for h in (rdns, host) if h and not _looks_like_ip(h)), "") or ip
            software = self.by_received_text(received) if received else None
            label = label.split(".")[0].lower() if label and not _looks_like_ip(label) else label
            return f"{INTERNAL} {label}".strip() + (f" ({software})" if software else "")
        if received:
            known = self.by_received_text(received)
            if known:
                return known
        for h in (rdns, host):
            if h and "." in h and not _looks_like_ip(h):
                return registrable(h)
        return UNKNOWN
