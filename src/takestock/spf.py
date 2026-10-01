"""Expand an SPF record into everything it authorises to send mail.

An SPF record (RFC 7208) can authorise senders indirectly: ``include:`` and
``redirect=`` pull in another domain's policy, ``a`` and ``mx`` name hosts by
their DNS records. :func:`expand` follows all of them and returns a
:class:`Surface`: the named hosts, the address ranges, the policies
traversed, and the two RFC 7208 §4.6.4 limits an evaluator applies, on
DNS-consuming terms (at most ten) and on void lookups (a recommended
ceiling of two lookups that return nothing).

The resolver is a parameter, so tests and callers can supply DNS answers
without the network.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .util import ERROR_PREFIX, run

#: RFC 7208 §4.6.4: at most ten terms that cause a DNS query.
LOOKUP_LIMIT = 10

_COSTS_A_LOOKUP = {"include", "a", "mx", "ptr", "exists", "redirect"}

#: RFC 7208 §4.6.4 recommends at most two void lookups.
VOID_LOOKUP_LIMIT = 2

# How a DNS question was answered, as far as void-lookup counting needs.
ANSWERED = "answered"
VOID = "void"                  # NOERROR with no answer, or NXDOMAIN
INCONCLUSIVE = "inconclusive"  # the resolver failed, so neither answered nor void
UNCLASSIFIED = "unclassified"  # the resolver reported no status at all

_TERM = re.compile(r"^([+\-~?]?)([A-Za-z][A-Za-z0-9_.\-]*)(?:([:=])(.*))?$")

_KNOWN = {"a", "mx", "ip4", "ip6", "include", "exists", "ptr", "all", "redirect", "exp"}

_TXT_STRING = re.compile(r'"([^"]*)"')


@dataclass(frozen=True)
class Term:
    """One SPF term: qualifier (``+ - ~ ?``), mechanism or modifier, and value."""

    qualifier: str
    kind: str
    value: str = ""


@dataclass(frozen=True)
class Answer:
    """A resolver's answer: the records and how the question was answered."""

    records: list[str]
    status: str = UNCLASSIFIED
    server: str = ""


@dataclass
class Surface:
    """Everything one domain's SPF record authorises, after following every reference."""

    domain: str
    record: str = ""
    published: bool = True
    all_qualifier: str = ""
    hosts: list[str] = field(default_factory=list)
    ranges: list[str] = field(default_factory=list)
    ipv6_ranges: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    unexpandable: list[str] = field(default_factory=list)
    lookups: int = 0
    depth: int = 0
    void_lookups: int = 0
    void_terms: list[str] = field(default_factory=list)
    inconclusive_lookups: int = 0
    inconclusive_terms: list[str] = field(default_factory=list)
    # False when the resolver never reported a status, so voids could not be told
    # apart from failures and the void count means nothing.
    void_measured: bool = False
    resolver: str = ""

    @property
    def addresses(self) -> int:
        """IPv4 addresses the ranges cover, overlaps counted once."""
        nets: list[ipaddress.IPv4Network] = []
        for r in self.ranges:
            try:
                nets.append(ipaddress.IPv4Network(r, strict=False))
            except ValueError:
                continue
        total = 0
        for net in ipaddress.collapse_addresses(nets):
            total += net.num_addresses
        return total

    @property
    def over_lookup_limit(self) -> bool:
        return self.lookups > LOOKUP_LIMIT

    @property
    def over_void_limit(self) -> bool:
        return self.void_measured and self.void_lookups > VOID_LOOKUP_LIMIT

    @property
    def at_void_limit(self) -> bool:
        return self.void_measured and self.void_lookups == VOID_LOOKUP_LIMIT


def combined(surfaces: list[Surface]) -> tuple[list[str], int, list[str], list[str]]:
    """(IPv4 ranges, IPv4 address count, IPv6 ranges, hosts) across several surfaces."""
    ranges = list(dict.fromkeys(r for s in surfaces for r in s.ranges))
    ipv6 = list(dict.fromkeys(r for s in surfaces for r in s.ipv6_ranges))
    hosts = list(dict.fromkeys(h for s in surfaces for h in s.hosts))
    return ranges, Surface(domain="", ranges=ranges).addresses, ipv6, hosts


#: A resolver takes (name, record type) and returns answer lines or an Answer.
Resolver = Callable[[str, str], "list[str] | Answer"]

_DIG_STATUS = re.compile(r"->>HEADER<<-.*?\bstatus:\s*([A-Z]+)")
_DIG_ANSWER_COUNT = re.compile(r"\bANSWER:\s*(\d+)")
_DIG_SERVER = re.compile(r";;\s*SERVER:\s*(\S+)")


def dns_resolver(name: str, rtype: str) -> Answer:
    """The live resolver: one ``dig`` query through the machine's own resolver."""
    out = run(["dig", "+noall", "+comment", "+answer", "+stats", rtype, name], timeout=20)
    if out.startswith(ERROR_PREFIX):
        return Answer([], INCONCLUSIVE)
    server = m.group(1) if (m := _DIG_SERVER.search(out)) else ""
    records = _rdata(out, rtype)
    status_m = _DIG_STATUS.search(out)
    if not status_m:
        return Answer(records, INCONCLUSIVE, server)
    rcode = status_m.group(1)
    count_m = _DIG_ANSWER_COUNT.search(out)
    count = int(count_m.group(1)) if count_m else len(records)
    if rcode == "NXDOMAIN":
        return Answer(records, VOID, server)
    if rcode == "NOERROR":
        return Answer(records, VOID if count == 0 else ANSWERED, server)
    return Answer(records, INCONCLUSIVE, server)


def _rdata(dig_output: str, rtype: str) -> list[str]:
    out = []
    for line in dig_output.splitlines():
        if not line.strip() or line.lstrip().startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) == 5 and fields[3].upper() == rtype.upper():
            out.append(fields[4].strip())
    return out


def parse(record: str) -> list[Term]:
    """The terms of an SPF record, version tag excluded; unparseable words are skipped."""
    out: list[Term] = []
    for raw in record.replace('"', " ").split():
        if raw.lower().startswith("v=spf1"):
            continue
        m = _TERM.match(raw)
        if not m:
            continue
        qualifier, kind, _sep, value = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
        out.append(Term(qualifier or "+", kind, (value or "").strip()))
    return out


def record_for(domain: str, resolve: Resolver) -> str:
    """The domain's ``v=spf1`` record, or "" when it publishes none."""
    return _record_and_answer(domain, resolve)[0]


def _record_and_answer(domain: str, resolve: Resolver) -> tuple[str, Answer]:
    answer = ask(resolve, domain, "TXT")
    for line in answer.records:
        joined = join_strings(line)
        if joined.lower().startswith("v=spf1"):
            return joined, answer
    return "", answer


def ask(resolve: Resolver, name: str, rtype: str) -> Answer:
    """Ask ``resolve``; a plain list of lines is wrapped as an unclassified Answer."""
    result = resolve(name, rtype)
    return result if isinstance(result, Answer) else Answer(list(result))


def join_strings(line: str) -> str:
    """Join a TXT record's quoted character strings, as RFC 7208 §3.3 requires."""
    strings = _TXT_STRING.findall(line)
    return ("".join(strings) if strings else line).strip()


def expand(domain: str, resolve: Resolver = dns_resolver) -> Surface:
    """Follow ``domain``'s SPF record through every reference it makes."""
    surface = Surface(domain=domain)
    seen: set[str] = set()
    record, answer = _record_and_answer(domain, resolve)
    _note_answer(surface, answer)
    surface.record = record
    if not record:
        surface.published = False
        return surface
    _walk(domain, record, surface, resolve, seen, depth=0)
    surface.hosts = list(dict.fromkeys(surface.hosts))
    surface.ranges = list(dict.fromkeys(surface.ranges))
    surface.ipv6_ranges = list(dict.fromkeys(surface.ipv6_ranges))
    surface.policies = list(dict.fromkeys(surface.policies))
    surface.unresolved = list(dict.fromkeys(surface.unresolved))
    surface.unexpandable = list(dict.fromkeys(surface.unexpandable))
    return surface


def _walk(current: str, record: str, surface: Surface, resolve: Resolver,
          seen: set[str], depth: int) -> None:
    surface.depth = max(surface.depth, depth)
    for term in parse(record):
        if term.kind in _COSTS_A_LOOKUP:
            surface.lookups += 1
        if term.kind == "all":
            # Only the top-level record's "all" decides what the domain denies.
            if depth == 0:
                surface.all_qualifier = f"{term.qualifier}all"
        elif term.kind in ("ip4", "ip6"):
            _add_range(surface, term.value)
        elif term.kind == "a":
            _add_host(surface, term.value or current, resolve, counts_as=_label(term, current))
        elif term.kind == "mx":
            for mx in _mx_hosts(term.value or current, resolve, surface, _label(term, current)):
                _add_host(surface, mx, resolve, counts_as=None)
        elif term.kind in ("include", "redirect"):
            _recurse(term.value, surface, resolve, seen, depth, _label(term, current))
        elif term.kind == "exp":
            continue
        else:
            label = f"{term.kind}:{term.value}" if term.value else term.kind
            surface.unexpandable.append(label if term.kind in _KNOWN
                                        else f"unknown mechanism {label}")


def _label(term: Term, current: str) -> str:
    return f"{term.kind}:{term.value}" if term.value else f"{term.kind} ({current})"


def _note_answer(surface: Surface, answer: Answer, counts_as: str | None = None) -> None:
    """Record how a lookup was answered; ``counts_as`` names the term it is charged to."""
    if answer.status != UNCLASSIFIED:
        surface.void_measured = True
    if answer.server and not surface.resolver:
        surface.resolver = answer.server
    if counts_as is None:
        return
    if answer.status == VOID:
        surface.void_lookups += 1
        surface.void_terms.append(counts_as)
    elif answer.status == INCONCLUSIVE:
        surface.inconclusive_lookups += 1
        surface.inconclusive_terms.append(counts_as)


def _recurse(target: str, surface: Surface, resolve: Resolver,
             seen: set[str], depth: int, counts_as: str | None = None) -> None:
    target = target.strip().rstrip(".").lower()
    if not target:
        return
    surface.policies.append(target)
    if target in seen:
        return
    seen.add(target)
    nested, answer = _record_and_answer(target, resolve)
    _note_answer(surface, answer, counts_as)
    if not nested:
        voided = answer.status == VOID
        surface.unresolved.append(
            f"{target} (policy published no SPF record"
            + (" — the DNS query returned nothing at all, a void lookup"
               if voided else "") + ")")
        return
    _walk(target, nested, surface, resolve, seen, depth + 1)


def _mx_hosts(domain: str, resolve: Resolver, surface: Surface | None = None,
              counts_as: str | None = None) -> list[str]:
    answer = ask(resolve, domain.strip().rstrip("."), "MX")
    if surface is not None:
        _note_answer(surface, answer, counts_as)
    out = []
    for line in answer.records:
        parts = line.split()
        if parts:
            out.append(parts[-1])
    return out


def _add_host(surface: Surface, host: str, resolve: Resolver,
              counts_as: str | None = None) -> None:
    host = host.split("/")[0].strip().rstrip(".").lower()
    if not host:
        return
    answer = ask(resolve, host, "A")
    if answer.records:
        _note_answer(surface, answer, counts_as)
        surface.hosts.append(host)
        return
    note = f"{host} (named by SPF, resolves to no address)"
    if counts_as is not None and answer.status == VOID:
        v6 = ask(resolve, host, "AAAA")
        if v6.records:
            counts_as += " — no A record; AAAA present, so this voids for an "\
                         "IPv4 evaluation and not an IPv6 one"
            note = f"{host} (named by SPF, has an IPv6 address but no IPv4 one)"
    _note_answer(surface, answer, counts_as)
    surface.unresolved.append(note)


def _add_range(surface: Surface, value: str) -> None:
    value = value.strip()
    if not value:
        return
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        surface.unexpandable.append(f"unparseable address term {value}")
        return
    if net.version == 6:
        surface.ipv6_ranges.append(str(net))
    else:
        surface.ranges.append(str(net))
