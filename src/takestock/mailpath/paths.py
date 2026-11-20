"""Group messages into flows: one direction, one sending domain, one route.

A *route* is the list of systems a message crossed, origin first, with hops
inside one system folded together (a platform's internal relays are one
station). The transport on each crossing between two systems is kept per
crossing, because that is the leg an organisation can act on: its own
relay to its gateway, its gateway to the recipient.

**Direction** is judged from the organisation's own domains (subdomains
included): its domain to its domain is *internal*, its domain to anyone else
is *outbound*, anyone else to its domain is *inbound*. A message that
involves none of its domains is not part of its picture and is left out.

A flow keeps counts and sizes, never an address: who wrote to whom is not
the finding; which route carried how much, how protected, is.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .headers import TLS_NONE, Message

INBOUND = "inbound"
OUTBOUND = "outbound"
INTERNAL = "internal"
SENT_COPY = "sent copy"
DIRECTIONS = (OUTBOUND, INTERNAL, INBOUND, SENT_COPY)

# Weakest first: used to state the weakest transport a crossing carried.
TLS_ORDER = ["none", "SSLv3", "TLS 1.0", "TLS 1.1", "not recorded", "TLS (version not recorded)",
             "web or API submission", "TLS 1.2", "TLS 1.3"]


def owns(domain: str, owned: set[str]) -> bool:
    d = domain.lower().rstrip(".")
    return bool(d) and any(d == o or d.endswith("." + o) for o in owned)


def owning(domain: str, owned: set[str]) -> str:
    d = domain.lower().rstrip(".")
    return next((o for o in sorted(owned, key=len, reverse=True) if d == o or d.endswith("." + o)), "")


def author_domain(msg: Message) -> str:
    """The From domain, or the original one when a list or group rewrote it."""
    if msg.original_from_domain and msg.original_from_domain != msg.from_domain:
        return msg.original_from_domain
    return msg.from_domain


def direction(msg: Message, owned: set[str]) -> str | None:
    """outbound, internal, inbound, "sent copy" (the sender's own copy, which records
    how a message entered the platform but not how it was delivered), or None."""
    sender = owns(author_domain(msg), owned)
    if sender and "SENT" in msg.labels and "INBOX" not in msg.labels:
        return SENT_COPY
    recipient = owns(msg.recipient_domain, owned)
    if sender and recipient:
        return INTERNAL
    if sender:
        return OUTBOUND
    if recipient:
        return INBOUND
    return None


@dataclass
class Leg:
    """A crossing from one system to the next, and the transport each message used."""

    tls: Counter = field(default_factory=Counter)
    ciphers: Counter = field(default_factory=Counter)
    plain_keyword: int = 0

    @property
    def weakest(self) -> str:
        seen = [t for t in TLS_ORDER if self.tls.get(t)]
        return seen[0] if seen else "not recorded"


def stations(msg: Message) -> tuple[list[str], list[tuple[str, str, bool]]]:
    """(systems in order, [(tls, cipher, plain keyword)] for each crossing between them)."""
    out: list[str] = []
    legs: list[tuple[str, str, bool]] = []
    for hp in msg.hops:
        src = hp.from_system or hp.by_system
        if not out and src:
            out.append(src)
        dst = hp.by_system or src
        if out and dst and dst != out[-1]:
            out.append(dst)
            legs.append((hp.tls, hp.cipher, hp.plain_keyword))
    return out, legs


@dataclass
class Flow:
    direction: str
    domain: str                       # the organisation's domain this flow belongs to
    sender_domain: str
    route: tuple[str, ...]
    messages: int = 0
    sized: int = 0
    bytes: int = 0
    first: str = ""
    last: str = ""
    legs: list[Leg] = field(default_factory=list)
    spf: Counter = field(default_factory=Counter)
    dkim: Counter = field(default_factory=Counter)
    dkim_aligned: int = 0
    dmarc: Counter = field(default_factory=Counter)
    signatures: Counter = field(default_factory=Counter)
    generators: Counter = field(default_factory=Counter)
    submissions: Counter = field(default_factory=Counter)
    kinds: Counter = field(default_factory=Counter)
    protection: Counter = field(default_factory=Counter)
    markings: Counter = field(default_factory=Counter)
    labels: Counter = field(default_factory=Counter)
    receivers: Counter = field(default_factory=Counter)
    internal_origin: int = 0
    rewritten: int = 0

    def add(self, msg: Message, legs: list[tuple[str, str, bool]]) -> None:
        self.messages += 1
        if msg.size is not None:
            self.sized += 1
            self.bytes += msg.size
        if msg.date:
            self.first = min(self.first or msg.date, msg.date)
            self.last = max(self.last, msg.date)
        while len(self.legs) < len(legs):
            self.legs.append(Leg())
        for leg, (tls, cipher, plain) in zip(self.legs, legs, strict=False):
            leg.tls[tls] += 1
            leg.plain_keyword += int(plain)
            if cipher:
                leg.ciphers[cipher] += 1
        a = msg.results
        self.spf[a.spf or "no result"] += 1
        best = "pass" if "pass" in a.dkim else (a.dkim[0] if a.dkim else "no result")
        self.dkim[best] += 1
        if any(r == "pass" and (d == msg.from_domain or msg.from_domain.endswith("." + d)
                                or d.endswith("." + msg.from_domain))
               for r, d in zip(a.dkim, a.dkim_domains, strict=False)):
            self.dkim_aligned += 1
        self.dmarc[a.dmarc or "no result"] += 1
        for s in msg.signatures:
            self.signatures[f"{s.domain} · {s.selector} · {s.algorithm}"] += 1
        for g in msg.generators or ["not identified"]:
            self.generators[g] += 1
        self.submissions[msg.submission or "not recorded"] += 1
        self.kinds[msg.auto or "person-to-person or unmarked"] += 1
        self.protection[msg.protection] += 1
        if msg.marking:
            self.markings[msg.marking] += 1
        for lab in msg.sensitivity_labels:
            self.labels[lab] += 1
        if msg.recipient_domain:
            self.receivers[msg.recipient_domain] += 1
        if author_domain(msg) != msg.from_domain:
            self.rewritten += 1
        if msg.hops and msg.hops[0].from_system.startswith("internal host"):
            self.internal_origin += 1

    def as_dict(self) -> dict:
        return {
            "direction": self.direction, "domain": self.domain, "sender_domain": self.sender_domain,
            "route": list(self.route), "messages": self.messages,
            "messages_with_size": self.sized, "bytes": self.bytes,
            "first": self.first, "last": self.last,
            "legs": [{"from": self.route[i], "to": self.route[i + 1], "weakest": leg.weakest,
                      "tls": dict(leg.tls), "ciphers": dict(leg.ciphers),
                      "esmtp_without_tls_claim": leg.plain_keyword}
                     for i, leg in enumerate(self.legs) if i + 1 < len(self.route)],
            "spf": dict(self.spf), "dkim": dict(self.dkim), "dkim_aligned_pass": self.dkim_aligned,
            "dmarc": dict(self.dmarc), "signatures": dict(self.signatures),
            "generators": dict(self.generators.most_common()),
            "submission": dict(self.submissions.most_common()),
            "kinds": dict(self.kinds), "content_protection": dict(self.protection),
            "markings": dict(self.markings), "sensitivity_labels": dict(self.labels),
            "receiver_domains": len(self.receivers), "internal_origin": self.internal_origin,
            "from_rewritten_by_list": self.rewritten,
        }


def flows(messages: list[Message], owned: set[str]) -> list[Flow]:
    """Every flow the messages make for an organisation owning ``owned``."""
    found: dict[tuple, Flow] = {}
    for msg in messages:
        d = direction(msg, owned)
        if d is None:
            continue
        route, legs = stations(msg)
        if not route:
            continue
        author = author_domain(msg)
        mine = owning(msg.recipient_domain if d == INBOUND else author, owned)
        key = (d, mine, author, tuple(route))
        if key not in found:
            found[key] = Flow(d, mine, author, tuple(route))
        found[key].add(msg, legs)
    return sorted(found.values(), key=lambda f: (DIRECTIONS.index(f.direction), -f.messages))


def cleartext_crossings(flow: Flow) -> int:
    return sum(leg.tls.get(TLS_NONE, 0) for leg in flow.legs)
