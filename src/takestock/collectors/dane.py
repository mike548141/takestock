"""DANE for mail: does each mail server publish its certificate in DNS?

DANE for SMTP (RFC 7672) lets a domain publish, in a TLSA record at
``_25._tcp.<mail server>``, which certificate or key its mail server will
present. A delivering server that finds a DNSSEC-authenticated TLSA record
must then insist on TLS and on a matching certificate, instead of trusting
whatever any public certificate authority signed.

For every domain the profile names, this collector reads the MX records,
then each mail server's TLSA records through several resolvers, and records
which servers publish one, whether the answers were authenticated, and
whether the certificate usages are ones an SMTP client may use (only
DANE-TA and DANE-EE are; RFC 7672 §3.1.3).

New Zealand's Secure Government Email framework sets no DANE requirement,
and its MTA-STS guide states that "the use of DANE is not recommended at
this stage". So a domain without DANE is recorded as a fact, not graded as
a failing.
"""

from __future__ import annotations

import concurrent.futures as futures
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .. import dnsevidence, roles
from ..digresponse import Response, norm, parse, query
from ..model import CryptoAsset, register_informational_prefixes
from ..util import now_date
from .dnssec import domains as profile_domains

SOURCE_NAME = "Public DNS (MX and TLSA), read through validating public resolvers"

SMTP_PORT = 25
TRANSPORT = "tcp"

# Certificate usage -> (name, whether an SMTP client may use it).
USAGES: dict[int, tuple[str, bool]] = {
    0: ("PKIX-TA", False),
    1: ("PKIX-EE", False),
    2: ("DANE-TA", True),
    3: ("DANE-EE", True),
}

SELECTORS: dict[int, str] = {0: "full certificate", 1: "public key"}
MATCHING: dict[int, str] = {0: "exact match", 1: "SHA2-256", 2: "SHA2-512"}

WORKERS = dnsevidence.SWEEP_WORKERS

#: Why an absent TLSA record is a fact here rather than an unmet obligation.
FRAMEWORK_FORCE = (
    "the New Zealand Secure Government Email framework sets no DANE requirement, and its "
    "MTA-STS guide states that \"the use of DANE is not recommended at this stage\", so a "
    "domain with no record is a measured fact rather than an unmet obligation")

ABSENT = "dane-absent"
PUBLISHED = "dane-published"
UNAUTHENTICATED = "dane-unauthenticated"
MX_UNAUTHENTICATED = "dane-mx-unauthenticated"
NO_MX = "dane-no-mx"
UNREADABLE = "dane-unreadable"
DISAGREE = "dane-resolvers-disagree"
SERVERS_UNREADABLE = "dane-servers-unreadable:"
USAGE_NOT_APPLICABLE = "dane-usage-not-applicable:"

# Facts and limits of the reading. An unauthenticated MX answer is the DNSSEC
# collector's finding already, so it is not counted a second time here.
register_informational_prefixes(
    ABSENT, PUBLISHED, NO_MX, UNREADABLE, DISAGREE, MX_UNAUTHENTICATED, SERVERS_UNREADABLE,
)

#: Reads (name, record type, resolver) and returns dig's text.
Reader = Callable[[str, str, str], str]


def _live_reader(name: str, rtype: str, resolver: str) -> str:
    return query(name, rtype, resolver, dnssec=True)


def tlsa_name(mail_server: str) -> str:
    """Where a mail server's TLSA records live."""
    return f"_{SMTP_PORT}._{TRANSPORT}.{norm(mail_server)}"


def mail_servers(resp: Response) -> list[str]:
    """The MX hosts in a response, most preferred first, without duplicates."""
    rows: list[tuple[int, str]] = []
    for rr in resp.records("MX"):
        if len(rr.rdata) < 2:
            continue
        try:
            preference = int(rr.rdata[0])
        except ValueError:
            continue
        host = norm(rr.rdata[1])
        if host:
            rows.append((preference, host))
    return [h for _, h in sorted(dict.fromkeys(rows))]


@dataclass
class Association:
    """One TLSA record: usage, selector, matching type and association data."""

    usage: int
    selector: int
    matching: int
    association: str

    @property
    def usable_for_smtp(self) -> bool:
        return USAGES.get(self.usage, ("", False))[1]

    def as_dict(self) -> dict:
        usage_name = USAGES.get(self.usage, (f"usage {self.usage}", False))[0]
        return {"usage": self.usage, "usage_name": usage_name,
                "usable_for_smtp": self.usable_for_smtp,
                "selector": self.selector,
                "selector_name": SELECTORS.get(self.selector, f"selector {self.selector}"),
                "matching_type": self.matching,
                "matching_name": MATCHING.get(self.matching, f"matching type {self.matching}"),
                "association_hex_length": len(self.association)}


def associations(resp: Response) -> list[Association]:
    """The TLSA records in a response."""
    out: list[Association] = []
    for rr in resp.records("TLSA"):
        if len(rr.rdata) < 4:
            continue
        try:
            usage, selector, matching = (int(rr.rdata[0]), int(rr.rdata[1]), int(rr.rdata[2]))
        except ValueError:
            continue
        out.append(Association(usage, selector, matching,
                               "".join(rr.rdata[3:]).upper()))
    return out


@dataclass
class ServerReading:
    """One mail server's TLSA answers, keyed by the resolver asked."""

    server: str
    name: str
    by_resolver: dict[str, Response]

    @property
    def answered(self) -> bool:
        return any(r.answered for r in self.by_resolver.values())

    @property
    def primary(self) -> Response | None:
        return next((r for r in self.by_resolver.values() if r.answered), None)

    @property
    def records(self) -> list[Association]:
        resp = self.primary
        return associations(resp) if resp else []

    @property
    def published_by_resolver(self) -> dict[str, bool]:
        return {dnsevidence.resolver_label(r): bool(associations(resp))
                for r, resp in self.by_resolver.items() if resp.answered}

    @property
    def authenticated(self) -> bool:
        resp = self.primary
        return bool(resp and resp.authenticated)

    def as_dict(self) -> dict:
        resp = self.primary
        return {"server": self.server, "queried": self.name,
                "status": (resp.status if resp else "")
                          or next((r.error for r in self.by_resolver.values() if r.error), ""),
                "authenticated": self.authenticated,
                "records": [a.as_dict() for a in self.records],
                "published_by_resolver": self.published_by_resolver}


def domains(target: dict) -> list[str]:
    """The domains read: the same population as the DNSSEC collector's."""
    return profile_domains(target)


def evaluate(domain: str, mx_by_resolver: dict[str, Response],
             readings: list[ServerReading], now: datetime) -> CryptoAsset:
    """The DANE row for one domain."""
    mx_primary = next((r for r in mx_by_resolver.values() if r.answered), None)
    servers = mail_servers(mx_primary) if mx_primary else []
    mx_authenticated = bool(mx_primary and mx_primary.authenticated)

    publishing = [r for r in readings if r.records]
    unusable = [a for r in publishing for a in r.records if not a.usable_for_smtp]
    unauthenticated = [r for r in publishing if not r.authenticated]
    disagreed = [r for r in readings if len(set(r.published_by_resolver.values())) > 1]
    unread = [r for r in readings if not r.answered]

    flags: list[str] = []
    if mx_primary is None:
        flags.append(UNREADABLE)
    elif not servers:
        flags.append(NO_MX)
    elif not any(r.answered for r in readings):
        flags.append(UNREADABLE)
    elif publishing:
        flags.append(PUBLISHED)
        if unauthenticated:
            flags.append(UNAUTHENTICATED)
        if unusable:
            flags.append(f"{USAGE_NOT_APPLICABLE}{len(unusable)}")
        if not mx_authenticated:
            flags.append(MX_UNAUTHENTICATED)
    else:
        flags.append(ABSENT)
    if unread and any(r.answered for r in readings):
        flags.append(f"{SERVERS_UNREADABLE}{len(unread)}")
    if disagreed:
        flags.append(DISAGREE)

    if mx_primary is None:
        note = "no resolver answered the mail-routing question for this domain"
    elif not servers:
        note = ("this domain publishes no mail-routing (MX) record, so no mail is "
                "delivered to it and there is no mail server to vouch for")
    elif not any(r.answered for r in readings):
        note = (f"no resolver answered for any of the {len(servers)} mail server(s) this "
                "domain routes to")
    elif publishing:
        note = (f"{len(publishing)} of {len(servers)} mail server(s) publish a certificate "
                "record (TLSA) in DNS"
                + ("; one or more of those answers was not authenticated by the resolver, so "
                   "a delivering server will not use it" if unauthenticated else "")
                + (f"; {len(unusable)} record(s) use a certificate usage an SMTP client "
                   "must treat as unusable" if unusable else ""))
    else:
        note = (f"none of the {len(servers)} mail server(s) this domain routes to publishes a "
                "certificate record (TLSA) in DNS, so a delivering server has nothing to "
                "check the receiving server's certificate against beyond the public "
                "certificate authorities")
    if unread and any(r.answered for r in readings):
        note += (f"; {len(unread)} of those server(s) went unread, so this is not a complete "
                 "answer for the domain")
    note += f". Measured on the mail the domain RECEIVES; {FRAMEWORK_FORCE}"

    return CryptoAsset(
        name=f"DANE {domain}", role=roles.email_record("dane", domain),
        data_state="email-auth", protocol="dane", host=norm(domain), source="dane",
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(now),
        flags=sorted(set(flags)), notes=note,
        extra={
            "read_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mail_servers": servers,
            "mail_servers_count": len(servers),
            "mx_authenticated": mx_authenticated,
            "servers_publishing": len(publishing),
            "servers_unread": len(unread),
            "record_name_pattern": f"_{SMTP_PORT}._{TRANSPORT}.<mail server>",
            "servers": [r.as_dict() for r in readings],
        })


def collect(target: dict, ref_time: datetime | None = None,
            reader: Reader | None = None,
            resolvers: tuple[str, ...] | None = None,
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Read every profile domain's MX hosts and their TLSA records."""
    population = domains(target)
    if not population:
        return [], []
    if reader is None:
        if not shutil.which("dig"):
            return [], ["dane: dig is not on PATH, so no TLSA record was read"]
        reader = _live_reader
    if resolvers is None:
        resolvers = dnsevidence.resolvers(target)
    now = ref_time or datetime.now(UTC)
    read = reader

    mx: dict[str, dict[str, Response]] = {
        d: {r: parse(read(d, "MX", r)) for r in resolvers} for d in population}

    questions: list[tuple[str, str, str]] = []
    for d in population:
        primary = next((r for r in mx[d].values() if r.answered), None)
        for server in (mail_servers(primary) if primary else []):
            for r in resolvers:
                questions.append((d, server, r))
    with futures.ThreadPoolExecutor(WORKERS) as pool:
        answers = list(pool.map(
            lambda q: parse(read(tlsa_name(q[1]), "TLSA", q[2])), questions))

    by_domain: dict[str, dict[str, dict[str, Response]]] = {d: {} for d in population}
    for (d, server, resolver), resp in zip(questions, answers, strict=True):
        by_domain[d].setdefault(server, {})[resolver] = resp

    assets = []
    for d in population:
        readings = [ServerReading(server=s, name=tlsa_name(s), by_resolver=v)
                    for s, v in by_domain[d].items()]
        assets.append(evaluate(d, mx[d], readings, now))
    failures = []
    if all(UNREADABLE in a.flags for a in assets):
        failures.append("dane: no resolver answered for any domain, so this run holds no "
                        "evidence about DANE either way")
    return assets, failures


__all__ = ["Association", "ServerReading", "associations", "collect", "domains",
           "evaluate", "mail_servers", "tlsa_name"]
