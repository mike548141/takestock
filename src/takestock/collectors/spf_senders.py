"""Who each domain's SPF record authorises to send mail, and the relays it names.

For every email domain the profile names, this collector expands the SPF
record through every ``include:``, ``redirect=``, ``a`` and ``mx`` term (see
:mod:`takestock.spf`) and writes one row describing the whole authorised
sending surface: named hosts, address ranges, the policies traversed, and
where the record stands against RFC 7208's two lookup limits.

With ``scan=True`` it also probes each named relay's STARTTLS on port 25,
using a probe function the caller supplies. Such a probe measures what the
relay accepts when it *receives*, never what it negotiates when it
*delivers*; the rows and gaps say so, because the two are easily confused.
Relays already declared as the organisation's inbound gateways
(``scan_targets.smtp_25``) are not probed again.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from .. import coverage, roles, spf
from ..coverage import Gap
from ..model import CryptoAsset
from ..util import now_date

SOURCE_NAME = "Public DNS — recursive SPF expansion"
SOURCE_PROBE = "Active STARTTLS scan (openssl) — relay named by an SPF record"
SOURCE_KEY = "spf_senders"

#: The profile key, under ``discovery``, listing the domains to expand.
TARGET_KEY = "email_domains"

#: The profile key, under ``scan_targets``, listing the declared inbound gateways.
GATEWAYS_KEY = "smtp_25"

#: Appended to every relay row, so the receiving reading is not mistaken for the sending one.
DIRECTION = ("a STARTTLS probe of this relay on 25/tcp measures what it ACCEPTS as a "
             "receiver, never what it negotiates when it DELIVERS to a recipient — the "
             "outbound half is not observable from outside and needs the sending "
             "platform's own transport report")

LOOKUP_LIMIT_FLAG = "spf-lookup-limit-exceeded"

LOOKUP_HEADROOM_FLAG = "spf-lookup-headroom-low"
#: Lookups left below which the headroom flag is raised.
LOOKUP_HEADROOM = 2

VOID_LIMIT_FLAG = "spf-void-lookup-limit-exceeded"
VOID_AT_LIMIT_FLAG = "spf-void-lookup-limit-reached"

#: Probes one relay: (host, role sentence) -> (row, failures). Supplied by the caller.
RelayProbe = Callable[[str, str], tuple[CryptoAsset, list[str]]]


def domains(target: dict) -> list[str]:
    """The email domains the profile names, de-duplicated."""
    declared = (target.get("discovery", {}) or {}).get(TARGET_KEY) or []
    return list(dict.fromkeys(str(d).strip() for d in declared if str(d).strip()))


def already_measured(target: dict) -> set[str]:
    """Hosts declared as inbound gateways, which another collector probes."""
    entries = (target.get("scan_targets", {}) or {}).get(GATEWAYS_KEY) or []
    out: set[str] = set()
    for entry in entries:
        host = (str((entry or {}).get("host") or "") if isinstance(entry, dict)
                else str(entry or "")).strip()
        if host:
            out.add(host)
    return out


def collect(target: dict, ref_time: datetime | None = None, scan: bool = False,
            resolve: spf.Resolver = spf.dns_resolver,
            probe: RelayProbe | None = None,
            carried: tuple[list[CryptoAsset], list[Gap]] | None = None,
            ) -> tuple[list[CryptoAsset], list[Gap]]:
    """Expand every email domain's SPF record; probe the named relays when ``scan``.

    ``carried`` is a previous run's relay rows and gaps, reused instead of
    probing again.
    """
    wanted = domains(target)
    if not wanted:
        return [], []
    surfaces = [spf.expand(d, resolve) for d in wanted]
    assets = [_surface_asset(s, ref_time) for s in surfaces]

    skip = already_measured(target)
    relays = _relays(surfaces, skip)
    gaps = coverage_gaps(surfaces, relays, skip, scan or carried is not None)
    if carried is not None:
        return assets + list(carried[0]), gaps + list(carried[1])
    if not scan:
        return assets, gaps
    if probe is None:
        gaps.append(no_probe_gap(len(relays)))
        return assets, gaps

    unreachable: list[str] = []
    for host, named_by in relays:
        asset, failures = probe(host, roles.spf_named_relay(host, named_by))
        asset.source, asset.source_name = SOURCE_KEY, SOURCE_PROBE
        asset.notes = "; ".join(b for b in [asset.notes, DIRECTION] if b)
        asset.extra["named_by_spf"] = ", ".join(named_by)
        assets.append(asset)
        if failures:
            unreachable.append(host)
    gaps += [unreachable_gap(h) for h in unreachable]
    return assets, gaps


def no_probe_gap(relays: int) -> Gap:
    """The gap recorded when probing was asked for and no probe was supplied."""
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"the {relays} SPF-named relay(s) were not probed: probing was requested and "
        "no STARTTLS probe was available to this collector",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("The servers allowed to send email for the organisation are listed "
                "but none was tested, so there is no evidence here about how they "
                "protect mail in transit."),
        harvest="Run again with a STARTTLS probe available.",
        nature=coverage.NO_DATA)


def unreachable_gap(host: str) -> Gap:
    """The gap recorded for one relay that did not answer."""
    return coverage.gap(
        coverage.COULD_NOT_TEST, _UNREACHABLE.format(host=host),
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("This machine is allowed to send email as this organisation and "
                "did not answer when its transport protection was checked. It may "
                "be perfectly configured; this run cannot say. Treat the "
                "email-encryption picture as covering the servers that did answer."),
        harvest=("A configuration statement from whoever runs this mail server, "
                 "usually the provider that sends on the organisation's behalf."),
        nature=coverage.NO_DATA)


_UNREACHABLE = (
    "SPF-named relay {host} did not answer on 25/tcp, so its STARTTLS posture is "
    "unmeasured. Not necessarily a fault: a host that only SENDS mail has no reason "
    "to accept it, and this tool cannot tell that case apart from a filtered port")


def _relays(surfaces: list[spf.Surface], skip: set[str]) -> list[tuple[str, list[str]]]:
    named_by: dict[str, list[str]] = {}
    for s in surfaces:
        for host in s.hosts:
            if host in skip:
                continue
            named_by.setdefault(host, []).append(s.domain)
    return list(named_by.items())


def _surface_asset(s: spf.Surface, ref_time: datetime | None) -> CryptoAsset:
    flags: list[str] = []
    if s.over_lookup_limit:
        flags.append(LOOKUP_LIMIT_FLAG)
    elif s.published and spf.LOOKUP_LIMIT - s.lookups <= LOOKUP_HEADROOM:
        flags.append(LOOKUP_HEADROOM_FLAG)
    if s.over_void_limit:
        flags.append(VOID_LIMIT_FLAG)
    elif s.at_void_limit:
        flags.append(VOID_AT_LIMIT_FLAG)
    return CryptoAsset(
        name=f"SPF sender surface {s.domain}",
        role=roles.email_record("spf-senders", s.domain),
        data_state="email-auth", protocol="spf-senders",
        host=s.domain, source=SOURCE_KEY, source_class="public",
        source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        flags=sorted(flags),
        notes=_surface_note(s, _read_at(ref_time)),
        extra={
            "all_qualifier": s.all_qualifier,
            "named_hosts": ", ".join(s.hosts),
            "named_host_count": len(s.hosts),
            "ipv4_range_count": len(s.ranges),
            "ipv4_address_count": s.addresses,
            "ipv6_range_count": len(s.ipv6_ranges),
            "policies_traversed": ", ".join(s.policies),
            "include_depth": s.depth,
            "dns_lookups": s.lookups,
            "dns_lookup_limit": spf.LOOKUP_LIMIT,
            **_void_fields(s, ref_time),
            **({"unresolved": "; ".join(s.unresolved)} if s.unresolved else {}),
            **({"unexpandable": "; ".join(s.unexpandable)} if s.unexpandable else {}),
        },
    )


def _read_at(ref_time: datetime | None) -> str:
    ref = ref_time or datetime.now(UTC)
    ref = ref.replace(tzinfo=UTC) if ref.tzinfo is None else ref.astimezone(UTC)
    return ref.strftime("%Y-%m-%dT%H:%M:%SZ")


def _void_fields(s: spf.Surface, ref_time: datetime | None) -> dict[str, object]:
    if not s.void_measured:
        return {"void_lookups_measured": False,
                "void_lookup_limit": spf.VOID_LOOKUP_LIMIT}
    read_at = _read_at(ref_time)
    return {
        "void_lookups_measured": True,
        "void_lookups": s.void_lookups,
        "void_lookup_limit": spf.VOID_LOOKUP_LIMIT,
        "dns_read_at": read_at,
        "dns_resolver": s.resolver or "unrecorded",
        **({"void_terms": "; ".join(s.void_terms)} if s.void_terms else {}),
        **({"inconclusive_lookups": s.inconclusive_lookups,
            "inconclusive_terms": "; ".join(s.inconclusive_terms)}
           if s.inconclusive_lookups else {}),
    }


def _surface_note(s: spf.Surface, read_at: str = "") -> str:
    if not s.published:
        return ("no SPF record published, so this domain authorises no sender and "
                "denies none either")
    bits = [
        f"authorises {len(s.hosts)} named host(s) and {len(s.ranges)} address range(s) "
        f"covering {s.addresses:,} IPv4 addresses",
    ]
    if s.ipv6_ranges:
        bits.append(f"plus {len(s.ipv6_ranges)} IPv6 range(s)")
    bits.append(f"through {len(s.policies)} policy domain(s), nested {s.depth} deep")
    bits.append(f"{s.lookups} of {spf.LOOKUP_LIMIT} permitted DNS lookups")
    bits.append(_void_note(s, read_at))
    bits.append(f"ends {s.all_qualifier or 'with no all mechanism'} — recorded, not graded")
    if s.unresolved:
        bits.append("; ".join(s.unresolved))
    return "; ".join(bits)


def _void_note(s: spf.Surface, read_at: str = "") -> str:
    if not s.void_measured:
        return (f"void lookups not measured (RFC 7208 §4.6.4 recommends at most "
                f"{spf.VOID_LOOKUP_LIMIT}): the resolver used reports no query status, "
                "and an empty answer alone cannot tell a void lookup from a resolver "
                "failure")
    where = f" by {s.resolver}" if s.resolver else ""
    when = f" at {read_at}" if read_at else " at the time of this observation"
    figure = (f"{s.void_lookups} void DNS lookup(s) as resolved{where}{when}, against "
              f"the {spf.VOID_LOOKUP_LIMIT} RFC 7208 §4.6.4 recommends at most")
    if s.void_terms:
        figure += f" — {'; '.join(s.void_terms)}"
    if s.over_void_limit:
        figure += ("; over the recommended ceiling, so an evaluator applying it returns "
                   "permerror for this record however few terms it spends")
    elif s.at_void_limit:
        figure += ("; at the recommended ceiling with no margin — legal today, and one "
                   "further term ceasing to resolve anywhere in the chain, including in "
                   "a policy somebody else publishes, makes it permerror")
    if s.inconclusive_lookups:
        figure += (f"; {s.inconclusive_lookups} further lookup(s) neither answered nor "
                   "came back empty, so this count is a floor")
    return figure


def coverage_gaps(surfaces: list[spf.Surface], relays: list[tuple[str, list[str]]],
                  skip: set[str], scan: bool) -> list[Gap]:
    """The limits of what the sender-surface reading can show."""
    range_list, addresses, ipv6_list, host_list = spf.combined(surfaces)
    ranges, ipv6, named = len(range_list), len(ipv6_list), len(host_list)
    gaps = [
        coverage.gap(coverage.COULD_NOT_TEST, (
            f"SPF authorises {ranges} distinct address range(s) covering {addresses:,} "
            f"IPv4 addresses (and {ipv6} IPv6 range(s)) across {len(surfaces)} domain(s), "
            "and a range names no host to connect to. Only the "
            f"{named} host(s) SPF names can be probed at all; the rest of the authorised "
            "sender surface is unmeasurable without an address sweep, which no clause of "
            "the target's authorisation permits"),
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("Where the sender policy authorises address ranges rather than "
                    "named servers, most of the machines allowed to send email in the "
                    "organisation's name cannot be checked. The email findings then "
                    "cover the named servers only, and the size of the permission is "
                    "itself worth reading."),
            harvest=("Narrowing the sender authorisation to named services is a "
                     "change to make, not data to collect."),
            nature=coverage.NO_DATA),
        coverage.gap(coverage.COULD_NOT_TEST, (
            "whether an outbound relay uses TLS when it DELIVERS is not observable from "
            "outside: a probe of 25/tcp measures the receiving side of the machine. The "
            "per-relay sending posture is therefore unmeasured, and an aggregate "
            "transport report cannot answer a per-path question. Nothing measured here "
            "describes the sending path at any level of detail — the inbound result is "
            "a different fact about the same machine, not a coarse version of this one"),
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("From outside, a mail server's receiving side can be seen and its "
                    "sending side cannot. So 'email is encrypted in transit' is "
                    "evidenced for the inbound direction and assumed for the outbound "
                    "one."),
            harvest=("The mail platform's own outbound transport report, exported by "
                     "its administrators."),
            nature=coverage.NO_DATA),
    ]
    if skip:
        gaps.append(coverage.gap(coverage.COULD_NOT_TEST, (
            f"{len(skip)} SPF-named host(s) are the declared inbound gateways and were "
            "not probed again here — their posture is the inbound gateway probe's row, "
            "and it is the receiving path rather than the sending one. That row is a "
            "full measurement of the inbound direction and no measurement at all of the "
            "outbound one"),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("These servers were measured once, as the route email comes IN "
                    "by, and are not measured again here as a route it goes OUT "
                    "by. Nothing is missing from the report, but it does not answer "
                    "the outbound question for them."),
            harvest="Covered by the outbound transport report named above.",
            nature=coverage.NO_DATA))
    if not scan:
        gaps.append(coverage.gap(coverage.COULD_NOT_TEST, (
            f"the {len(relays)} SPF-named relay(s) were not probed: this observation ran "
            "without --scan, so the sender surface is recorded and no handshake was "
            "attempted"),
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("This run recorded which servers may send email for the "
                    "organisation but did not test any of them, so there is no "
                    "evidence here about how that email is protected in transit. "
                    "The list is not a result."),
            harvest="Re-run with the live checks enabled.",
            nature=coverage.NO_DATA))
    return gaps
