"""CAA: which certificate authorities each domain allows, against the certificates it holds.

A CAA record (RFC 8659) names the certificate authorities permitted to issue
certificates for a domain; an authority must check it at issuance. This
collector reads each domain's CAA record set through several resolvers and
records what it allows, whether wildcards follow the same list, whether a
reporting address (``iodef``) is published, and whether issuance is bound to
an account (``accounturi``, RFC 8657).

It then compares today's record with the certificates the
certificate-transparency read found. For each certificate it finds the
record set that governs that name (the "relevant" set, found by climbing from
the name towards the root) and asks whether the certificate's issuer is on
it. Issuer names are mapped to the CAA identifiers authorities publish using
``caa_issuers`` in ``data/dns-services.yaml``; an issuer missing from that map
is reported as unmapped, never as unauthorised. DNS keeps no history, so a
certificate issued before the record changed can disagree with it honestly.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import shutil
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .. import ctcache, dnsevidence, roles
from ..digresponse import Response, norm, parse, query
from ..model import CryptoAsset, register_informational_prefixes
from ..util import now_date
from .dnssec import domains as profile_domains

SOURCE_NAME = "Public DNS (CAA), compared with the Certificate Transparency read"

#: CAA property tags RFC 8659 and its extensions define.
KNOWN_TAGS = {"issue", "issuewild", "iodef", "contactemail", "contactphone",
              "issuemail", "issuevmc"}

WORKERS = dnsevidence.SWEEP_WORKERS

# Limits of the reading, and hardenings no standard obliges a domain holder to
# adopt. A missing record, an unauthorised issuer and a critical unknown tag
# stay adverse.
register_informational_prefixes(
    "caa-unreadable", "caa-issuer-unmapped:", "caa-names-unreadable:",
    "caa-resolvers-disagree", "caa-names-own-set:", "caa-no-iodef",
    "caa-wildcard-follows-issue", "caa-no-account-binding",
)

#: Reads (name, resolver) and returns dig's text for a CAA query.
Reader = Callable[[str, str], str]


def _live_reader(name: str, resolver: str) -> str:
    return query(name, "CAA", resolver)


@dataclass
class Property:
    """One CAA property: flags byte, tag and value."""

    flags: int
    tag: str
    value: str

    @property
    def issuer_domain(self) -> str:
        """The issuer identifier an ``issue``/``issuewild`` value names (before any ``;``)."""
        return self.value.split(";", 1)[0].strip().lower()

    @property
    def parameters(self) -> dict[str, str]:
        """The ``key=value`` parameters after the issuer identifier."""
        out = {}
        for part in self.value.split(";")[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip().lower()] = v.strip()
        return out

    def as_dict(self) -> dict:
        return {"flags": self.flags, "tag": self.tag, "value": self.value}


def properties(resp: Response) -> list[Property]:
    """The CAA properties in a response's answer section."""
    out = []
    for rr in resp.records("CAA"):
        if len(rr.rdata) < 3:
            continue
        try:
            flag_byte = int(rr.rdata[0])
        except ValueError:
            continue
        value = " ".join(rr.rdata[2:])
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        out.append(Property(flag_byte, rr.rdata[1].lower(), value))
    return out


@dataclass
class Relevant:
    """The record set governing one name, and the names asked on the way to it."""

    name: str
    found_at: str = ""
    owner: str = ""
    props: list[Property] = field(default_factory=list)
    path: list[dict] = field(default_factory=list)
    error: str = ""


def climb(name: str, reader: Reader, resolver: str,
          cache: dict[str, Response] | None = None) -> Relevant:
    """Find the CAA record set that governs ``name`` (RFC 8659 §3).

    Asks ``name``, then its parent, and so on towards the root, stopping at
    the first non-empty set. An alias is followed by the resolver, so the
    owner the answer names may differ from the name asked.
    """
    cache = {} if cache is None else cache
    labels = norm(name).removeprefix("*.").split(".")
    out = Relevant(name=norm(name))
    for i in range(len(labels)):
        current = ".".join(labels[i:])
        if current not in cache:
            cache[current] = parse(reader(current, resolver))
        resp = cache[current]
        aliases = [" ".join(rr.rdata) for rr in resp.records("CNAME")]
        out.path.append({"name": current, "status": resp.status or resp.error,
                         "aliases": aliases})
        if resp.error or resp.status not in ("NOERROR", "NXDOMAIN"):
            out.error = f"{current}: {resp.error or resp.status}"
            return out
        props = properties(resp)
        if props:
            owners = [norm(rr.owner) for rr in resp.records("CAA")]
            out.found_at, out.props, out.owner = current, props, owners[0]
            return out
    return out


def authorised(props: list[Property], wildcard: bool) -> tuple[bool, set[str]]:
    """(whether the set restricts issuance, the issuer identifiers it allows).

    For a wildcard name ``issuewild`` governs when present, else ``issue``.
    """
    issue = [p for p in props if p.tag == "issue"]
    wild = [p for p in props if p.tag == "issuewild"]
    governing = wild if (wildcard and wild) else issue
    if not governing:
        return False, set()
    return True, {p.issuer_domain for p in governing if p.issuer_domain}


def issuer_domains(issuer: str, issuer_map: Mapping[str, Iterable[str]]) -> tuple[str, ...]:
    """The CAA identifiers an issuer publishes, from ``issuer_map``; () when unmapped."""
    return tuple(issuer_map.get((issuer or "").strip().lower(), ()) or ())


def certificates_under(domain: str, certificates: Iterable[CryptoAsset]) -> list[CryptoAsset]:
    """Certificate rows for ``domain`` or a name beneath it that record their issuer."""
    d = norm(domain)
    return [c for c in certificates
            if c.data_state == "certificate" and c.host
            and (norm(c.host).removeprefix("*.") == d or norm(c.host).endswith("." + d))
            and (c.extra or {}).get("issuer")]


def evaluate(domain: str, apex_by_resolver: dict[str, Response],
             certificates: list[CryptoAsset], relevant: dict[str, Relevant],
             now: datetime,
             issuer_map: Mapping[str, Iterable[str]] | None = None) -> CryptoAsset:
    """The CAA row for one domain, from its apex readings and the certificates beneath it."""
    issuer_map = issuer_map or {}
    readings = {r: sorted((p.flags, p.tag, p.value) for p in properties(resp))
                for r, resp in apex_by_resolver.items() if resp.answered}
    distinct = {tuple(v) for v in readings.values()}
    primary = next((r for r, resp in apex_by_resolver.items() if resp.answered), "")
    answered = any(resp.answered for resp in apex_by_resolver.values())
    props = properties(apex_by_resolver[primary]) if answered else []
    restricts, allowed = authorised(props, wildcard=False)
    wild_restricts, wild_allowed = authorised(props, wildcard=True)
    iodef = [p.value for p in props if p.tag == "iodef"]

    flags: list[str] = []
    if not answered:
        flags.append("caa-unreadable")
    elif not props:
        flags.append("caa-absent")
    if restricts:
        flags.append("issuance-locked")
    if props and not iodef:
        flags.append("caa-no-iodef")
    if restricts and not any(p.tag == "issuewild" for p in props):
        flags.append("caa-wildcard-follows-issue")
    if restricts and not any("accounturi" in p.parameters for p in props
                             if p.tag in ("issue", "issuewild")):
        flags.append("caa-no-account-binding")
    # The critical bit (128) on a tag the authority does not understand forbids issuance.
    if any(p.flags & 128 and p.tag not in KNOWN_TAGS for p in props):
        flags.append("caa-critical-unknown-tag")
    if len(distinct) > 1:
        flags.append("caa-resolvers-disagree")

    consistent: list[str] = []
    not_authorised: list[dict] = []
    unmapped: list[dict] = []
    unreadable: list[str] = []
    own_set: list[dict] = []
    for cert in certificates:
        host = norm(cert.host)
        rel = relevant.get(host.removeprefix("*."))
        issuer = cert.extra.get("issuer", "")
        row = {"host": host, "issuer": issuer,
               "not_before": cert.extra.get("not_before", "")}
        if rel is None or rel.error:
            unreadable.append(host)
            continue
        if rel.owner and rel.owner != norm(domain):
            own_set.append({"host": host, "governed_by": rel.owner,
                            "found_by_asking": rel.found_at})
        cert_restricts, cert_allowed = authorised(rel.props, host.startswith("*."))
        if not cert_restricts:
            consistent.append(host)
            continue
        known = issuer_domains(issuer, issuer_map)
        if not known:
            unmapped.append(row)
        elif set(known) & cert_allowed:
            consistent.append(host)
        else:
            not_authorised.append({**row, "authorised": sorted(cert_allowed)})
    if not_authorised:
        flags.append(f"caa-issuer-not-authorised:{len(not_authorised)}")
    if unmapped:
        flags.append(f"caa-issuer-unmapped:{len(unmapped)}")
    if own_set:
        flags.append(f"caa-names-own-set:{len(own_set)}")
    if unreadable:
        flags.append(f"caa-names-unreadable:{len(unreadable)}")

    issued = sorted(c.extra.get("not_before", "") for c in certificates
                    if c.extra.get("not_before"))
    checked = len(certificates) - len(unreadable)
    if not answered:
        note = "no resolver answered the CAA question"
    elif not props:
        note = "no CAA record: any publicly trusted certificate authority may issue"
    else:
        note = (f"authorised issuers: {', '.join(sorted(allowed)) or 'none'}; "
                f"{len(consistent)} of {checked} certificates in the Certificate "
                "Transparency read came from an authorised issuer"
                + (f", {len(not_authorised)} did not" if not_authorised else "")
                + (f", {len(unmapped)} from an issuer this check cannot map"
                   if unmapped else "")
                + ("; no reporting address (iodef)" if not iodef else "")
                + ("; wildcard certificates follow the same list"
                   if "caa-wildcard-follows-issue" in flags else ""))
    note += (". CAA is checked by the issuing authority at issuance only, and DNS "
             "keeps no history of the record, so this compares today's record with "
             "certificates issued earlier")

    return CryptoAsset(
        name=f"CAA {domain}", role=roles.email_record("caa", domain),
        data_state="email-auth", protocol="caa", host=norm(domain), source="caa",
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(now),
        flags=sorted(set(flags)), notes=note,
        extra={
            "read_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "records": [p.as_dict() for p in props],
            "records_by_resolver": {dnsevidence.resolver_label(r): [list(t) for t in v]
                                    for r, v in readings.items()},
            "authorised_issue": sorted(allowed),
            "authorised_issuewild": sorted(wild_allowed) if wild_restricts else [],
            "iodef": iodef,
            "certificates_checked": checked,
            "wildcard_certificates_checked": sum(
                1 for c in certificates if norm(c.host).startswith("*.")),
            "certificates_consistent": len(consistent),
            "certificates_not_authorised": not_authorised,
            "certificates_issuer_unmapped": unmapped,
            "names_with_own_set": own_set,
            "names_unreadable": unreadable,
            "issued_between": [issued[0], issued[-1]] if issued else [],
        })


def wildcard_certificates(raw_dir: Path | None, domains: Iterable[str]) -> list[CryptoAsset]:
    """Wildcard certificates from the raw transparency answers, as minimal certificate rows.

    The ``ct_dns`` collector folds ``*.name`` into ``name``; CAA treats a
    wildcard differently (``issuewild``), so the raw answers are re-read here.
    """
    if raw_dir is None:
        return []
    out: dict[tuple[str, str, str], CryptoAsset] = {}
    for domain in domains:
        path = raw_dir / ctcache.raw_name(domain)
        try:
            records = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        for rec in records if isinstance(records, list) else []:
            issuer_obj = rec.get("issuer") or {}
            issuer = issuer_obj.get("friendly_name") or issuer_obj.get("name", "")
            nb = rec.get("not_before", "")
            for name in rec.get("dns_names", []) or []:
                n = norm(str(name))
                if not n.startswith("*.") or not (n == "*." + domain or n.endswith("." + domain)):
                    continue
                out.setdefault((n, issuer, nb), CryptoAsset(
                    name=f"certificate {n}", data_state="certificate", protocol="tls",
                    host=n, source="ct_dns",
                    extra={"issuer": issuer, "not_before": nb, "wildcard_from_ct_read": True}))
    return list(out.values())


def collect(target: dict, certificates: Iterable[CryptoAsset],
            ref_time: datetime | None = None, reader: Reader | None = None,
            resolvers: tuple[str, ...] | None = None,
            raw_dir: Path | None = None,
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Read each profile domain's CAA set and compare it with ``certificates``."""
    population = profile_domains(target)
    if not population:
        return [], []
    if reader is None:
        if not shutil.which("dig"):
            return [], ["caa: dig is not on PATH, so no CAA record was read"]
        reader = _live_reader
    if resolvers is None:
        resolvers = dnsevidence.resolvers(target)
    issuer_map = dnsevidence.services(target).get("caa_issuers") or {}
    now = ref_time or datetime.now(UTC)
    certs = list(certificates) + wildcard_certificates(raw_dir, population)
    primary = resolvers[0]
    cache: dict[str, Response] = {}

    names = sorted({norm(c.host).removeprefix("*.") for d in population
                    for c in certificates_under(d, certs)})
    with futures.ThreadPoolExecutor(WORKERS) as pool:
        climbed = dict(zip(names, pool.map(lambda n: climb(n, reader, primary, cache), names),
                           strict=True))

    assets = []
    for d in population:
        apex = {r: parse(reader(d, r)) for r in resolvers}
        assets.append(evaluate(d, apex, certificates_under(d, certs), climbed, now,
                               issuer_map))
    failures = []
    if all("caa-unreadable" in a.flags for a in assets):
        failures.append("caa: no resolver answered for any domain")
    return assets, failures
