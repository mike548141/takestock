"""Grade mail-authentication readings against Secure Government Email.

New Zealand's Secure Government Email (SGE) Common Implementation Framework
sets requirements for agencies' email domains: SPF ending in ``-all``, DMARC
at ``p=reject``, MTA-STS in enforce mode, TLS Reporting, a TLS 1.2 floor,
denying records on names that send no mail, and more. The requirement set,
with each deciding sentence quoted, is ``data/secure-government-email.yaml``.

:func:`evaluate` reads a run's rows (from ``ct_dns``, ``spf_senders`` and,
where supplied, a mail-host TLS probe and a per-message mail transport
export) and returns one :class:`Conformance` row per requirement and subject:
``pass``, ``fail`` or ``not-measured``. Not measured is a first-class result
with a reason: nothing outside the organisation can see it
(``no-instrument``), nothing reads it yet (``not-collected``), or the check
ran and could not settle it (``inconclusive``). A reading that can only ever
find a breach (a sweep over an incomplete list of names, say) reports a
failure when it finds one and stays unmeasured otherwise; it never claims
conformance it cannot show.

:func:`apply_conformance` marks the rows behind each unmet *must* with the
requirement, so a reader of the asset sees the standard beside the grade.

**Parked domains.** A domain the profile lists under ``discovery.domains``
and not ``discovery.email_domains`` sends and receives no mail
(:func:`parked_domains`). The framework's rules for domains that send no mail
apply to it: the blank SPF record ``v=spf1 -all``, the empty DKIM key
``v=DKIM1; p=`` and a ``p=reject`` DMARC policy (with no ``sp=`` or ``np=``
weaker than reject), all stated as must. :func:`evaluate` reads each parked
domain against those requirements, on its own records, in rows marked ``parked``. The names
beneath a parked domain are swept and read as an email domain's sub-domains
are, in rows marked ``parked`` whose subject is
:func:`parked_subdomains_subject`; like every sweep row, they can find a breach
and show conformance only over a population known to be complete (below).
Whether a parked domain publishes a null MX (RFC 7505) is not a framework
requirement; it is reported beside them in
:attr:`Report.parked`, with the guidance that recommends it.

**Discovered sub-domains that handle mail.** The sub-domain sweep sets aside
the names that show signs of sending or receiving mail. Those are email domains
to a receiver, so :func:`evaluate` reads them against the rules for email
domains, in rows marked ``discovered`` whose subject is
:func:`discovered_mail_subject`: SGE-SPF-01; SGE-DMARC-01, SGE-DMARC-04,
SGE-DMARC-R02, SGE-DMARC-R03 and SGE-DMARC-R05 (a name with no DMARC record of
its own takes the record RFC 9989 policy discovery finds, :func:`policy_record`,
and its ``sp=``, ``np=`` or ``p=``); SGE-MTASTS-01 and SGE-MTASTS-02 (the
``_mta-sts`` record and the policy file, RFC 8461); SGE-TLSRPT-01 (the
``_smtp._tls`` record, RFC 8460); and SGE-DKIM-R01 and SGE-DKIM-R02 (the keys
under the selectors tried, RFC 6376; with no key found, the name is counted
neither way). These rows can fail and never pass, even on an attested-complete
zone file, because which names send mail is judged from DNS signals a sending
name need not publish (:data:`_MAIL_POPULATION`).

**Which names the sweep reads, and when a sweep may pass.** The sweep reads
every name the observation knows beneath a domain: certificate transparency,
the owner names in supplied zone files, the profile's domain lists and scan
targets, and the names sender policies point at, each kept with its source.
Those are a floor, so a sweep row can fail and otherwise stays not measured.
Where the target profile attests a domain's zone file complete
(``dns_zones.complete_zones``), and every name was read, settled and agreed
with the file, the rows for names that send no mail may pass, and say on what
attestation (:func:`_whole_population`). The mail-handling rows stay fail-only
(above).

**Sub-domains that do not exist.** RFC 9989 (DMARC, which obsoletes RFC 7489)
adds the ``np=`` tag, the policy for non-existent sub-domains. Wherever a
root's DMARC record is read for the names beneath it, an ``np=`` weaker than
``reject`` fails the row (:func:`_np_weaker_than_reject`).

Run as ``python -m takestock.sge <target>`` for a text report.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config, dnsevidence
from .exits import guarded
from .plaintext import PLAINTEXT_FLAG

PASS = "pass"
FAIL = "fail"
NOT_MEASURED = "not-measured"

# Why a row is not measured.
NO_INSTRUMENT = "no-instrument"
NOT_COLLECTED = "not-collected"
INCONCLUSIVE = "inconclusive"

UNMEASURED_LABEL = {
    NO_INSTRUMENT: "nothing outside the organisation can see this",
    NOT_COLLECTED: "visible from outside, but nothing reads it yet",
    INCONCLUSIVE: "the check ran and could not settle it",
}


@dataclass
class Conformance:
    """One requirement read against one subject (a domain, a host, or the organisation)."""

    requirement: str
    title: str
    level: str
    scope: str
    subject: str
    status: str
    observed: str = ""
    reason: str = ""
    evidence: str = ""
    source: str = ""
    citation: str = ""
    record: str = ""
    subject_note: str = ""
    #: True for a reading of a parked domain (see :func:`parked_domains`).
    parked: bool = False
    #: True for a reading of sub-domains the sweep found, not domains the profile names.
    discovered: bool = False

    @property
    def breaches_must(self) -> bool:
        """True for a failed requirement the standard states as must."""
        return self.status == FAIL and self.level == "must"


#: Why a parked domain's null MX is read, and at what force. It is not a
#: framework requirement, so it never counts as a breach.
NULL_MX_GUIDANCE = (
    "Not a Secure Government Email requirement. RFC 7505 §3 defines the null MX "
    "(an MX record of \"0 .\") as the way a domain says it accepts no mail. The M3AAWG "
    "Protecting Parked Domains Best Common Practices (December 2015) call it \"the "
    "recommended way to indicate that a domain is not meant to receive email\", and the "
    "UK NCSC's Protecting parked domains guidance says a domain with an address record "
    "but no MX records \"should create a null MX record\"."
)

#: Null MX states, as read by :func:`takestock.collectors.ct_dns.parked_assets`.
NULL_MX_STATES = {
    "published": "null MX published",
    "alongside-other-mx": "null MX published beside other MX records",
    "mail-exchangers": "MX records naming mail servers; no null MX",
    "no-mx": "no MX record and no null MX",
}

PARKED_NOTE = ("parked domain: listed under discovery.domains and not under "
               "discovery.email_domains, so read as a domain that sends and receives no mail")


@dataclass
class ParkedDomain:
    """One parked domain's null MX reading, which no framework requirement grades."""

    domain: str
    null_mx: str = ""
    observed: str = ""
    records: list[str] = field(default_factory=list)
    evidence: str = ""

    @property
    def published(self) -> bool:
        return self.null_mx == "published"


@dataclass
class Report:
    """Every conformance row, and the standard's own description."""

    rows: list[Conformance] = field(default_factory=list)
    standard: dict[str, Any] = field(default_factory=dict)
    #: Each parked domain read, with its null MX reading.
    parked: list[ParkedDomain] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {PASS: 0, FAIL: 0, NOT_MEASURED: 0}
        for r in self.rows:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def breaches(self) -> list[Conformance]:
        return [r for r in self.rows if r.breaches_must]

    def unmeasured_reasons(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.rows:
            if r.status == NOT_MEASURED:
                out[r.reason] = out.get(r.reason, 0) + 1
        return out


def load_standard(path: str | None = None) -> dict:
    """The requirement set: the workspace's copy if present, else the bundled one."""
    p = config.data_file("secure-government-email.yaml") if path is None else path
    return _isoformat_dates(config.load_yaml_strict(Path(p)))


def _isoformat_dates(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _isoformat_dates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_isoformat_dates(v) for v in value]
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    return value


def _get(asset: Any, key: str, default: Any = None) -> Any:
    if isinstance(asset, dict):
        return asset.get(key, default)
    return getattr(asset, key, default)


def _set(asset: Any, key: str, value: Any) -> None:
    if isinstance(asset, dict):
        asset[key] = value
    else:
        setattr(asset, key, value)


def _by(assets: list[Any], protocol: str, host: str | None = None) -> list[Any]:
    out = [a for a in assets if _get(a, "protocol") == protocol]
    if host is not None:
        out = [a for a in out if _get(a, "host") == host]
    return out


def _version_rank(v: str) -> tuple[int, int] | None:
    m = re.match(r"^\s*(tls|ssl)v?\s*([0-9]+)(?:[._]([0-9]+))?\s*$", v.strip().lower())
    if not m:
        return None
    family, major, minor = m.group(1), int(m.group(2)), int(m.group(3) or 0)
    return (0 if family == "ssl" else 1, major * 100 + minor)


def _floor_met(versions: list[str], minimum: str) -> tuple[bool, list[str]]:
    floor = _version_rank(minimum)
    if floor is None:                        # pragma: no cover — data would be wrong
        return True, []
    unorderable = [v for v in versions if _version_rank(v) is None]
    ranked = [r for r in (_version_rank(v) for v in versions) if r is not None]
    return any(r >= floor for r in ranked), unorderable


def _version_ok(versions: list[str], forbidden: list[str]) -> tuple[bool, list[str]]:
    def norm(v: str) -> str:
        return re.sub(r"^(tls|ssl)v", r"\1", re.sub(r"[^a-z0-9]", "", v.lower()))

    bad = {norm(f) for f in forbidden}
    bad |= {"tls10"} if "tls1" in bad else set()
    offered = [v for v in versions if norm(v) in bad]
    return (not offered), offered


def _absent(asset: Any) -> bool:
    """True for a row recording a measured absence: the lookup settled and found no record."""
    return (_get(asset, "extra") or {}).get("present") is False


def _settled_by(asset: Any) -> str:
    """How an absence was measured: the name asked, and each resolver's reply."""
    lookup = (_get(asset, "extra") or {}).get("lookup") or {}
    replies = [f"{lk.get('rcode') or 'no reply'} from {lk.get('resolver', '')}"
               + (f" at {lk['at']}" if lk.get("at") else "")
               for lk in lookup.get("lookups") or []]
    name = lookup.get("name") or ""
    if not (name and replies):
        return "the lookup settled and returned no such record"
    return (f"the TXT lookup for {name} settled and returned no such record "
            f"({'; '.join(replies)})")


def _graded_elsewhere(req: dict, subject: str, record: str, primary: str) -> Conformance:
    return _unmeasured(
        req, subject, INCONCLUSIVE,
        f"no {record} record is published, so there is nothing for this requirement to "
        f"read; the missing record is graded under {primary}")


def _eval_spf(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "spf", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no SPF record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no SPF record",
                reason=("the domain publishes no v=spf1 record, so a receiver has no "
                        "sender policy to apply and no sender is denied; the standard "
                        "requires one ending -all. " + _settled_by(a)),
                evidence=str(_get(a, "name") or ""), source=req["source"]))
            continue
        record = str((_get(a, "extra") or {}).get("record") or _get(a, "notes") or "")
        flags = list(_get(a, "flags") or [])
        if "hardfail-all" in flags:
            status, reason, qualifier = PASS, "", "-all (hardfail)"
        elif "softfail-all" in flags:
            status = FAIL
            qualifier = "~all (softfail)"
            reason = ("record ends ~all (softfail); the standard requires -all, "
                      "and calls softfail a weak posture that permits unknown senders")
        else:
            status = FAIL
            qualifier = "no -all or ~all"
            reason = "record ends neither -all nor ~all, so no sender is denied"
        reason = "; ".join(x for x in [reason, _spf_evaluability(assets, d)] if x)
        rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"],
                                d, status, observed=qualifier, reason=reason,
                                evidence=str(_get(a, "name") or ""), source=req["source"],
                                record=record))
    return rows


_VOID_OVER = "spf-void-lookup-limit-exceeded"
_VOID_AT = "spf-void-lookup-limit-reached"
_TERMS_OVER = "spf-lookup-limit-exceeded"


def _spf_evaluability(assets: list[Any], domain: str) -> str:
    found = _by(assets, "spf-senders", domain)
    if not found:
        return ""
    a = found[0]
    flags = list(_get(a, "flags") or [])
    extra = _get(a, "extra") or {}
    when = extra.get("dns_read_at") or ""
    resolver = extra.get("dns_resolver") or ""
    taken = (f" as resolved by {resolver} at {when}" if when and resolver else "")
    if _TERMS_OVER in flags:
        return (f"and the record spends {extra.get('dns_lookups')} DNS-consuming terms "
                f"against the {extra.get('dns_lookup_limit')} RFC 7208 §4.6.4 permits, so "
                "a conforming receiver returns permerror and never reaches this qualifier")
    if _VOID_OVER in flags:
        return (f"and {extra.get('void_lookups')} of its DNS lookups returned nothing"
                f"{taken}, over the {extra.get('void_lookup_limit')} RFC 7208 §4.6.4 "
                "recommends, so an evaluator applying that recommendation returns "
                "permerror and never reaches this qualifier")
    if _VOID_AT in flags:
        return (f"and {extra.get('void_lookups')} of its DNS lookups returned nothing"
                f"{taken} — exactly the ceiling RFC 7208 §4.6.4 recommends, so the record "
                "is evaluable today with no margin, and one further term ceasing to "
                "resolve makes it permerror before this qualifier is read")
    return ""


def _eval_dmarc(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no DMARC record",
                reason=("the domain publishes no DMARC record, so a receiver applies no "
                        "policy to mail failing authentication; the standard requires "
                        "p=reject. " + _settled_by(a)),
                evidence=str(_get(a, "name") or ""), source=req["source"]))
            continue
        record = str(_get(a, "notes") or "")
        p = re.search(r"\bp=(\w+)", record)
        policy = p.group(1) if p else "absent"
        pct = re.search(r"\bpct=(\d+)", record)
        share = int(pct.group(1)) if pct else 100
        if policy != "reject":
            status = FAIL
            reason = f"policy is p={policy}; the standard requires p=reject"
        elif share < 100:
            status = FAIL
            reason = (f"the record reads p=reject but pct={share}, so the reject policy "
                      f"is applied to {share}% of failing mail and the other "
                      f"{100 - share}% falls through to no action at all — the domain "
                      "does not have a reject policy for most of the mail this "
                      "requirement is about")
        else:
            status, reason = PASS, ""
        rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"],
                                d, status, observed=f"p={policy}; pct={share}",
                                reason=reason, evidence=str(_get(a, "name") or ""),
                                source=req["source"], record=record))
    return rows


def _eval_mta_sts(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "mta-sts", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no MTA-STS record was read for this domain"))
            continue
        a = found[0]
        record = str(_get(a, "notes") or "")
        extra = _get(a, "extra") or {}
        published = bool(extra["published"]) if "published" in extra else True
        if not published:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no _mta-sts record",
                reason=("no _mta-sts TXT record is published, so no sender ever fetches "
                        "a policy for this domain and the mode in any policy file is "
                        "never read — the requirement's 'enabled' clause, unmet, "
                        "independently of the mode"),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
            continue
        faults = _mta_sts_policy_faults(extra)
        if faults:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="policy not valid",
                reason=("; ".join(faults) + ". A sender that cannot fetch a valid policy "
                        "and holds no cached one delivers as though the domain had not implemented "
                        "MTA-STS (RFC 8461 §3.3), so the published record puts no mode, enforce or "
                        "otherwise, into effect"
                        + (f"; curl reported: {extra['policy_fetch_error']}"
                           if extra.get("policy_fetch_error") else "")),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
            continue
        mode = re.search(r"mode=(\w+)", record)
        value = mode.group(1) if mode else "unknown"
        if value == "unknown" and extra.get("policy_reachable") is False:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "the TXT record is published but the policy file could not be fetched "
                "from this machine, so the mode was not read; that is a limit of this "
                "instrument, not a finding about the domain, and it is not graded as a "
                "breach"
                + (f"; curl reported: {extra['policy_fetch_error']}"
                   if extra.get("policy_fetch_error") else "")))
            continue
        status = PASS if value == "enforce" else FAIL
        reason = "" if status == PASS else (
            f"policy mode is {value}; only enforce mandates TLS and prevents a "
            "downgrade to sending in the clear")
        rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"],
                                d, status, observed=f"mode={value}", reason=reason,
                                evidence=str(_get(a, "name") or ""), source=req["source"],
                                record=record))
    return rows


def _mta_sts_policy_faults(extra: dict) -> list[str]:
    """Why the row's policy fetch gave no valid policy (RFC 8461 §3.2, §3.3), or [].

    Read only from a row that recorded the fetch's HTTP status and certificate
    result; an observation taken before those were kept gives no fault.
    """
    if "policy_http_status" not in extra and "policy_certificate_valid" not in extra:
        return []
    status = extra.get("policy_http_status")
    return dnsevidence.mta_sts_faults(
        extra.get("policy_certificate_valid"), int(status) if status is not None else None,
        extra.get("policy_version"), extra.get("policy_max_age"))


def _eval_dkim_keysize(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    minimum = int(req.get("minimum_bits", 2048))
    for d in domains:
        found = _by(assets, "dkim", d)
        if not found:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "no DKIM selector answered; the probe tries known selectors, so "
                "this is silence rather than proof that none is published"))
            continue
        for a in found:
            bits = (_get(a, "extra") or {}).get("key_bits")
            if not bits:
                rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                        "selector answered but no key size could be read"))
                continue
            status = PASS if int(bits) >= minimum else FAIL
            reason = "" if status == PASS else (
                f"{bits}-bit key is below the {minimum}-bit the standard strongly "
                "recommends — permitted on legacy systems, so a recommendation "
                "unmet rather than a requirement breached")
            rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"],
                                    d, status, observed=f"{bits}-bit RSA", reason=reason,
                                    evidence=str(_get(a, "name") or ""), source=req["source"]))
    return rows


def _bulk_mail_indicator(assets: list[Any], domain: str,
                         bulk_mail_domains: tuple[str, ...] = ()) -> str:
    """A note when the domain's sender policy includes a known bulk-mail provider's policy."""
    found = _by(assets, "spf-senders", domain)
    if not found or not bulk_mail_domains:
        return ""
    traversed = str((_get(found[0], "extra") or {}).get("policies_traversed") or "")
    named = sorted({p for p in bulk_mail_domains if p in traversed})
    if not named:
        return ""
    return (f"its sender policy authorises {', '.join(named)}, a bulk-mail provider "
            "— a reason to think the recommendation may not apply to this domain at "
            "all, though authorising a provider is not evidence that mail went that "
            "way")


def _eval_dkim_alignment(req: dict, assets: list[Any], domains: list[str],
                         bulk_mail_domains: tuple[str, ...] = ()) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(_graded_elsewhere(req, d, "DMARC", "SGE-DMARC-01"))
            continue
        record = str(_get(a, "notes") or "")
        m = re.search(r"adkim=(\w)", record)
        value = m.group(1) if m else "r"
        if value == "s":
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, PASS,
                observed=f"adkim={value}",
                reason=("strict DKIM alignment is published, which is the value the "
                        "standard recommends; the standard permits relaxed alignment "
                        "for bulk-sending domains but forbids strict for none, so this "
                        "meets the recommendation without having to establish "
                        "whether the domain sends bulk mail"),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
            continue
        detail = (
            "relaxed DKIM alignment is published"
            + ("" if m else ", by omitting the tag, which RFC 9989 §4.7 reads as relaxed")
            + ", and the standard recommends strict ONLY where a domain is not "
              "involved with bulk mail sending — which of the organisation's domains "
              "are is not established, so whether this recommendation applies here is "
              "unsettled and no verdict is claimed in either direction. What would "
              "settle it: the sending sources the organisation's DMARC aggregate "
              "reports name per domain, or a per-sending-domain breakdown of a "
              "per-message transport export")
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"adkim={value}", reason=NOT_COLLECTED, evidence=detail,
            source=req["source"], record=record,
            subject_note=_bulk_mail_indicator(assets, d, bulk_mail_domains)))
    return rows


def _eval_tls_rpt(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "tls-rpt", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no TLS-RPT record was read for this domain"))
            continue
        a = found[0]
        extra = _get(a, "extra") or {}
        published = bool(extra.get("published"))
        record = str(extra.get("record") or "")
        rua = re.search(r"rua=([^;\s]+)", record)
        if not published:
            status, reason = FAIL, "no _smtp._tls TXT record is published for this domain"
        elif not rua:
            status, reason = FAIL, (
                "a v=TLSRPTv1 record is published but carries no rua= reporting "
                "address, so no receiver has anywhere to send a report and a failed "
                "delivery is never seen; the standard's expected value is "
                "'v=TLSRPTv1; rua=mailto:<address>'")
        else:
            status, reason = PASS, ""
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d,
            status, observed=str(_get(a, "notes") or ""), reason=reason,
            evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
    return rows


def _eval_ned_dmarc(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    partial = str(req.get("partial") or "").strip()
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        record = "" if _absent(a) else str(_get(a, "notes") or "")
        tags = _dmarc_tags(_dmarc_record(a))
        sp = tags.get("sp", "")
        weak = []
        if sp.lower() == "none":
            weak.append(("sp=none", (
                "the root record sets sp=none, so every sub-domain without a "
                "DMARC record of its own inherits no policy; the DMARC guide "
                "says all domains must have a p=reject policy, and the "
                "framework says even sp=reject only partially resolves this")))
        np_weak = _np_weaker_than_reject(tags)
        if np_weak:
            weak.append((f"np={tags['np']}", np_weak))
        if weak:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="; ".join(w[0] for w in weak),
                reason="; ".join(x for x in [
                    *(w[1] for w in weak),
                    (f"what this row does NOT read: {partial}" if partial else ""),
                ] if x),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
        else:
            rows.append(_ned_dmarc_from_sweep(req, assets, d, _dmarc_record(a), sp, partial))
    return rows


#: Each DMARC policy tag, and the tags a receiver falls back to when it is absent
#: (RFC 9989 §4.7: ``np`` falls back to ``sp`` then ``p``; ``sp`` to ``p``).
_POLICY_FALLBACK = {"p": ("p",), "sp": ("sp", "p"), "np": ("np", "sp", "p")}


def _np_weaker_than_reject(tags: dict[str, str]) -> str:
    """Why a record's explicit ``np=`` fails the reject requirement, or "" when it does not.

    RFC 9989 §4.7 (which obsoletes RFC 7489) defines ``np`` as the policy "for
    non-existent subdomains of the given Organizational Domain", and says: "It
    applies only to non-existent subdomains of the Organizational Domain
    queried and not to either existing subdomains or the domain itself." And:
    "If the "np" tag is absent, the policy specified by the "sp" tag (if the
    "sp" tag is present) or the policy specified by the "p" tag (if the "sp"
    tag is not present) MUST be applied for non-existent subdomains." A name
    that does not exist publishes no record of its own, so ``np=`` is the only
    policy a receiver applies to mail claiming one, and a value weaker than
    ``reject`` leaves every such name, of which there is no end, without a
    reject policy. The framework's §9 applies the requirement *"All domains
    must have a p=reject DMARC policy"* to *"all non-email domains, sub-domains
    and all new domains"*, and a name nobody has created yet is the plainest
    case of a domain that sends no mail. An absent ``np=`` inherits ``sp=`` or
    ``p=``, which are graded on their own, so only an explicit ``np=`` is read
    here; nothing here can pass a row, because non-existent names are only
    part of what is beneath the domain.
    """
    np_ = tags.get("np", "")
    if not np_ or np_.lower() == "reject":
        return ""
    return (f"the record sets np={np_}, so mail claiming a name beneath the domain that does "
            "not exist in DNS is not rejected: RFC 9989 §4.7 has receivers apply np= to "
            "non-existent sub-domains, and such a name publishes no record of its own to "
            "override it; the framework applies the p=reject requirement to sub-domains and "
            "all new domains")


@dataclass
class HeldRecords:
    """The DMARC records an observation holds at and beneath one domain.

    ``records`` maps each name read to its record ("" for a settled read
    that found none); ``unsettled`` are names whose read did not settle.
    ``walkable`` is False for an observation whose sweep did not read the
    names a walk passes, and then only the domain's own record is applied.
    """

    domain: str
    records: dict[str, str] = field(default_factory=dict)
    unsettled: set[str] = field(default_factory=set)
    walkable: bool = False


def held_dmarc(assets: list[Any], domain: str) -> HeldRecords:
    """Every DMARC record the observation read at or beneath ``domain``.

    From the domain's own DMARC row, the sub-domain sweep's names (both the
    names that send no mail and those that do) and the intermediate names the
    sweep read for policy discovery (``extra.intermediate_dmarc``). An
    observation taken before the sweep read intermediate names holds none,
    and is marked not ``walkable``.
    """
    held = HeldRecords(domain.lower().strip("."))
    root = _by(assets, "dmarc", domain)
    if root:
        held.records[held.domain] = _dmarc_record(root[0])
    for a in _by(assets, "ned-dmarc", domain):
        extra = _get(a, "extra") or {}
        held.walkable = held.walkable or "names_without_own_dmarc" in extra
        for n in extra.get("names_without_own_dmarc") or []:
            held.records.setdefault(str(n), "")
        held.records.update({str(n): str(r) for n, r in (extra.get("dmarc_records") or {}).items()})
        for n, rec in (extra.get("intermediate_dmarc") or {}).items():
            held.records[str(n)] = str(rec)
        held.unsettled.update(str(n) for n in [*(extra.get("names_unread") or []),
                                               *(extra.get("names_unsettled") or []),
                                               *(extra.get("intermediate_unsettled") or [])])
    for a in _by(assets, "subdomain-mail", domain):
        for n, rec in ((_get(a, "extra") or {}).get("names") or {}).items():
            held.records[str(n)] = str((rec or {}).get("dmarc_record") or "")
    return held


#: What :func:`policy_record` returns when a walk passes a name it holds no reading of.
UNREAD = None

class Unsettled(str):
    """A discovered-name judge's answer when what it needs was not read, saying why.

    The name is counted neither way (:func:`_discovered_rows`).
    """


class NotRead(Unsettled):
    """An :class:`Unsettled` answer because the observation never read the record at all."""


#: What a discovered-name judge returns when the name's DMARC policy walk
#: passes a name that was not read.
NOT_SETTLED = Unsettled("a name between it and the domain was not read, and its DMARC record "
                        "could govern it (RFC 9989 §4.10)")


def policy_record(name: str, held: HeldRecords) -> tuple[str, str] | None:
    """The DMARC record a receiver applies to ``name``, and the name it is published at.

    RFC 9989 §4.10.1: the record at ``name`` itself, else the record of its
    Organizational Domain, else the record of its public suffix domain (PSD).
    The Organizational Domain comes from the DNS Tree Walk
    (:func:`takestock.dnsevidence.tree_walk`) by §4.10.2, reading the records
    found from the longest name to the shortest: one with ``psd=n`` is the Organizational Domain; one with
    ``psd=y`` makes the name one label below it the Organizational Domain;
    otherwise it is the name with the fewest labels that publishes a record.
    So a record at an intermediate name governs the names beneath it only
    when it says ``psd=n``, when the record above it says ``psd=y``, or when
    nothing above it publishes one.

    The walk is read only as far as ``held.domain``: the names above it are
    not read. Returns ``("", "")`` when no record is found, and
    :data:`UNREAD` when the walk passes a name between ``name`` and the
    domain that was not read or did not settle, since that name's record
    could change the answer.
    """
    name = name.lower().strip(".")
    own = held.records.get(name, "")
    if own:
        return name, own
    path = [n for n in dnsevidence.tree_walk(name)
            if n == held.domain or n.endswith("." + held.domain)]
    if any(n in held.unsettled or n not in held.records for n in path):
        return UNREAD
    found = [(n, held.records[n]) for n in path if held.records[n]]
    if not found:
        return "", ""
    by_name = dict(found)
    for n, rec in found:
        psd = _dmarc_tags(rec).get("psd", "").lower()
        if psd == "n":
            return n, rec
        if psd == "y":
            org = ".".join(name.split(".")[-(n.count(".") + 2):])
            return (org, by_name[org]) if by_name.get(org) else (n, rec)
    return found[-1]


def _rejects(tags: dict[str, str], policy_key: str) -> bool:
    """True when ``policy_key``, or the tag a receiver falls back to, is reject at pct=100."""
    policy = next((tags[k] for k in _POLICY_FALLBACK[policy_key] if tags.get(k)), "")
    return policy.lower() == "reject" and _int(tags.get("pct", "100")) >= 100


def _ned_dmarc_from_sweep(req: dict, assets: list[Any], domain: str,
                          root_record: str, sp: str, partial: str,
                          head: str | None = None) -> Conformance:
    found = _by(assets, "ned-dmarc", domain)
    if head is None:
        head = (f"root record has sp={sp or 'unset'}, which is not the failing value, "
                "so the root alone settles nothing; proving the requirement needs each "
                "sub-domain's own record — ")
    if not found:
        return _unmeasured(req, domain, NOT_COLLECTED, head + _subdomain_limit(
            assets, [domain], "DMARC", owed=(
                "this observation carries no reading of each name's own DMARC record — "
                "a run with the sub-domain sweep reads them")))
    a = found[0]
    extra = _get(a, "extra") or {}
    if not extra.get("control_usable", False):
        return _unmeasured(req, domain, INCONCLUSIVE, _control_unusable(extra))
    in_scope = _int(extra.get("names_in_scope"))
    if not in_scope:
        return _unmeasured(
            req, domain, NOT_COLLECTED,
            head + "and no sub-domain of this domain was both enumerated and found not "
            "to send mail, so there is nothing to read it against")
    records = dict(extra.get("dmarc_records") or {})
    own_bad = sorted(n for n, rec in records.items()
                     if not _rejects(_dmarc_tags(str(rec)), "p"))
    without_own = in_scope - len(records)
    # A name that came back NXDOMAIN takes np= from the record that governs it
    # (RFC 9989 §4.7 and §4.10.1), and one that exists takes its sp=. An
    # observation without the list treats every name as existing.
    gone_names = set(extra.get("names_nonexistent") or [])
    gone = len([n for n in gone_names if n not in records])
    walked = _walked_policies(assets, domain, extra)
    unread: list[str] = []
    elsewhere: dict[str, str] = {}
    if walked is None:
        root_tags = _dmarc_tags(root_record)
        fallback_bad = ((without_own - gone) if not _rejects(root_tags, "sp") else 0) + (
            gone if not _rejects(root_tags, "np") else 0)
    else:
        governed, unread = walked
        fallback_bad = sum(1 for n, (_at, rec) in governed.items()
                           if not _rejects(_dmarc_tags(rec), "np" if n in gone_names else "sp"))
        elsewhere = {n: at for n, (at, _rec) in governed.items()
                     if at and at != domain.lower().strip(".")}
    limit = f"what this row does NOT read: {partial}" if partial else ""
    note = [f"read {extra.get('read_at', '')} via {', '.join(extra.get('resolvers') or [])}"]
    if _sources_note(extra):
        note.append(_sources_note(extra))
    note[:0] = _walk_notes(elsewhere, unread)
    if fallback_bad:
        note.insert(0, f"{fallback_bad} of the {in_scope} enumerated sub-domain(s) that show "
                       "no sign of sending mail publish no DMARC record of their own and "
                       + ("take the record policy discovery finds for them (RFC 9989 "
                          "§4.10.1), which does not reject all failing mail for them (sp= for "
                          "a name that exists, np= for one that does not)"
                          if root_record or elsewhere else
                          "no record at or above them publishes one for them to fall back to"))
    if own_bad:
        note.insert(0, f"{len(own_bad)} publish a record of their own that does not reject "
                       f"all failing mail: {', '.join(own_bad)}")
    if own_bad or fallback_bad:
        return Conformance(
            req["id"], req["title"], req["level"], req["scope"], domain, FAIL,
            observed=f"{len(own_bad) + fallback_bad} of {in_scope} sub-domains without a "
                     "reject policy",
            reason="; ".join(x for x in [
                ("a sub-domain that sends no mail is left without a reject policy, on its "
                 "own record or on the record it falls back to; the DMARC guide says "
                 "all domains must have a p=reject policy"),
                _SWEEP_INSTRUMENT, limit] if x),
            evidence=str(_get(a, "name") or ""), source=req["source"],
            record="; ".join(filter(None, [
                f"root record: {root_record or 'none published'}",
                *(f"{n}: {records[n]}" for n in own_bad)])),
            subject_note="; ".join(note))
    whole, why_not = _whole_population(extra, unread)
    if whole:
        return Conformance(
            req["id"], req["title"], req["level"], req["scope"], domain, PASS,
            observed=f"all {in_scope} sub-domains reject",
            reason="; ".join([
                "every sub-domain that shows no sign of sending mail rejects, on its own "
                "record or through the record policy discovery finds for it", whole]),
            evidence=str(_get(a, "name") or ""), source=req["source"],
            subject_note="; ".join(note))
    return Conformance(
        req["id"], req["title"], req["level"], req["scope"], domain, NOT_MEASURED,
        observed=f"all {in_scope - len(unread)} sub-domains read reject",
        reason=NOT_COLLECTED,
        evidence=("every enumerated sub-domain that shows no sign of sending mail rejects, "
                  "on its own record or through the record policy discovery finds for it, "
                  "and "
                  "that is not the same as every sub-domain doing so: " + _SWEEP_POPULATION
                  + ". No verdict is claimed in either direction" + _floor_note(why_not)
                  + (f". What this row does not read either: {partial}" if partial else "")),
        source=req["source"], subject_note="; ".join(note))


def _walked_policies(assets: list[Any], domain: str, extra: dict
                     ) -> tuple[dict[str, tuple[str, str]], list[str]] | None:
    """The record governing each swept name with none of its own, by :func:`policy_record`.

    Returns ``(governed, unread)``: each such name's ``(published at, record)``,
    and the names whose walk passes a name that was not read. ``None`` when
    the sweep row does not list those names (an observation taken before it
    did), and then only the domain's own record is read for them.
    """
    names = extra.get("names_without_own_dmarc")
    if names is None:
        return None
    held = held_dmarc(assets, domain)
    governed: dict[str, tuple[str, str]] = {}
    unread: list[str] = []
    for n in names:
        got = policy_record(str(n), held)
        if got is UNREAD:
            unread.append(str(n))
        else:
            governed[str(n)] = got
    return governed, unread


def _walk_notes(elsewhere: dict[str, str], unread: list[str]) -> list[str]:
    """Notes naming the swept names a walk did not settle at the domain's own record."""
    out = []
    if elsewhere:
        out.append("governed by a record below the domain (RFC 9989 §4.10.2): " + "; ".join(
            f"{n} by {at}" for n, at in sorted(elsewhere.items())))
    if unread:
        out.append(f"{len(unread)} name(s) counted neither way, because a name between them "
                   "and the domain was not read, and its DMARC record could govern them "
                   "(RFC 9989 §4.10): " + ", ".join(sorted(unread)))
    return out


def _control_note(extra: dict) -> str:
    """Said when the sweep's absence control was trusted because a wildcard answered it."""
    if extra.get("control_basis") != dnsevidence.CONTROL_WILDCARD:
        return ""
    return ("the absence control was answered by the published wildcard with exactly the "
            "wildcard's record, as a wildcard does for a name that does not exist directly "
            "beneath the domain (RFC 4592 §3.3.1), so "
            "each name was read for its own response code and agreed records, a wildcard "
            "answer being the record a receiver is given for it")


_SWEEP_INSTRUMENT = (
    "read from public DNS, each name asked of every configured resolver with "
    "retries, and with a name nobody has registered asked in the same batch so "
    "that a run which simply failed to reach the resolvers cannot read as a run "
    "that found nothing"
)

_SWEEP_POPULATION = (
    "an incomplete list of sub-domains still settles this in one direction, and "
    "only one: the framework asks for the record on every sub-domain, so a single "
    "name without it is the answer, while any number of names carrying it says "
    "nothing about the names not seen. That is why this row can report a "
    "breach and, unless the profile attests a zone file complete, can never "
    "report conformance"
)


def _control_unusable(extra: dict) -> str:
    """Why nothing is graded from a sweep whose absence control was not trusted."""
    if extra.get("control_basis") == dnsevidence.RESOLVER_SYNTHESISES:
        return ("a resolver answered, with records, a random name under a domain that "
                "publishes nothing (RFC 6761 §6.4; RFC 8020 §2), so it invents answers: "
                "this is an unusable resolver reading, not a wildcard, and nothing is "
                "graded against this domain from it")
    return ("the sweep's control name answered when it should not have, so this run "
            "cannot tell a record that is absent from a resolver that did not reply; "
            "nothing is graded against this domain from it")


def _whole_population(extra: dict, unread: list[str] | None = None) -> tuple[str, str]:
    """Whether a sweep read the whole population of names, not a floor.

    Returns ``(basis, "")`` when it did: the profile attests a zone file
    complete (:func:`takestock.collectors.ct_dns.zone_population`), and every
    name was read and settled, none was beyond the ceiling, none of ``unread``
    (names a policy walk could not settle) is left, and the live reading
    agrees with the files. Returns ``("", why)`` when a zone file is attested
    and one of those fails, and ``("", "")`` when none is attested.
    """
    pop = extra.get("population") or {}
    if not pop:
        return "", ""
    zones = ", ".join(pop.get("zones") or [pop.get("zone", "")])
    head = f"a zone file is attested complete for {pop.get('zone', '')}, but "
    if not pop.get("complete"):
        return "", head + str(pop.get("why_not") or "the attestation was not accepted")
    blockers = [
        (extra.get("names_unread"), "some names were not read"),
        (extra.get("names_unsettled"), "the resolvers disagreed on some names"),
        (_int(extra.get("names_dropped_by_cap")), "some names were beyond the sweep's ceiling"),
        (unread, "some names' policy walk passed a name that was not read"),
        (extra.get("names_disagreeing_with_zone"),
         "the live reading and the zone files disagree on "
         + ", ".join(extra.get("names_disagreeing_with_zone") or [])
         + ", so the files no longer describe the zone"),
    ]
    for present, why in blockers:
        if present:
            return "", head + why + ", so the names read are still a floor"
    return (f"the names read are the whole population, not a floor: they include every "
            f"name in the zone file(s) for {zones}, which {pop.get('attested_by')} attested "
            f"complete on {pop.get('attested_on')} (dns_zones.complete_zones in the target "
            "profile), and every name was read, settled, and agreed with the files"), ""


def _mail_names_graded(assets: list[Any], domain: str) -> set[str]:
    """The names beneath ``domain`` that :func:`_discovered_rows` grades as email domains.

    Those held in a mail-handling sub-domain row for ``domain`` whose control
    name was usable. A note saying a name is graded against the rules for
    email domains is true only for these.
    """
    return {str(n) for a in _by(assets, "subdomain-mail", domain)
            if (_get(a, "extra") or {}).get("control_usable", False)
            for n in ((_get(a, "extra") or {}).get("names") or {})}


def _floor_note(why_not: str) -> str:
    return f". {why_not[0].upper()}{why_not[1:]}" if why_not else ""


def _eval_ned_records(req: dict, assets: list[Any], domains: list[str],
                      protocol: str, record_kind: str) -> list[Conformance]:
    rows = []
    partial = str(req.get("partial") or "").strip()
    for d in domains:
        found = _by(assets, protocol, d)
        if not found:
            rows.append(_unmeasured(
                req, d, NOT_COLLECTED,
                "no sub-domain record sweep is in this observation, so no sub-domain's "
                "own record has been read — "
                + _subdomain_limit(assets, [d], record_kind, wired=True)))
            continue
        a = found[0]
        extra = _get(a, "extra") or {}
        expected = str(extra.get("expected_record") or "")
        wildcard = str(extra.get("wildcard_name") or "")
        wildcard_ok = bool(extra.get("wildcard_conformant"))
        in_scope = _int(extra.get("names_in_scope"))
        missing = list(extra.get("names_without_record") or [])
        sending = list(extra.get("names_email_enabled") or [])
        unread = list(extra.get("names_unread") or [])
        record = (f"{wildcard} → {extra.get('wildcard_record') or 'no record'} "
                  f"({extra.get('wildcard_rcode') or 'no agreed status'})")

        if not extra.get("control_usable", False):
            rows.append(_unmeasured(req, d, INCONCLUSIVE, _control_unusable(extra)))
            continue
        declared = str(req.get("record") or "").replace("<domain>", d)
        if declared and wildcard and declared.lower() != wildcard.lower():
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                f"the standard names {declared} as the record to publish and the sweep "
                f"read {wildcard} instead, so what was measured is not what the "
                "requirement asks about and nothing is graded against this domain"))
            continue
        if not in_scope:
            rows.append(_unmeasured(
                req, d, NOT_COLLECTED,
                "no sub-domain of this domain was both enumerated and found not to send "
                "mail, so there is nothing here to read the requirement against — "
                + _subdomain_limit(assets, [d], record_kind, wired=True)))
            continue

        note = [
            f"{len(missing)} of the {in_scope} enumerated sub-domain name(s) beneath this "
            f"domain that show no sign of sending mail publish no {expected} record"
            if missing else
            f"all {in_scope} enumerated sub-domain name(s) beneath this domain carry "
            f"{expected}",
            (f"the wildcard {wildcard} carries {expected}, which a receiver is given for "
             "every name beneath that does not exist; a name that exists without a record "
             "of its own is not covered by it" if wildcard_ok else
             f"no wildcard record is published at {wildcard}, so there is no blanket "
             "control and each name answers only for itself"),
            f"read {extra.get('read_at', '')} via {', '.join(extra.get('resolvers') or [])}",
            _sources_note(extra),
            _control_note(extra),
        ]
        note = [x for x in note if x]
        graded = _mail_names_graded(assets, d)
        if any(n in graded for n in sending):
            note.append("excluded as email-enabled on the evidence, and graded against the "
                        "rules for email domains instead: "
                        + ", ".join(n for n in sending if n in graded))
        if any(n not in graded for n in sending):
            note.append("excluded as email-enabled on the evidence, and not graded against the "
                        "rules for email domains either, because this observation holds no "
                        "usable mail-handling reading of them: "
                        + ", ".join(n for n in sending if n not in graded))
        if unread:
            note.append(f"NOT READ, so not counted either way: {', '.join(unread)}")
        if extra.get("names_unsettled"):
            note.append("RESOLVERS DISAGREED, so not counted either way: "
                        + ", ".join(extra["names_unsettled"]))
        if extra.get("names_dropped_by_cap"):
            note.append(f"{extra['names_dropped_by_cap']} further name(s) were beyond the "
                        "sweep's ceiling and were not read")

        whole, why_not = _whole_population(extra)
        if missing:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{len(missing)} of {in_scope} sub-domains without {expected}",
                reason="; ".join(x for x in [
                    (f"the framework asks for {expected} on every sub-domain that does not "
                     "send mail, and sub-domains that carry no record of their own are not "
                     "covered by the parent domain's, because a receiver asks the name "
                     "itself and stops there"),
                    _SWEEP_INSTRUMENT,
                    *([whole] if whole else [
                        _SWEEP_POPULATION,
                        (f"what this row does NOT read: {partial}" if partial else "")]),
                ] if x),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record=record, subject_note="; ".join(note)))
            continue
        if whole:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, PASS,
                observed=f"all {in_scope} sub-domains carry {expected}",
                reason="; ".join([
                    f"every sub-domain that shows no sign of sending mail carries {expected}",
                    whole, _SWEEP_INSTRUMENT]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record=record, subject_note="; ".join(note)))
            continue
        rows.append(_unmeasured(
            req, d, NOT_COLLECTED,
            f"every sub-domain name read for this domain carries {expected}, and that "
            "is not the same as every sub-domain carrying it: " + _SWEEP_POPULATION
            + ". No verdict is claimed in either direction" + _floor_note(why_not)
            + (f". What this row does not read either: {partial}" if partial else "")))
    return rows


def _eval_ned_spf(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    return _eval_ned_records(req, assets, domains, "ned-spf", "SPF")


def _eval_ned_dkim(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    return _eval_ned_records(req, assets, domains, "ned-dkim", "DKIM")


_TLS_FLOOR_UNREAD = (
    "reads the receiving path only — what the organisation's mail hosts offer an "
    "inbound sender; the same requirement's sending clause is not measured by this "
    "check, and is read from a per-message mail transport export when one is supplied"
)

_TLS_FLOOR_READ_ELSEWHERE = (
    "reads the receiving path only — what the organisation's mail hosts offer an inbound "
    "sender; the same requirement's sending clause is measured separately, on "
    "the {subject} row below"
)

_SENDING_SUBJECT = "outbound mail (all paths)"

#: The ``source`` of rows from a per-message mail transport export. Each row is one
#: mail path and carries, in ``extra``: ``direction`` (inbound or outbound),
#: ``messages``, ``no_tls_messages``, ``tls_distribution`` ("TLS1.2=n; ..."),
#: ``window`` (the period the export covers), ``connector_present`` (yes/no:
#: whether a configured route, such as a connector or relay definition, governs
#: the path, where the platform routes mail that way), and for mail exchanged with
#: government organisations ``govt_messages``, ``govt_no_tls_messages``,
#: ``govt_tls_distribution``, ``govt_days``, ``govt_identified_by`` and
#: ``govt_counterparty_domains`` (``_total`` for the whole export).
TRANSPORT_SOURCE = "mail_transport"
_SENDING_SOURCE = TRANSPORT_SOURCE

_NO_TLS = "no tls"

_SENDING_LIMITS = (
    "each reading is the transport negotiated with the IMMEDIATE peer for one "
    "delivery, which, where the platform routes mail through configured connectors "
    "or a relay, is that relay and not the final recipient, so onward legs are out "
    "of frame; and the finding is bounded by "
    "the export's own window"
)


def _eval_tls_floor(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    forbidden = list(req.get("forbidden_versions") or [])
    sending = _eval_tls_sending(req, assets, forbidden)
    measured_sending = sending.status != NOT_MEASURED
    limit = (_TLS_FLOOR_READ_ELSEWHERE.format(subject=_SENDING_SUBJECT)
             if measured_sending else _TLS_FLOOR_UNREAD)

    named = _mx_named(assets, domains)
    hosts = _mail_hosts(assets, domains)
    if not named:
        return [_unmeasured(req, "", NOT_COLLECTED,
                            "no MX host has been measured for TLS versions"), sending]
    rows = []
    for host in sorted(named):
        a = hosts.get(host)
        if a is None:
            rows.append(_unprobed_mx(req, host, named[host], assets))
            continue
        versions = list(_get(a, "protocol_versions") or [])
        if not versions:
            if _no_encryption_offered(a):
                rows.append(Conformance(
                    req["id"], req["title"], req["level"], req["scope"], host,
                    FAIL, observed="no TLS offered",
                    reason=("the gateway answered EHLO without advertising STARTTLS, so "
                            "mail delivered to it crosses the network in clear — the "
                            "'no-TLS' the requirement forbids by name; measured, not "
                            "inferred from the port number"),
                    evidence=str(_get(a, "name") or ""), source=req["source"]))
            else:
                rows.append(_unmeasured(req, host, INCONCLUSIVE,
                                        "host was reached but offered no version list"))
            continue
        ok, offered = _version_ok(versions, forbidden)
        if not ok:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], host,
                FAIL, observed=", ".join(versions),
                reason=f"offers {', '.join(offered)}, which the standard forbids",
                evidence=str(_get(a, "name") or ""), source=req["source"]))
            continue
        met, unorderable = _floor_met(versions, str(req.get("minimum_version") or ""))
        if not met:
            rows.append(_unmeasured(
                req, host, INCONCLUSIVE,
                f"the host offers {', '.join(versions)}, none of which this check can "
                f"place at or above the {req.get('minimum_version')} floor the same "
                "requirement sets — and nothing it offers is on the standard's "
                "forbidden list either, so the floor is unconfirmed rather than "
                "breached"
                + (f"; the version spelling(s) it could not order were "
                   f"{', '.join(unorderable)}" if unorderable else "")))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], host,
            PASS, observed=", ".join(versions),
            reason=(f"offers {req.get('minimum_version')} or better and nothing the "
                    f"standard forbids; {limit}"),
            evidence=str(_get(a, "name") or ""), source=req["source"]))
    rows.append(sending)
    return rows


def _no_encryption_offered(asset: Any) -> bool:
    return any(str(f).startswith(PLAINTEXT_FLAG) for f in (_get(asset, "flags") or []))


def _eval_tls_sending(req: dict, assets: list[Any],
                      forbidden: list[str]) -> Conformance:
    paths = [a for a in assets
             if _get(a, "source") == _SENDING_SOURCE
             and str((_get(a, "extra") or {}).get("direction", "")).lower() == "outbound"]
    if not paths:
        return _unmeasured(
            req, _SENDING_SUBJECT, NOT_COLLECTED,
            "the per-message mail transport export is not in this observation, so "
            "what the organisation's own outbound deliveries negotiated has not been "
            "read; the routing configuration cannot answer it, because an opportunistic "
            "path and an enforced one look identical until a far end offers no TLS")

    total = clear = 0
    versions: dict[str, int] = {}
    for a in paths:
        extra = _get(a, "extra") or {}
        total += _int(extra.get("messages"))
        clear += _int(extra.get("no_tls_messages"))
        for name, count in _distribution(str(extra.get("tls_distribution") or "")).items():
            versions[name] = versions.get(name, 0) + count

    named = [v for v in versions if v.strip().lower() != _NO_TLS]
    _, legacy = _version_ok(named, forbidden)
    window = _sending_window(assets)
    evidence = EVIDENCE_SEPARATOR.join(str(_get(a, "name") or "") for a in paths)
    observed = (f"{clear:,} of {total:,} outbound messages with no TLS at all"
                if total else "no outbound messages in the export")

    faults = []
    if clear:
        faults.append(
            f"{clear:,} of the {total:,} outbound messages in this record left with no "
            f"transport encryption at all{window} — readable to anyone positioned on the "
            "network path, and the 'sending unencrypted' the requirement forbids by name")
    if legacy:
        faults.append(
            f"deliveries negotiated {', '.join(sorted(legacy))}{window}, below the "
            "TLS 1.2 minimum the same sentence sets")
    if faults:
        return Conformance(
            req["id"], req["title"], req["level"], req["scope"], _SENDING_SUBJECT,
            FAIL, observed=observed,
            reason="; ".join(faults) + f". What this cannot say: {_SENDING_LIMITS}.",
            evidence=evidence, source=req["source"],
            record="; ".join(f"{v}={n:,}" for v, n in sorted(versions.items(),
                                                             key=lambda kv: -kv[1])))
    return Conformance(
        req["id"], req["title"], req["level"], req["scope"], _SENDING_SUBJECT,
        PASS, observed=observed,
        reason=(f"every one of the {total:,} outbound messages in this record left at "
                f"TLS 1.2 or better{window}, with none in clear. What this cannot say: "
                f"{_SENDING_LIMITS}."),
        evidence=evidence, source=req["source"],
        record="; ".join(f"{v}={n:,}" for v, n in sorted(versions.items(),
                                                         key=lambda kv: -kv[1])))


_ITLS_SUBJECT = "mail with government organisations"

_ITLS_GLOSS = (
    "Implicit TLS means the session is encrypted from its first byte on a "
    "dedicated port, as against STARTTLS, where the session opens in the clear "
    "and upgrades")


def _eval_implicit_tls(req: dict, assets: list[Any],
                       domains: list[str]) -> list[Conformance]:
    return [_implicit_tls_paths(req, assets), *_implicit_tls_receiving(req, assets, domains)]


#: Why no ``implicit_tls`` row is read for SGE-ITLS-01. That collector reads
#: TLS from the first byte on ports 465, 993 and 995, which is RFC 8314's
#: Implicit TLS for message submission and mailbox access; RFC 8314 §1 says it
#: "does not address the use of TLS with SMTP for message relay". No Secure
#: Government Email document names a port. The framework's own route to the
#: requirement on the receiving side is a rule that rejects inbound connections
#: without TLS, and inbound mail from another organisation arrives by relay on
#: port 25 (RFC 5321 §4.5.4), negotiated by STARTTLS (RFC 3207).
_ITLS_PORTS_NOT_READ = (
    "TLS rows on ports 465, 993 and 995 are not read for this requirement: they show "
    "RFC 8314 Implicit TLS for mail submission and mailbox access, which RFC 8314 §1 "
    "says does not cover relay between mail servers, and no Secure Government Email "
    "document names a port")

_ITLS_RECEIVING_UNSEEN = (
    "whether the host refuses a sender that does not start TLS cannot be seen by a "
    "probe that delivers no mail, so this row never passes; whether the requirement "
    "binds the organisation also turns on SGE Restricted Group membership, which "
    "nothing read here establishes")


def _implicit_tls_receiving(req: dict, assets: list[Any],
                            domains: list[str]) -> list[Conformance]:
    """SGE-ITLS-01's receiving side: one row per MX host, from its port-25 probe.

    A host that offers no STARTTLS on port 25 cannot receive mail from another
    organisation under TLS at all, which no reading of the requirement allows;
    one that offers it shows a necessary condition only. Neither is graded
    either way: the requirement's binding force depends on Restricted Group
    membership (TLS Deployment Guide §4.5), as for the sending side, and the
    same no-STARTTLS host already fails SGE-TLS-01. A host with no port-25
    probe is *not collected*. See :data:`_ITLS_PORTS_NOT_READ` for why
    ``implicit_tls`` rows are not read.
    """
    named = _mx_named(assets, domains)
    hosts = _mail_hosts(assets, domains)
    rows = []
    for host in sorted(named):
        a = hosts.get(host)
        if a is None:
            row = _unprobed_mx(req, host, named[host], assets)
            row.evidence += f". {_ITLS_PORTS_NOT_READ}"
            rows.append(row)
            continue
        if _no_encryption_offered(a):
            observed = "no STARTTLS offered on port 25"
            detail = ("the gateway answered EHLO on port 25 without advertising STARTTLS, so "
                      "mail delivered to it by another organisation crosses the network in "
                      "clear or not at all, and TLS cannot be required on that path; the "
                      "same reading fails SGE-TLS-01 for this host. ")
        elif _get(a, "protocol_versions"):
            observed = "STARTTLS offered on port 25"
            detail = ("the gateway offers STARTTLS on port 25, which is necessary for "
                      "receiving mail under TLS and is not the requirement itself: ")
        else:
            rows.append(_unmeasured(req, host, INCONCLUSIVE,
                                    "the host was reached on port 25 but offered no version "
                                    f"list. {_ITLS_PORTS_NOT_READ}"))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], host, NOT_MEASURED,
            reason=INCONCLUSIVE, observed=observed,
            evidence=f"{detail}{_ITLS_RECEIVING_UNSEEN}. {_ITLS_PORTS_NOT_READ}",
            source=req["source"], record=str(_get(a, "name") or "")))
    return rows


def _implicit_tls_paths(req: dict, assets: list[Any]) -> Conformance:
    """SGE-ITLS-01 on the mail the organisation exchanged with government organisations."""
    transport = [a for a in assets
                 if _get(a, "source") == _SENDING_SOURCE
                 and str((_get(a, "extra") or {}).get("direction", "")).strip()]
    paths = [a for a in transport
             if "govt_messages" in (_get(a, "extra") or {})]
    if not paths:
        if transport:
            return _unmeasured(
                req, _ITLS_SUBJECT, NOT_COLLECTED,
                f"this observation carries the per-message mail transport export "
                f"in {len(transport)} path rows, but none of them carries the "
                f"government-counterparty split this requirement is read against; "
                f"reading the same export with that split produces the population")
        return _unmeasured(
            req, _ITLS_SUBJECT, NOT_COLLECTED,
            "the per-message mail transport export is not in this observation, so "
            "the mail exchanged with government organisations — the population "
            "the TLS Deployment Guide narrows this requirement to — has not been "
            "read at all. " + _ITLS_GLOSS + ", and no external probe can see "
            "either one on a path the organisation sends over; the export is what "
            "puts a measured population under the requirement")

    totals: dict[str, int] = {}
    clear: dict[str, int] = {}
    unenforced: dict[str, int] = {}
    unenforced_clear = 0
    unenforced_days = 0
    versions: dict[str, int] = {}
    domain_tally = 0
    classifier = ""
    for a in paths:
        extra = _get(a, "extra") or {}
        direction = str(extra.get("direction", "")).strip().lower() or "unknown"
        n = _int(extra.get("govt_messages"))
        if not n:
            continue
        totals[direction] = totals.get(direction, 0) + n
        clear[direction] = clear.get(direction, 0) + _int(extra.get("govt_no_tls_messages"))
        classifier = classifier or str(extra.get("govt_identified_by") or "")
        if str(extra.get("connector_present", "")).strip().lower() == "no":
            unenforced[direction] = unenforced.get(direction, 0) + n
            unenforced_clear += _int(extra.get("govt_no_tls_messages"))
            unenforced_days = max(unenforced_days, _int(extra.get("govt_days")))
        for name, count in _distribution(
                str(extra.get("govt_tls_distribution") or "")).items():
            if name.strip().lower() != "none":
                versions[name] = versions.get(name, 0) + count

    total = sum(totals.values())
    domain_tally = max(
        [_int((_get(a, "extra") or {}).get("govt_counterparty_domains_total"))
         for a in assets if _get(a, "source") == _SENDING_SOURCE]
        + [_int((_get(a, "extra") or {}).get("govt_counterparty_domains"))
           for a in paths] or [0])
    window = _sending_window(assets)
    evidence_names = EVIDENCE_SEPARATOR.join(str(_get(a, "name") or "") for a in paths)
    if not total:
        return _unmeasured(
            req, _ITLS_SUBJECT, INCONCLUSIVE,
            "the per-message mail transport export was read and carries no message "
            "to or from a government counterparty" + window + ", identified by "
            + (classifier or "counterparty domain") + " — so this requirement's "
            "population is empty in what was read rather than measured and clean")

    split = ", ".join(f"{n:,} {d}" for d, n in sorted(totals.items(),
                                                      key=lambda kv: -kv[1]))
    total_clear = sum(clear.values())
    measured = (
        f"The organisation exchanged {total:,} messages with government counterparties across "
        f"{domain_tally:,} of their domains{window} ({split}; counterparties "
        f"identified by {classifier or 'counterparty domain'}), and "
        + (f"{total_clear:,} of them crossed with no transport encryption at all"
           if total_clear else
           "every one of them was carried under TLS 1.2 or better, with none in "
           "the clear")
        + ".")
    shortfall = (
        f" That is a necessary condition for this requirement rather than the "
        f"requirement itself. {_ITLS_GLOSS}. Neither the per-message export nor "
        f"a per-route report, where the platform keeps one, records the port or how "
        f"a session was established, so a forced-STARTTLS path and an Implicit TLS "
        f"path are written identically and what was read cannot tell them apart.")
    applicability = (
        " Whether the requirement binds the organisation is also open: the TLS "
        "Deployment Guide makes Implicit TLS mandatory between SGE Restricted Group "
        "members, and nothing read here establishes membership.")
    unenforced_total = sum(unenforced.values())
    enforcement = ""
    if unenforced_total:
        enforcement = (
            f" One part of the population is measured rather than inferred: "
            f"{unenforced_total:,} of those {total:,} messages, on at least "
            f"{unenforced_days:,} separate days of the window, travelled on a path with no "
            f"configured route (a connector or relay definition) governing them, where "
            f"transport security is negotiated with each peer rather than required by "
            f"a routing policy"
            + (f" — and that path carried {unenforced_clear:,} of the cleartext "
               f"deliveries" if unenforced_clear else "")
            + ".")
    parts = [f"{v}={n:,}" for v, n in sorted(versions.items(), key=lambda kv: -kv[1])]
    if evidence_names:
        parts.append(f"read from {evidence_names}")
    distribution = "; ".join(parts)
    closes = (
        " What would close this row: written confirmation of the organisation's SGE "
        "Restricted Group membership status, and — where it applies, and where the "
        "platform routes mail through configured connectors or a relay — the full "
        "definitions of the routes carrying government traffic, including the relay "
        "hosts and ports, which is the record that says how the session is "
        "established. Both are administrative reads, not probes.")
    return Conformance(
        req["id"], req["title"], req["level"], req["scope"], _ITLS_SUBJECT,
        NOT_MEASURED, reason=INCONCLUSIVE,
        observed=(f"{total:,} messages with government organisations, "
                  f"{total_clear:,} with no TLS"),
        evidence=measured + shortfall + applicability + enforcement + closes,
        source=req["source"], record=distribution)


def _int(value: Any) -> int:
    try:
        return int(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        return 0


def _distribution(value: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in value.split(";"):
        name, _, count = part.rpartition("=")
        if name.strip():
            out[name.strip()] = out.get(name.strip(), 0) + _int(count)
    return out


def _sending_window(assets: list[Any]) -> str:
    for a in assets:
        if _get(a, "source") != _SENDING_SOURCE:
            continue
        window = str((_get(a, "extra") or {}).get("window") or "").strip()
        if window:
            return f" over the window the export covers, {window}"
    return ""


#: The port an inbound sender delivers to, on which STARTTLS (RFC 3207) is
#: offered: SMTP relay, port 25 (RFC 5321 §4.5.4, under Receiving Strategy).
SMTP_RELAY_PORT = "25"


def _mx_named(assets: list[Any], domains: list[str]) -> dict[str, list[str]]:
    """Each mail host the domains' MX records name, with the domains naming it.

    A null MX (``0 .``, RFC 7505) names no host and is left out.
    """
    named: dict[str, list[str]] = {}
    for d in domains:
        for a in _by(assets, "mx", d):
            for rec in (_get(a, "extra") or {}).get("records", []) or []:
                m = re.search(r"(\d+\s+)?([\w.-]+?)\.?$", str(rec).strip())
                host = m.group(2).lower().strip(".") if m else ""
                if host and d not in named.setdefault(host, []):
                    named[host].append(d)
    return named


def _mail_hosts(assets: list[Any], domains: list[str]) -> dict[str, Any]:
    """The STARTTLS probe row of each MX host, on port 25 only.

    A TLS row for the same host on another port reads a different service (a
    web server, or a submission port), and a row with no port is not a probe
    at all (a certificate-transparency record of the name, for example), so
    neither says what an inbound sender is offered.
    """
    named = _mx_named(assets, domains)
    out: dict[str, Any] = {}
    for a in assets:
        host = str(_get(a, "host") or "").lower()
        if host not in named or _get(a, "protocol") != "tls":
            continue
        if str(_get(a, "port") or "").strip() != SMTP_RELAY_PORT:
            continue
        if host in out and not _get(a, "protocol_versions"):
            continue
        out[host] = a
    return out


def _unprobed_mx(req: dict, host: str, domains: list[str], assets: list[Any]) -> Conformance:
    """The row for an MX host the observation holds no port-25 probe of."""
    other = sorted({str(_get(a, "port") or "") for a in _by(assets, "tls", host)}
                   - {"", SMTP_RELAY_PORT})
    return _unmeasured(
        req, host, NOT_COLLECTED,
        f"published as an MX host of {', '.join(domains)}, and this observation holds no "
        "STARTTLS probe of it on port 25, so the TLS versions it offers an inbound sender "
        "were not read; listing it under scan_targets.smtp_25 and running with --scan "
        "reads them"
        + (f". TLS rows for it on port(s) {', '.join(other)} read another service and are "
           "not used" if other else ""))


def _discovered_subdomains(assets: list[Any], domain: str) -> list[str]:
    out = set()
    suffix = "." + domain.lower().strip(".")
    for a in assets:
        if _get(a, "data_state") != "discovery":
            continue
        host = str(_get(a, "host") or "").lower().strip(".")
        if host.endswith(suffix):
            out.add(host)
    return sorted(out)


def _subdomain_limit(assets: list[Any], domains: list[str], record: str,
                     wired: bool = False, owed: str | None = None) -> str:
    counts = {d: len(_discovered_subdomains(assets, d)) for d in domains}
    total = sum(counts.values())
    if owed is None:
        owed = ("this observation carries no reading from that sweep — a run with the "
                "sub-domain sweep reads it"
                if wired else
                "reading the record over that list needs one DNS lookup per name")
    if not total:
        return ("no sub-domain names have been enumerated in this run, so the "
                f"{record} record on each of them is unread; certificate-transparency "
                "enumeration is the route already built for this and produced nothing "
                "here")
    where = (f"under {domains[0]}" if len(domains) == 1 else
             f"across {len([d for d in counts if counts[d]])} of the {len(domains)} "
             f"domains ({max(counts.values())} of them under "
             f"{max(counts, key=lambda d: counts[d])} alone)")
    return (f"{total} sub-domain name(s) {where} are already enumerated in this run "
            f"from certificate transparency, and {owed}. What that would still not "
            "prove: certificate transparency lists names that appeared in a public "
            "certificate, and a sub-domain needing a denying record is exactly one "
            "nobody serves TLS on, so even a complete join would bound this "
            "requirement rather than close it")


def _dmarc_record(asset: Any) -> str:
    if _absent(asset):
        return ""
    return str((_get(asset, "extra") or {}).get("record") or _get(asset, "notes") or "")


def _dmarc_tags(record: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in record.strip().strip('"').split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            out[key.strip().lower()] = value.strip()
    return out


def _eval_dmarc_reporting(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        record = _dmarc_record(a)
        rua = _dmarc_tags(record).get("rua", "")
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no DMARC record",
                reason=("the domain publishes no DMARC record, so no receiver sends an "
                        "aggregate report anywhere and no reporting tool can be receiving "
                        "one. " + _settled_by(a)),
                evidence=str(_get(a, "name") or ""), source=req["source"]))
            continue
        if not rua:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no rua= address",
                reason=("the DMARC record publishes no aggregate reporting address, so "
                        "no receiver sends a report anywhere and no reporting tool can be "
                        "receiving one"),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
            continue
        hosts = sorted({m.group(1).lower() for m in re.finditer(r"@([\w.-]+)", rua)})
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"reports addressed to {', '.join(hosts) or rua}",
            reason=NO_INSTRUMENT,
            evidence=("aggregate reports are addressed to a published reporting "
                      "destination, which is consistent with a reporting tool but does "
                      "not show that one processes them or that anyone reads its output; "
                      "that is inside the organisation and cannot be seen from here"),
            source=req["source"], record=record))
    return rows


def _eval_spf_alignment(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no DMARC record",
                reason=("the domain publishes no DMARC record, so no alignment is "
                        "published at all; the DMARC guide recommends strict (aspf=s) — a "
                        "recommendation unmet, not a requirement breached. "
                        + _settled_by(a)),
                evidence=str(_get(a, "name") or ""), source=req["source"]))
            continue
        record = _dmarc_record(a)
        tags = _dmarc_tags(record)
        value = tags.get("aspf", "r").lower() or "r"
        if value == "s":
            status, reason = PASS, ""
        else:
            status = FAIL
            reason = ("relaxed SPF alignment is published"
                      + ("" if "aspf" in tags else
                         ", by omitting the tag, which RFC 9989 §4.7 reads as relaxed")
                      + "; the DMARC guide recommends strict (aspf=s) — a recommendation "
                        "unmet, not a requirement breached")
        rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"],
                                d, status, observed=f"aspf={value}", reason=reason,
                                evidence=str(_get(a, "name") or ""), source=req["source"],
                                record=record))
    return rows


def _eval_dmarc_unused_tags(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    unwanted = [str(t).lower() for t in (req.get("tags") or [])]
    rows = []
    for d in domains:
        found = _by(assets, "dmarc", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no DMARC record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(_graded_elsewhere(req, d, "DMARC", "SGE-DMARC-01"))
            continue
        record = _dmarc_record(a)
        tags = _dmarc_tags(record)
        present = [t for t in unwanted if t in tags]
        if not present:
            status, reason = PASS, ""
        else:
            status = FAIL
            reason = (f"the record publishes {', '.join(present)}, which the DMARC guide "
                      "says should not be used; " + _unused_tags_why(present)
                      + " — a recommendation unmet, not a requirement breached")
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, status,
            observed=("none of " + ", ".join(unwanted)) if not present else
            "; ".join(f"{t}={tags[t]}" for t in present),
            reason=reason, evidence=str(_get(a, "name") or ""), source=req["source"],
            record=record))
    return rows


def _unused_tags_why(present: list[str]) -> str:
    """Why the DMARC guide asks for each of ``present`` to be left out."""
    why = []
    if "ruf" in present or "fo" in present:
        why.append("forensic reporting (ruf, and fo which configures it) is the "
                   "guide's most emphatic case — 'Do not enable RUF reporting' — "
                   "because forensic reports can carry message headers, subjects "
                   "and bodies to a third party")
    if any(t in present for t in ("pct", "rf", "ri")):
        why.append("pct, rf and ri were removed from DMARC by RFC 9989 (Appendix "
                   "C.5.2), whose tag registry marks them historic (§9.3)")
    return "; ".join(why)


def _eval_dmarc_unused_tags_and_beneath(req: dict, assets: list[Any],
                                        domains: list[str]) -> list[Conformance]:
    """SGE-DMARC-R03 on each email domain's own record, then on the swept names beneath it.

    The swept names' rows take the subject *sub-domains of* the domain
    (:func:`parked_subdomains_subject`), so they never merge with the
    domain's own row.
    """
    beneath = _eval_subdomain_unused_tags(req, assets, domains)
    for row in beneath:
        row.subject = parked_subdomains_subject(row.subject)
    return _eval_dmarc_unused_tags(req, assets, domains) + beneath


def _eval_spf_mechanisms(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    limit = " ".join(str(req.get("partial") or "").split())
    for d in domains:
        found = _by(assets, "spf", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no SPF record was read for this domain"))
            continue
        a = found[0]
        if _absent(a):
            rows.append(_graded_elsewhere(req, d, "SPF", "SGE-SPF-01"))
            continue
        record = str((_get(a, "extra") or {}).get("record") or _get(a, "notes") or "")
        terms = record.strip().strip('"').split()
        ptr = [t for t in terms if re.match(r"^[+\-~?]?ptr(:|$)", t, re.IGNORECASE)]
        ranges = [t for t in terms if re.match(r"^[+\-~?]?ip[46]:", t, re.IGNORECASE)]
        listed = ", ".join(ranges) if ranges else "no ip4 or ip6 ranges"
        if ptr:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=" ".join(ptr),
                reason=("the record uses the ptr mechanism, which the SPF guide says not "
                        "to use — a recommendation unmet, not a requirement breached"),
                evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"no ptr; {listed}", reason=INCONCLUSIVE,
            evidence=("the record uses no ptr mechanism. " + limit).strip(),
            source=req["source"], record=record))
    return rows


def _partial(req: dict) -> str:
    return " ".join(str(req.get("partial") or "").split())


def _mx_host_names(records: list[Any]) -> list[str]:
    """The host names MX records name, lower-cased and sorted.

    A null MX (``0 .``, RFC 7505 §3) names no host and is left out.
    """
    out = []
    for rec in records:
        m = re.search(r"(\d+\s+)?([\w.-]+?)\.?$", str(rec).strip())
        if m and m.group(2).strip("."):
            out.append(m.group(2).lower())
    return sorted(set(out))


def _mx_hosts(assets: list[Any], domain: str) -> list[str] | None:
    found = _by(assets, "mx", domain)
    if not found:
        return None
    return _mx_host_names((_get(found[0], "extra") or {}).get("records", []) or [])


def _mta_sts_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return pattern == host


def _eval_mta_sts_mx(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "mta-sts", d)
        if not found:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no MTA-STS record was read for this domain"))
            continue
        a = found[0]
        extra = _get(a, "extra") or {}
        if "published" in extra and not extra["published"]:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "no _mta-sts TXT record is published, so no policy is ever fetched and "
                "there are no mx entries to compare; the missing record is graded under "
                "SGE-MTASTS-01"))
            continue
        if _mta_sts_policy_faults(extra):
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "the policy fetch gave no valid policy, so it has no mx entries a sender "
                "would apply; that is graded under SGE-MTASTS-01"))
            continue
        if extra.get("policy_reachable") is False:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "the policy file could not be fetched from this machine, so its mx "
                "entries were not read; that is a limit of this instrument, not a "
                "finding about the domain"))
            continue
        if "mx" not in extra:
            rows.append(_unmeasured(
                req, d, NOT_COLLECTED,
                "this observation does not carry the policy file's mx entries, so "
                "they were not compared"))
            continue
        entries = [str(e).strip() for e in (extra.get("mx") or []) if str(e).strip()]
        hosts = _mx_hosts(assets, d)
        if hosts is None:
            rows.append(_unmeasured(req, d, INCONCLUSIVE,
                                    "no MX record reading exists for this domain, so there "
                                    "is nothing to compare the policy's entries with"))
            continue
        wild = [e for e in entries if "*" in e]
        unmatched = [h for h in hosts if not any(_mta_sts_matches(e, h) for e in entries)]
        extra_entries = [e for e in entries
                         if "*" not in e and e.lower().rstrip(".") not in hosts]
        record = f"policy mx: {', '.join(entries) or 'none'}; MX: {', '.join(hosts) or 'none'}"
        faults = []
        if unmatched:
            faults.append(f"the domain's MX host(s) {', '.join(unmatched)} are matched by no "
                          "mx entry in the policy, so a sending server enforcing the policy "
                          "refuses to deliver to them")
        if wild:
            faults.append(f"the policy uses the wildcard entry {', '.join(wild)}, which the "
                          "MTA-STS guide says must not be used")
        aside = (f"the policy also lists {', '.join(extra_entries)}, which the domain does "
                 "not publish as an MX host; the requirement's sentence does not forbid "
                 "that, so it is reported and not graded" if extra_entries else "")
        if faults:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{len(unmatched)} of {len(hosts)} MX host(s) unlisted"
                         + (f"; wildcard {', '.join(wild)}" if wild else ""),
                reason="; ".join(faults), evidence=str(_get(a, "name") or ""),
                source=req["source"], record=record, subject_note=aside))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, PASS,
            observed=f"all {len(hosts)} MX host(s) listed; no wildcard",
            reason=("every MX host the domain publishes is named by an mx entry in the "
                    "policy, and no entry uses a wildcard; read from the published MX "
                    "records and the policy file in the same run"),
            evidence=str(_get(a, "name") or ""), source=req["source"], record=record,
            subject_note=aside))
    return rows


def _eval_spf_legacy(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        found = _by(assets, "spf", d)
        if not found:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "no sender-policy reading exists for this domain, so its TXT records "
                "were not examined for an SPF2.0 record"))
            continue
        a = found[0]
        extra = _get(a, "extra") or {}
        if "legacy_spf2_records" not in extra:
            rows.append(_unmeasured(
                req, d, NOT_COLLECTED,
                "this observation kept only the first v=spf1 record at the domain, so "
                "an SPF2.0 record beside it would not have been seen"))
            continue
        legacy = [str(r).strip().strip('"') for r in (extra.get("legacy_spf2_records") or [])]
        spf1 = list(extra.get("spf_records") or [])
        aside = (f"the domain also publishes {len(spf1)} v=spf1 records where there "
                 "should be one; that is not what this row grades" if len(spf1) > 1 else "")
        if legacy:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{len(legacy)} SPF2.0 record(s)",
                reason=("the domain publishes an SPF2.0 record, which the SPF guide says "
                        "should be removed from DNS — a recommendation unmet, not a "
                        "requirement breached"),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record=" | ".join(legacy), subject_note=aside))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, PASS,
            observed="no SPF2.0 record",
            reason="no SPF2.0 record is published among the TXT records at the domain",
            evidence=str(_get(a, "name") or ""), source=req["source"],
            record=str(extra.get("record") or ""), subject_note=aside))
    return rows


def _eval_dkim_distinct_keys(req: dict, assets: list[Any],
                             domains: list[str]) -> list[Conformance]:
    readings = [a for a in assets if _get(a, "protocol") == "dkim"]
    by_key: dict[str, set[str]] = {}
    for a in readings:
        extra = _get(a, "extra") or {}
        key = str(extra.get("public_key") or "")
        if key:
            by_key.setdefault(key, set()).add(str(extra.get("selector") or ""))
    rows = []
    for d in domains:
        found = _by(assets, "dkim", d)
        if not found:
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                "no DKIM selector answered; the probe tries known selectors, so "
                "this is silence rather than proof that none is published"))
            continue
        if any("public_key" not in (_get(a, "extra") or {}) for a in found):
            rows.append(_unmeasured(
                req, d, NOT_COLLECTED,
                "this observation kept only each DKIM key's size, so two selectors "
                "publishing one key could not be told apart"))
            continue
        selectors = sorted({str((_get(a, "extra") or {}).get("selector") or "")
                            for a in found})
        shared = sorted({
            sel for a in found
            for key in [str((_get(a, "extra") or {}).get("public_key") or "")]
            if key and len(by_key.get(key, set())) > 1
            for sel in by_key[key]})
        evidence = EVIDENCE_SEPARATOR.join(str(_get(a, "name") or "") for a in found)
        if shared:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"one public key under selectors {', '.join(shared)}",
                reason=("the selectors named publish the same public key, so they sign "
                        "with the same private key; the DKIM guide gives each platform its "
                        "own selector and says not to share a private key across services "
                        "— a recommendation unmet, not a requirement breached. What this "
                        "cannot exclude: one platform publishing its key under two names. "
                        + _partial(req)),
                evidence=evidence, source=req["source"]))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"{len(selectors)} selector(s), no key shared",
            reason=INCONCLUSIVE,
            evidence=("no selector that answered shares its public key with any other "
                      "selector read in this run. " + _partial(req)
                      + " No verdict is claimed in either direction."),
            source=req["source"],
            subject_note=f"selector(s) that answered: {', '.join(selectors)}"))
    return rows


def _ned_dmarc_asset(req: dict, assets: list[Any], domain: str
                     ) -> tuple[Any, dict] | Conformance:
    found = _by(assets, "ned-dmarc", domain)
    if not found:
        return _unmeasured(
            req, domain, NOT_COLLECTED,
            "this observation holds no reading of the sub-domains' own DMARC records, "
            "so nothing is graded against this domain; a run with the sub-domain "
            "sweep reads them")
    a = found[0]
    extra = _get(a, "extra") or {}
    if not extra.get("control_usable", False):
        return _unmeasured(req, domain, INCONCLUSIVE, _control_unusable(extra))
    if not _int(extra.get("names_in_scope")):
        return _unmeasured(
            req, domain, NOT_COLLECTED,
            "no sub-domain of this domain was both enumerated and found not to send "
            "mail, so there is nothing here to read the requirement against")
    return a, extra


def _sources_note(extra: dict) -> str:
    """Where the swept names came from, counted by source (a name can have several)."""
    counts = extra.get("names_by_source") or {}
    return ("names from " + ", ".join(f"{src} ({n})" for src, n in counts.items())
            if counts else "")


def _ned_scope_note(extra: dict) -> str:
    note = [f"read {extra.get('read_at', '')} via {', '.join(extra.get('resolvers') or [])}"]
    if _sources_note(extra):
        note.append(_sources_note(extra))
    if _control_note(extra):
        note.append(_control_note(extra))
    if extra.get("names_email_enabled"):
        note.append("excluded as email-enabled, so not read for this: "
                    + ", ".join(extra["names_email_enabled"]))
    if extra.get("names_unread"):
        note.append("NOT READ, so not counted either way: "
                    + ", ".join(extra["names_unread"]))
    if extra.get("names_unsettled"):
        note.append("RESOLVERS DISAGREED, so not counted either way: "
                    + ", ".join(extra["names_unsettled"]))
    if extra.get("names_dropped_by_cap"):
        note.append(f"{extra['names_dropped_by_cap']} further name(s) were beyond the "
                    "sweep's ceiling and were not read")
    return "; ".join(note)


def _eval_subdomain_sp(req: dict, assets: list[Any], domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        got = _ned_dmarc_asset(req, assets, d)
        if isinstance(got, Conformance):
            rows.append(got)
            continue
        a, extra = got
        records = dict(extra.get("dmarc_records") or {})
        with_sp = sorted(n for n, rec in records.items() if "sp" in _dmarc_tags(str(rec)))
        in_scope = _int(extra.get("names_in_scope"))
        if with_sp:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{len(with_sp)} of {in_scope} sub-domains set sp=",
                reason="; ".join([
                    ("a sub-domain beneath this organisational domain publishes its own "
                     "sp= tag, which the DMARC guide says should only ever be set on "
                     "organisation level domains — a recommendation unmet, not a "
                     "requirement breached"),
                    _SWEEP_INSTRUMENT,
                    f"what this row does NOT read: {_partial(req)}"]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record="; ".join(f"{n}: {records[n]}" for n in with_sp),
                subject_note="; ".join([f"sub-domains setting sp=: {', '.join(with_sp)}",
                                        _ned_scope_note(extra)])))
            continue
        whole, why_not = _whole_population(extra)
        if whole:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, PASS,
                observed=f"none of {in_scope} sub-domains sets sp=",
                reason="; ".join(["no sub-domain that shows no sign of sending mail "
                                  "publishes its own sp= tag", whole]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                subject_note=_ned_scope_note(extra)))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"none of {in_scope} sub-domains sets sp=",
            reason=NOT_COLLECTED,
            evidence=("no enumerated sub-domain that shows no sign of sending mail "
                      "publishes its own sp= tag, and that is not the same as none doing "
                      "so. " + _partial(req) + " No verdict is claimed in either direction"
                      + _floor_note(why_not) + "."),
            source=req["source"], subject_note=_ned_scope_note(extra)))
    return rows


def _eval_subdomain_unused_tags(req: dict, assets: list[Any],
                                domains: list[str]) -> list[Conformance]:
    """SGE-DMARC-R03 on the DMARC records the swept names beneath each domain publish.

    Only a name's own record is read: a name without one is given the
    parent's record, which is graded on the parent's own row. A record
    carrying a tag the guide says not to use fails the row; otherwise the row
    is not measured, because the names are a floor. A domain with no sweep
    reading, or no name in scope, gets no row here, since its own row already
    reads the requirement; a sweep whose control could not be trusted is
    reported as inconclusive.
    """
    unwanted = [str(t).lower() for t in (req.get("tags") or [])]
    rows = []
    for d in domains:
        got = _ned_dmarc_asset(req, assets, d)
        if isinstance(got, Conformance):
            if got.reason == INCONCLUSIVE:
                rows.append(got)
            continue
        a, extra = got
        records = dict(extra.get("dmarc_records") or {})
        carrying = {n: present for n in sorted(records)
                    if (present := [t for t in unwanted if t in _dmarc_tags(str(records[n]))])}
        if carrying:
            every = sorted({t for present in carrying.values() for t in present})
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{len(carrying)} of {len(records)} sub-domain records carry "
                         + ", ".join(every),
                reason="; ".join([
                    ("a sub-domain's own DMARC record publishes a tag the DMARC guide says "
                     "should not be used: "
                     + "; ".join(f"{n} ({', '.join(p)})" for n, p in carrying.items())
                     + "; " + _unused_tags_why(every)
                     + " — a recommendation unmet, not a requirement breached"),
                    _SWEEP_INSTRUMENT]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record="; ".join(f"{n}: {records[n]}" for n in carrying),
                subject_note=_ned_scope_note(extra)))
            continue
        whole, why_not = _whole_population(extra)
        if whole:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, PASS,
                observed=f"none of {len(records)} sub-domain records carries them",
                reason="; ".join([
                    "no DMARC record published by a sub-domain that shows no sign of "
                    f"sending mail carries {', '.join(unwanted)}", whole]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                subject_note=_ned_scope_note(extra)))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"none of {len(records)} sub-domain records carries them",
            reason=NOT_COLLECTED,
            evidence=("no DMARC record published by an enumerated sub-domain that shows no "
                      f"sign of sending mail carries {', '.join(unwanted)}, and that is not "
                      "the same as none doing so: " + _SWEEP_POPULATION
                      + ". No verdict is claimed in either direction"
                      + _floor_note(why_not) + "."),
            source=req["source"], subject_note=_ned_scope_note(extra)))
    return rows


def _eval_subdomain_dmarc_alignment(req: dict, assets: list[Any],
                                    domains: list[str]) -> list[Conformance]:
    rows = []
    for d in domains:
        got = _ned_dmarc_asset(req, assets, d)
        if isinstance(got, Conformance):
            rows.append(got)
            continue
        a, extra = got
        records = dict(extra.get("dmarc_records") or {})
        root = _by(assets, "dmarc", d)
        root_record = _dmarc_record(root[0]) if root else ""
        root_tags = _dmarc_tags(root_record)
        in_scope = _int(extra.get("names_in_scope"))

        def short(tags: dict[str, str]) -> list[str]:
            out = []
            if tags.get("adkim", "r").lower() != "s":
                out.append(f"adkim={tags.get('adkim', 'r (by default)')}")
            if tags.get("aspf", "r").lower() != "s":
                out.append(f"aspf={tags.get('aspf', 'r (by default)')}")
            if not tags.get("rua"):
                out.append("no rua=")
            return out

        own_short = {n: short(_dmarc_tags(str(rec))) for n, rec in records.items()}
        own_failing = sorted(n for n, s in own_short.items() if s)
        without_own = in_scope - len(records)
        inherited = short(root_tags) if root_record else ["no DMARC record at all"]
        failing_by_fallback = without_own if (without_own and inherited) else 0
        walked = _walked_policies(assets, d, extra)
        walk_notes: list[str] = []
        if walked is not None:
            governed, unread = walked
            by_record = {n: (at, short(_dmarc_tags(rec)) if rec else ["no DMARC record at all"])
                         for n, (at, rec) in governed.items()}
            failing_by_fallback = sum(1 for _at, s in by_record.values() if s)
            elsewhere = {n: at for n, (at, _s) in by_record.items() if at and at != d}
            walk_notes = _walk_notes(elsewhere, unread)
            if elsewhere:
                inherited = sorted({x for n in elsewhere for x in by_record[n][1]}
                                   | (set(short(root_tags)) if root_record else set()))

        if own_failing or failing_by_fallback:
            parts = []
            if failing_by_fallback:
                parts.append(
                    f"{failing_by_fallback} of the {in_scope} enumerated sub-domain(s) that "
                    "show no sign of sending mail publish no DMARC record of their own, so a "
                    "receiver applies the record policy discovery finds for them (RFC 9989 "
                    f"§4.10.1), which reads {', '.join(inherited)}"
                    if root_record or (walked and any(at for at, _r in walked[0].values()))
                    else
                    f"{without_own} of the {in_scope} enumerated sub-domain(s) publish no "
                    "DMARC record of their own and "
                    + ("the organisational domain publishes no DMARC record for them to "
                       "fall back to" if root and _absent(root[0]) else
                       "no organisational record was read for them to fall back to"))
            if own_failing:
                parts.append(
                    f"{len(own_failing)} publish a record of their own short of it: "
                    + "; ".join(f"{n} ({', '.join(own_short[n])})" for n in own_failing))
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"{failing_by_fallback + len(own_failing)} of {in_scope} "
                         "sub-domains without strict alignment and a reporting address",
                reason="; ".join([
                    ("the framework's record for non-email sub-domains sets strict SPF "
                     "and DKIM alignment and a reporting address — a recommendation "
                     "unmet, not a requirement breached. The stricter reading of 'set "
                     "every sub-domain's record', that each must publish its own, would "
                     "fail a sub-domain with no record of its own outright"),
                    _SWEEP_INSTRUMENT,
                    f"what this row does NOT read: {_partial(req)}"]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                record="; ".join(filter(None, [
                    f"organisational record: {root_record}" if root_record else "",
                    *(f"{n}: {records[n]}" for n in own_failing)])),
                subject_note="; ".join([*parts, *walk_notes, _ned_scope_note(extra)])))
            continue
        whole, why_not = _whole_population(extra, walked[1] if walked else None)
        if whole:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, PASS,
                observed=f"all {in_scope} sub-domains meet it",
                reason="; ".join([
                    "every sub-domain that shows no sign of sending mail carries strict "
                    "alignment and a reporting address, on its own record or the one it "
                    "falls back to", whole]),
                evidence=str(_get(a, "name") or ""), source=req["source"],
                subject_note="; ".join([*walk_notes, _ned_scope_note(extra)])))
            continue
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d, NOT_MEASURED,
            observed=f"all {in_scope - len(walked[1] if walked else [])} sub-domains read "
                     "meet it",
            reason=NOT_COLLECTED,
            evidence=("every enumerated sub-domain that shows no sign of sending mail "
                      "carries strict alignment and a reporting address, on its own "
                      "record or the organisational one it falls back to, and that is not "
                      "the same as every sub-domain doing so. " + _partial(req)
                      + " No verdict is claimed in either direction"
                      + _floor_note(why_not) + "."),
            source=req["source"],
            subject_note="; ".join([*walk_notes, _ned_scope_note(extra)])))
    return rows


def _unmeasured(req: dict, subject: str, reason_kind: str, detail: str) -> Conformance:
    return Conformance(req["id"], req["title"], req["level"], req["scope"], subject,
                       NOT_MEASURED, reason=reason_kind, observed="",
                       evidence=detail, source=req["source"])


# ── Parked domains ───────────────────────────────────────────────────────

def parked_domains(target: dict) -> list[str]:
    """Domains in ``discovery.domains`` and not ``discovery.email_domains``: no mail either way."""
    return dnsevidence.parked_domains(target)


def _is_parked_row(asset: Any) -> bool:
    return bool((_get(asset, "extra") or {}).get("parked"))


def _parked_rows(assets: list[Any], protocol: str, domain: str) -> list[Any]:
    """A parked domain's ``protocol`` rows: those marked parked, else any for that host.

    A row is marked ``extra.parked`` when the collector read the domain as
    parked. An observation taken while the domain was not listed as parked, or
    by a tool that does not mark the rows, can still hold the domain's SPF and
    DMARC rows unmarked. They are the same DNS records, read the same way, so
    they are graded too, and the row says so (:data:`PARKED_UNMARKED_NOTE`);
    without them a breach on the domain would go unseen.
    """
    found = _by(assets, protocol, domain)
    return [a for a in found if _is_parked_row(a)] or found


#: Said beside a parked domain's grade when it was read from a row not marked parked.
PARKED_UNMARKED_NOTE = (
    "read from a row that is not marked as a parked reading: the observation was taken "
    "without this domain listed as parked, or by a tool that does not mark such rows. It "
    "is the same DNS record either way, so it is graded")


def _as_parked(rows: list[Conformance], assets: list[Any] | None = None,
               protocol: str = "") -> list[Conformance]:
    """Mark rows as readings of a parked domain.

    With ``assets`` and ``protocol``, a row graded from a reading not marked
    parked also carries :data:`PARKED_UNMARKED_NOTE`.
    """
    for row in rows:
        row.parked = True
        found = _parked_rows(assets, protocol, row.subject) if assets and protocol else []
        unmarked = PARKED_UNMARKED_NOTE if found and not _is_parked_row(found[0]) else ""
        row.subject_note = "; ".join(x for x in (PARKED_NOTE, row.subject_note, unmarked)
                                     if x)
    return rows


def _parked_unread(req: dict, domain: str, record: str, assets: list[Any]) -> Conformance:
    """The row for a parked domain with no reading of ``record``.

    When the observation holds no parked reading of any domain, it was taken
    without parked readings at all, and the row says so plainly (not
    collected) rather than suggesting a lookup failed.
    """
    if not any(_is_parked_row(a) for a in assets):
        return _unmeasured(
            req, domain, NOT_COLLECTED,
            f"this observation holds no {record} reading of this domain and no parked "
            "reading of any domain, so it was taken without this domain listed as parked, "
            "or by a tool that does not read parked domains; nothing is claimed either way, "
            "and a run with the domain listed as parked reads it")
    return _unmeasured(req, domain, INCONCLUSIVE,
                       f"no {record} reading of this parked domain is in the observation: "
                       "the lookup did not settle, or the DNS collector did not run")


def _eval_parked_spf(req: dict, assets: list[Any], parked: list[str]) -> list[Conformance]:
    rows = []
    for d in parked:
        found = _parked_rows(assets, "spf", d)
        if not found:
            rows.append(_parked_unread(req, d, "SPF", assets))
            continue
        a = found[0]
        record = str((_get(a, "extra") or {}).get("record") or "").strip('"')
        flags = list(_get(a, "flags") or [])
        common = {"evidence": str(_get(a, "name") or ""), "source": req["source"]}
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no SPF record",
                reason=("the domain publishes no v=spf1 record, so nothing denies mail that "
                        "claims to come from it; the framework asks a domain that sends no "
                        "mail for the blank record v=spf1 -all. " + _settled_by(a)),
                **common))
        elif dnsevidence.is_denying_spf(record):
            rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"], d,
                                    PASS, observed="v=spf1 -all", record=record, **common))
        else:
            qualifier = ("-all" if "hardfail-all" in flags else
                         "~all" if "softfail-all" in flags else "no -all")
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed=f"not blank; ends {qualifier}",
                reason=("the record is not the blank v=spf1 -all: "
                        + ("it ends -all but still permits senders, so it says the domain "
                           "sends mail" if qualifier == "-all" else
                           f"it ends {qualifier}, so mail claiming the domain is not denied")),
                record=record, **common))
    return _as_parked(rows, assets, "spf")


def _eval_parked_dmarc(req: dict, assets: list[Any], parked: list[str]) -> list[Conformance]:
    """SGE-NED-DMARC-01 on each parked domain: its own ``p=``, and the ``sp=`` it sets for names beneath.

    The policy is read as for an email domain: ``p=reject`` at ``pct=100``
    passes. A parked domain is then also failed when its record sets ``sp=``
    to anything but ``reject``. The deciding sentence is the requirement's
    own, *"All domains must have a p=reject DMARC policy"* (DMARC guide §3),
    which the framework's §9 extends to *"all non-email domains, sub-domains
    and all new domains"*. A name beneath a parked domain sends no mail
    either, and when it publishes no DMARC record of its own a receiver
    applies the parent's ``sp=``, or ``p=`` when ``sp=`` is absent (RFC 7489
    §6.3; RFC 9989, which obsoletes it, keeps the tag). So ``sp=none`` or
    ``sp=quarantine`` leaves every such name without a reject policy, and an
    absent ``sp=`` inherits ``p=reject``. The framework's further sentence,
    that the requirement *"remains even if the root level domain has
    SP=reject set"*, does not decide this row: it says ``sp=reject`` on the
    parent does not discharge the requirement for the names beneath, so it
    makes ``sp=reject`` necessary, never sufficient. An ``np=`` weaker than
    ``reject`` fails the row too, for names beneath that do not exist
    (:func:`_np_weaker_than_reject`). The names beneath that do exist are read
    by the sub-domain sweep, in their own rows
    (:func:`_eval_parked_subdomain_dmarc`).
    """
    rows = []
    for d in parked:
        found = _parked_rows(assets, "dmarc", d)
        if not found:
            rows.append(_parked_unread(req, d, "DMARC", assets))
            continue
        rows += [_parked_subdomain_policy(row, _dmarc_record(found[0]))
                 for row in _eval_dmarc(req, found, [d])]
    return _as_parked(rows, assets, "dmarc")


def _parked_subdomain_policy(row: Conformance, record: str) -> Conformance:
    """Fail a parked domain's DMARC row whose ``sp=`` or ``np=`` is anything but reject.

    ``sp=`` covers names beneath that exist; ``np=`` covers names that do not
    (see :func:`_np_weaker_than_reject`). Each, when present, is shown in the
    row's ``observed``.
    """
    tags = _dmarc_tags(record)
    sp = tags.get("sp", "")
    reasons = [row.reason]
    for key in ("sp", "np"):
        if tags.get(key):
            row.observed = "; ".join(x for x in [row.observed, f"{key}={tags[key]}"] if x)
    if sp and sp.lower() != "reject":
        reasons.append(
            f"the record sets sp={sp}, so a name beneath this domain that publishes no DMARC "
            "record of its own is not rejected; the domain sends no mail, so neither do the "
            "names beneath it, and the framework applies the p=reject requirement to "
            "sub-domains of non-email domains too")
    reasons.append(_np_weaker_than_reject(tags))
    if any(reasons[1:]):
        row.status = FAIL
        row.reason = "; ".join(x for x in reasons if x)
    return row


def _eval_parked_dmarc_alignment(req: dict, assets: list[Any],
                                 parked: list[str]) -> list[Conformance]:
    rows = []
    for d in parked:
        found = _parked_rows(assets, "dmarc", d)
        if not found:
            rows.append(_parked_unread(req, d, "DMARC", assets))
            continue
        a = found[0]
        if _absent(a):
            rows.append(_graded_elsewhere(req, d, "DMARC", "SGE-NED-DMARC-01"))
            continue
        record = _dmarc_record(a)
        tags = _dmarc_tags(record)
        short = [f"{k}={tags.get(k, 'r (by default)')}" for k in ("adkim", "aspf")
                 if tags.get(k, "r").lower() != "s"]
        if not tags.get("rua"):
            short.append("no rua=")
        rows.append(Conformance(
            req["id"], req["title"], req["level"], req["scope"], d,
            FAIL if short else PASS,
            observed=", ".join(short) or "adkim=s, aspf=s, rua= present",
            reason=("the framework's record for a domain that sends no mail sets strict SPF "
                    "and DKIM alignment and a reporting address; this one reads "
                    + ", ".join(short) + " — a recommendation unmet, not a breach"
                    if short else ""),
            evidence=str(_get(a, "name") or ""), source=req["source"], record=record))
    return _as_parked(rows, assets, "dmarc")


def _eval_parked_spf_legacy(req: dict, assets: list[Any],
                            parked: list[str]) -> list[Conformance]:
    """SGE-SPF-R02 on each parked domain: an SPF2.0 record is removed from DNS.

    Read as for an email domain (:func:`_eval_spf_legacy`), from the TXT
    records the parked domain's SPF reading kept.
    """
    rows = []
    for d in parked:
        found = _parked_rows(assets, "spf", d)
        rows += (_eval_spf_legacy(req, found, [d]) if found
                 else [_parked_unread(req, d, "SPF", assets)])
    return _as_parked(rows, assets, "spf")


def _eval_parked_dmarc_unused_tags(req: dict, assets: list[Any],
                                   parked: list[str]) -> list[Conformance]:
    """SGE-DMARC-R03 on each parked domain's own DMARC record (:func:`_eval_dmarc_unused_tags`)."""
    rows = []
    for d in parked:
        found = _parked_rows(assets, "dmarc", d)
        if not found:
            rows.append(_parked_unread(req, d, "DMARC", assets))
        elif _absent(found[0]):
            rows.append(_graded_elsewhere(req, d, "DMARC", "SGE-NED-DMARC-01"))
        else:
            rows += _eval_dmarc_unused_tags(req, found, [d])
    return _as_parked(rows, assets, "dmarc")


def _eval_parked_dkim(req: dict, assets: list[Any], parked: list[str]) -> list[Conformance]:
    """SGE-NED-DKIM-01 on each parked domain, read at ``*._domainkey.<domain>``.

    Graded in both directions, because the parked domain's own wildcard record
    is read rather than a sample of names: the empty key ``v=DKIM1; p=``
    passes; no DKIM record there, or one carrying a key, fails; a lookup that
    did not settle leaves the row inconclusive. A selector published under its
    own name answers ahead of the wildcard, and selectors cannot be listed, so
    a pass speaks for every selector nobody has published, except one beneath
    a name that exists under ``_domainkey``, which the wildcard does not answer
    (RFC 4592 §2.2.1).
    """
    rows = []
    for d in parked:
        found = _parked_rows(assets, "dkim-wildcard", d)
        if not found:
            rows.append(_parked_unread(req, d, "DKIM", assets))
            continue
        a = found[0]
        at = dnsevidence.dkim_wildcard_name(d)
        declared = str(req.get("record") or "").replace("<domain>", d)
        if declared and declared.lower() != at.lower():
            rows.append(_unmeasured(
                req, d, INCONCLUSIVE,
                f"the standard names {declared} as the record to publish and the reading is of "
                f"{at}, so what was measured is not what the requirement asks about"))
            continue
        record = str((_get(a, "extra") or {}).get("record") or "").strip('"')
        want = dnsevidence.BLANK_DKIM_DISPLAY
        common = {"evidence": str(_get(a, "name") or ""), "source": req["source"]}
        if _absent(a):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="no DKIM record",
                reason=(f"no v=DKIM1 record is published at {at}, so receivers are not told "
                        "that no mail from the domain is ever signed; the framework asks a "
                        f"domain that sends no mail for the blank record {want}. "
                        + _settled_by(a)),
                **common))
        elif dnsevidence.is_blank_dkim(record):
            rows.append(Conformance(req["id"], req["title"], req["level"], req["scope"], d,
                                    PASS, observed=want, record=record, **common))
        else:
            keyed = bool(_dmarc_tags(record).get("p"))
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], d, FAIL,
                observed="not blank; carries a key" if keyed else "not blank; no p= tag",
                reason=(f"the record at {at} is not the blank {want}: "
                        + ("it carries a public key, so a receiver would accept a signature "
                           "made with the matching private key from a domain that sends no "
                           "mail" if keyed else
                           "it has no p= tag, so it does not say the key is revoked")),
                record=record, **common))
    return _as_parked(rows, assets, "dkim-wildcard")


def parked_subdomains_subject(domain: str) -> str:
    """The subject of a row reading the names beneath a parked domain, not the domain itself."""
    return f"sub-domains of {domain}"


def _beneath_parked(rows: list[Conformance]) -> list[Conformance]:
    """Re-subject sweep rows run over parked domains, and mark them parked."""
    for row in rows:
        if row.subject:
            row.subject = parked_subdomains_subject(row.subject)
    return _as_parked(rows)


def _eval_parked_subdomain_dmarc(req: dict, assets: list[Any],
                                 parked: list[str]) -> list[Conformance]:
    """SGE-NED-DMARC-01 on the swept names beneath each parked domain.

    Read as for an email domain's sub-domains (:func:`_ned_dmarc_from_sweep`):
    each name's own record, or the parked domain's own DMARC record as the
    organisational fallback (``sp=`` for a name that exists, ``np=`` for one
    that does not). The parked domain's ``sp=`` and ``np=`` themselves are
    graded on its own row (:func:`_eval_parked_dmarc`), so they are not
    graded a second time here.
    """
    partial = str(req.get("partial") or "").strip()
    rows = []
    for d in parked:
        root = _by(assets, "dmarc", d)
        root_record = _dmarc_record(root[0]) if root else ""
        sp = _dmarc_tags(root_record).get("sp", "")
        rows.append(_ned_dmarc_from_sweep(
            req, assets, d, root_record, sp, partial,
            head=("the parked domain's own sp= and np= are graded on its own row; this row "
                  "reads the names beneath it, which needs each one's own record — ")))
    return rows


#: The evaluator for each requirement that reads parked domains.
_PARKED_EVALUATORS: dict[str, Callable[..., list[Conformance]]] = {
    "SGE-NED-SPF-01": _eval_parked_spf,
    "SGE-NED-DKIM-01": _eval_parked_dkim,
    "SGE-NED-DMARC-01": _eval_parked_dmarc,
    "SGE-NED-DMARC-R01": _eval_parked_dmarc_alignment,
    "SGE-SPF-R02": _eval_parked_spf_legacy,
    "SGE-DMARC-R03": _eval_parked_dmarc_unused_tags,
}

#: The evaluator for each requirement read over the swept names beneath a parked
#: domain. These are the evaluators an email domain's sub-domains are read with,
#: so they keep the same honesty: the names known are a floor, so a missing
#: record proves a breach and any number of conformant names proves nothing,
#: unless the profile attests a zone file complete (:func:`_whole_population`).
_PARKED_SUBDOMAIN_EVALUATORS: dict[str, Callable[..., list[Conformance]]] = {
    "SGE-NED-SPF-01": _eval_ned_spf,
    "SGE-NED-DKIM-01": _eval_ned_dkim,
    "SGE-NED-DMARC-01": _eval_parked_subdomain_dmarc,
    "SGE-NED-DMARC-R01": _eval_subdomain_dmarc_alignment,
    "SGE-DMARC-R05": _eval_subdomain_sp,
    "SGE-DMARC-R03": _eval_subdomain_unused_tags,
}


#: The requirements a parked domain is read against, in the order they are listed.
PARKED_REQUIREMENTS: tuple[str, ...] = tuple(_PARKED_EVALUATORS)

#: The requirements the names beneath a parked domain are read against.
PARKED_SUBDOMAIN_REQUIREMENTS: tuple[str, ...] = tuple(_PARKED_SUBDOMAIN_EVALUATORS)


def _parked_requirement_rows(req: dict, assets: list[Any],
                             parked: list[str]) -> list[Conformance]:
    """Every parked row for ``req``: each parked domain's own record, then the names beneath."""
    if not parked or req.get("measurable") != "observed":
        return []
    rows: list[Conformance] = []
    if req["id"] in _PARKED_EVALUATORS:
        rows += _PARKED_EVALUATORS[req["id"]](req, assets, parked)
    if req["id"] in _PARKED_SUBDOMAIN_EVALUATORS:
        rows += _beneath_parked(_PARKED_SUBDOMAIN_EVALUATORS[req["id"]](req, assets, parked))
    return rows


def _parked_readings(assets: list[Any], parked: list[str]) -> list[ParkedDomain]:
    out = []
    for d in parked:
        found = _parked_rows(assets, "null-mx", d)
        if not found:
            out.append(ParkedDomain(d, observed=(
                "not read: the MX lookup did not settle, or the DNS collector did not run"
                if any(_is_parked_row(a) for a in assets) else
                "not read: this observation holds no parked reading of any domain")))
            continue
        extra = _get(found[0], "extra") or {}
        state = str(extra.get("null_mx") or "")
        out.append(ParkedDomain(d, null_mx=state, observed=NULL_MX_STATES.get(state, state),
                                records=[str(r) for r in extra.get("records") or []],
                                evidence=str(_get(found[0], "name") or "")))
    return out


# ── Discovered sub-domains that handle mail ──────────────────────────────

def discovered_mail_subject(domain: str) -> str:
    """The subject of a row reading the swept names beneath ``domain`` that handle mail."""
    return f"mail-handling sub-domains of {domain}"


#: Said beside every row reading discovered mail-handling sub-domains.
DISCOVERED_NOTE = ("discovered: names the sub-domain sweep found beneath this domain (in "
                   "certificate-transparency logs, supplied zone files, the profile or "
                   "sender policies) and judged to send or receive mail, not domains the "
                   "profile names as email domains; the list is a floor")


def _spf_qualifier(record: str) -> str:
    """How an SPF record ends, read as the collector reads it: -all, ~all, or neither."""
    return "~all" if "~all" in record else "-all" if "-all" in record else ""


#: Why a row reading discovered mail-handling sub-domains never reports conformance.
_MAIL_POPULATION = (
    "the names read are a floor, and an attested-complete zone file would not make them "
    "the whole population this requirement is about: it binds every email-enabled or "
    "email-sending domain, and which names send mail is judged here from what DNS shows "
    "(an MX record, a sender policy that authorises senders, or the parent's sender "
    "policy naming the name), while a name can send mail with none of those. So a "
    "complete list of names is not a complete list of sending domains, and this row can "
    "report a breach and never conformance"
)


def _discovered_rows(req: dict, assets: list[Any], roots: list[str],
                     judge: Callable[[dict, str, dict, str], str]) -> list[Conformance]:
    """One row per root whose sweep holds settled mail-handling names, graded by ``judge``.

    ``judge(req, name, records, root_record)`` returns why the name falls short,
    "" when it meets the requirement, or an :class:`Unsettled` saying why what
    it needs was not read. A name short of it fails the row. A name not
    settled is counted neither way: it is left out of the names read and
    listed, with why, in the row's note. When every name read meets it the
    row is not measured, never met, even where a zone file is attested
    complete (:data:`_MAIL_POPULATION`). When every name is unsettled because
    the observation never read the record (:class:`NotRead`), the row says
    not collected; otherwise inconclusive. A root whose sweep found no such
    name gets no row.

    ``records`` is the name's entry in the sweep row's ``extra.names``, with
    ``policy`` (the DMARC record :func:`policy_record` finds for it) and
    ``dkim_keys_seen`` (every DKIM public key the observation read, with the
    selector names publishing it) added.
    """
    rows = []
    keys_seen = _dkim_keys_seen(assets)
    for d in roots:
        found = _by(assets, "subdomain-mail", d)
        if not found:
            continue
        a = found[0]
        extra = _get(a, "extra") or {}
        names: dict[str, dict] = dict(extra.get("names") or {})
        if not names:
            continue
        subject = discovered_mail_subject(d)
        common = {"evidence": str(_get(a, "name") or ""), "source": req["source"]}
        if not extra.get("control_usable", False):
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], subject, NOT_MEASURED,
                reason=INCONCLUSIVE,
                evidence=(_control_unusable(extra)
                          if extra.get("control_basis") == dnsevidence.RESOLVER_SYNTHESISES
                          else "the sweep's control name answered and no published wildcard "
                          "explains it, so this run cannot tell a record that is absent from "
                          "a resolver that did not reply; nothing is graded from it"),
                source=req["source"], discovered=True))
            continue
        root = _by(assets, "dmarc", d)
        root_record = _dmarc_record(root[0]) if root else ""
        held = held_dmarc(assets, d)
        verdicts = {n: judge(req, n, {**names[n], "dkim_keys_seen": keys_seen,
                                      **({"policy": policy_record(n, held)}
                                         if held.walkable else {})},
                             root_record)
                    for n in sorted(names)}
        unsettled = {n: why for n, why in verdicts.items() if isinstance(why, Unsettled)}
        short = {n: why for n, why in verdicts.items() if why and n not in unsettled}
        settled = [n for n in sorted(names) if n not in unsettled]
        why_mail = "; ".join(f"{n} {names[n].get('because') or 'handles mail'}"
                             for n in sorted(names))
        note = "; ".join(x for x in [
            (f"{len(unsettled)} of the {len(names)} name(s) counted neither way: "
             + "; ".join(f"{n} ({why})" for n, why in unsettled.items()) if unsettled else ""),
            f"read {extra.get('read_at', '')} via {', '.join(extra.get('resolvers') or [])}",
            _control_note(extra), f"why each is read as handling mail: {why_mail}"] if x)
        if not short and not settled:
            never_read = all(isinstance(why, NotRead) for why in unsettled.values())
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], subject, NOT_MEASURED,
                reason=NOT_COLLECTED if never_read else INCONCLUSIVE,
                observed=f"none of {len(names)} settled",
                evidence=("this observation did not read what the requirement needs on these "
                          "names; an observation taken with the sub-domain sweep reads it"
                          if never_read else
                          "no mail-handling sub-domain could be read against this "
                          "requirement, so nothing is graded in either direction"),
                source=req["source"], subject_note=note, discovered=True))
            continue
        if short:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], subject, FAIL,
                observed=f"{len(short)} of {len(settled)} short of it",
                reason="; ".join([
                    "a sub-domain that handles mail is an email domain to a receiver, so the "
                    "rule for email domains applies to it: "
                    + "; ".join(f"{n}: {why}" for n, why in short.items()),
                    _SWEEP_INSTRUMENT]),
                record="; ".join(f"{n}: {_discovered_record(req, names[n])}" for n in short),
                subject_note=note, discovered=True, **common))
        else:
            rows.append(Conformance(
                req["id"], req["title"], req["level"], req["scope"], subject, NOT_MEASURED,
                reason=NOT_COLLECTED, observed=f"all {len(settled)} read meet it",
                evidence=(f"every mail-handling sub-domain read ({', '.join(settled)}) "
                          "meets it, and that is not the same as every one doing so: "
                          + _MAIL_POPULATION + ". No verdict is claimed in either direction"),
                source=req["source"], subject_note=note, discovered=True))
    return rows


def _discovered_record(req: dict, records: dict) -> str:
    """The record a discovered-name row quotes for ``req``: the one its judge read."""
    rid = req["id"]
    if rid.startswith("SGE-MTASTS"):
        sts = records.get("mta_sts") or {}
        mx = ", ".join(sts.get("mx") or [])
        return (f"{sts.get('record') or 'no _mta-sts record'}; policy mode="
                f"{sts.get('mode') or 'unread'}" + (f"; policy mx: {mx}" if mx else "")
                + (f"; MX: {', '.join(_mx_host_names(records.get('mx_records') or []))}"
                   if rid == "SGE-MTASTS-02" else ""))
    if rid.startswith("SGE-TLSRPT"):
        return str((records.get("tls_rpt") or {}).get("record") or "none published")
    if rid.startswith("SGE-DKIM"):
        keys = [k for k in records.get("dkim") or [] if k.get("public_key")]
        return ", ".join(f"selector {k.get('selector')} ({k.get('key_bits') or '?'}-bit)"
                         for k in keys) or "no key answered"
    key = "spf_record" if rid.startswith("SGE-SPF") else "dmarc_record"
    return str(records.get(key) or "none published")


def _judge_spf(req: dict, name: str, records: dict, root_record: str) -> str:
    spf = str(records.get("spf_record") or "")
    if not spf:
        return "publishes no v=spf1 record, so no sender is denied"
    ends = _spf_qualifier(spf)
    return ("" if ends == "-all" else
            "its record ends ~all (softfail), and the standard requires -all" if ends else
            "its record ends neither -all nor ~all, so no sender is denied")


def _governing_dmarc(records: dict, root_record: str) -> tuple[str, str] | Unsettled:
    """The DMARC record a receiver applies to a discovered name, and where it is published.

    The name's own record (published at "the name itself", given as ``""``
    for where); otherwise the record RFC 9989 §4.10.1 discovery finds
    (``records["policy"]``, :func:`policy_record`), or the organisational
    domain's own record (``root_record``) for an observation that holds no
    walk. :data:`NOT_SETTLED` when the walk passes a name that was not read.
    ``("", "")`` when no record applies.
    """
    own = str(records.get("dmarc_record") or "")
    if own:
        return "", own
    if "policy" in records:
        if records["policy"] is UNREAD:
            return NOT_SETTLED
        at, record = records["policy"]
        return str(at), str(record)
    return "", root_record


def _applied_where(at: str, records: dict) -> str:
    """Words for which DMARC record was applied: the name's own, or the one at ``at``."""
    if records.get("dmarc_record"):
        return "its own DMARC record"
    return (f"the DMARC record at {at}, which a receiver applies to it (RFC 9989 §4.10.1)"
            if at else "the organisational domain's DMARC record, which a receiver applies "
            "to it (RFC 9989 §4.10.1)")


def _judge_dmarc(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DMARC-01 on one name: its own record, or the record policy discovery finds.

    A name with no DMARC record of its own is not failed for that alone. A
    receiver applies the record RFC 9989 §4.10.1 discovery finds for it
    (``records["policy"]``, from :func:`policy_record`; the organisational
    record when that is absent): its ``sp=`` for a name that exists, its
    ``np=`` for one that does not, and ``p=`` when those are absent (§4.7).
    A name whose walk passes a name that was not read is :data:`NOT_SETTLED`.
    """
    own = str(records.get("dmarc_record") or "")
    if own:
        tags = _dmarc_tags(own)
        if _rejects(tags, "p"):
            return ""
        return (f"its own record reads p={tags.get('p') or 'absent'}"
                + (f", pct={tags['pct']}" if tags.get("pct") else "")
                + "; the standard requires p=reject on all of its failing mail")
    got = _governing_dmarc(records, root_record)
    if isinstance(got, Unsettled):
        return got
    at, governing = got
    if not governing:
        return ("publishes no DMARC record of its own, and no record at or above it "
                "publishes one for it to fall back to")
    key = "sp" if records.get("exists", True) else "np"
    tags = _dmarc_tags(governing)
    if _rejects(tags, key):
        return ""
    policy = next((f"{k}={tags[k]}" for k in _POLICY_FALLBACK[key] if tags.get(k)), "no policy")
    return (f"publishes no DMARC record of its own, so a receiver applies the {key}= policy "
            f"of the record {'at ' + at if at else 'policy discovery finds'} (RFC 9989 "
            f"§4.10.1, falling back as §4.7 says), which reads {policy}; the standard "
            "requires p=reject")


def _judge_sp_tag(req: dict, name: str, records: dict, root_record: str) -> str:
    own = str(records.get("dmarc_record") or "")
    sp = _dmarc_tags(own).get("sp", "")
    return (f"its own record sets sp={sp}, which the DMARC guide says should only ever be set "
            "on organisation level domains — a recommendation unmet, not a requirement "
            "breached" if sp else "")


def _judge_unused_tags(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DMARC-R03 on one name's own DMARC record; the parent's is graded on its own row."""
    tags = _dmarc_tags(str(records.get("dmarc_record") or ""))
    present = [t for t in (str(x).lower() for x in req.get("tags") or []) if t in tags]
    return (f"its own record publishes {', '.join(present)}, which the DMARC guide says "
            f"should not be used; {_unused_tags_why(present)} — a recommendation unmet, not a "
            "requirement breached" if present else "")


def _judge_dmarc_reporting(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DMARC-04 on one name: the ``rua=`` of the DMARC record a receiver applies to it.

    One-directional, like the email-domain row: no reporting address means no
    reporting tool can be receiving reports; an address proves no tool.
    """
    got = _governing_dmarc(records, root_record)
    if isinstance(got, Unsettled):
        return got
    at, record = got
    if not record:
        return ("publishes no DMARC record of its own and none at or above it applies, so "
                "no receiver sends an aggregate report about mail claiming it and no "
                "reporting tool can be receiving one")
    if _dmarc_tags(record).get("rua"):
        return ""
    return (f"{_applied_where(at, records)} publishes no rua= aggregate reporting address, "
            "so no receiver sends a report about mail claiming it and no reporting tool can "
            "be receiving one")


def _judge_spf_alignment(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DMARC-R02 on one name: the ``aspf=`` of the DMARC record a receiver applies to it."""
    got = _governing_dmarc(records, root_record)
    if isinstance(got, Unsettled):
        return got
    at, record = got
    if not record:
        return ("no DMARC record applies to it, so no alignment is published at all; the "
                "DMARC guide recommends strict (aspf=s) — a recommendation unmet, not a "
                "requirement breached")
    tags = _dmarc_tags(record)
    if (tags.get("aspf") or "r").lower() == "s":
        return ""
    return (f"{_applied_where(at, records)} publishes relaxed SPF alignment"
            + ("" if "aspf" in tags else ", by omitting the tag, which RFC 9989 §4.7 reads "
               "as relaxed")
            + "; the DMARC guide recommends strict (aspf=s) — a recommendation unmet, not a "
              "requirement breached")


def _mail_reading(records: dict, key: str, label: str) -> dict | Unsettled:
    """A discovered name's ``key`` reading (``mta_sts``, ``tls_rpt``), or why it was not read."""
    if key in records:
        return dict(records[key] or {})
    why = (records.get("not_read") or {}).get(label)
    if why:
        return Unsettled(f"its {label} lookup did not settle ({why}), so nothing is claimed "
                         "either way")
    return NotRead(f"this observation did not read its {label} record")


def _judge_mta_sts(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-MTASTS-01 on one name, read as :func:`_eval_mta_sts` reads an email domain.

    Fails a missing ``_mta-sts`` record (RFC 8461 §3.1), a policy that is not
    valid (an invalid certificate, a non-200 answer or a redirect, §3.3; a
    missing ``version: STSv1`` or a bad ``max_age``, §3.2), and a mode other
    than enforce. A policy the instrument could not fetch is not settled.
    """
    sts = _mail_reading(records, "mta_sts", "MTA-STS")
    if isinstance(sts, Unsettled):
        return sts
    if not sts.get("published"):
        return ("publishes no _mta-sts TXT record, so no sender fetches a policy for it "
                "(RFC 8461 §3.1) and no mode, enforce or otherwise, is in effect")
    faults = _mta_sts_policy_faults(sts)
    if faults:
        return ("its policy is not valid: " + "; ".join(faults) + ". A sender that holds no "
                "cached policy delivers as though MTA-STS were not implemented (RFC 8461 §3.3)")
    mode = str(sts.get("mode") or "")
    if not mode and sts.get("policy_reachable") is False:
        return Unsettled("its _mta-sts record is published but its policy file could not be "
                         "fetched from this machine, which is a limit of this instrument"
                         + (f"; curl reported: {sts['policy_fetch_error']}"
                            if sts.get("policy_fetch_error") else ""))
    if mode == "enforce":
        return ""
    return (f"its policy mode is {mode or 'unknown'}; only enforce mandates TLS and prevents "
            "a downgrade to sending in the clear")


def _judge_mta_sts_mx(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-MTASTS-02 on one name: its policy's mx lines against its MX records, no wildcards."""
    sts = _mail_reading(records, "mta_sts", "MTA-STS")
    if isinstance(sts, Unsettled):
        return sts
    if not sts.get("published") or _mta_sts_policy_faults(sts):
        return Unsettled("it has no valid MTA-STS policy, so there are no mx entries a sender "
                         "would apply; that is graded under SGE-MTASTS-01")
    if sts.get("policy_reachable") is False:
        return Unsettled("its policy file could not be fetched from this machine, so its mx "
                         "entries were not read")
    entries = [str(e).strip() for e in sts.get("mx") or [] if str(e).strip()]
    hosts = _mx_host_names(records.get("mx_records") or [])
    wild = [e for e in entries if "*" in e]
    unmatched = [h for h in hosts if not any(_mta_sts_matches(e, h) for e in entries)]
    faults = []
    if unmatched:
        faults.append(f"its MX host(s) {', '.join(unmatched)} are matched by no mx entry in "
                      "its policy, so a sending server enforcing the policy refuses to deliver "
                      "to them")
    if wild:
        faults.append(f"its policy uses the wildcard entry {', '.join(wild)}, which the "
                      "MTA-STS guide says must not be used")
    return "; ".join(faults)


def _judge_tls_rpt(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-TLSRPT-01 on one name: a ``v=TLSRPTv1`` record with a ``rua=`` at ``_smtp._tls``."""
    rpt = _mail_reading(records, "tls_rpt", "TLS-RPT")
    if isinstance(rpt, Unsettled):
        return rpt
    if not rpt.get("published"):
        return ("publishes no _smtp._tls TXT record (RFC 8460 §3), so TLS Reporting is not "
                "enabled for it")
    if not re.search(r"rua=([^;\s]+)", str(rpt.get("record") or "")):
        return ("its v=TLSRPTv1 record carries no rua= reporting address, so a report has "
                "nowhere to go; the standard's expected value is "
                "'v=TLSRPTv1; rua=mailto:<address>'")
    return ""


def _dkim_reading(records: dict) -> list[dict] | Unsettled:
    """The DKIM keys that answered at a discovered name, or why there are none to read.

    An answer with the empty key ``v=DKIM1; p=`` publishes no key, and is left
    out. No key at all is not settled, never a pass or a fail: selector names
    cannot be listed, so silence under the selectors tried proves nothing.
    """
    if "dkim" not in records:
        return NotRead("this observation did not read its DKIM selectors")
    answered = list(records.get("dkim") or [])
    keys = [k for k in answered if k.get("public_key")]
    if keys:
        return keys
    if answered:
        return Unsettled("every selector that answered gives the empty key v=DKIM1; p=, "
                         "which publishes no key")
    tried = records.get("dkim_selectors_tried")
    return Unsettled(f"none of the {tried or 'known'} selector(s) tried answered; selector "
                     "names cannot be listed, so this is silence rather than proof that no "
                     "key is published")


def _judge_dkim_keysize(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DKIM-R01 on one name: each key found under a known selector is at least 2048-bit."""
    keys = _dkim_reading(records)
    if isinstance(keys, Unsettled):
        return keys
    minimum = int(req.get("minimum_bits", 2048))
    weak = [k for k in keys if k.get("key_bits") and int(k["key_bits"]) < minimum]
    if weak:
        named = ", ".join(f"{k.get('selector')} ({k.get('key_bits')}-bit)" for k in weak)
        return (f"selector(s) {named} publish an RSA key below the {minimum}-bit the DKIM "
                "guide strongly recommends — permitted on legacy systems, so a "
                "recommendation unmet rather than a requirement breached")
    if any(not k.get("key_bits") for k in keys):
        return Unsettled("a selector answered with a key whose size could not be read")
    return ""


def _dkim_keys_seen(assets: list[Any]) -> dict[str, list[str]]:
    """Every DKIM public key the observation read, with the selector names that publish it.

    From the email domains' DKIM rows and the mail-handling sub-domains' readings.
    """
    seen: dict[str, set[str]] = {}
    for a in _by(assets, "dkim"):
        extra = _get(a, "extra") or {}
        if extra.get("public_key"):
            seen.setdefault(str(extra["public_key"]), set()).add(str(extra.get("selector") or ""))
    for a in _by(assets, "subdomain-mail"):
        for rec in ((_get(a, "extra") or {}).get("names") or {}).values():
            for k in (rec or {}).get("dkim") or []:
                if k.get("public_key"):
                    seen.setdefault(str(k["public_key"]), set()).add(str(k.get("selector") or ""))
    return {k: sorted(v) for k, v in seen.items()}


def _judge_dkim_distinct_keys(req: dict, name: str, records: dict, root_record: str) -> str:
    """SGE-DKIM-R02 on one name: no key of its own is published under another selector name.

    Read as :func:`_eval_dkim_distinct_keys` reads an email domain, across
    every key the observation holds (``records["dkim_keys_seen"]``).
    """
    keys = _dkim_reading(records)
    if isinstance(keys, Unsettled):
        return keys
    seen = records.get("dkim_keys_seen") or {}
    shared = sorted({sel for k in keys for sel in seen.get(str(k["public_key"]), [])
                     if len(seen.get(str(k["public_key"]), [])) > 1})
    if not shared:
        return ""
    return (f"the selectors {', '.join(shared)} publish one public key, so they sign with one "
            "private key; the DKIM guide gives each platform its own selector and says not "
            "to share a private key across services — a recommendation unmet, not a "
            "requirement breached")


#: The judge for each requirement read on discovered mail-handling sub-domains,
#: from the records the sweep holds (SPF, DMARC and MX) and the MTA-STS, TLS-RPT
#: and DKIM readings taken of each such name (``ct_dns.read_mail_subdomains``).
#: SGE-DMARC-R01 is left out: its email-domain row never fails, because whether a
#: domain sends bulk mail is not visible, and these rows can only fail.
_DISCOVERED_JUDGES: dict[str, Callable[[dict, str, dict, str], str]] = {
    "SGE-SPF-01": _judge_spf,
    "SGE-DMARC-01": _judge_dmarc,
    "SGE-DMARC-R05": _judge_sp_tag,
    "SGE-DMARC-R03": _judge_unused_tags,
    "SGE-DMARC-04": _judge_dmarc_reporting,
    "SGE-DMARC-R02": _judge_spf_alignment,
    "SGE-MTASTS-01": _judge_mta_sts,
    "SGE-MTASTS-02": _judge_mta_sts_mx,
    "SGE-TLSRPT-01": _judge_tls_rpt,
    "SGE-DKIM-R01": _judge_dkim_keysize,
    "SGE-DKIM-R02": _judge_dkim_distinct_keys,
}

#: The requirements discovered mail-handling sub-domains are read against.
DISCOVERED_REQUIREMENTS: tuple[str, ...] = tuple(_DISCOVERED_JUDGES)


def _discovered_requirement_rows(req: dict, assets: list[Any], domains: list[str],
                                 parked: list[str]) -> list[Conformance]:
    """Rows for ``req`` on the mail-handling sub-domains beneath email and parked domains."""
    judge = _DISCOVERED_JUDGES.get(req["id"])
    if judge is None or req.get("measurable") != "observed":
        return []
    rows = _discovered_rows(req, assets, list(domains), judge)
    beneath_parked = _discovered_rows(req, assets, list(parked), judge)
    for row in [*rows, *beneath_parked]:
        row.subject_note = "; ".join(x for x in (DISCOVERED_NOTE, row.subject_note) if x)
    return rows + _as_parked(beneath_parked)


#: The evaluator for each observable requirement.
_EVALUATORS: dict[str, Callable[..., list[Conformance]]] = {
    "SGE-SPF-01": _eval_spf,
    "SGE-DMARC-01": _eval_dmarc,
    "SGE-MTASTS-01": _eval_mta_sts,
    "SGE-DKIM-R01": _eval_dkim_keysize,
    "SGE-DMARC-R01": _eval_dkim_alignment,
    "SGE-TLS-01": _eval_tls_floor,
    "SGE-TLSRPT-01": _eval_tls_rpt,
    "SGE-NED-DMARC-01": _eval_ned_dmarc,
    "SGE-ITLS-01": _eval_implicit_tls,
    "SGE-NED-SPF-01": _eval_ned_spf,
    "SGE-NED-DKIM-01": _eval_ned_dkim,
    "SGE-DMARC-04": _eval_dmarc_reporting,
    "SGE-DMARC-R02": _eval_spf_alignment,
    "SGE-DMARC-R03": _eval_dmarc_unused_tags_and_beneath,
    "SGE-SPF-R01": _eval_spf_mechanisms,
    "SGE-MTASTS-02": _eval_mta_sts_mx,
    "SGE-SPF-R02": _eval_spf_legacy,
    "SGE-DKIM-R02": _eval_dkim_distinct_keys,
    "SGE-DMARC-R05": _eval_subdomain_sp,
    "SGE-NED-DMARC-R01": _eval_subdomain_dmarc_alignment,
}


def _awaiting(req: dict, assets: list[Any], domains: list[str]) -> str:
    return str(req.get("awaiting") or "no collector produces this fact yet").strip()


def citation(std: dict, req: dict) -> str:
    """The source document a requirement was read from: title, version, date, index, digest."""
    key = req.get("document")
    if not key:
        return ""
    d = (std.get("documents") or {}).get(key)
    if not d:
        return ""
    out = str(d.get("title", key))
    if d.get("version"):
        out += f" v{d['version']}"
    if d.get("date"):
        out += f" ({d['date']})"
    if d.get("index"):
        out += f", index {d['index']}"
    if d.get("sha256"):
        out += f", SHA-256 {d['sha256']}…"
    return out


def evaluate(assets: list[Any], domains: list[str], standard: dict | None = None,
             bulk_mail_domains: tuple[str, ...] = (),
             parked: list[str] | tuple[str, ...] = ()) -> Report:
    """Read every requirement against ``assets`` for the email ``domains``.

    ``bulk_mail_domains`` are SPF policy domains of bulk-mail providers; a
    sender policy that includes one is noted beside the strict-alignment row.
    ``parked`` are domains that send and receive no mail (:func:`parked_domains`):
    each is read against the requirements for such domains, in rows marked
    ``parked``, and its null MX reading goes in :attr:`Report.parked`. The
    swept names beneath each are read in further rows marked ``parked``, with
    :func:`parked_subdomains_subject` as their subject. Swept names beneath an
    email or parked domain that handle mail are read against the rules for
    email domains, in rows marked ``discovered`` with
    :func:`discovered_mail_subject` as their subject.
    """
    std = standard or load_standard()
    parked = list(parked)
    rows: list[Conformance] = []
    for req in std.get("requirements", []):
        parked_rows = _parked_requirement_rows(req, assets, parked)
        measurable = req.get("measurable")
        if measurable == "no-instrument":
            rows.append(_unmeasured(
                req, "", NO_INSTRUMENT,
                req.get("note") or "not observable from outside the organisation"))
            continue
        if measurable == "not-collected":
            detail = _awaiting(req, assets, domains)
            if req.get("scope") == "email-domain":
                rows.extend(_unmeasured(req, d, NOT_COLLECTED, detail) for d in domains)
            else:
                rows.append(_unmeasured(req, "", NOT_COLLECTED, detail))
            continue
        fn = _EVALUATORS.get(req["id"])
        if fn is None:
            rows.append(_unmeasured(req, "", NOT_COLLECTED,
                                    "marked observable but no evaluator is wired for it"))
            continue
        if fn is _eval_dkim_alignment:
            rows.extend(fn(req, assets, domains, bulk_mail_domains))
        else:
            rows.extend(fn(req, assets, domains))
        rows.extend(_discovered_requirement_rows(req, assets, domains, parked))
        rows.extend(parked_rows)
    cites = {r["id"]: citation(std, r) for r in std.get("requirements", [])}
    for row in rows:
        row.citation = cites.get(row.requirement, "")
    return Report(rows=rows, standard=std.get("standard", {}),
                  parked=_parked_readings(assets, parked))


#: The ``standards_verdict`` a row behind an unmet must receives.
NON_CONFORMANT = "non-conformant"

SAME_FACT = ("This is the same finding as the conformance table's row for the "
             "requirement above, seen from the asset rather than from the "
             "standard — one fact, not two.")


def apply_conformance(assets: list[Any], domains: list[str],
                      standard: dict | None = None,
                      bulk_mail_domains: tuple[str, ...] = (),
                      parked: list[str] | tuple[str, ...] = ()) -> int:
    """Evaluate, then mark the rows behind each unmet must; returns how many were marked."""
    if not domains and not parked:
        return 0
    return _mark(assets, evaluate(assets, domains, standard, bulk_mail_domains, parked))


#: Joins several asset names in one conformance row's ``evidence``.
EVIDENCE_SEPARATOR = " · "


def _mark(assets: list[Any], report: Report) -> int:
    by_name: dict[str, list[Conformance]] = {}
    for row in report.breaches():
        for name in str(row.evidence or "").split(EVIDENCE_SEPARATOR):
            if name.strip():
                by_name.setdefault(name.strip(), []).append(row)
    marked = 0
    for a in assets:
        rows = by_name.get(str(_get(a, "name") or ""))
        if not rows:
            continue
        _set(a, "standards_verdict", NON_CONFORMANT)
        _set(a, "standards_requirement", " · ".join(
            f"{r.requirement} ({r.level}) — {r.title}" for r in rows))
        _set(a, "standards_observed", " · ".join(
            filter(None, [" · ".join(r.observed for r in rows if r.observed),
                          next((r.record for r in rows if r.record), "")])))
        _set(a, "standards_citation", " · ".join(
            dict.fromkeys(r.citation for r in rows if r.citation)))
        marked += 1
    return marked


def _format(report: Report, domains: list[str]) -> str:
    std = report.standard
    counts = report.counts()
    out = [
        f"{std.get('name', 'Secure Government Email')} v{std.get('version', '?')}"
        " — conformance",
        f"deadline {std.get('deadline', '')} · {len(domains)} domain(s) · "
        f"{counts[PASS]} pass · {counts[FAIL]} fail · {counts[NOT_MEASURED]} not measured",
        "",
    ]
    mark = {PASS: "PASS", FAIL: "FAIL", NOT_MEASURED: "----"}
    for row in report.rows:
        subject = ((row.subject or "(organisation)") + (" (parked)" if row.parked else "")
                   + (" (discovered)" if row.discovered else ""))
        line = f"{mark[row.status]}  {row.requirement:<16} {subject:<26} {row.observed[:44]}"
        out.append(line.rstrip())
        if row.status == NOT_MEASURED:
            out.append(f"      {row.reason}: {row.evidence}")
        elif row.reason:
            out.append(f"      {row.reason}")
    if report.parked:
        out += ["", f"Parked domains ({len(report.parked)}): read against the rules for "
                    "domains that send no mail, in the rows above marked (parked)."]
        for p in report.parked:
            out.append(f"  {p.domain:<26} null MX: {p.observed}")
        out.append("  " + NULL_MX_GUIDANCE)
    breaches = report.breaches()
    out += ["", f"{len(breaches)} unmet MUST requirement(s)."]
    if breaches:
        by_req: dict[str, list[str]] = {}
        for b in breaches:
            by_req.setdefault(f"{b.requirement} — {b.title}", []).append(b.subject)
        for req, subjects in by_req.items():
            out.append(f"  {req}: {', '.join(subjects)}")
    return "\n".join(out)


def bulk_mail_domains(target: dict) -> tuple[str, ...]:
    """Bulk-mail providers' SPF policy domains, from the profile's ``sge.bulk_mail_domains``."""
    own = (target.get("sge") or {}).get("bulk_mail_domains") or []
    return tuple(str(d).strip().lower() for d in own if str(d).strip())


def main(argv: list[str] | None = None) -> int:
    """Print the conformance report for a target's latest (or named) observation.

    Exits 1 when a MUST requirement is unmet, 0 when none is, and 2 for wrong
    arguments or an unreadable input (see :mod:`takestock.exits`).
    """
    return guarded("takestock.sge", _main, argv)


def _main(argv: list[str] | None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="takestock.sge",
                                 description=(__doc__ or "").split("\n")[0])
    ap.add_argument("target", help="target profile name, e.g. the stem of targets/<name>.yaml")
    ap.add_argument("--observation", default="latest",
                    help="observation directory under observations/ (default: latest)")
    ap.add_argument("--json", action="store_true", help="emit rows as JSON")
    args = ap.parse_args(argv)

    from dataclasses import asdict

    cfg = config.load_target(args.target)
    domains = list((cfg.get("discovery") or {}).get("email_domains") or [])
    path = config.observations_dir() / args.observation / "assets.json"
    with path.open() as f:
        assets = json.load(f)

    report = evaluate(assets, domains, bulk_mail_domains=bulk_mail_domains(cfg),
                      parked=parked_domains(cfg))
    if args.json:
        print(json.dumps({"standard": report.standard,
                          "counts": report.counts(),
                          "rows": [asdict(r) for r in report.rows]},
                         indent=2, default=str))
    else:
        print(_format(report, domains))
    return 1 if report.breaches() else 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
