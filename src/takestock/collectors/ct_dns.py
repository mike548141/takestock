"""Certificate transparency and public DNS: names, certificates and mail-authentication records.

Two passive readings, neither of which touches the organisation's hosts:

* **Certificate transparency.** Every publicly trusted certificate is logged.
  For each domain under ``discovery.domains`` this collector pages through a
  certificate-transparency search service (``ct_search_api`` in
  ``data/dns-services.yaml`` or the target's ``dns:`` block), and turns the
  issuances into one ``discovery`` row per name found (with whether it
  resolves over IPv4, IPv6 or both) and one ``certificate`` row for the most
  recent certificate on each name. The raw answers are kept as
  ``raw/ct-<domain>.json`` with a page record beside them, so a later run can
  reuse a complete, recent answer (:mod:`takestock.ctcache`).
* **Mail authentication.** For each domain under ``discovery.email_domains``
  it reads MX, SPF, DMARC, MTA-STS (record and policy file), TLS-RPT and the
  DKIM keys under each selector tried, and then sweeps the sub-domain names
  the transparency read found for the denying SPF, empty DKIM and DMARC
  records a name that sends no mail should publish.

Search services limit how often they may be asked. When one says "wait",
the run can park the remaining domains in a :class:`CTDeferral`, let other
collectors run, and finish them with :func:`resume`.

When no search endpoint is configured, transparency is simply not read: the
failures list then carries a :class:`~takestock.coverage.Gap` saying so
(:func:`not_configured_gap`) rather than a failure, because nothing went
wrong. An endpoint that is configured and does not answer is a failure.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import coverage, ctcache, dnsevidence, roles
from ..model import CryptoAsset, cert_expiry_flag, register_informational_prefixes
from ..util import (
    cert_signature_token,
    days_remaining,
    dig,
    http_get,
    http_json,
    keychain_secret,
    now_date,
    parse_cert_time,
    rsa_key_bits_from_dkim,
)

SOURCE_CT = "Certificate Transparency logs (search service)"
SOURCE_DNS = "Public DNS"

#: Environment variable, then keychain item, holding the search service's API token.
TOKEN_ENV = "TAKESTOCK_CT_TOKEN"
TOKEN_KEYCHAIN_ITEM = "takestock-ct-token"

# Expiry is a property of time passing, not of the estate getting worse.
register_informational_prefixes("expired", "renewal-overdue", "expiry-soon")

#: Receives one progress line at a time.
Progress = Callable[[str], None]

CT_ATTEMPTS = 2
CT_RETRY_BACKOFF_SECONDS = 2.0

CT_PAGE_PAUSE_SECONDS = 1.0
CT_PAGE_PAUSE_MAX_SECONDS = 5.0

#: Pages read for one domain before the collector stops asking.
CT_MAX_PAGES = 40

DNS_PROGRESS_EVERY = 20

#: The wait assumed when a rate-limited answer carries no Retry-After header.
CT_DEFER_DEFAULT_WAIT_SECONDS = 300.0

#: The longest Retry-After a run will honour before giving up on the rest.
CT_DEFER_MAX_WAIT_SECONDS = 900.0

#: How many times one run will wait out the service's window.
CT_MAX_DEFERRALS = 2

# Indirection so tests can drive the clock.
_now: Callable[[], float] = time.monotonic
_wait: Callable[[float], None] = time.sleep


def token() -> str:
    """The search service's API token, or "" to ask anonymously."""
    return os.environ.get(TOKEN_ENV, "").strip() or keychain_secret(TOKEN_KEYCHAIN_ITEM)


def search_endpoint(target: dict) -> str:
    """The configured certificate-transparency search endpoint; "" when none is."""
    return str(dnsevidence.services(target).get("ct_search_api") or "").strip()


@dataclass
class _Cursor:
    """Where one domain's paged read has got to."""

    domain: str
    records: list = field(default_factory=list)
    pages: int = 0
    after: str = ""
    used: set[str] = field(default_factory=set)
    deferrals: int = 0


@dataclass
class CTDeferral:
    """Domains parked by a rate limit, to be finished by :func:`resume`."""

    max_wait: float = CT_DEFER_MAX_WAIT_SECONDS
    max_deferrals: int = CT_MAX_DEFERRALS
    pending: list[_Cursor] = field(default_factory=list)
    resume_at: float = 0.0
    deferrals: int = 0
    given_up: str = ""
    retry_after_seconds: list[float] = field(default_factory=list)
    waited_seconds: float = 0.0
    domains_deferred: set[str] = field(default_factory=set)
    target: dict = field(default_factory=dict)
    raw_dir: Path | None = None
    ref_time: datetime | None = None
    progress: Progress | None = None
    discovered: set[str] = field(default_factory=set)
    ned_pending: bool = False
    api: str = ""

    @property
    def happened(self) -> bool:
        return bool(self.deferrals or self.given_up)

    def offer(self, cursor: _Cursor, resp: dict) -> bool:
        """Park ``cursor`` if the run may still wait; False (and why) once it may not."""
        wait = _retry_after(resp)
        if self.deferrals >= self.max_deferrals:
            self.given_up = (f"still rate-limited after waiting out the search service's "
                             f"window {self.deferrals} time(s) in this run "
                             f"(ct_dns.CT_MAX_DEFERRALS)")
            return False
        if wait > self.max_wait:
            self.given_up = (f"the search service asked for a {wait:.0f}s wait, longer "
                             f"than the {self.max_wait:.0f}s this run will wait "
                             "(ct_dns.CT_DEFER_MAX_WAIT_SECONDS)")
            return False
        self.deferrals += 1
        self.retry_after_seconds.append(wait)
        self.resume_at = max(self.resume_at, _now() + wait)
        self.park(cursor)
        return True

    def park(self, cursor: _Cursor) -> None:
        cursor.deferrals += 1
        self.pending.append(cursor)
        self.domains_deferred.add(cursor.domain)

    def record(self) -> dict:
        """What the deferral did, for the observation's summary."""
        return {
            "deferrals": self.deferrals,
            "max_deferrals": self.max_deferrals,
            "max_wait_seconds": self.max_wait,
            "retry_after_seconds": self.retry_after_seconds,
            "waited_seconds": round(self.waited_seconds, 1),
            "domains_deferred": sorted(self.domains_deferred),
            "outcome": (f"gave up: {self.given_up}" if self.given_up
                        else "every deferred lookup was resumed"),
        }


def _retry_after(resp: dict) -> float:
    raw = str((resp.get("headers") or {}).get("retry-after", "")).strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        return CT_DEFER_DEFAULT_WAIT_SECONDS


def _ct_fetch(url: str, bearer: str, note: Progress,
              attempts: int = CT_ATTEMPTS,
              backoff: float = CT_RETRY_BACKOFF_SECONDS,
              sleep: Callable[[float], None] = time.sleep) -> tuple[object, dict]:
    """GET one page, retrying only when nothing at all came back."""
    payload: object = None
    meta: dict = {}
    for attempt in range(1, attempts + 1):
        resp: dict = {}
        payload = http_json(url, bearer=bearer, meta=resp)
        meta = resp
        if payload is not None or resp.get("status"):
            return payload, meta
        if attempt < attempts:
            wait = backoff * attempt
            note(f"      … no response (attempt {attempt}/{attempts}); retrying in {wait:g}s")
            sleep(wait)
    return payload, meta


def not_configured_gap(domains: int) -> coverage.Gap:
    """The gap for a run with no certificate-transparency endpoint configured."""
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        "not measured: no certificate-transparency search endpoint is configured "
        "(`ct_search_api` in data/dns-services.yaml or the target's `dns:` block), so no "
        f"certificate or name was read from the logs for {domains} domain(s)",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Certificates and published names known only from the logs are missing, so "
                "an endpoint absent from this observation may simply not have been looked "
                "for."),
        harvest="Configure a certificate-transparency search endpoint and run again.",
        nature=coverage.NO_DATA)


def failure_gap(failures: list[str]) -> str:
    """The coverage-gap sentence for domains whose transparency read did not finish."""
    n = len(failures)
    return (f"Certificate Transparency could not be read to the end for {n} domain(s) "
            "— certificates and endpoints for those domains are missing from this "
            "observation, so they are absent because nobody looked, not because "
            "they are gone (the reason for each is in collector_failures)")


@dataclass(frozen=True)
class CTRead:
    """The outcome of reading one domain: names found, and how the read ended."""

    names: dict[str, dict] = field(default_factory=dict)
    failure: str = ""
    partial: str = ""
    pages: int = 0
    records: int = 0
    exhausted: bool = False
    stopped_because: str = ""
    deferred: bool = False

    @property
    def ok(self) -> bool:
        return not self.failure and not self.partial and self.exhausted


def _page_url(api: str, domain: str, after: str = "") -> str:
    url = (f"{api}?domain={quote(domain, safe='')}"
           "&include_subdomains=true&expand=dns_names&expand=issuer&expand=pubkey")
    return f"{url}&after={quote(after, safe='')}" if after else url


@dataclass
class _PagesRead:
    records: list
    pages: int
    exhausted: bool
    stopped: str
    error: str
    rate_limited: bool = False
    resp: dict = field(default_factory=dict)


def _ct_read(cursor: _Cursor, api: str, note: Progress,
             sleep: Callable[[float], None] = time.sleep,
             max_pages: int = 0) -> _PagesRead:
    """Page through the service from ``cursor``, until empty, an error, or the ceiling."""
    domain = cursor.domain
    max_pages = max_pages or CT_MAX_PAGES
    records = cursor.records
    used = cursor.used
    while cursor.pages < max_pages:
        if cursor.pages:
            sleep(min(CT_PAGE_PAUSE_SECONDS * cursor.pages, CT_PAGE_PAUSE_MAX_SECONDS))
        payload, resp = _ct_fetch(_page_url(api, domain, cursor.after), token(), note)
        cursor.pages += 1
        pages = cursor.pages
        where = f"page {pages}"

        limited = resp.get("status") == 429 or (
            isinstance(payload, dict) and payload.get("code") == "rate_limited")
        if limited:
            return _PagesRead(records, pages, False, f"rate-limited on {where}",
                              f"{domain}: Certificate Transparency lookup RATE-LIMITED by "
                              f"the search service on {where}"
                              f"{ctcache.rate_limit_detail(resp)}. "
                              f"Wait and re-run, or set an API token in {TOKEN_ENV}.",
                              rate_limited=True, resp=resp)
        if payload is None:
            return _PagesRead(records, pages, False, f"no response on {where}",
                              f"{domain}: Certificate Transparency lookup failed (no "
                              f"response on {where})")
        if isinstance(payload, dict):
            code = payload.get("code", "error")
            return _PagesRead(records, pages, False, f"error '{code}' on {where}",
                              f"{domain}: Certificate Transparency lookup returned error "
                              f"'{code}' on {where}")
        if not isinstance(payload, list):
            return _PagesRead(records, pages, False, f"unexpected shape on {where}",
                              f"{domain}: Certificate Transparency lookup returned an "
                              f"unexpected shape on {where}")

        if not payload:
            return _PagesRead(records, pages, True, "the endpoint returned an empty page", "")

        records.extend(payload)
        note(f"      … {where}: {len(payload)} issuance(s), {len(records)} so far")

        after = str(payload[-1].get("id") or "")
        if not after:
            return _PagesRead(records, pages, False,
                              "the last record carried no id, so no cursor could be formed", "")
        if after in used:
            return _PagesRead(records, pages, False,
                              f"the cursor did not advance past {where} — the endpoint "
                              "returned a page it had already given", "")
        used.add(after)
        cursor.after = after

    return _PagesRead(records, cursor.pages, False,
                      f"the {max_pages}-page ceiling stopped the read",
                      f"{domain}: Certificate Transparency read stopped at the "
                      f"{max_pages}-page ceiling with {len(records)} record(s) — the "
                      "endpoint had more to give and this collector refused to keep "
                      "asking (ct_dns.CT_MAX_PAGES)")


def _write_page_record(raw_dir: Path | None, domain: str, note: dict) -> None:
    if raw_dir is None:
        return
    (raw_dir / ctcache.pages_name(domain)).write_text(json.dumps(note, indent=2, sort_keys=True))


def _issuer_label(issuer_obj: dict) -> str:
    return str(issuer_obj.get("friendly_name") or issuer_obj.get("name") or "").strip()


def _ct_names(domain: str, raw_dir: Path | None, api: str,
              cached: ctcache.Cached | None = None,
              progress: Progress | None = None,
              deferral: CTDeferral | None = None,
              cursor: _Cursor | None = None) -> CTRead:
    """Read (or reuse) one domain's issuances and index them by name."""
    note: Progress = progress or (lambda _m: None)
    cursor = cursor or _Cursor(domain)
    rate_limited = False
    if cached is not None:
        records: list = list(cached.payload)
        pages, exhausted = 0, True
        stopped = f"reused from {cached.observation}, which read to the end"
        error = ""
        fetched = "reused"
    elif deferral is not None and deferral.given_up:
        records, pages, exhausted = cursor.records, cursor.pages, False
        stopped = "not re-asked: " + deferral.given_up
        error = (f"{domain}: Certificate Transparency lookup NOT COMPLETED — "
                 f"{deferral.given_up}")
        note(f"    · Certificate Transparency: {domain} not asked — {deferral.given_up}")
        fetched = "live"
    else:
        resuming = bool(cursor.pages)
        note(f"    · Certificate Transparency: {'resuming' if resuming else 'asking'} "
             f"about {domain}"
             f"{f' from page {cursor.pages + 1}' if resuming else ''} …")
        started = time.monotonic()
        got = _ct_read(cursor, api, note)
        records, pages, exhausted, stopped, error = (
            got.records, got.pages, got.exhausted, got.stopped, got.error)
        rate_limited = got.rate_limited
        took = time.monotonic() - started
        if rate_limited and deferral is not None and deferral.offer(cursor, got.resp):
            wait = max(0.0, deferral.resume_at - _now())
            note(f"      ↳ search allowance used ({stopped}"
                 f"{ctcache.rate_limit_detail(got.resp)}); {len(records)} issuance(s) held, "
                 f"the rest of {domain} deferred until the window reopens in ~{wait:.0f}s")
            return CTRead(pages=pages, records=len(records), deferred=True,
                          stopped_because=stopped)
        if rate_limited and deferral is not None and deferral.given_up:
            error = f"{error} Not deferred: {deferral.given_up}."
        note(f"      ↳ {len(records)} issuance(s) over {pages} page(s) in {took:.1f}s "
             f"— {'read to the end' if exhausted else 'INCOMPLETE: ' + stopped}")
        fetched = "live"

    if raw_dir and (records or not error):
        (raw_dir / ctcache.raw_name(domain)).write_text(json.dumps(records))
        _write_page_record(raw_dir, domain, {
            "domain": domain,
            "source": fetched,
            "pages": pages,
            "records": len(records),
            "exhausted": exhausted,
            "stopped_because": stopped,
            "last_id": str(records[-1].get("id") or "") if records else "",
            "rate_limit_deferrals": cursor.deferrals,
        })

    if error and not records:
        return CTRead(failure=error, pages=pages, stopped_because=stopped)

    names: dict[str, dict] = {}
    for c in records:
        issuer = _issuer_label(c.get("issuer") or {})
        not_before = parse_cert_time(c.get("not_before", ""))
        for n in c.get("dns_names", []):
            if n == domain or n.endswith("." + domain):
                n = n.removeprefix("*.")
                meta = names.setdefault(n, {"issuers": set(), "current": None, "current_nb": None})
                if issuer:
                    meta["issuers"].add(issuer)
                if not_before and (meta["current_nb"] is None or not_before > meta["current_nb"]):
                    meta["current_nb"] = not_before
                    meta["current"] = c

    partial = ""
    if error:
        partial = (f"{error} — {len(names)} endpoint(s) were still discovered and "
                   "are reported, but this domain's certificate list is INCOMPLETE "
                   "and its counts are a floor, not a total")
    return CTRead(names=names, partial=partial, pages=pages, records=len(records),
                  exhausted=exhausted, stopped_because=stopped)


def _cert_asset(host: str, issuance: dict, ref_time: datetime | None = None,
                collected_at: str = "") -> CryptoAsset | None:
    """A certificate row from one issuance record; None without an expiry date."""
    not_after = parse_cert_time(issuance.get("not_after", ""))
    if not_after is None:
        return None
    remaining = days_remaining(not_after, ref_time)
    not_before = parse_cert_time(issuance.get("not_before", ""))
    lifetime_days = (not_after - not_before).days if not_before else None
    pk = issuance.get("pubkey") or {}
    sig = cert_signature_token(pk.get("type", ""), pk.get("bit_length"), pk.get("curve"))
    issuer_obj = issuance.get("issuer") or {}
    issuer = _issuer_label(issuer_obj)

    flag = cert_expiry_flag(remaining, lifetime_days)
    flags = [flag] if flag else []

    if remaining < 0:
        when = f"expired {not_after.date().isoformat()} ({-remaining}d ago)"
    elif flag == "renewal-overdue":
        when = (f"renewal OVERDUE: expires {not_after.date().isoformat()} ({remaining}d "
                f"remaining) — short-lived certificate past the point its automated "
                f"renewal should already have fired")
    else:
        when = f"expires {not_after.date().isoformat()} ({remaining}d remaining)"
    notes = f"{when}; issuer={issuer}; key={sig or 'unrecognised'}"

    return CryptoAsset(
        name=f"certificate {host}",
        role=roles.certificate(host, roles.classify_host(host)),
        data_state="certificate",
        protocol="tls",
        host=host,
        source="ct_dns",
        source_class="public",
        source_name=SOURCE_CT,
        collected_at=collected_at or now_date(ref_time),
        signatures=[sig] if sig else [],
        flags=flags,
        notes=notes,
        extra={
            "not_before": issuance.get("not_before", ""),
            "not_after": issuance.get("not_after", ""),
            "days_remaining": remaining,
            "issuer": issuer,
            "issuer_dn": str(issuer_obj.get("name") or ""),
            "pubkey": pk,
            "pubkey_sha256": issuance.get("pubkey_sha256", "") or "",
            "cert_sha256": issuance.get("cert_sha256", "") or "",
        },
    )


def collect(
    target: dict, raw_dir: Path | None = None, ref_time: datetime | None = None,
    observations: Path | None = None, refresh: bool = False,
    max_age_days: int = ctcache.CT_CACHE_DAYS,
    progress: Progress | None = None,
    deferral: CTDeferral | None = None,
) -> tuple[list[CryptoAsset], list[str], list[ctcache.Cached]]:
    """Read transparency for every domain and mail records for every email domain.

    Returns (rows, failures, answers reused from earlier observations).
    """
    note: Progress = progress or (lambda _m: None)
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    disc = target.get("discovery", {}) or {}
    reused: list[ctcache.Cached] = []
    api = search_endpoint(target)
    if deferral is not None:
        deferral.api = api

    ct_domains = list(disc.get("domains", []) or [])
    if ct_domains and not api:
        failures.append(not_configured_gap(len(ct_domains)))
        ct_domains = []
    for domain in ct_domains:
        cached = (None if refresh or observations is None
                  else ctcache.find(domain, observations, max_age_days, ref_time))
        ct_date = cached.observed if cached else now_date(ref_time)
        if cached:
            reused.append(cached)
        elif deferral is not None and deferral.pending:
            deferral.park(_Cursor(domain))
            note(f"    · Certificate Transparency: {domain} deferred unasked — the "
                 "search allowance is already used")
            continue
        read = _ct_names(domain, raw_dir, api, cached, progress, deferral=deferral)
        if read.deferred:
            continue
        failures.extend(_read_failures(read))
        assets.extend(_endpoint_assets(domain, read.names, ct_date, ref_time, note))

    discovered = {str(a.host).lower().strip(".") for a in assets
                  if a.data_state == "discovery" and a.host}
    parked = deferral is not None and bool(deferral.pending)
    asked = dnsevidence.resolvers(target)
    selectors = dnsevidence.dkim_selectors(target)

    for domain in disc.get("email_domains", []) or []:
        note(f"    · email-auth DNS records for {domain} …")
        assets.extend(_email_assets(domain, ref_time, selectors))
        if not parked:
            assets.extend(_ned_sweep(domain, discovered, ref_time, note, asked))

    if parked and deferral is not None:
        deferral.target, deferral.raw_dir = target, raw_dir
        deferral.ref_time, deferral.progress = ref_time, progress
        deferral.discovered = discovered
        deferral.ned_pending = bool(disc.get("email_domains"))
        wait = max(0.0, deferral.resume_at - _now())
        note(f"    ↪ search allowance used; resuming {len(deferral.pending)} "
             f"lookup(s) after ~{wait:.0f}s, other collectors running meanwhile"
             + (" (the sub-domain SPF/DKIM sweep waits with them, because its "
                "names come from those lookups)" if deferral.ned_pending else ""))

    return assets, failures, reused


def resume(deferral: CTDeferral) -> tuple[list[CryptoAsset], list[str]]:
    """Finish every parked domain, waiting out the service's window first."""
    note: Progress = deferral.progress or (lambda _m: None)
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    while deferral.pending:
        remaining = min(max(0.0, deferral.resume_at - _now()), deferral.max_wait)
        if deferral.given_up:
            remaining = 0.0
        domains = ", ".join(c.domain for c in deferral.pending)
        if remaining > 0:
            note(f"  · ct_dns: resuming {len(deferral.pending)} deferred Certificate "
                 f"Transparency lookup(s) ({domains}) — waiting ~{remaining:.0f}s more "
                 "for the search service's window")
            _wait(remaining)
            deferral.waited_seconds += remaining
        else:
            note(f"  · ct_dns: resuming {len(deferral.pending)} deferred Certificate "
                 f"Transparency lookup(s) ({domains}) — the window has already passed")
        round_ = deferral.pending
        deferral.pending = []
        for cur in round_:
            # A domain deferred again in this round parks the rest behind it.
            if deferral.pending and not deferral.given_up:
                deferral.park(cur)
                continue
            read = _ct_names(cur.domain, deferral.raw_dir, deferral.api, None,
                             deferral.progress, deferral=deferral, cursor=cur)
            if read.deferred:
                continue
            failures.extend(_read_failures(read))
            new = _endpoint_assets(cur.domain, read.names, now_date(deferral.ref_time),
                                   deferral.ref_time, note)
            assets.extend(new)
            deferral.discovered |= {str(a.host).lower().strip(".") for a in new
                                    if a.data_state == "discovery" and a.host}

    if deferral.ned_pending:
        deferral.ned_pending = False
        asked = dnsevidence.resolvers(deferral.target)
        for domain in (deferral.target.get("discovery", {}) or {}).get("email_domains", []) or []:
            assets.extend(_ned_sweep(domain, deferral.discovered, deferral.ref_time, note,
                                     asked))
    return assets, failures


def _read_failures(read: CTRead) -> list[str]:
    return [m for m in (read.failure, read.partial) if m]


def _endpoint_assets(domain: str, names: dict[str, dict], ct_date: str,
                     ref_time: datetime | None, note: Progress) -> list[CryptoAsset]:
    """A discovery row per name, plus a certificate row for its latest certificate."""
    assets: list[CryptoAsset] = []
    if names:
        note(f"    · resolving {len(names)} endpoint(s) discovered for {domain} over DNS …")
    started = time.monotonic()
    for done, (host, meta) in enumerate(sorted(names.items()), start=1):
        if done % DNS_PROGRESS_EVERY == 0:
            note(f"      … {done}/{len(names)} ({time.monotonic() - started:.0f}s elapsed)")
        stack = _ip_stack(host)
        category = roles.classify_host(host)
        assets.append(CryptoAsset(
            name=f"endpoint {host}",
            role=roles.discovered_endpoint(host, category),
            data_state="discovery",
            protocol="tls",
            host=host,
            source="ct_dns",
            source_class="public",
            source_name=SOURCE_CT,
            collected_at=ct_date,
            notes=f"CT category={category}; issuers={','.join(sorted(meta['issuers']))}; "
                  f"{_stack_note(stack['ip_stack'])}",
            extra={"category": category, "issuers": sorted(meta["issuers"]), **stack},
        ))
        if meta.get("current"):
            cert = _cert_asset(host, meta["current"], ref_time, ct_date)
            if cert:
                assets.append(cert)
    return assets


def _ned_sweep(domain: str, discovered: set[str], ref_time: datetime | None,
               note: Progress, resolvers: tuple[str, ...] = ("",)) -> list[CryptoAsset]:
    beneath = sorted(n for n in discovered if n.endswith("." + domain))
    note(f"    · sub-domain SPF, DKIM and DMARC records under {domain} "
         f"({len(beneath)} name(s), 4 corroborated lookups each) …")
    return _ned_assets(domain, beneath, ref_time, resolvers)


def _ip_stack(host: str) -> dict[str, str]:
    v4 = [a for a in dig(host, "A") if _looks_like_v4(a)]
    v6 = [a for a in dig(host, "AAAA") if ":" in a]
    if v4 and v6:
        stack = "dual-stack"
    elif v4:
        stack = "ipv4-only"
    elif v6:
        stack = "ipv6-only"
    else:
        stack = "unresolved"
    return {"ip_stack": stack,
            "ipv4_addresses": ",".join(v4), "ipv6_addresses": ",".join(v6)}


def _looks_like_v4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _stack_note(stack: str) -> str:
    return {
        "dual-stack": "resolves over both IPv4 and IPv6",
        "ipv4-only": "resolves over IPv4 only",
        "ipv6-only": "resolves over IPv6 ONLY — an active check that probes IPv4 "
                     "addresses never reaches this endpoint",
        "unresolved": "resolves to no address record at all — a name in a Certificate "
                      "Transparency log with nothing behind it publicly",
    }[stack]


def _tls_rpt_record(lines: list[str]) -> tuple[str, bool, str]:
    raw = " ".join(lines).replace('"', "")
    published = "v=TLSRPTv1" in raw
    m = re.search(r"rua=([^;\s]+)", raw)
    return raw, published, (m.group(1) if m else "")


def _email_assets(domain: str, ref_time: datetime | None = None,
                  selectors: list[str] | None = None) -> list[CryptoAsset]:
    """MX, SPF, DMARC, MTA-STS, TLS-RPT and DKIM rows for one email domain."""
    out: list[CryptoAsset] = []
    collected_at = now_date(ref_time)
    common: dict[str, Any] = {"host": domain, "source": "ct_dns", "source_class": "public",
              "source_name": SOURCE_DNS, "collected_at": collected_at,
              "data_state": "email-auth"}

    mx = dig(domain, "MX")
    out.append(CryptoAsset(name=f"MX {domain}", role=roles.email_record("mx", domain),
                           protocol="mx", notes="; ".join(mx) or "none",
                           extra={"records": mx}, **common))

    txt = dig(domain, "TXT")
    spf_records = [t for t in txt if "v=spf1" in t.lower()]
    legacy_spf2 = [t for t in txt if re.search(r"spf2\.0", t, re.I)]
    spf = spf_records[0] if spf_records else ""
    if spf or legacy_spf2:
        flags = []
        if spf:
            flags.append("softfail-all" if "~all" in spf else
                         ("hardfail-all" if "-all" in spf else "neutral-all"))
        if len(spf_records) > 1:
            flags.append("duplicate-spf")
        if legacy_spf2:
            flags.append("legacy-spf2")
        notes = spf.strip('"')[:200] if spf else "no v=spf1 record published"
        if len(spf_records) > 1:
            notes += f"; {len(spf_records)} v=spf1 records published (should be one)"
        if legacy_spf2:
            notes += f"; {len(legacy_spf2)} legacy SPF2.0 record(s) present"
        out.append(CryptoAsset(name=f"SPF {domain}", role=roles.email_record("spf", domain),
                               protocol="spf", flags=flags, notes=notes,
                               extra={"record": spf, "spf_records": spf_records,
                                      "legacy_spf2_records": legacy_spf2}, **common))

    dmarc = dig(f"_dmarc.{domain}", "TXT")
    drec = next((t for t in dmarc if "v=DMARC1" in t), "")
    if drec:
        flags = []
        p = re.search(r"\bp=(\w+)", drec)
        sp = re.search(r"\bsp=(\w+)", drec)
        if p and p.group(1) == "reject":
            flags.append("dmarc-reject")
        if sp and sp.group(1) == "none":
            flags.append("subdomains-unprotected")
        out.append(CryptoAsset(name=f"DMARC {domain}", role=roles.email_record("dmarc", domain),
                               protocol="dmarc", flags=flags, notes=drec.strip('"')[:200],
                               extra={"record": drec}, **common))

    sts = dig(f"_mta-sts.{domain}", "TXT")
    published = any("v=STSv1" in t for t in sts)
    policy = http_get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    reachable = not policy.startswith("__ERROR__")
    mode = re.search(r"mode:\s*(\w+)", policy) if reachable else None
    mx_lines = re.findall(r"(?im)^\s*mx:\s*(\S+)", policy) if reachable else []
    out.append(CryptoAsset(
        name=f"MTA-STS {domain}", role=roles.email_record("mta-sts", domain),
        protocol="mta-sts",
        flags=(["enforce"] if (published and mode and mode.group(1) == "enforce")
               else [] if published else ["no-mta-sts-record"]),
        notes=(f"mode={mode.group(1) if mode else 'unknown'}"
               + (f"; mx={','.join(mx_lines)}" if mx_lines else "") if published
               else "no _mta-sts TXT record published, so no sender fetches a policy"),
        extra={"published": published, "policy_reachable": reachable,
               "mode": mode.group(1) if mode else "",
               "mx": mx_lines,
               "record": " ".join(sts)}, **common))

    rpt, rpt_published, rua = _tls_rpt_record(dig(f"_smtp._tls.{domain}", "TXT"))
    out.append(CryptoAsset(
        name=f"TLS-RPT {domain}", role=roles.email_record("tls-rpt", domain),
        protocol="tls-rpt",
        flags=[] if rpt_published else ["no-tls-reporting"],
        notes=(f"reports to {rua}" if rpt_published and rua else
               "published, no reporting address" if rpt_published else
               "no TLS-RPT record published"),
        extra={"record": rpt, "published": rpt_published}, **common))

    for sel in selectors if selectors is not None else list(dnsevidence.DEFAULT_DKIM_SELECTORS):
        base = f"{sel}._domainkey.{domain}"
        cname = dig(base, "CNAME")
        target_name = cname[0].rstrip(".") if cname else base
        rec = " ".join(dig(target_name, "TXT")).replace('"', "")
        if "p=" not in rec and "DKIM1" not in rec:
            continue
        bits = rsa_key_bits_from_dkim(rec)
        key_match = re.search(r"p=([A-Za-z0-9+/=]*)", rec.replace(" ", ""))
        public_key = key_match.group(1) if key_match else ""
        flags = ["weak-key-1024"] if bits and bits <= 1024 else []
        out.append(CryptoAsset(
            name=f"DKIM {sel}.{domain}", role=roles.email_signing_key(domain, sel),
            protocol="dkim",
            signatures=[f"rsa_{bits}"] if bits else [],
            flags=flags, notes=f"selector={sel}; key~{bits}-bit RSA; via {target_name}",
            extra={"selector": sel, "key_bits": bits, "public_key": public_key},
            **common))

    return out


# Protocol names of the three sub-domain rows (no email: "ned").
NED_SPF = "ned-spf"
NED_DKIM = "ned-dkim"
NED_DMARC = "ned-dmarc"


def _ned_assets(domain: str, names: list[str],
                ref_time: datetime | None = None,
                resolvers: tuple[str, ...] = ("",)) -> list[CryptoAsset]:
    """Three rows summarising a sub-domain sweep: SPF, DKIM, and DMARC on each name."""
    cap = dnsevidence.capture_subdomains(domain, names, resolvers)
    return ned_rows(domain, cap, ref_time)


def ned_rows(domain: str, cap: dict, ref_time: datetime | None = None) -> list[CryptoAsset]:
    """The three sub-domain rows from a :func:`dnsevidence.capture_subdomains` result."""
    collected_at = now_date(ref_time)
    in_scope = [r for r in cap["subdomains"] if not r["email_enabled"] and r["read"]]
    sending = [r["name"] for r in cap["subdomains"] if r["email_enabled"]]
    unread = [r["name"] for r in cap["subdomains"] if not r["read"]]
    shared = {
        "resolvers": cap["resolvers"],
        "tries": cap["tries"],
        "read_at": cap["captured_at"],
        "control_name": cap["control"]["name"],
        "control_rcode": cap["control"]["rcode"],
        "control_usable": cap["control"]["usable"],
        "names_offered": cap["names_offered"],
        "names_dropped_by_cap": cap["names_dropped_by_cap"],
        "names_read": len(cap["subdomains"]) - len(unread),
        "names_unread": unread,
        "names_in_scope": len(in_scope),
        "names_resolving": sum(1 for r in in_scope if r["exists"]),
        "names_email_enabled": sending,
    }
    common: dict[str, Any] = {"host": domain, "source": "ct_dns", "source_class": "public",
              "source_name": SOURCE_DNS, "collected_at": collected_at,
              "data_state": "email-auth"}

    out: list[CryptoAsset] = []
    for protocol, wildcard, conformant_key, want in (
            (NED_SPF, cap["wildcard_spf"], "spf_conformant", dnsevidence.DENYING_SPF_DISPLAY),
            (NED_DKIM, cap["wildcard_dkim"], "dkim_conformant", dnsevidence.BLANK_DKIM_DISPLAY)):
        missing = sorted(r["name"] for r in in_scope if not r[conformant_key])
        covered = shared["names_in_scope"] - len(missing)
        wildcard_ok = (dnsevidence.is_denying_spf(wildcard["record"]) if protocol == NED_SPF
                       else dnsevidence.is_blank_dkim(wildcard["record"]))
        out.append(CryptoAsset(
            name=f"{'SPF' if protocol == NED_SPF else 'DKIM'} on sub-domains of {domain}",
            role=roles.email_record(protocol, domain), protocol=protocol,
            notes=(f"{len(missing)} of {shared['names_in_scope']} enumerated sub-domain "
                   f"name(s) that show no sign of sending mail publish no '{want}' record; "
                   f"wildcard {wildcard['name']} "
                   + ("carries it" if wildcard_ok else "is not published")),
            extra={
                **shared,
                "expected_record": want,
                "wildcard_name": wildcard["name"],
                "wildcard_record": wildcard["record"],
                "wildcard_rcode": wildcard["rcode"],
                "wildcard_agreed": wildcard["agreed"],
                "wildcard_conformant": wildcard_ok,
                "names_with_record": covered,
                "names_without_record": missing,
            }, **common))

    with_dmarc = sorted(r["name"] for r in in_scope if r.get("dmarc_record"))
    with_sp_tag = sorted(r["name"] for r in in_scope
                         if re.search(r"(?:^|;)\s*sp\s*=", r.get("dmarc_record", ""), re.I))
    out.append(CryptoAsset(
        name=f"DMARC on sub-domains of {domain}",
        role=roles.email_record(NED_DMARC, domain), protocol=NED_DMARC,
        notes=(f"{len(with_sp_tag)} of {shared['names_in_scope']} enumerated sub-domain "
               "name(s) that show no sign of sending mail publish their own sp= tag "
               "— which the DMARC guide says should only ever be set on organisational "
               f"domains; {len(with_dmarc)} publish a DMARC record of their own at all"
               if shared["names_in_scope"] else
               "no sub-domain names enumerated to check for their own DMARC record"),
        extra={
            **shared,
            "names_with_own_dmarc": with_dmarc,
            "names_with_sp_tag": with_sp_tag,
            "dmarc_records": {r["name"]: r["dmarc_record"] for r in in_scope
                              if r.get("dmarc_record")},
        }, **common))
    return out
