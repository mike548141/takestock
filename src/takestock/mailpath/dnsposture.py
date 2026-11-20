"""A domain's published mail posture, read from public DNS and its MTA-STS policy.

For each domain: where its mail is received (MX, and whether it publishes a
null MX saying it receives none), who may send as it (SPF, with every
include named as a system), its DMARC policy and where reports go, the DKIM
keys found at the selectors tried, MTA-STS (the TXT record and the policy
file), TLS reporting, BIMI, whether the zone is signed (a DS record at the
parent) and DANE (TLSA records on each MX).

**Limits.** DKIM selectors cannot be listed from DNS: only the selectors
tried are read, so "no key found" means none at those names. The caller
should pass the selectors seen in headers and DMARC reports as well as the
common ones. A resolver answer is one resolver's view at one moment.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .. import spf as spfmod
from ..util import dig, http_get_full, rsa_key_bits_from_dkim
from .systems import Catalogue

COMMON_SELECTORS = ("google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2",
                    "dkim", "mail", "smtp", "mx", "key1", "key2", "sig1", "everlytickey1",
                    "mandrill", "pm", "zendesk1", "zendesk2", "mxvault", "amazonses", "cm",
                    "hs1", "hs2", "sendgrid", "smtpapi", "fm1", "fm2", "fm3", "protonmail")

Resolve = Callable[[str, str], list[str]]


def _txt(lines: list[str]) -> list[str]:
    return [spfmod.join_strings(x) for x in lines]


def _tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


@dataclass
class Posture:
    domain: str
    mx: list[tuple[int, str]] = field(default_factory=list)
    null_mx: bool = False
    mx_systems: list[str] = field(default_factory=list)
    spf: str = ""
    spf_includes: list[str] = field(default_factory=list)
    spf_systems: list[str] = field(default_factory=list)
    spf_all: str = ""
    dmarc: str = ""
    dmarc_tags: dict[str, str] = field(default_factory=dict)
    dmarc_reporting: list[str] = field(default_factory=list)
    dkim: dict[str, str] = field(default_factory=dict)        # selector -> "rsa 2048" etc
    mta_sts_txt: str = ""
    mta_sts_policy: dict[str, object] = field(default_factory=dict)
    tls_rpt: str = ""
    bimi: str = ""
    dnssec: bool = False
    tlsa: dict[str, int] = field(default_factory=dict)        # mx host -> TLSA records

    @property
    def sends(self) -> bool:
        return not (self.spf_all in ("-all",) and not self.spf_includes and not self.dkim_keys)

    @property
    def dkim_keys(self) -> list[str]:
        return [s for s, v in self.dkim.items() if v and "revoked" not in v]

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["mx"] = [f"{p} {h}" for p, h in self.mx]
        return d


def default_resolve(name: str, rtype: str) -> list[str]:
    return dig(name, rtype)


def dkim_key(record: str) -> str:
    tags = _tags(record)
    p = tags.get("p", None)
    if p is None:
        return ""
    if not p:
        return "revoked (empty key)"
    kind = tags.get("k", "rsa").lower()
    if kind == "rsa":
        bits = rsa_key_bits_from_dkim(record)
        return f"rsa {bits}" if bits else "rsa"
    return kind


def read(domain: str, catalogue: Catalogue, selectors: list[str] | None = None,
         resolve: Resolve = default_resolve, fetch_policy: bool = True) -> Posture:
    p = Posture(domain)
    for line in resolve(domain, "MX"):
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            host = parts[1].rstrip(".").lower()
            if host == "":
                p.null_mx = True
            p.mx.append((int(parts[0]), host or "."))
    p.mx.sort()
    if p.mx == [(0, ".")]:
        p.null_mx = True
    p.mx_systems = list(dict.fromkeys(
        catalogue.name_host(h) for _, h in p.mx if h != "."))
    for rec in _txt(resolve(domain, "TXT")):
        if rec.lower().startswith("v=spf1"):
            p.spf = rec
        elif rec.lower().startswith("v=bimi1"):
            p.bimi = rec
    if p.spf:
        for term in p.spf.split()[1:]:
            t = term.lstrip("+-~?")
            if t.lower().startswith(("include:", "redirect=")):
                p.spf_includes.append(re.split(r"[:=]", t, maxsplit=1)[1].lower())
            if t.lower() == "all":
                p.spf_all = term
        p.spf_systems = list(dict.fromkeys(
            catalogue.by_spf_include(i) or i for i in p.spf_includes))
    for rec in _txt(resolve(f"_dmarc.{domain}", "TXT")):
        if rec.lower().startswith("v=dmarc1"):
            p.dmarc = rec
            p.dmarc_tags = _tags(rec)
    for tag in ("rua", "ruf"):
        for uri in p.dmarc_tags.get(tag, "").split(","):
            host = uri.strip().rpartition("@")[2].split("!")[0].lower()
            if host:
                p.dmarc_reporting.append(f"{tag}: {catalogue.by_host(host) or host}")
    tried = list(dict.fromkeys([*(selectors or []), *COMMON_SELECTORS]))
    # A wildcard record answers every selector the same way; read it once.
    probe = f"takestock-wildcard-check._domainkey.{domain}"
    wildcard = next((dkim_key(r) for r in _txt(resolve(probe, "TXT")) if "p=" in r), "")
    if wildcard:
        p.dkim["*"] = f"wildcard: {wildcard}"
        tried = list(selectors or [])
    for sel in tried:
        recs = _txt(resolve(f"{sel}._domainkey.{domain}", "TXT"))
        for rec in recs:
            if "p=" in rec:
                p.dkim[sel] = dkim_key(rec)
                break
    for rec in _txt(resolve(f"_mta-sts.{domain}", "TXT")):
        if rec.lower().startswith("v=stsv1"):
            p.mta_sts_txt = rec
    if p.mta_sts_txt and fetch_policy:
        body, meta = http_get_full(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
        pol: dict[str, object] = {"http_status": meta.get("status")}
        mxs = []
        for line in body.splitlines():
            k, sep, v = line.partition(":")
            if sep and k.strip().lower() in ("version", "mode", "max_age"):
                pol[k.strip().lower()] = v.strip()
            elif sep and k.strip().lower() == "mx":
                mxs.append(v.strip())
        pol["mx"] = mxs
        p.mta_sts_policy = pol
    for rec in _txt(resolve(f"_smtp._tls.{domain}", "TXT")):
        if rec.lower().startswith("v=tlsrptv1"):
            p.tls_rpt = rec
    if not p.bimi:
        for rec in _txt(resolve(f"default._bimi.{domain}", "TXT")):
            if rec.lower().startswith("v=bimi1"):
                p.bimi = rec
    p.dnssec = bool(resolve(domain, "DS"))
    for _, host in p.mx:
        if host != ".":
            p.tlsa[host] = len(resolve(f"_25._tcp.{host}", "TLSA"))
    return p
