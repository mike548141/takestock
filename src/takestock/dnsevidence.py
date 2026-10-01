"""Timestamped, resolver-corroborated DNS and mail-transport evidence.

A DNS answer is a claim made by one resolver at one moment. This module asks
the same question of several resolvers, stamps every answer with when it was
asked and of whom, and reports whether they agreed, so a mail-authentication
finding can be checked later rather than taken on trust.

It also holds the pieces the DNS collectors share:

* :func:`services` and :func:`resolvers`: which public resolvers, control
  zone and search endpoints to use, from ``data/dns-services.yaml`` and the
  target profile's ``dns:`` block;
* :func:`dkim_selectors`: the DKIM selector names to try;
* :func:`capture_subdomains`: the sweep of sub-domain names for the denying
  SPF, empty DKIM and DMARC records a name that sends no mail should carry.

Run as ``python -m takestock.dnsevidence <target>`` for a readable transcript.
"""

from __future__ import annotations

import base64
import concurrent.futures as futures
import datetime
import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from . import config, tls_session
from .util import ERROR_PREFIX, USER_AGENT, run

#: The data file naming the public services DNS collectors use by default.
SERVICES_FILE = "dns-services.yaml"

#: The target-profile key whose mapping overrides the data file, field by field.
TARGET_KEY = "dns"

# DKIM selector names tried when the target profile names none of its own.
# These are common defaults that large mail platforms and mail software
# publish, not any one organisation's choices. A selector is an arbitrary
# label, so no list can be complete: put the organisation's own selectors in
# the target profile as ``discovery.dkim_selectors``.
DEFAULT_DKIM_SELECTORS = (
    "selector1", "selector2",
    "google",
    "default", "dkim", "mail", "smtp",
    "s1", "s2", "k1", "sig1",
)

TLS_VERSIONS = ("tls1", "tls1_1", "tls1_2", "tls1_3")

TLS_LABEL = {"tls1": "TLS 1.0", "tls1_1": "TLS 1.1",
             "tls1_2": "TLS 1.2", "tls1_3": "TLS 1.3"}

#: Versions the Secure Government Email framework forbids on mail connections.
FORBIDDEN_BY_SGE = ("tls1", "tls1_1")

#: How the machine's own resolver is shown where a resolver address would be.
SYSTEM_RESOLVER_LABEL = "system resolver"


def services(target: dict | None = None) -> dict[str, Any]:
    """The public services to use: the data file, overridden by the target's ``dns:``."""
    path = config.data_file(SERVICES_FILE)
    base = config.load_yaml_strict(path) if path.exists() else {}
    own = (target or {}).get(TARGET_KEY) or {}
    if not isinstance(own, dict):
        raise ValueError(f"target `{TARGET_KEY}:` must be a mapping, not {type(own).__name__}")
    return {**base, **{k: v for k, v in own.items() if v not in (None, "", [], {})}}


def resolvers(target: dict | None = None) -> tuple[str, ...]:
    """The resolvers to ask, in order; ``("",)`` (the system resolver) when none is named."""
    named = [str(r).strip() for r in services(target).get("resolvers") or [] if str(r).strip()]
    return tuple(dict.fromkeys(named)) or ("",)


def resolver_label(resolver: str) -> str:
    """A resolver address for display; the empty string reads as the system resolver."""
    return resolver or SYSTEM_RESOLVER_LABEL


def dkim_selectors(target: dict | None = None) -> list[str]:
    """Selectors to try: the profile's own first, then the common defaults."""
    own = ((target or {}).get("discovery") or {}).get("dkim_selectors") or []
    return list(dict.fromkeys([str(s).strip() for s in own if str(s).strip()]
                              + list(DEFAULT_DKIM_SELECTORS)))


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _at(resolver: str) -> list[str]:
    return [f"@{resolver}"] if resolver else []


@dataclass
class Lookup:
    """One question asked of one resolver, with when it was asked and what came back."""

    name: str
    rtype: str
    resolver: str
    at: str
    answers: list[str] = field(default_factory=list)
    error: str = ""
    rcode: str = ""

    @property
    def empty(self) -> bool:
        return not self.error and not self.answers


@dataclass
class Corroborated:
    """The same question asked of several resolvers."""

    name: str
    rtype: str
    lookups: list[Lookup] = field(default_factory=list)

    @property
    def agreed(self) -> bool:
        """True when every resolver that answered gave the same set of records."""
        seen = {tuple(sorted(lk.answers)) for lk in self.lookups if not lk.error}
        return len(seen) <= 1

    @property
    def value(self) -> list[str]:
        """The first answering resolver's records."""
        for lk in self.lookups:
            if not lk.error:
                return lk.answers
        return []

    @property
    def resolvers_asked(self) -> list[str]:
        return [resolver_label(lk.resolver) for lk in self.lookups]

    @property
    def rcode(self) -> str:
        """The response code, when every resolver that gave one agrees; else ""."""
        seen = {lk.rcode for lk in self.lookups if not lk.error and lk.rcode}
        return seen.pop() if len(seen) == 1 else ""


def lookup(name: str, rtype: str, resolver: str) -> Lookup:
    """Ask one resolver for the answer lines only."""
    at = _now()
    out = run(["dig", "+short", "+time=5", "+tries=1", rtype, name, *_at(resolver)],
              timeout=25)
    if out.startswith(ERROR_PREFIX):
        return Lookup(name, rtype, resolver, at, error=out.replace(ERROR_PREFIX, "").strip())
    answers = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return Lookup(name, rtype, resolver, at, answers=answers)


def corroborate(name: str, rtype: str, resolvers: tuple[str, ...] = ("",)) -> Corroborated:
    """Ask every resolver in ``resolvers`` the same question."""
    return Corroborated(name, rtype, [lookup(name, rtype, r) for r in resolvers])


#: Tries and per-try timeout for the sub-domain sweep, which must tell an
#: absent record from a resolver that did not reply.
SWEEP_TRIES = 3
SWEEP_TIMEOUT = 8

#: Concurrent lookups in a sweep.
SWEEP_WORKERS = 6

#: A label nobody registers, asked in the same batch as the real names: it
#: must come back NXDOMAIN, or absences in that batch cannot be trusted.
CONTROL_LABEL = "takestock-absence-control"

# dig prints some types under another name: an HTTPS query is shown as TYPE65
# by older versions.
_ANSWER_TYPES: dict[str, tuple[str, ...]] = {"TYPE65": ("TYPE65", "HTTPS")}


def lookup_status(name: str, rtype: str, resolver: str,
                  tries: int = SWEEP_TRIES, timeout: int = SWEEP_TIMEOUT) -> Lookup:
    """Ask one resolver and keep the response code as well as the answers."""
    at = _now()
    out = run(["dig", f"+time={timeout}", f"+tries={tries}", rtype, name, *_at(resolver)],
              timeout=timeout * tries + 20)
    if out.startswith(ERROR_PREFIX):
        return Lookup(name, rtype, resolver, at, error=out.replace(ERROR_PREFIX, "").strip())
    status = re.search(r"status:\s*(\w+)", out)
    answers = []
    for line in out.splitlines():
        if line.startswith(";") or not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5 and parts[3] in _ANSWER_TYPES.get(rtype, (rtype,)):
            answers.append(parts[4].strip())
    if not status:
        return Lookup(name, rtype, resolver, at,
                      error="no response code in the dig output; the query was not answered")
    return Lookup(name, rtype, resolver, at, answers=answers, rcode=status.group(1))


def corroborate_status(name: str, rtype: str,
                       resolvers: tuple[str, ...] = ("",)) -> Corroborated:
    """:func:`lookup_status` against every resolver."""
    return Corroborated(name, rtype, [lookup_status(name, rtype, r) for r in resolvers])


def _txt_joined(answers: list[str]) -> str:
    joined = " ".join(answers)
    parts = re.findall(r'"([^"]*)"', joined)
    return "".join(parts) if parts else joined.strip()


def _pick_txt(answers: list[str], prefix: str) -> str:
    """The first TXT answer starting with ``prefix`` (case-insensitive), joined."""
    for raw in answers:
        text = _txt_joined([raw])
        if text.lower().startswith(prefix.lower()):
            return text
    return ""


def _starttls(host: str, version: str) -> dict:
    """Offer exactly one TLS version to ``host`` over SMTP STARTTLS on port 25."""
    at = _now()
    try:
        p = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:25",
             "-starttls", "smtp", f"-{version}"],
            capture_output=True, text=True, timeout=30, input="",
        )
    except FileNotFoundError:
        return {"version": version, "at": at, "state": "could-not-ask",
                "detail": "openssl is not on PATH"}
    except subprocess.TimeoutExpired:
        return {"version": version, "at": at, "state": "could-not-ask",
                "detail": "no answer within 30s"}

    out = p.stdout + p.stderr
    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", out, re.M)
    ciph = re.search(r"^\s*Cipher\s*:\s*(\S+)", out, re.M)
    if proto and ciph and ciph.group(1) not in ("0000", "(NONE)"):
        return {"version": version, "at": at, "state": "accepted",
                "protocol": proto.group(1), "cipher": ciph.group(1)}
    if tls_session.CLIENT_CANNOT_OFFER.search(out):
        return {"version": version, "at": at, "state": "could-not-ask",
                "detail": ("the probing openssl would not offer this version at its "
                           "security level, so the server was never asked; "
                           + tls_session.LEGACY_PROTOCOLS_HOW)}
    alert = re.search(r"(alert [a-z ]+|handshake failure|"
                      r"unsupported protocol|wrong version number)", out, re.I)
    if alert:
        return {"version": version, "at": at, "state": "refused",
                "detail": alert.group(1).strip()}
    return {"version": version, "at": at, "state": "could-not-ask",
            "detail": "no handshake and no recognisable refusal"}


def mta_sts_policy(domain: str) -> dict:
    """Fetch the domain's MTA-STS policy file (RFC 8461) and read its fields."""
    at = _now()
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    out = run(["curl", "-sS", "--connect-timeout", "10", "-m", "25",
               "-w", "\\n__HTTP__%{http_code} __TLSVERIFY__%{ssl_verify_result}",
               "-A", USER_AGENT, url], timeout=35)
    if out.startswith(ERROR_PREFIX):
        return {"url": url, "at": at, "state": "could-not-fetch",
                "detail": out.replace(ERROR_PREFIX, "").strip()}
    body = out.split("__HTTP__")[0].strip()
    status = re.search(r"__HTTP__(\d+)", out)
    verify = re.search(r"__TLSVERIFY__(\d+)", out)
    fields: dict[str, Any] = {}
    for line in body.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "mx":
                fields.setdefault("mx", []).append(v)
            else:
                fields[k] = v
    return {
        "url": url, "at": at, "state": "fetched",
        "http_status": int(status.group(1)) if status else 0,
        "certificate_validates": bool(verify and verify.group(1) == "0"),
        "mode": fields.get("mode", ""),
        "max_age": fields.get("max_age", ""),
        "mx": fields.get("mx", []),
        "body": body,
    }


def capture_domain(domain: str, resolvers: tuple[str, ...] = ("",),
                   selectors: list[str] | None = None) -> dict:
    """Every mail-authentication record for ``domain``, corroborated across resolvers."""
    spf_q = corroborate(domain, "TXT", resolvers)
    dmarc_q = corroborate(f"_dmarc.{domain}", "TXT", resolvers)
    sts_q = corroborate(f"_mta-sts.{domain}", "TXT", resolvers)
    rpt_q = corroborate(f"_smtp._tls.{domain}", "TXT", resolvers)
    mx_q = corroborate(domain, "MX", resolvers)

    dkim = []
    for sel in selectors if selectors is not None else list(DEFAULT_DKIM_SELECTORS):
        name = f"{sel}._domainkey.{domain}"
        lk = lookup(name, "TXT", resolvers[0])
        text = _txt_joined(lk.answers)
        if "p=" not in text and "v=DKIM1" not in text:
            continue
        key = re.search(r"p=([A-Za-z0-9+/=]*)", text)
        dkim.append({
            "selector": sel, "name": name, "resolver": resolver_label(lk.resolver),
            "at": lk.at, "record": text,
            "key_bits": _rsa_bits(key.group(1)) if key and key.group(1) else 0,
            "key_present": bool(key and key.group(1)),
        })

    return {
        "domain": domain,
        "spf": {"record": _pick_txt(spf_q.value, "v=spf1"),
                "agreed": spf_q.agreed, "asked": spf_q.resolvers_asked,
                "lookups": [asdict(lk) for lk in spf_q.lookups]},
        "dmarc": {"record": _pick_txt(dmarc_q.value, "v=DMARC1"),
                  "agreed": dmarc_q.agreed, "asked": dmarc_q.resolvers_asked,
                  "lookups": [asdict(lk) for lk in dmarc_q.lookups]},
        "mta_sts_txt": {"record": _pick_txt(sts_q.value, "v=STSv1"),
                        "agreed": sts_q.agreed,
                        "lookups": [asdict(lk) for lk in sts_q.lookups]},
        "tls_rpt": {"record": _pick_txt(rpt_q.value, "v=TLSRPTv1"),
                    "agreed": rpt_q.agreed,
                    "lookups": [asdict(lk) for lk in rpt_q.lookups]},
        "mx": {"records": mx_q.value, "agreed": mx_q.agreed,
               "lookups": [asdict(lk) for lk in mx_q.lookups]},
        "mta_sts_policy": mta_sts_policy(domain),
        "dkim": dkim,
    }


# The records a name that sends no mail should publish, per the Secure
# Government Email framework: an SPF policy authorising nobody, and a DKIM key
# record with an empty key.
DENYING_SPF = "v=spf1 -all"
BLANK_DKIM = "v=dkim1; p="

DENYING_SPF_DISPLAY = "v=spf1 -all"
BLANK_DKIM_DISPLAY = "v=DKIM1; p="

#: The most sub-domain names one sweep reads; the rest are counted, not read.
SWEEP_MAX_NAMES = 400


def spf_wildcard_name(domain: str) -> str:
    """Where a wildcard sender policy covering every sub-domain would be published."""
    return f"*.{domain}"


def dkim_wildcard_name(domain: str) -> str:
    """Where a wildcard DKIM record covering every selector would be published."""
    return f"*._domainkey.{domain}"


def is_denying_spf(record: str) -> bool:
    """True for exactly ``v=spf1 -all`` (spacing and case aside)."""
    return " ".join(record.lower().split()) == DENYING_SPF


def is_blank_dkim(record: str) -> bool:
    """True for a DKIM1 record whose ``p=`` tag is present and empty."""
    tags = {}
    for part in record.split(";"):
        k, _, v = part.partition("=")
        if k.strip():
            tags[k.strip().lower()] = v.strip()
    return tags.get("v", "").lower() == "dkim1" and "p" in tags and tags["p"] == ""


def sender_policy_hosts(record: str) -> list[str]:
    """Hosts an SPF record names directly with ``a:`` or ``mx:``."""
    out = []
    for token in record.split():
        for prefix in ("a:", "mx:"):
            if token.lower().startswith(prefix):
                host = token[len(prefix):].split("/")[0].strip().rstrip(".").lower()
                if host:
                    out.append(host)
    return sorted(set(out))


@dataclass
class SubdomainRecords:
    """What one sub-domain name publishes, and whether it shows signs of sending mail."""

    name: str
    at: str = ""
    resolvers: list[str] = field(default_factory=list)
    rcode: str = ""
    agreed: bool = True
    read: bool = True
    spf_record: str = ""
    mx_records: list[str] = field(default_factory=list)
    dkim_name: str = ""
    dkim_record: str = ""
    dmarc_name: str = ""
    dmarc_record: str = ""
    email_enabled: bool = False
    email_enabled_because: str = ""

    @property
    def exists(self) -> bool:
        return self.rcode != "NXDOMAIN"

    @property
    def spf_conformant(self) -> bool:
        return is_denying_spf(self.spf_record)

    @property
    def dkim_conformant(self) -> bool:
        return is_blank_dkim(self.dkim_record)


def _read_subdomain(name: str, resolvers: tuple[str, ...]) -> SubdomainRecords:
    txt = corroborate_status(name, "TXT", resolvers)
    mx = corroborate_status(name, "MX", resolvers)
    dkim_at = dkim_wildcard_name(name)
    dkim = corroborate_status(dkim_at, "TXT", resolvers)
    dmarc_at = f"_dmarc.{name}"
    dmarc = corroborate_status(dmarc_at, "TXT", resolvers)
    every = [txt, mx, dkim, dmarc]
    return SubdomainRecords(
        name=name,
        at=txt.lookups[0].at if txt.lookups else _now(),
        resolvers=[resolver_label(r) for r in resolvers],
        rcode=txt.rcode,
        agreed=all(q.agreed for q in every),
        read=all(any(not lk.error for lk in q.lookups) for q in every),
        spf_record=_pick_txt(txt.value, "v=spf1"),
        mx_records=list(mx.value),
        dkim_name=dkim_at,
        dkim_record=_pick_txt(dkim.value, "v=DKIM1"),
        dmarc_name=dmarc_at,
        dmarc_record=_pick_txt(dmarc.value, "v=DMARC1"),
    )


def _scope(rec: SubdomainRecords, named_senders: set[str]) -> None:
    """Mark a name as email-enabled when the evidence says it sends or receives mail."""
    if rec.mx_records:
        rec.email_enabled = True
        rec.email_enabled_because = "publishes an MX record, so mail is routed to this name"
    elif rec.name in named_senders:
        rec.email_enabled = True
        rec.email_enabled_because = ("the parent domain's own sender policy names it as a "
                                     "permitted sender, so mail leaves under this name")
    elif rec.spf_record and not rec.spf_conformant:
        rec.email_enabled = True
        rec.email_enabled_because = ("publishes a sender policy that authorises senders "
                                     "rather than denying them")


def _corroborated_block(q: Corroborated, prefix: str) -> dict:
    return {
        "name": q.name,
        "record": _pick_txt(q.value, prefix),
        "rcode": q.rcode,
        "agreed": q.agreed,
        "asked": q.resolvers_asked,
        "at": q.lookups[0].at if q.lookups else "",
        "lookups": [asdict(lk) for lk in q.lookups],
    }


def capture_subdomains(domain: str, names: list[str],
                       resolvers: tuple[str, ...] = ("",),
                       workers: int = SWEEP_WORKERS,
                       max_names: int = SWEEP_MAX_NAMES) -> dict:
    """Read each sub-domain name's SPF, MX, DKIM wildcard and DMARC records.

    The wildcards under ``domain`` itself and an absence control are read in
    the same batch. ``control.usable`` is False when the control name did not
    come back NXDOMAIN, and then no absence in the batch means anything.
    """
    own_spf = corroborate(domain, "TXT", resolvers)
    own_record = _pick_txt(own_spf.value, "v=spf1")
    named_senders = set(sender_policy_hosts(own_record))

    wildcard_spf = corroborate_status(spf_wildcard_name(domain), "TXT", resolvers)
    wildcard_dkim = corroborate_status(dkim_wildcard_name(domain), "TXT", resolvers)
    control = corroborate_status(f"{CONTROL_LABEL}.{domain}", "TXT", resolvers)

    wanted = sorted(dict.fromkeys(n.lower().strip(".") for n in names if n))
    truncated = max(0, len(wanted) - max_names)
    wanted = wanted[:max_names]

    read: list[SubdomainRecords] = []
    if wanted:
        with futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            read = list(pool.map(lambda n: _read_subdomain(n, resolvers), wanted))
    for rec in read:
        _scope(rec, named_senders)

    return {
        "domain": domain,
        "captured_at": _now(),
        "resolvers": [resolver_label(r) for r in resolvers],
        "tries": SWEEP_TRIES,
        "sender_policy": {"record": own_record, "named_hosts": sorted(named_senders)},
        "wildcard_spf": _corroborated_block(wildcard_spf, "v=spf1"),
        "wildcard_dkim": _corroborated_block(wildcard_dkim, "v=DKIM1"),
        "control": {**_corroborated_block(control, "v=spf1"),
                    "usable": control.rcode == "NXDOMAIN"},
        "subdomains": [asdict(r) | {"exists": r.exists,
                                    "spf_conformant": r.spf_conformant,
                                    "dkim_conformant": r.dkim_conformant}
                       for r in read],
        "names_offered": len(names),
        "names_dropped_by_cap": truncated,
    }


def _rsa_bits(b64: str) -> int:
    """The RSA modulus size of a DER SubjectPublicKeyInfo, read by ``openssl``; 0 if unread."""
    import os
    import tempfile
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except ValueError:
        return 0
    fd, path = tempfile.mkstemp(suffix=".der")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(der)
        out = run(["openssl", "rsa", "-pubin", "-inform", "DER",
                   "-in", path, "-noout", "-text"], timeout=15)
        m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", out)
        return int(m.group(1)) if m else 0
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def capture_host(host: str, resolvers: tuple[str, ...] = ("",)) -> dict:
    """Offer each TLS version in turn to a mail host and record which it accepts."""
    addr = corroborate(host, "A", resolvers)
    probes = [_starttls(host, v) for v in TLS_VERSIONS]
    accepted = [p["version"] for p in probes if p["state"] == "accepted"]
    refused = [p["version"] for p in probes if p["state"] == "refused"]
    unknown = [p["version"] for p in probes if p["state"] == "could-not-ask"]
    return {
        "host": host,
        "addresses": sorted({a for lk in addr.lookups for a in lk.answers}),
        "addresses_agreed": addr.agreed,
        "address_lookups": [asdict(lk) for lk in addr.lookups],
        "probes": probes,
        "accepted": [TLS_LABEL[v] for v in accepted],
        "refused": [TLS_LABEL[v] for v in refused],
        "unmeasured": [TLS_LABEL[v] for v in unknown],
        "forbidden_offered": [TLS_LABEL[v] for v in accepted if v in FORBIDDEN_BY_SGE],
    }


def transcript(evidence: dict) -> str:
    """A readable, timestamped transcript of a :func:`capture`."""
    out: list[str] = []
    out.append(f"DNS AND MAIL TRANSPORT EVIDENCE — captured {evidence['captured_at']}")
    out.append(f"resolvers: {', '.join(evidence['resolvers'])}")
    out.append("")
    for d in evidence["domains"]:
        out.append(f"── {d['domain']} " + "─" * max(0, 60 - len(d["domain"])))
        for label, key in (("SPF", "spf"), ("DMARC", "dmarc"),
                           ("MTA-STS TXT", "mta_sts_txt"), ("TLS-RPT", "tls_rpt")):
            blk = d[key]
            first = blk["lookups"][0]
            agree = "all resolvers agree" if blk["agreed"] else "RESOLVERS DISAGREE"
            out.append(f"  {label:<12} [{first['at']}] {agree}")
            out.append(f"    {blk['record'] or '(no record)'}")
        mx = d["mx"]
        out.append(f"  {'MX':<12} [{mx['lookups'][0]['at']}] "
                   f"{'all resolvers agree' if mx['agreed'] else 'RESOLVERS DISAGREE'}")
        for r in mx["records"]:
            out.append(f"    {r}")
        pol = d["mta_sts_policy"]
        out.append(f"  {'MTA-STS pol':<12} [{pol['at']}] HTTP {pol.get('http_status', 0)} "
                   f"certificate {'validates' if pol.get('certificate_validates') else 'DOES NOT VALIDATE'}")
        for line in (pol.get("body") or "").splitlines():
            out.append(f"    {line}")
        for k in d["dkim"]:
            bits = f"RSA {k['key_bits']}-bit" if k["key_bits"] else "no key in record"
            out.append(f"  {'DKIM':<12} [{k['at']}] {k['selector']}: {bits}")
        out.append("")
    for h in evidence["hosts"]:
        stable = "" if h.get("addresses_agreed", True) else "  ⚠ RESOLVERS DISAGREE ON ADDRESS"
        out.append(f"── {h['host']} ({', '.join(h['addresses']) or 'no address'})"
                   f"{stable} " + "─" * 12)
        for p in h["probes"]:
            label = TLS_LABEL[p["version"]]
            if p["state"] == "accepted":
                out.append(f"  [{p['at']}] {label:<8} accepted — {p['protocol']} {p['cipher']}")
            elif p["state"] == "refused":
                out.append(f"  [{p['at']}] {label:<8} refused  — {p['detail']}")
            else:
                out.append(f"  [{p['at']}] {label:<8} NOT MEASURED — {p['detail']}")
        if h["unmeasured"]:
            out.append(f"  ⚠ unmeasured versions: {', '.join(h['unmeasured'])} — "
                       f"this host's floor is not established")
        out.append("")
    out.extend(subdomain_transcript(evidence.get("subdomains") or []))
    return "\n".join(out)


def subdomain_transcript(captures: list[dict]) -> list[str]:
    """Transcript lines for :func:`capture_subdomains` results."""
    out: list[str] = []
    for cap in captures:
        d = cap["domain"]
        out.append(f"══ sub-domains of {d} " + "═" * max(0, 50 - len(d)))
        out.append(f"  resolvers {', '.join(cap['resolvers'])}, {cap['tries']} tries each, "
                   f"captured {cap['captured_at']}")
        for label, key, want in (("wildcard SPF", "wildcard_spf", DENYING_SPF_DISPLAY),
                                 ("wildcard DKIM", "wildcard_dkim", BLANK_DKIM_DISPLAY)):
            blk = cap[key]
            agree = "all resolvers agree" if blk["agreed"] else "RESOLVERS DISAGREE"
            out.append(f"  {label:<14} {blk['name']}")
            out.append(f"    [{blk['at']}] {blk['rcode'] or 'no agreed status'} · {agree}")
            out.append(f"    {blk['record'] or '(no record)'}   — the standard asks for "
                       f"'{want}' here")
        ctl = cap["control"]
        out.append(f"  {'control':<14} {ctl['name']}")
        out.append(f"    [{ctl['at']}] {ctl['rcode'] or 'no agreed status'} — "
                   + ("absence is distinguishable, so the readings below mean what they say"
                      if ctl["usable"] else
                      "⚠ THIS SHOULD HAVE BEEN NXDOMAIN. Either a wildcard answers for every "
                      "name under this domain, or the resolver is not telling absences apart "
                      "— the readings below are not evidence of absence"))
        if cap.get("names_dropped_by_cap"):
            out.append(f"  ⚠ {cap['names_dropped_by_cap']} name(s) beyond the sweep ceiling "
                       f"were not read")
        out.append(f"  {len(cap['subdomains'])} sub-domain name(s) read:")
        for r in cap["subdomains"]:
            if not r.get("read", True):
                out.append(f"    {r['name']:<52} NOT READ — a resolver could not be asked")
                continue
            marks = [
                "SPF " + (r["spf_record"] if r["spf_record"] else "none"),
                "DKIM " + (r["dkim_record"] if r["dkim_record"] else "none"),
            ]
            if r["mx_records"]:
                marks.append("MX " + "; ".join(r["mx_records"]))
            if r["email_enabled"]:
                marks.append("SENDS MAIL — " + r["email_enabled_because"])
            flag = "" if r.get("agreed", True) else "  ⚠ RESOLVERS DISAGREE"
            out.append(f"    [{r['at']}] {r['name']:<52} {r['rcode'] or '?':<9} "
                       f"{' · '.join(marks)}{flag}")
        out.append("")
    return out


def capture(domains: list[str], hosts: list[str],
            resolvers: tuple[str, ...] = ("",),
            subdomains: dict[str, list[str]] | None = None,
            selectors: list[str] | None = None) -> dict:
    """Capture every domain's records, every host's TLS versions, and optionally a sweep."""
    return {
        "captured_at": _now(),
        "resolvers": [resolver_label(r) for r in resolvers],
        "domains": [capture_domain(d, resolvers, selectors) for d in domains],
        "hosts": [capture_host(h, resolvers) for h in hosts],
        "subdomains": [capture_subdomains(d, (subdomains or {}).get(d, []), resolvers)
                       for d in domains] if subdomains is not None else [],
    }


def discovered_subdomains(target: str, observation: str = "latest") -> dict[str, list[str]]:
    """Sub-domain names an existing observation discovered, grouped by email domain."""
    cfg = config.load_target(target)
    domains = list((cfg.get("discovery") or {}).get("email_domains") or [])
    path = config.observations_dir() / observation / "assets.json"
    with path.open() as f:
        assets = json.load(f)
    out: dict[str, list[str]] = {d: [] for d in domains}
    for a in assets:
        if a.get("data_state") != "discovery":
            continue
        host = str(a.get("host") or "").lower().strip(".")
        for d in domains:
            if host.endswith("." + d):
                out[d].append(host)
                break
    return {d: sorted(set(v)) for d, v in out.items()}


def _authorisation_problems(target: dict) -> list[str]:
    """Why the profile does not authorise probing live hosts; [] when it does.

    A profile authorises active probing with an ``authorisation:`` mapping
    carrying ``scope``, ``authorised_by`` and ``date``. This is a record of
    who agreed to what, checked before any connection is opened.
    """
    auth = target.get("authorisation")
    if not isinstance(auth, dict) or not auth:
        return ["no `authorisation:` stanza in the target profile"]
    return [f"`authorisation.{key}` is missing or empty"
            for key in ("scope", "authorised_by", "date") if not str(auth.get(key, "")).strip()]


def main(argv: list[str] | None = None) -> int:
    """Print (or emit as JSON) a capture for the target profile's email domains."""
    import argparse

    ap = argparse.ArgumentParser(
        prog="takestock.dnsevidence",
        description="Timestamped, resolver-corroborated DNS and mail-transport evidence")
    ap.add_argument("target", help="target profile name, e.g. the stem of targets/<name>.yaml")
    ap.add_argument("--json", action="store_true", help="emit the full capture as JSON")
    ap.add_argument("--transport", action="store_true",
                    help="also probe TLS versions on the mail hosts (needs an "
                         "authorisation stanza in the target profile)")
    ap.add_argument("--subdomains", action="store_true",
                    help="also sweep every sub-domain name an existing observation "
                         "discovered, for the denying SPF and blank DKIM records a "
                         "name that sends no mail should publish")
    ap.add_argument("--observation", default="latest",
                    help="observation to take the sub-domain names from (default: latest)")
    args = ap.parse_args(argv)

    cfg = config.load_target(args.target)
    domains = list((cfg.get("discovery") or {}).get("email_domains") or [])
    asked = resolvers(cfg)

    hosts: list[str] = []
    if args.transport:
        problems = _authorisation_problems(cfg)
        if problems:
            print("REFUSED: --transport opens connections to live mail hosts and needs")
            print("an `authorisation:` stanza in the target profile. Problems:")
            for p in problems:
                print(f"  · {p}")
            return 2
        seen: set[str] = set()
        for d in domains:
            for rec in corroborate(d, "MX", asked[:1]).value:
                name = rec.split()[-1].rstrip(".") if rec.split() else ""
                if name and name not in seen:
                    seen.add(name)
                    hosts.append(name)

    subdomains = discovered_subdomains(args.target, args.observation) if args.subdomains else None
    evidence = capture(domains, hosts, asked, subdomains=subdomains,
                       selectors=dkim_selectors(cfg))
    print(json.dumps(evidence, indent=2) if args.json else transcript(evidence))

    disagreements = [
        (d["domain"], k) for d in evidence["domains"]
        for k in ("spf", "dmarc", "mta_sts_txt", "tls_rpt", "mx")
        if not d[k]["agreed"]
    ]
    disagreements += [(c["domain"], f"sub-domain {r['name']}")
                      for c in (evidence.get("subdomains") or [])
                      for r in c["subdomains"] if not r.get("agreed", True)]
    for c in evidence.get("subdomains") or []:
        if not c["control"]["usable"]:
            disagreements.append((c["domain"], "the sub-domain sweep's absence control"))
    if disagreements:
        print("\nRESOLVERS DISAGREED — every reading below needs settling before use:")
        for dom, k in disagreements:
            print(f"  · {dom}: {k}")
    return 1 if disagreements else 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
