"""HTTP Strict Transport Security (HSTS) on the authorised HTTPS endpoints.

A site that redirects plain HTTP to HTTPS still takes its first request in
clear, and that request (and the redirect) can be stripped on the path. HSTS
(RFC 6797) tells a browser to refuse plain HTTP to the host from then on;
``preload`` closes the first visit too. This collector makes one HTTPS
request to ``/`` on each endpoint with ``curl`` and grades the
``Strict-Transport-Security`` header:

=================  ==========  =========================================
header             verdict     why
=================  ==========  =========================================
absent             weak        no policy reaches the browser
malformed          weak        RFC 6797 §6.1: the browser ignores it
``max-age=0``      weak        RFC 6797 §6.1.1: it deletes the policy
short max-age      acceptable  under one year; flagged
one year or more   acceptable  ``includeSubDomains``/``preload`` recorded
no HTTPS answer    unknown     nothing was read, so nothing is concluded
=================  ==========  =========================================

The verdict never reaches ``strong``: HSTS limits a downgrade of the first
request, it does not make the TLS session stronger.

Alongside the header it records which HTTP version answered, any
``Alt-Svc`` advertisement, and the DNS HTTPS record (RFC 9460), so a reader
can see whether the endpoint advertises HTTP/3.

A third-party endpoint is often served by many machines behind one name, so
it is read several times (default 3, set ``TAKESTOCK_HSTS_THIRD_PARTY_READS``)
and the weakest reading is reported, with a flag when they disagree.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .. import __version__, coverage, digresponse, inside_scope, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..util import is_ipv6_literal, now_date, run, scan_address

SOURCE = "hsts"
SOURCE_NAME = "HSTS policy check (curl) — internet-facing endpoint"

#: One year, the max-age the browser preload lists require.
HSTS_MIN_MAX_AGE = 31_536_000

#: Written by curl's ``-w`` after the headers, carrying the address it connected to.
CONNECTED_MARKER = "__takestock_connected_to__"
CURL_FLAGS = ("-sS", "-o", "/dev/null", "-D", "-", "-A", f"takestock/{__version__}",
              "-w", rf"\n{CONNECTED_MARKER} %{{remote_ip}}\n")
REQUEST_TIMEOUT = 20
RUN_TIMEOUT = 30

HEADER_NAME = "strict-transport-security"

# Outcomes.
ENFORCED = "enforced"
SHORT = "short-max-age"
ZERO = "max-age-zero"
MALFORMED = "malformed"
ABSENT = "absent"
UNREADABLE = "unreadable"

# Flags.
ABSENT_FLAG = "hsts-absent"
MALFORMED_FLAG = "hsts-malformed"
ZERO_FLAG = "hsts-max-age-zero"
SHORT_FLAG = "hsts-max-age-short:"
UNREADABLE_FLAG = "hsts-unreadable"
SUBDOMAINS_FLAG = "hsts-include-subdomains"
PRELOAD_FLAG = "hsts-preload"
DIFFERS_FLAG = "hsts-differs-between-servers"

register_informational_prefixes(UNREADABLE_FLAG, SUBDOMAINS_FLAG, PRELOAD_FLAG, DIFFERS_FLAG)

_STATUS_LINE = re.compile(r"^HTTP/([\d.]+)\s+(\d{3})")
_MAX_AGE = re.compile(r"^max-age\s*=\s*\"?(\d+)\"?$", re.IGNORECASE)


@dataclass(frozen=True)
class HstsPolicy:
    """What one HTTPS response said about HSTS."""

    present: bool = False
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    header: str = ""
    header_count: int = 0
    status: int | None = None
    malformed: bool = False
    http_version: str = ""
    alt_svc: tuple[str, ...] = ()

    @property
    def effective(self) -> bool:
        """True when a browser would hold a policy after this response."""
        return self.present and not self.malformed and bool(self.max_age)

    @property
    def outcome(self) -> str:
        """One of the outcome constants above (never ``unreadable``)."""
        if not self.present:
            return ABSENT
        if self.malformed:
            return MALFORMED
        if not self.max_age:
            return ZERO
        return ENFORCED if self.max_age >= HSTS_MIN_MAX_AGE else SHORT


def scan_hosts(target: dict) -> list[str]:
    """The organisation's published hosts, then third-party ``saas_443`` hosts, de-duplicated."""
    st = target.get("scan_targets", {}) or {}
    hosts: list[str] = []
    seen: set[str] = set()
    third_party = [e.get("host") if isinstance(e, dict) else e for e in st.get("saas_443") or []]
    for host in roles.published_hosts(target) + third_party:
        h = str(host or "").strip()
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts


def _url(host: str) -> str:
    address = scan_address(host)
    return f"https://[{address}]/" if is_ipv6_literal(host) else f"https://{address}/"


def _curl_command(host: str) -> list[str]:
    return ["curl", *CURL_FLAGS, "-m", str(REQUEST_TIMEOUT), _url(host)]


def parse_policy(header: str) -> tuple[int | None, bool, bool, bool]:
    """(max_age, includeSubDomains, preload, malformed) from one header value.

    RFC 6797 §6.1 requires exactly one ``max-age`` directive with a
    non-negative integer value; anything else is malformed.
    """
    max_age: int | None = None
    include_subdomains = preload = False
    max_age_seen = 0
    malformed = False
    for token in header.split(";"):
        directive = token.strip()
        if not directive:
            continue
        lowered = directive.lower()
        if lowered.startswith("max-age"):
            max_age_seen += 1
            m = _MAX_AGE.match(directive)
            if m:
                max_age = int(m.group(1))
            else:
                malformed = True
        elif lowered == "includesubdomains":
            include_subdomains = True
        elif lowered == "preload":
            preload = True
    if max_age_seen != 1:
        malformed = True
    return max_age, include_subdomains, preload, malformed


ALT_SVC_HEADER = "alt-svc"


def parse_response(out: str) -> HstsPolicy | None:
    """Read ``curl -D -`` headers; None when no HTTP response came back.

    Only the last response counts (a redirect chain prints several), and the
    first HSTS header is the one a browser processes (RFC 6797 §8.1).
    """
    if out.startswith("__ERROR__"):
        return None
    status: int | None = None
    version = ""
    headers: list[str] = []
    alt_svc: list[str] = []
    for line in out.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        m = _STATUS_LINE.match(stripped)
        if m:
            version, status = f"HTTP/{m.group(1)}", int(m.group(2))
            headers, alt_svc = [], []
            continue
        name, sep, value = stripped.partition(":")
        key = name.strip().lower() if sep else ""
        if key == HEADER_NAME:
            headers.append(value.strip())
        elif key == ALT_SVC_HEADER:
            alt_svc.append(value.strip())
    if status is None:
        return None
    if not headers:
        return HstsPolicy(status=status, http_version=version, alt_svc=tuple(alt_svc))
    max_age, subdomains, preload, malformed = parse_policy(headers[0])
    return HstsPolicy(present=True, max_age=max_age, include_subdomains=subdomains,
                      preload=preload, header=headers[0], header_count=len(headers),
                      status=status, malformed=malformed, http_version=version,
                      alt_svc=tuple(alt_svc))


_ALT_SVC_ALTERNATIVE = re.compile(r'(?:^|,)\s*([^\s=,;"]+)\s*=\s*"[^"]*"')


def alt_svc_protocols(values: Sequence[str]) -> list[str]:
    """The ALPN protocol IDs an ``Alt-Svc`` header advertises (RFC 7838)."""
    ids: set[str] = set()
    for value in values:
        for m in _ALT_SVC_ALTERNATIVE.finditer(value):
            ids.add(unquote(m.group(1)).lower())
    return sorted(ids)


def is_h3(alpn_id: str) -> bool:
    """True for HTTP/3 (``h3``) or one of its drafts (``h3-29``)."""
    return alpn_id == "h3" or alpn_id.startswith("h3-")


# The DNS HTTPS record (RFC 9460). Asked for by number so an older dig that
# does not know the mnemonic still sends the right question.
HTTPS_RRTYPE = "TYPE65"
_HTTPS_ANSWER_TYPES = ("TYPE65", "HTTPS")

DNS_PUBLISHED = "published"
DNS_NONE = "none-published"
DNS_FAILED = "lookup-failed"
DNS_DISAGREE = "resolvers-disagree"

_ANSWERED_RCODES = ("NOERROR", "NXDOMAIN")

_SVC_KEYS = {0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port",
             4: "ipv4hint", 5: "ech", 6: "ipv6hint"}


def parse_https_rdata(rdata: str) -> dict | None:
    """Priority, target and ALPN list of one HTTPS record, presentation or generic form."""
    text = rdata.strip()
    if text.startswith("\\#"):
        return _parse_generic(text)
    m = re.match(r"^(\d+)\s+(\S+)(.*)$", text)
    if not m:
        return None
    alpn_m = re.search(r'(?:^|\s)alpn=("([^"]*)"|(\S+))', m.group(3))
    alpn_text = (alpn_m.group(2) if alpn_m and alpn_m.group(2) is not None
                 else alpn_m.group(3) if alpn_m else "")
    return {"priority": int(m.group(1)), "target": m.group(2),
            "alpn": [a for a in alpn_text.split(",") if a],
            "no_default_alpn": bool(re.search(r"(?:^|\s)no-default-alpn(?:\s|=|$)", m.group(3)))}


def _parse_generic(text: str) -> dict | None:
    """An RFC 3597 ``\\# <len> <hex>`` record, decoded per RFC 9460 §2.2."""
    parts = text.split()
    try:
        length = int(parts[1])
        data = bytes.fromhex("".join(parts[2:]))
    except (IndexError, ValueError):
        return None
    if len(data) != length or len(data) < 3:
        return None
    priority = int.from_bytes(data[0:2], "big")
    i, labels = 2, []
    while True:
        if i >= len(data):
            return None
        n = data[i]
        i += 1
        if n == 0:
            break
        if n > 63 or i + n > len(data):
            return None
        labels.append(data[i:i + n].decode("ascii", "replace"))
        i += n
    alpn: list[str] = []
    no_default = False
    while i < len(data):
        if i + 4 > len(data):
            return None
        key = int.from_bytes(data[i:i + 2], "big")
        vlen = int.from_bytes(data[i + 2:i + 4], "big")
        value = data[i + 4:i + 4 + vlen]
        if len(value) != vlen:
            return None
        i += 4 + vlen
        if _SVC_KEYS.get(key) == "alpn":
            j = 0
            while j < len(value):
                k = value[j]
                if j + 1 + k > len(value):
                    return None
                alpn.append(value[j + 1:j + 1 + k].decode("ascii", "replace"))
                j += 1 + k
        elif _SVC_KEYS.get(key) == "no-default-alpn":
            no_default = True
    return {"priority": priority, "target": ".".join(labels) + "." if labels else ".",
            "alpn": alpn, "no_default_alpn": no_default}


def _record_text(rec: dict) -> str:
    mode = "alias" if rec["priority"] == 0 else f"priority {rec['priority']}"
    alpn = f" alpn={','.join(rec['alpn'])}" if rec["alpn"] else ""
    return f"{mode} target {rec['target']}{alpn}"


def resolvers_for(target: dict) -> tuple[str, ...]:
    """The resolvers to ask: the profile's ``dns_resolvers:`` list, else the system's."""
    named = [str(r).strip() for r in (target.get("dns_resolvers") or []) if str(r).strip()]
    return tuple(named) or ("",)


def _https_answers(resp: digresponse.Response) -> list[str]:
    return [" ".join(rr.rdata) for rr in resp.answer
            if rr.rtype.upper() in _HTTPS_ANSWER_TYPES]


def read_https_record(host: str, resolvers: tuple[str, ...] = ("",)) -> dict:
    """Ask each resolver for ``host``'s HTTPS record and read whether it advertises HTTP/3.

    Resolvers that answered must agree, or the outcome is
    ``resolvers-disagree``. An empty answer counts as "none published" only
    when at least two resolvers (or the only one asked) returned it.
    """
    label = [r or "system resolver" for r in resolvers]
    replies = [digresponse.parse(digresponse.query(host, HTTPS_RRTYPE, r)) for r in resolvers]

    def answered(resp: digresponse.Response) -> bool:
        return resp.answered and resp.status in _ANSWERED_RCODES

    usable = [(name, resp) for name, resp in zip(label, replies, strict=True) if answered(resp)]
    failed = [f"{name}: {resp.error or resp.status or 'no response code'}"
              for name, resp in zip(label, replies, strict=True) if not answered(resp)]
    base = {
        "dns_https_resolvers": label,
        "dns_https_resolvers_answered": len(usable),
        "dns_https_rcode": sorted({resp.status for _, resp in usable}),
        "dns_https_detail": "; ".join(failed),
    }
    unread: dict[str, Any] = {"dns_https_records": [], "dns_https_alpn": [],
                              "dns_https_advertises_h3": None}
    answer_sets = {tuple(sorted(_https_answers(resp))) for _, resp in usable}
    if len(answer_sets) > 1:
        return {**base, "dns_https_outcome": DNS_DISAGREE, **unread}
    answers = list(next(iter(answer_sets))) if answer_sets else []
    if not answers:
        if len(usable) < min(2, len(resolvers)) or not usable:
            return {**base, "dns_https_outcome": DNS_FAILED, **unread}
        return {**base, "dns_https_outcome": DNS_NONE, "dns_https_records": [],
                "dns_https_alpn": [], "dns_https_advertises_h3": False}
    parsed = [parse_https_rdata(a) for a in answers]
    records = [_record_text(p) if p else f"unreadable: {a}"
               for p, a in zip(parsed, answers, strict=True)]
    service = [p for p in parsed if p and p["priority"] > 0]
    alpn = sorted({x.lower() for p in service for x in p["alpn"]})
    h3: bool | None
    if any(is_h3(x) for x in alpn):
        h3 = True
    elif service and len(service) == len(parsed):
        h3 = False
    else:
        h3 = None
    return {**base, "dns_https_outcome": DNS_PUBLISHED, "dns_https_records": records,
            "dns_https_alpn": alpn, "dns_https_advertises_h3": h3}


def http3_advertised(alt_svc_h3: bool | None, dns_h3: bool | None) -> bool | None:
    """True if either channel advertises HTTP/3; False only if both were read and neither does."""
    if alt_svc_h3 or dns_h3:
        return True
    if alt_svc_h3 is False and dns_h3 is False:
        return False
    return None


def evidence(host: str, policy: HstsPolicy | None, detail: str = "") -> str:
    """The plain-language note for one endpoint's reading."""
    if policy is None:
        return (f"No HTTPS response from {host}: the HSTS policy could not be read "
                f"({detail or 'no detail'}). Nothing is concluded either way — this row "
                "says the check did not settle it, NOT that the endpoint publishes no "
                "policy.")

    where = f"HTTP {policy.status} over HTTPS"
    if not policy.present:
        return (f"{host} answered ({where}) with no Strict-Transport-Security header, so "
                "a browser is never told to refuse plain HTTP to this host. Any redirect "
                "from port 80 travels in clear and can be stripped on-path, and so can "
                "the first request of every visit. Measured on '/' only.")
    if policy.malformed:
        return (f"{host} sent a Strict-Transport-Security header this check could not read "
                f"a single valid max-age from ({where}): {policy.header!r}. RFC 6797 §6.1 "
                "has the browser ignore such a header entirely, so no policy reaches the "
                "client — the same exposure as sending none, with the appearance of a "
                "control. The header is recorded verbatim so the parsing can be checked.")
    if not policy.max_age:
        return (f"{host} sent `max-age=0` ({where}): RFC 6797 §6.1.1 makes that an "
                "instruction to DELETE any policy the browser already holds, so this is "
                "not a short policy but the absence of one, asserted. Plain HTTP to this "
                "host is permitted again from the next request.")
    extras = [d for d, on in (("includeSubDomains", policy.include_subdomains),
                              ("preload", policy.preload)) if on]
    carries = (f", with {' and '.join(extras)}" if extras
               else ", with neither includeSubDomains nor preload")
    lapse = ("" if policy.max_age >= HSTS_MIN_MAX_AGE else
             f" That is under the {HSTS_MIN_MAX_AGE}s (one year) the browser preload lists "
             "require, so the protection lapses for any client that has not visited inside "
             "the window.")
    first_visit = ("" if policy.preload else
                   " HSTS is only honoured after one clean HTTPS visit, so the very first "
                   "request from a given browser is still strippable; `preload` is the only "
                   "mechanism that closes that.")
    return (f"{host} publishes HSTS with max-age={policy.max_age}s ({where}){carries}, so a "
            f"browser that has seen it refuses plain HTTP to this host.{lapse}{first_visit}")


def _asset(host: str, policy: HstsPolicy | None, detail: str,
           ref_time: datetime | None, role: str = "",
           dns_https: dict | None = None) -> CryptoAsset:
    asset = CryptoAsset(
        name=f"HSTS {host}:443", role=role, data_state="in-transit", protocol="hsts",
        host=host, port="443", source=SOURCE, internet_facing=True,
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        notes=evidence(host, policy, detail),
    )
    outcome = UNREADABLE if policy is None else policy.outcome
    flags: set[str] = set()
    if policy is None:
        asset.verdict = "unknown"
        flags.add(UNREADABLE_FLAG)
    elif outcome == ABSENT:
        asset.verdict = "weak"
        flags.add(ABSENT_FLAG)
    elif outcome == MALFORMED:
        asset.verdict = "weak"
        flags.add(MALFORMED_FLAG)
    elif outcome == ZERO:
        asset.verdict = "weak"
        flags.add(ZERO_FLAG)
    else:
        asset.verdict = "acceptable"
        if outcome == SHORT:
            flags.add(f"{SHORT_FLAG}{policy.max_age}")
        if policy.include_subdomains:
            flags.add(SUBDOMAINS_FLAG)
        if policy.preload:
            flags.add(PRELOAD_FLAG)
    asset.flags = sorted(flags)
    asset.extra = {
        "hsts_outcome": outcome,
        "hsts_present": None if policy is None else policy.present,
        "hsts_effective": None if policy is None else policy.effective,
        "hsts_max_age": None if policy is None else policy.max_age,
        "hsts_include_subdomains": None if policy is None else policy.include_subdomains,
        "hsts_preload": None if policy is None else policy.preload,
        "hsts_header": "" if policy is None else policy.header,
        "hsts_header_count": 0 if policy is None else policy.header_count,
        "http_status": None if policy is None else policy.status,
        "hsts_probe_detail": detail,
    }
    alt_h3 = None if policy is None else any(is_h3(p) for p in alt_svc_protocols(policy.alt_svc))
    asset.extra.update({
        "http_negotiated_protocol": None if policy is None else (policy.http_version or None),
        "alt_svc_headers": [] if policy is None else list(policy.alt_svc),
        "alt_svc_protocols": [] if policy is None else alt_svc_protocols(policy.alt_svc),
        "alt_svc_advertises_h3": alt_h3,
    })
    if dns_https is not None:
        asset.extra.update(dns_https)
    asset.extra["http3_advertised"] = http3_advertised(
        alt_h3, asset.extra.get("dns_https_advertises_h3"))
    return asset


# Raw captures keep the headers as evidence, minus anything that could be a
# credential or a session, and minus per-request trace identifiers that
# change on every read and carry no evidence.
REDACTED_HEADERS = ("set-cookie", "cookie", "authorization", "proxy-authorization",
                    "www-authenticate", "proxy-authenticate")
REDACTION = "<redacted by takestock: value not needed, and may be a session token>"

NOISE_HEADERS = ("x-request-id", "request-id", "x-correlation-id", "x-trace-id",
                 "traceparent", "tracestate", "server-timing")
NOISE_REDACTION = "<elided by takestock: per-request trace id, not evidence>"


def redact_capture(out: str) -> str:
    """A curl header dump with credentials redacted and trace ids elided."""
    lines = []
    for line in out.splitlines():
        name, sep, _ = line.partition(":")
        key = name.strip().lower()
        if sep and key in REDACTED_HEADERS:
            lines.append(f"{name}: {REDACTION}")
        elif sep and key in NOISE_HEADERS:
            lines.append(f"{name}: {NOISE_REDACTION}")
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if out.endswith("\n") else "")


#: Response headers that say which server or edge answered, kept to tell reads apart.
SERVER_IDENTITY_HEADERS = ("server", "via", "x-served-by", "x-cache")


def split_connected_address(out: str) -> tuple[str, str]:
    """(curl output without the marker line, the address curl connected to)."""
    kept: list[str] = []
    address = ""
    for line in out.splitlines(keepends=True):
        if line.startswith(CONNECTED_MARKER):
            address = line[len(CONNECTED_MARKER):].strip()
        else:
            kept.append(line)
    return "".join(kept), address


def server_identity(out: str) -> str:
    """The identity headers of the last response, as ``name=value; ...``."""
    found: dict[str, str] = {}
    for line in out.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if _STATUS_LINE.match(stripped):
            found = {}
            continue
        name, sep, value = stripped.partition(":")
        key = name.strip().lower() if sep else ""
        value = value.strip()
        if key in SERVER_IDENTITY_HEADERS and value:
            found[key] = value
    return "; ".join(f"{k}={found[k]}" for k in SERVER_IDENTITY_HEADERS if k in found)


THIRD_PARTY_READS = 3
THIRD_PARTY_READS_ENV = "TAKESTOCK_HSTS_THIRD_PARTY_READS"
READ_PAUSE_SECONDS = 1.0
_pause = time.sleep

_OUTCOME_RANK = {ABSENT: 0, MALFORMED: 0, ZERO: 0, SHORT: 1, ENFORCED: 2}


@dataclass(frozen=True)
class HeaderRead:
    """One request's result: the policy (None if no answer), where it came from, and why not."""

    policy: HstsPolicy | None
    address: str
    identity: str
    detail: str


def third_party_hosts(target: dict) -> set[str]:
    """``saas_443`` hosts that are not also the organisation's own published hosts."""
    st = target.get("scan_targets", {}) or {}
    ours = set(roles.published_hosts(target))
    out: set[str] = set()
    for e in st.get("saas_443") or []:
        h = str((e.get("host") if isinstance(e, dict) else e) or "").strip()
        if h and h not in ours:
            out.add(h)
    return out


def third_party_reads() -> tuple[int, str]:
    """(reads per third-party host, a problem line if the setting was unusable)."""
    raw = os.environ.get(THIRD_PARTY_READS_ENV, "").strip()
    if not raw:
        return THIRD_PARTY_READS, ""
    if raw.isdigit() and int(raw) >= 1:
        return int(raw), ""
    return THIRD_PARTY_READS, (
        f"hsts: {THIRD_PARTY_READS_ENV}={raw!r} is not a whole number of at least 1, so "
        f"third-party names were read {THIRD_PARTY_READS} times (the default) instead.")


def _read_once(host: str, raw_dir: Path | None, index: int) -> HeaderRead:
    out = run(_curl_command(host), timeout=RUN_TIMEOUT)
    if raw_dir:
        suffix = "" if index == 1 else f".read{index}"
        (raw_dir / f"hsts-{host}{suffix}.txt").write_text(redact_capture(out))
    dump, address = split_connected_address(out)
    policy = parse_response(dump)
    return HeaderRead(policy=policy, address=address,
                      identity="" if policy is None else server_identity(dump),
                      detail="" if policy is not None else dump.strip()[:200])


def _reading_text(policy: HstsPolicy) -> str:
    h3 = any(is_h3(p) for p in alt_svc_protocols(policy.alt_svc))
    return (f"HSTS {policy.header or 'absent'} · "
            f"{'alt-svc advertises HTTP/3' if h3 else 'no HTTP/3 alt-svc'} · "
            f"{policy.http_version or 'protocol unread'}")


def combine_reads(reads: list[HeaderRead]) -> tuple[HstsPolicy | None, dict]:
    """Fold several reads of one name into the weakest policy, plus what each read saw.

    A directive counts only if every answered read carried it; an Alt-Svc
    advertisement counts if any did.
    """
    answered = [r for r in reads if r.policy is not None]
    policies = [r.policy for r in answered if r.policy is not None]
    groups: dict[str, list[HeaderRead]] = {}
    for r, p in zip(answered, policies, strict=True):
        groups.setdefault(_reading_text(p), []).append(r)
    readings = []
    for text, rs in groups.items():
        where = sorted({f"{r.address or 'address unread'}"
                        f"{' (' + r.identity + ')' if r.identity else ''}" for r in rs})
        readings.append(f"{len(rs)} of {len(reads)}: {text} · from {'; '.join(where)}")
    extra: dict[str, Any] = {
        "header_reads": len(reads),
        "header_reads_answered": len(answered),
        "header_readings": readings,
        "header_reads_agree": None if len(answered) < 2 else len(groups) == 1,
        "connected_address": "; ".join(sorted({r.address for r in reads if r.address})) or None,
        "server_identity": " | ".join(sorted({r.identity for r in answered if r.identity})),
    }
    if not answered:
        return None, extra
    base = min(policies, key=lambda p: (_OUTCOME_RANK[p.outcome], p.max_age or 0))
    alt: list[str] = []
    for p in policies:
        for v in p.alt_svc:
            if v not in alt:
                alt.append(v)
    combined = replace(
        base,
        include_subdomains=all(p.include_subdomains for p in policies),
        preload=all(p.preload for p in policies),
        alt_svc=tuple(alt))
    return combined, extra


def _reads_sentence(extra: dict) -> str:
    n, answered = extra["header_reads"], extra["header_reads_answered"]
    unanswered = (f" {n - answered} of them got no response and count neither way."
                  if answered < n else "")
    if extra["header_reads_agree"] is False:
        return (f" This third-party name was read {n} times and the servers answered "
                f"differently ({'; '.join(extra['header_readings'])}). The policy stated is "
                "the weakest read; a directive counts only if every read carried it; "
                f"HTTP/3 counts as advertised if any read did.{unanswered}")
    if extra["header_reads_agree"]:
        return (f" This third-party name was read {n} times and every answered read "
                "agreed — which does not prove every server behind the name answers the "
                f"same.{unanswered}")
    return f" This third-party name was read {n} times.{unanswered}"


def _check_host(host: str, raw_dir: Path | None, ref_time: datetime | None,
                role: str = "", reads: int = 1,
                resolvers: tuple[str, ...] = ("",)) -> CryptoAsset:
    results: list[HeaderRead] = []
    for i in range(1, reads + 1):
        if i > 1:
            _pause(READ_PAUSE_SECONDS)
        results.append(_read_once(host, raw_dir, i))
    extra: dict[str, Any]
    if reads == 1:
        only = results[0]
        policy, detail = only.policy, only.detail
        extra = {"connected_address": only.address or None, "server_identity": only.identity}
    else:
        policy, extra = combine_reads(results)
        detail = "" if policy is not None else results[0].detail
    asset = _asset(host, policy, detail, ref_time, role, read_https_record(host, resolvers))
    asset.extra.update(extra)
    if reads > 1:
        asset.notes += _reads_sentence(extra)
        if extra["header_reads_agree"] is False:
            asset.flags = sorted(set(asset.flags) | {DIFFERS_FLAG})
    return asset


def coverage_gaps(target: dict, assets: list[CryptoAsset]) -> list[coverage.Gap]:
    """What this run could not read: endpoints with no HTTPS answer, names with no agreed DNS answer."""
    gaps: list[coverage.Gap] = []
    unreadable = [a for a in assets if a.extra.get("hsts_outcome") == UNREADABLE]
    if unreadable:
        gaps.append(coverage.gap(coverage.COULD_NOT_TEST, (
            f"HSTS on {len(unreadable)} endpoint(s) — asked and got no HTTPS response, so "
            "no Strict-Transport-Security policy was read there: "
            f"{', '.join(sorted(a.host for a in unreadable))}"),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("For these websites this run could not check whether browsers are "
                    "told to refuse an unencrypted connection. The finding for every "
                    "other site stands; these are not counted either way."),
            harvest=("A re-check once the site responds, or confirmation from whoever "
                     "hosts it."),
            nature=coverage.NO_DATA))
    unsettled = [a for a in assets
                 if a.extra.get("dns_https_outcome") in (DNS_FAILED, DNS_DISAGREE)]
    if unsettled:
        gaps.append(coverage.gap(coverage.COULD_NOT_TEST, (
            f"DNS HTTPS record on {len(unsettled)} name(s) — the resolvers asked did not "
            "give an agreed answer, so whether these names advertise HTTP/3 in DNS was "
            f"not read: {', '.join(sorted(a.host for a in unsettled))}"),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("For these names it is not known whether DNS tells clients to try "
                    "HTTP/3. Every other name's reading stands."),
            harvest="The same lookup on the next run.",
            nature=coverage.NO_DATA))
    return gaps


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """Read HSTS on every authorised HTTPS endpoint; return (assets, failures)."""
    hosts = scan_hosts(target)
    if not hosts:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]
    if not shutil.which("curl"):
        return [], ["hsts: curl is not on PATH, so the Strict-Transport-Security check "
                    f"did not run against any of the {len(hosts)} authorised endpoint(s). "
                    "This run holds NO evidence about HSTS."]

    role_by_host = roles.scan_target_roles(target)
    n_reads, reads_problem = third_party_reads()
    third_party = third_party_hosts(target)
    resolvers = resolvers_for(target)
    assets = [_check_host(h, raw_dir, ref_time, role_by_host.get(h, ""),
                          n_reads if h in third_party else 1, resolvers) for h in hosts]

    failures: list[str] = [reads_problem] if reads_problem else []
    if all(a.extra.get("hsts_outcome") == UNREADABLE for a in assets):
        failures.append(
            f"hsts: none of the {len(assets)} endpoint(s) returned an HTTPS response, so no "
            "Strict-Transport-Security policy was read anywhere. That pattern points at a "
            "local problem (name resolution, outbound access, TLS trust), not at the "
            "endpoints — this run says NOTHING about HSTS coverage.")
    return assets, failures
