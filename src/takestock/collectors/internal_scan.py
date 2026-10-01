"""TLS, STARTTLS and cleartext checks on named services inside the network.

An inside probe: it reads ``scan_targets.internal_services`` and needs its
own ``authorisation.internal_services`` record beside the profile's general
one (:mod:`takestock.inside_scope`). Each entry names one host and one port::

    scan_targets:
      internal_services:
        - { host: dir-01.example.test, port: 636 }
        - { host: mail-01.example.test, port: 143, role: "Staff mailbox retrieval" }

**What it refuses** (nothing is contacted): a port that is not in
:data:`INTERNAL_PORTS`, an ``ip:`` key, a port that is not one number, a
host named twice on the same port, and lists longer than the ceilings
:mod:`~takestock.collectors.plaintext_scan` holds. Adding a port is a code
change, not a profile edit.

**Four kinds of port**, each measured with the functions the outside-in
collectors already use:

* ``tls``: TLS from the first byte. Measured as :mod:`tls_scan` measures
  443: suite enumeration, one pinned handshake per version, the default
  negotiation and the certificate. An open port that completes no
  handshake is then asked one plain ``http://`` request, so "did not speak
  TLS" can become the measured "serves HTTP in clear".
* ``ldap-starttls``: LDAP on 389, upgraded with the StartTLS extended
  operation. nmap's ``ssl-enum-ciphers`` and ``ssl-cert`` send that
  operation themselves; ``openssl s_client`` has no LDAP StartTLS option in
  every build, so no pinned handshake is made and TLS 1.3 is marked unknown.
* ``starttls``: IMAP, POP3 and SMTP. Two rows. The session row enumerates
  the suites accepted over STARTTLS and adds one pinned handshake per
  version. The sign-in row reads the capability list on the plain
  connection and says whether a password is invited before encryption.
* ``http``: one port-state probe, then one explicit ``http://`` request with
  curl. A ``400`` is not taken as cleartext: a TLS server commonly answers a
  plain request on its TLS port that way.

On the WinRM ports (5985 and 5986) it also sends one unauthenticated
``POST /wsman`` and records the authentication schemes the ``401`` offers.
That moves no verdict: an offered scheme is not an accepted one.

It never authenticates or sends a credential. What it sends is what an
ordinary client sends first: a TLS handshake, ``CAPABILITY``/``CAPA``/``EHLO``
and one HTTP request.

Guard declaration: every refusal **forbids the act**. A probe that has left
the machine cannot be recalled.
"""

from __future__ import annotations

import re
import shutil
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import inside_scope, tls_session
from ..config import load_port_encryption
from ..inside_scope import MAX_HOSTS
from ..model import NA_VERDICT, CryptoAsset
from ..plaintext import CLEARTEXT, PLAINTEXT_FLAG, apply_posture, lookup
from ..tls_session import COULD_NOT_ASK, OFFERED
from ..util import is_ipv6_literal, now_date, run, scan_address
from . import hsts, plaintext_scan, smtp_starttls, tls_scan

SOURCE = "internal_scan"
SOURCE_NAME = "Active probe (nmap, openssl, curl) — inside the network, authorised separately"
#: The ``scan_targets`` (and ``authorisation``) key for this probe.
TARGET_KEY = "internal_services"

TLS, STARTTLS, HTTP = "tls", "starttls", "http"
LDAP_STARTTLS = "ldap-starttls"

#: Finding: a plaintext password path is advertised before encryption.
CLEARTEXT_AUTH_FLAG = "cleartext-auth-offered:"
#: Finding: a port expected to carry TLS completed no handshake.
NO_HANDSHAKE_FLAG = "implicit-tls-no-handshake:"

NO_PORT_TABLE = ("nmap produced no port table for this port, so nothing was measured "
                 "here — see the run's failures")

ENUMERATED_OVER_STARTTLS = (
    "suites shown are every suite nmap's ssl-enum-ciphers found accepted at TLS 1.0-1.2 "
    "over STARTTLS, so the weakest accepted suite is on the row; TLS 1.3 comes from the "
    "pinned handshake, which nmap cannot enumerate")

_NZISM = "NZISM v3.9 16.1.33.C.01"
#: The standard each sign-in row is read against.
AUTH_BASIS = {
    "imap": (f"RFC 3501 § 6.2.3 (a server advertises LOGINDISABLED until STARTTLS, and "
             f"sites SHOULD NOT permit LOGIN without it) and {_NZISM}"),
    "pop3": _NZISM,
    "smtp": (f"RFC 4954 § 4 (servers SHOULD NOT permit a plaintext password mechanism "
             f"without STARTTLS) and {_NZISM}"),
}
NZISM_NOTE = ("NZISM 16.1.33.C.01 says agencies MUST protect system authentication data in "
              "transit on organisation networks; it binds New Zealand government agencies "
              "and is a standard adopted by choice elsewhere")


@dataclass(frozen=True)
class InternalPort:
    """How one allow-listed port is measured."""

    kind: str
    service: str
    starttls: str = ""
    script: str = ""
    slug: str = ""


#: Every port this probe will send to. Well-known service ports only.
INTERNAL_PORTS: dict[int, InternalPort] = {
    443: InternalPort(TLS, "HTTPS", slug="https"),
    465: InternalPort(TLS, "SMTP submission over TLS", slug="smtps"),
    636: InternalPort(TLS, "LDAPS", slug="ldaps"),
    993: InternalPort(TLS, "IMAPS", slug="imaps"),
    995: InternalPort(TLS, "POP3S", slug="pop3s"),
    3269: InternalPort(TLS, "LDAPS global catalogue", slug="ldaps-gc"),
    5986: InternalPort(TLS, "WinRM over HTTPS", slug="winrm-https"),
    8443: InternalPort(TLS, "HTTPS on an alternate port", slug="https-alt"),
    389: InternalPort(LDAP_STARTTLS, "LDAP with StartTLS", slug="ldap-starttls"),
    25: InternalPort(STARTTLS, "SMTP", "smtp", "smtp-commands"),
    110: InternalPort(STARTTLS, "POP3", "pop3", "pop3-capabilities"),
    143: InternalPort(STARTTLS, "IMAP", "imap", "imap-capabilities"),
    587: InternalPort(STARTTLS, "SMTP submission", "smtp", "smtp-commands"),
    80: InternalPort(HTTP, "HTTP"),
    5985: InternalPort(HTTP, "WinRM over HTTP"),
    8080: InternalPort(HTTP, "HTTP on an alternate port"),
}

#: WinRM listener ports and the scheme each speaks.
WINRM_PORTS: dict[int, str] = {5985: "http", 5986: "https"}
WINRM_PATH = "/wsman"
WINRM_CONTENT_TYPE = "application/soap+xml;charset=UTF-8"


@dataclass(frozen=True)
class Probe:
    """One authorised (host, port) and the role the profile gave it."""

    host: str
    port: int
    spec: InternalPort
    role: str = ""


@dataclass
class Capabilities:
    """What a mail service advertised on the plain connection."""

    read: bool = False
    starttls: bool = False
    plaintext_auth: list[str] = field(default_factory=list)
    login_disabled: bool = False
    raw: str = ""


def declared(target: Mapping) -> bool:
    """True when the profile names ``scan_targets.internal_services`` at all."""
    return inside_scope.declared(target, TARGET_KEY)


def plan(target: Mapping) -> list[Probe]:
    """The authorised probes, or :class:`~takestock.inside_scope.InsideRefused`."""
    where = f"`scan_targets.{TARGET_KEY}`"
    probes: list[Probe] = []
    for i, entry in enumerate(inside_scope.entries(target, TARGET_KEY)):
        label = f"{where}[{i}]"
        if not isinstance(entry, Mapping):
            raise inside_scope.InsideRefused(f"{label}: must be a mapping with `host:` and `port:`")
        if "ip" in entry:
            raise inside_scope.InsideRefused(
                f"{label}: this probe takes `host:` only — name the host to probe there")
        host = inside_scope.check_host(str(entry.get("host") or ""), label)
        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise inside_scope.InsideRefused(
                f"{label}: port {port!r} is not a single port number. Ranges and lists are "
                "refused by construction")
        if port not in INTERNAL_PORTS:
            raise inside_scope.InsideRefused(
                f"{label}: port {port} is not on this collector's allow-list "
                f"({', '.join(str(p) for p in sorted(INTERNAL_PORTS))}). Adding a port is a "
                "code change, not a profile edit")
        probes.append(Probe(host, port, INTERNAL_PORTS[port],
                            str(entry.get("role") or "").strip()))
    inside_scope.check_unique(((p.host, p.port) for p in probes), where)
    inside_scope.check_ceiling(len({p.host for p in probes}), MAX_HOSTS, where)
    inside_scope.check_ceiling(len(probes), plaintext_scan.MAX_PROBE_PAIRS, where,
                               "(host, port) pairs")
    per_host: dict[str, int] = {}
    for p in probes:
        key = scan_address(p.host).lower()
        per_host[key] = per_host.get(key, 0) + 1
    for h, n in sorted(per_host.items()):
        inside_scope.check_ceiling(n, plaintext_scan.MAX_PORTS_PER_HOST, f"{where}: {h}",
                                   "ports")
    return probes


def _family(host: str) -> list[str]:
    return ["-6"] if is_ipv6_literal(host) else []


def _netloc(host: str) -> str:
    addr = scan_address(host)
    return f"[{addr}]" if is_ipv6_literal(host) else addr


def enum_command(host: str, port: int) -> list[str]:
    """nmap's suite enumeration on one port."""
    return ["nmap", "-Pn", *_family(host), "-p", str(port), "--script", "ssl-enum-ciphers",
            scan_address(host)]


def capability_command(host: str, port: int, script: str) -> list[str]:
    """nmap reading a mail service's capability list, forced onto the named port."""
    return ["nmap", *plaintext_scan.NMAP_FLAGS, *_family(host), "-p", str(port),
            "--script", f"+{script}", scan_address(host)]


def curl_command(host: str, port: int) -> list[str]:
    """One explicit plain-HTTP request, which cannot fall back to TLS."""
    return ["curl", *hsts.CURL_FLAGS, "-m", str(hsts.REQUEST_TIMEOUT),
            f"http://{_netloc(host)}:{port}/"]


def winrm_command(host: str, port: int) -> list[str]:
    """One unauthenticated, empty ``POST /wsman``."""
    scheme = WINRM_PORTS[port]
    insecure = ["-k"] if scheme == "https" else []
    return ["curl", *hsts.CURL_FLAGS, "-m", str(hsts.REQUEST_TIMEOUT), "-X", "POST",
            "-H", f"Content-Type: {WINRM_CONTENT_TYPE}", "--data", "", *insecure,
            f"{scheme}://{_netloc(host)}:{port}{WINRM_PATH}"]


_GLUED_TAG = re.compile(r"A\d{4}$")
_SASL = re.compile(r"SASL\(([^)]*)\)")
_SMTP_AUTH = re.compile(r"^AUTH[ =](.*)$", re.I)
_PLAIN_MECHANISMS = ("PLAIN", "LOGIN")


def _script_body(out: str, script: str) -> str:
    head = re.compile(rf"^\|_?\s*{re.escape(script)}:\s*(.*)$")
    body: list[str] = []
    grab = False
    for line in out.splitlines():
        m = head.match(line)
        if m:
            grab = True
            body.append(m.group(1))
            if line.startswith("|_"):
                break
            continue
        if grab:
            if not line.startswith("|"):
                break
            body.append(line.lstrip("|_").strip())
            if line.startswith("|_"):
                break
    return "\n".join(body).strip()


def _failed(body: str) -> bool:
    low = body.lower()
    return (not body or low.startswith("error") or "couldn't establish" in low
            or "doesn't support" in low or "failed to" in low)


def parse_imap_capabilities(out: str) -> Capabilities:
    """Read ``imap-capabilities``.

    nmap joins the tagged completion line onto the capability line, so the
    last capability can arrive with the command tag glued on
    (``LOGINDISABLEDA0001``); the tag is stripped.
    """
    body = _script_body(out, "imap-capabilities")
    if _failed(body):
        return Capabilities(raw=body)
    caps = {_GLUED_TAG.sub("", tok) for tok in body.split()} - {""}
    plain = sorted(c for c in caps if c.upper() in ("AUTH=PLAIN", "AUTH=LOGIN"))
    login_disabled = "LOGINDISABLED" in caps
    if not login_disabled:
        plain = ["LOGIN command (no LOGINDISABLED)", *plain]
    return Capabilities(read=True, starttls="STARTTLS" in caps, plaintext_auth=plain,
                        login_disabled=login_disabled, raw=body)


def parse_pop3_capabilities(out: str) -> Capabilities:
    """Read ``pop3-capabilities``: ``USER`` or a plaintext SASL mechanism is a password path."""
    body = _script_body(out, "pop3-capabilities")
    if _failed(body):
        return Capabilities(raw=body)
    toks = body.split()
    plain = ["USER"] if "USER" in toks else []
    sasl = _SASL.search(body)
    if sasl:
        plain += [f"SASL {m}" for m in sasl.group(1).split() if m.upper() in _PLAIN_MECHANISMS]
    return Capabilities(read=True, starttls="STLS" in toks, plaintext_auth=plain, raw=body)


def parse_smtp_commands(out: str) -> Capabilities:
    """Read ``smtp-commands``: the first line is the EHLO extension list."""
    body = _script_body(out, "smtp-commands")
    if _failed(body):
        return Capabilities(raw=body)
    ehlo = body.splitlines()[0]
    exts = [e.strip() for e in ehlo.split(",") if e.strip()]
    plain: set[str] = set()
    for e in exts:
        m = _SMTP_AUTH.match(e)
        if m:
            plain |= {f"AUTH {w}" for w in m.group(1).split() if w.upper() in _PLAIN_MECHANISMS}
    return Capabilities(read=True, starttls=any(e.upper() == "STARTTLS" for e in exts),
                        plaintext_auth=sorted(plain), raw=ehlo)


_PARSERS: dict[str, Callable[[str], Capabilities]] = {
    "imap-capabilities": parse_imap_capabilities,
    "pop3-capabilities": parse_pop3_capabilities,
    "smtp-commands": parse_smtp_commands,
}

_STATUS_LINE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})", re.M)
_STATUS_BLOCK = re.compile(r"(?=^HTTP/[\d.]+\s+\d{3})", re.M)
_WWW_AUTH = re.compile(r"^www-authenticate:\s*(.+?)\s*$", re.M | re.I)


def parse_winrm_auth(out: str) -> tuple[int | None, list[str]]:
    """(status code, authentication schemes offered) from the last response."""
    text = (out or "").replace("\r\n", "\n")
    blocks = [b for b in _STATUS_BLOCK.split(text) if _STATUS_LINE.match(b)]
    if not blocks:
        return None, []
    last = blocks[-1]
    m = _STATUS_LINE.match(last)
    code = int(m.group(1)) if m else None
    schemes: list[str] = []
    for value in _WWW_AUTH.findall(last):
        for part in value.split(","):
            word = part.strip().split(" ", 1)[0]
            if word and "=" not in word and word not in schemes:
                schemes.append(word)
    return code, schemes


def _last_line(text: str) -> str:
    lines = [ln for ln in (text or "").splitlines()
             if ln.strip() and hsts.CONNECTED_MARKER not in ln]
    return lines[-1].strip()[:160] if lines else ""


def winrm_sentence(port: int, code: int | None, schemes: list[str], out: str) -> str:
    """What the unauthenticated ``POST /wsman`` showed, as a sentence for the row."""
    if code == 401:
        basic = any(s.lower() == "basic" for s in schemes)
        if not basic:
            verdict = "not offered"
        elif WINRM_PORTS[port] == "http":
            verdict = ("OFFERED over plain HTTP (a password sent base64-encoded, readable on "
                       "the network if the listener also accepts unencrypted messages, "
                       "which this header cannot show)")
        else:
            verdict = "OFFERED inside TLS (a password sent base64-encoded)"
        return (f"An unauthenticated POST {WINRM_PATH} was answered 401 offering "
                f"{', '.join(schemes) or 'no scheme'}; Basic is {verdict}.")
    if code is None:
        return (f"An unauthenticated POST {WINRM_PATH} got no HTTP answer "
                f"({_last_line(out)!r}), so the offered authentication schemes are not "
                "measured.")
    return (f"An unauthenticated POST {WINRM_PATH} was answered {code}, not 401, so no "
            "authentication scheme was offered to read; whether this is a WinRM listener "
            "is not shown.")


def attach_winrm_auth(asset: CryptoAsset, probe: Probe, raw_dir: Path | None) -> None:
    """Send the ``POST /wsman`` and record what it showed on ``asset``."""
    host, port = probe.host, probe.port
    out = run(winrm_command(host, port), timeout=hsts.RUN_TIMEOUT)
    if raw_dir:
        (raw_dir / f"internal-winrm-{scan_address(host)}-{port}.txt").write_text(out)
    code, schemes = parse_winrm_auth(out)
    basic = any(s.lower() == "basic" for s in schemes)
    asset.extra.update({"winrm_status": code, "winrm_auth_offered": ", ".join(schemes),
                        "winrm_basic_offered": basic if code == 401 else None})
    asset.notes = "; ".join(b for b in [asset.notes, winrm_sentence(port, code, schemes, out)]
                            if b)


def _stamp(asset: CryptoAsset, probe: Probe, ref_time: datetime | None) -> CryptoAsset:
    asset.source = SOURCE
    asset.source_name = SOURCE_NAME
    asset.source_class = "private"
    asset.internet_facing = False
    asset.collected_at = now_date(ref_time)
    asset.role = probe.role or f"Internal service — {probe.spec.service}"
    asset.extra = {**asset.extra, "service": f"{probe.port}/tcp",
                   "internal_service": probe.spec.service}
    return asset


def _unmeasured(probe: Probe, protocol: str, ref_time: datetime | None,
                name: str = "") -> CryptoAsset:
    a = CryptoAsset(name=name or f"{probe.spec.service} {probe.host}:{probe.port}",
                    data_state="in-transit", protocol=protocol, host=probe.host,
                    port=str(probe.port), verdict="unknown", notes=NO_PORT_TABLE)
    return _stamp(a, probe, ref_time)


def _http_table(port: int, service: str) -> dict[str, Mapping[str, str]]:
    """The port table, plus a cleartext HTTP row for ``port`` if it has none."""
    table: dict[str, Mapping[str, str]] = dict(load_port_encryption())
    if lookup(str(port), "tcp", table) is None:
        table[f"{port}/tcp"] = {
            "port": str(port), "transport": "tcp", "protocol": "http", "posture": CLEARTEXT,
            "exposure": "", "remediability": "", "frontable": "",
            "notes": f"{service}; declared HTTP by this probe's port list"}
    return table


def _state_row(probe: Probe, obs: plaintext_scan.PortObservation,
               table: Mapping, ref_time: datetime | None) -> CryptoAsset:
    outcome, evidence = plaintext_scan.classify(obs, lookup(obs.port, "tcp", table),
                                                host_unreached=plaintext_scan.no_answer(obs.state))
    a = plaintext_scan._asset(probe.host, obs, outcome, evidence, table, ref_time)
    a.name = f"{probe.spec.service} {probe.host}:{probe.port}"
    return _stamp(a, probe, ref_time)


def _port_obs(out: str, port: int) -> plaintext_scan.PortObservation | None:
    return plaintext_scan.parse_nmap(out).ports.get(f"{port}/tcp")


def cleartext_http_row(probe: Probe, obs: plaintext_scan.PortObservation, curl_out: str,
                       ref_time: datetime | None, expected_tls: bool) -> CryptoAsset:
    """The row for an open port once a plain ``http://`` request has been answered (or not)."""
    table = _http_table(probe.port, probe.spec.service)
    row = lookup(str(probe.port), "tcp", table) or {}
    status, code, location = plaintext_scan.parse_http_answer(curl_out)
    tls_note = (" This port is expected to carry TLS and completed no TLS handshake at "
                "TLS 1.0-1.3.") if expected_tls else ""
    if row.get("posture") != CLEARTEXT:
        outcome, evidence = plaintext_scan.classify(obs, row)
        if status:
            evidence += (f" A request sent in clear was answered `{status}`, so the HTTP "
                         "transport is plain; whether the messages on it are encrypted is a "
                         "configuration fact this probe cannot read.")
    elif code is None:
        outcome = plaintext_scan.INCONCLUSIVE
        evidence = (f"{probe.port}/tcp is OPEN and an ordinary HTTP request sent in clear got "
                    f"no HTTP answer (curl: {_last_line(curl_out)!r}). Something is listening "
                    "and did not speak plain HTTP; nothing is concluded either way." + tls_note)
    elif code == 400:
        outcome = plaintext_scan.INCONCLUSIVE
        evidence = (f"{probe.port}/tcp is OPEN and answered a request sent in clear with "
                    f"`{status}`. A TLS server commonly answers a plain request on its TLS "
                    "port this way, so a 400 is not taken as a cleartext service." + tls_note)
    elif 300 <= code < 400 and location.lower().startswith("https://"):
        outcome = plaintext_scan.REDIRECT_HTTPS
        evidence = (f"{probe.port}/tcp answered a request sent in clear with `{status}` and a "
                    f"redirect to {location}: the client is sent to HTTPS. The redirect itself "
                    "travels in clear." + tls_note)
    else:
        outcome = plaintext_scan.CLEARTEXT_SERVED
        evidence = (f"Actively probed: {probe.port}/tcp answered an ordinary HTTP request sent "
                    f"in clear with `{status}`"
                    + (f" (redirect to {location})" if location else "")
                    + ". Measured with an explicit http:// request that cannot fall back to "
                    "TLS, not inferred from the port number." + tls_note)
    a = plaintext_scan._asset(probe.host, obs, outcome, evidence, table, ref_time)
    a.name = f"{probe.spec.service} {probe.host}:{probe.port}"
    a.extra["http_status"] = status
    if expected_tls:
        a.extra["expected"] = "tls"
    return _stamp(a, probe, ref_time)


def _run_curl(probe: Probe, raw_dir: Path | None) -> str:
    out = run(curl_command(probe.host, probe.port), timeout=hsts.RUN_TIMEOUT)
    if raw_dir:
        (raw_dir / f"internal-curl-{scan_address(probe.host)}-{probe.port}.txt").write_text(out)
    return out


def _run_enum(probe: Probe, raw_dir: Path | None) -> str:
    out = run(enum_command(probe.host, probe.port), timeout=180)
    if raw_dir:
        (raw_dir / f"internal-nmap-tls-{scan_address(probe.host)}-{probe.port}.txt").write_text(out)
    return out


def measure_tls(probe: Probe, raw_dir: Path | None, ref_time: datetime | None) -> CryptoAsset:
    """One row for a port that carries TLS from the first byte."""
    host, port = probe.host, probe.port
    out = _run_enum(probe, raw_dir)
    obs = _port_obs(out, port)
    if obs is None:
        return _unmeasured(probe, "tls", ref_time)
    if obs.state != "open":
        return _state_row(probe, obs, load_port_encryption(), ref_time)

    parsed = tls_scan.parse_enum_ciphers(out) if "ssl-enum-ciphers" in out else None
    probed = tls_scan.probe_versions(host, port, host, raw_dir)
    offered = tls_session.versions_in_state(probed, OFFERED)
    if parsed is None and not offered:
        curl_out = _run_curl(probe, raw_dir)
        status, code, _loc = plaintext_scan.parse_http_answer(curl_out)
        if code is not None and code != 400:
            return cleartext_http_row(probe, obs, curl_out, ref_time, expected_tls=True)
        a = CryptoAsset(
            name=f"{probe.spec.service} {host}:{port}", data_state="in-transit",
            protocol="tls", host=host, port=str(port), verdict="unknown",
            flags=[f"{NO_HANDSHAKE_FLAG}{probe.spec.slug}"],
            extra={"version_probe": tls_session.describe(probed), "http_status": status},
            notes=(f"SOMETHING IS LISTENING AND IT DID NOT SPEAK TLS — {host} answered on "
                   f"port {port}, where {probe.spec.service} is expected to carry TLS, and "
                   "completed no handshake at TLS 1.0-1.3; an ordinary HTTP request in clear "
                   f"got no usable answer either (curl: {_last_line(curl_out)!r})."))
        return _stamp(a, probe, ref_time)

    versions, version_note, version_flags = tls_scan.merge_versions(
        parsed["versions"] if parsed else [], probed)
    notes = [f"nmap least-strength grade {parsed['grade']}"] if parsed and parsed["grade"] else []
    if parsed is None:
        notes.append("nmap's ssl-enum-ciphers returned nothing although a handshake completed, "
                     "so the suites shown are what each pinned handshake chose, not the full "
                     "accepted set")
    if version_note:
        notes.append(version_note)
    suites = parsed["suites"] if parsed else sorted(
        {smtp_starttls.iana_suite_name(probed[v].cipher) or probed[v].cipher
         for v in offered if probed[v].cipher})
    a = CryptoAsset(
        name=f"{probe.spec.service} {host}:{port}", data_state="in-transit", protocol="tls",
        host=host, port=str(port), protocol_versions=versions,
        key_exchange=parsed["key_exchange"] if parsed else [],
        symmetric=suites, flags=sorted(version_flags), notes="; ".join(notes),
        extra={"nmap_grade": parsed["grade"] if parsed else None,
               "versions_enumerated": ", ".join(parsed["versions"]) if parsed else "",
               "version_probe": tls_session.describe(probed)})
    tls_scan.attach_negotiation(a, host, port, host, raw_dir)
    tls_scan.attach_cert_detail(a, host, port, raw_dir, ref_time)
    if port in WINRM_PORTS:
        attach_winrm_auth(a, probe, raw_dir)
    return _stamp(a, probe, ref_time)


def measure_ldap_starttls(probe: Probe, raw_dir: Path | None,
                          ref_time: datetime | None) -> CryptoAsset:
    """One row for LDAP upgraded with StartTLS, measured by nmap alone."""
    host, port = probe.host, probe.port
    out = _run_enum(probe, raw_dir)
    obs = _port_obs(out, port)
    name = f"{probe.spec.service} {host}:{port}"
    if obs is None:
        return _unmeasured(probe, "tls", ref_time)
    if obs.state != "open":
        return _state_row(probe, obs, load_port_encryption(), ref_time)
    parsed = tls_scan.parse_enum_ciphers(out) if "ssl-enum-ciphers" in out else None
    if parsed is None:
        a = CryptoAsset(
            name=name, data_state="in-transit", protocol="ldap", host=host, port=str(port),
            verdict="unknown",
            notes=(f"{host} answered on {port} and nmap's StartTLS enumeration returned "
                   "nothing. Either the server refused the StartTLS operation or answered in "
                   "a form nmap did not accept, and nmap does not say which, so neither "
                   "'no StartTLS' nor 'cleartext only' is claimed."))
        return _stamp(a, probe, ref_time)
    probed = {"TLSv1.3": tls_session.TlsSession(COULD_NOT_ASK)}
    versions, version_note, version_flags = tls_scan.merge_versions(parsed["versions"], probed)
    notes = [f"nmap least-strength grade {parsed['grade']}"] if parsed["grade"] else []
    notes.append("measured over LDAP StartTLS by nmap alone; no pinned handshake was made")
    if version_note:
        notes.append(version_note)
    a = CryptoAsset(
        name=name, data_state="in-transit", protocol="tls", host=host, port=str(port),
        protocol_versions=versions, key_exchange=parsed["key_exchange"],
        symmetric=parsed["suites"], flags=sorted(version_flags), notes="; ".join(notes),
        extra={"nmap_grade": parsed["grade"], "starttls": "offered",
               "versions_enumerated": ", ".join(parsed["versions"]),
               "version_probe": tls_session.describe(probed)})
    tls_scan.attach_cert_detail(a, host, port, raw_dir, ref_time)
    return _stamp(a, probe, ref_time)


def measure_starttls(probe: Probe, raw_dir: Path | None,
                     ref_time: datetime | None) -> list[CryptoAsset]:
    """A session row and, when the capability list was read, a sign-in row."""
    host, port, spec = probe.host, probe.port, probe.spec
    proto = spec.starttls
    name = f"{spec.service} STARTTLS {host}:{port}"
    out = run(capability_command(host, port, spec.script), timeout=plaintext_scan.RUN_TIMEOUT)
    if raw_dir:
        (raw_dir / f"internal-nmap-{spec.script}-{scan_address(host)}-{port}.txt").write_text(out)
    obs = _port_obs(out, port)
    table = load_port_encryption()
    if obs is None:
        return [_unmeasured(probe, "tls", ref_time, name)]
    if obs.state != "open":
        return [_state_row(probe, obs, table, ref_time)]

    caps = _PARSERS[spec.script](out)
    enum_out = _run_enum(probe, raw_dir)
    parsed = (tls_scan.parse_enum_ciphers(enum_out)
              if "ssl-enum-ciphers" in enum_out else None)
    transcripts: dict[str, str] = {}
    probed = tls_scan.probe_versions(host, port, host, raw_dir, starttls=proto,
                                     transcripts=transcripts)
    offered = tls_session.versions_in_state(probed, OFFERED)
    unknown = tls_session.versions_in_state(probed, COULD_NOT_ASK)
    versions, version_note, version_flags = tls_scan.merge_versions(
        parsed["versions"] if parsed else [], probed)
    openssl_saw_none = any(smtp_starttls._NO_STARTTLS.search(t) for t in transcripts.values())

    suites, raw_suites, groups = [], [], set()
    for v in offered:
        cipher = probed[v].cipher
        if cipher:
            raw_suites.append(f"{v}={cipher}")
            suites.append(smtp_starttls.iana_suite_name(cipher) or cipher)
        g = smtp_starttls.parse_server_temp_key(transcripts.get(v, ""))
        if g:
            groups.add(g)
    flags: set[str] = set(version_flags)
    if unknown:
        flags.add(tls_scan.VERSION_PROBE_UNAVAILABLE)
    encrypted = bool(offered or parsed)
    session = CryptoAsset(
        name=name, data_state="in-transit", protocol="tls", host=host, port=str(port),
        protocol_versions=versions if parsed else sorted(dict.fromkeys(offered)),
        key_exchange=sorted(groups | set(parsed["key_exchange"] if parsed else [])),
        symmetric=parsed["suites"] if parsed else sorted(dict.fromkeys(suites)),
        flags=sorted(flags),
        extra={"starttls": "offered" if encrypted else "no encrypted session established",
               "starttls_advertised": caps.starttls if caps.read else None,
               "capabilities": caps.raw,
               "version_probe": tls_session.describe(probed),
               "nmap_grade": parsed["grade"] if parsed else None,
               "versions_enumerated": ", ".join(parsed["versions"]) if parsed else "",
               **({"negotiated_suites": "; ".join(raw_suites)} if raw_suites else {})})
    notes: list[str] = []
    if parsed and parsed["grade"]:
        notes.append(f"nmap least-strength grade {parsed['grade']}")
    if encrypted:
        tls_scan.attach_cert_detail(session, host, port, raw_dir, ref_time)
        notes.append(ENUMERATED_OVER_STARTTLS if parsed else
                     f"{smtp_starttls.PREFERENCE_ONLY} (nmap's ssl-enum-ciphers returned "
                     "nothing over STARTTLS here)")
        if parsed and version_note:
            notes.append(version_note)
    elif (caps.read and not caps.starttls) or (not caps.read and openssl_saw_none):
        session.verdict = "weak"
        session.flags = sorted(set(session.flags) | {f"{PLAINTEXT_FLAG}{proto}"})
        how = ("its capability list names no STARTTLS" if caps.read
               else "openssl found no STARTTLS in its reply")
        notes.append(f"NO ENCRYPTION AVAILABLE — {host} answered on {spec.service} port {port} "
                     f"and {how}, so this service runs in clear. Measured, not inferred from "
                     "the port number.")
    else:
        apply_posture(session, table, "tcp", evidence=(
            "The service advertised STARTTLS (or its capabilities could not be read) and no "
            "handshake completed at TLS 1.0-1.3; a refused upgrade and a refusal of every "
            "pinned version look the same to openssl, so neither is claimed."))
    if unknown and not (parsed and version_note):
        notes.append(f"version probe could not run for {', '.join(unknown)} — those versions "
                     "are unknown, not absent")
    if not caps.read:
        notes.append(f"the capability list could not be read ({caps.raw or 'no script output'}), "
                     "so whether a password is invited before encryption is not measured")
    session.notes = "; ".join(b for b in [session.notes, *notes] if b)
    rows = [_stamp(session, probe, ref_time)]
    if caps.read:
        rows.append(auth_row(probe, caps, ref_time))
    return rows


def auth_row(probe: Probe, caps: Capabilities, ref_time: datetime | None) -> CryptoAsset:
    """Is a password invited on the plain connection, before encryption?"""
    proto = probe.spec.starttls
    basis = AUTH_BASIS[proto]
    a = CryptoAsset(
        name=f"{probe.spec.service} sign-in before encryption {probe.host}:{probe.port}",
        data_state="in-transit", protocol=proto, host=probe.host, port=str(probe.port),
        extra={"plaintext_auth_advertised": ", ".join(caps.plaintext_auth),
               "starttls_advertised": caps.starttls, "login_disabled": caps.login_disabled,
               "capabilities": caps.raw, "standard": basis})
    if caps.plaintext_auth:
        a.verdict = "weak"
        a.flags = [f"{CLEARTEXT_AUTH_FLAG}{proto}"]
        when = ("before STARTTLS" if caps.starttls
                else "and the service offers no STARTTLS at all")
        a.notes = (f"PASSWORD INVITED IN CLEAR — on the unencrypted connection, "
                   f"{probe.host}:{probe.port} advertises {', '.join(caps.plaintext_auth)} "
                   f"{when}. A client configured to use it sends the password readable on "
                   "the network. Measured from the service's own capability list. "
                   f"Standard: {basis}. {NZISM_NOTE}.")
    else:
        a.verdict = NA_VERDICT
        a.notes = (f"No plaintext password path is advertised before encryption on "
                   f"{probe.host}:{probe.port}"
                   + (" (LOGINDISABLED is advertised)" if caps.login_disabled else "")
                   + ". Measured from the service's own capability list; it says what the "
                   "service advertises, not what it would accept from a client that ignored "
                   f"the list. Standard: {basis}.")
    return _stamp(a, probe, ref_time)


def measure_http(probe: Probe, raw_dir: Path | None, ref_time: datetime | None) -> CryptoAsset:
    """One row for a port declared to speak HTTP."""
    host, port = probe.host, probe.port
    out = run(plaintext_scan._nmap_command(host, [f"{port}/tcp"]),
              timeout=plaintext_scan.RUN_TIMEOUT)
    if raw_dir:
        (raw_dir / f"internal-nmap-http-{scan_address(host)}-{port}.txt").write_text(out)
    obs = _port_obs(out, port)
    if obs is None:
        return _unmeasured(probe, "http", ref_time)
    if obs.state != "open":
        return _state_row(probe, obs, _http_table(port, probe.spec.service), ref_time)
    row = cleartext_http_row(probe, obs, _run_curl(probe, raw_dir), ref_time,
                             expected_tls=False)
    if port in WINRM_PORTS:
        attach_winrm_auth(row, probe, raw_dir)
    return row


def budget_lines(probes: list[Probe]) -> list[str]:
    """Every host and port, printed before anything runs."""
    out = [f"[{SOURCE}] probe budget — every host and every port, before anything runs",
           f"  hosts    : {len({p.host for p in probes})} (ceiling {MAX_HOSTS})",
           f"  pairs    : {len(probes)} (ceiling {plaintext_scan.MAX_PROBE_PAIRS})",
           "  never    : a credential, a login, or any vulnerability script"]
    out += [f"  probe    : {p.host}:{p.port}  [{p.spec.kind}: {p.spec.service}]" for p in probes]
    return out


def _settle() -> None:
    time.sleep(plaintext_scan.INTER_HOST_SECONDS)


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def tools_needed(probes: list[Probe]) -> set[str]:
    """The programs a plan needs on PATH."""
    kinds = {p.spec.kind for p in probes}
    return ({"nmap"} | ({"openssl"} if kinds & {TLS, STARTTLS} else set())
            | ({"curl"} if kinds & {TLS, HTTP} else set()))


def collect(target: Mapping, raw_dir: Path | None = None, ref_time: datetime | None = None,
            announce: Callable[[str], None] | None = None
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every authorised (host, port); return (assets, failures)."""
    if not declared(target):
        return [], []
    try:
        probes = plan(target)
    except inside_scope.InsideRefused as exc:
        return [], [inside_scope.refusal(SOURCE, exc)]
    if not probes:
        return [], []
    say = _announce if announce is None else announce
    lines = budget_lines(probes)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "internal-budget.txt").write_text("\n".join(lines) + "\n")
    missing = sorted(t for t in tools_needed(probes) if not shutil.which(t))
    if missing:
        return [], [f"{SOURCE}: {', '.join(missing)} not on PATH, so none of the "
                    f"{len(probes)} declared (host, port) pair(s) was probed. This run holds "
                    "no evidence about them."]
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    last_host = ""
    for probe in probes:
        if last_host and probe.host != last_host:
            _settle()
        last_host = probe.host
        if probe.spec.kind == TLS:
            rows = [measure_tls(probe, raw_dir, ref_time)]
        elif probe.spec.kind == STARTTLS:
            rows = measure_starttls(probe, raw_dir, ref_time)
        elif probe.spec.kind == LDAP_STARTTLS:
            rows = [measure_ldap_starttls(probe, raw_dir, ref_time)]
        else:
            rows = [measure_http(probe, raw_dir, ref_time)]
        if any(r.notes == NO_PORT_TABLE for r in rows):
            failures.append(f"{SOURCE} {probe.host}:{probe.port}: nmap produced no port table, "
                            "so this pair was not measured. Absence here is not evidence of "
                            "anything.")
        assets += rows
    return assets, failures
