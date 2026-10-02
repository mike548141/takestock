"""Does Intel AMT firmware answer on 16992/16993, and over what?

Intel Active Management Technology (AMT) is an out-of-band management
interface built into some machines' firmware. It runs below the operating
system and answers on its own ports. A listener inventory taken from the
operating system can show a socket bound to 16992; it cannot show that the
firmware answers on the network. This probe asks, one named host at a time.

An inside probe: it reads ``scan_targets.intel_amt`` and needs its own
``authorisation.intel_amt`` record (:mod:`takestock.inside_scope`).

**What it sends.** One unauthenticated ``GET /`` per port with curl:
16992 as ``http://`` and 16993 as ``https://`` (certificate not checked,
because the question is identification, not trust). Where the 16993 request
reached something, the TLS measurement :mod:`tls_scan` makes on 443 follows,
as a second row graded by the baseline. It never sends a credential, answers
a Digest challenge, or tests for any vulnerability. The ports are fixed in
:data:`AMT_PORTS`; a profile cannot add one.

**How AMT is recognised.** By the ``Server:`` header, against the strings
nmap's service-detection database (``nmap-service-probes``) uses for Intel
AMT: ``Intel(R) Active Management Technology <version>``, ``Intel(R) Standard
Manageability <version>`` and ``AMT``.

**Outcomes**, per host and port:

* ``amt-answered``: AMT's ``Server:`` header came back. On 16992 that is the
  management interface in clear, graded through the port table; on 16993 this
  row stays ``unknown`` and the TLS row carries the strength.
* ``other-http``: an HTTP answer from something that is not AMT.
* ``no-http-answer``: a connection was made and no HTTP answer came back.
* ``no-connection``: refused or no route (curl does not say which).
* ``no-answer``: the attempt timed out, so nothing is measured.

Each row records ``amt_listener_finding`` (``confirmed``, ``not-confirmed``
or ``unmeasured``) for comparison with a listener inventory. A
``not-confirmed`` is scoped to where the probe ran from: AMT answers only on
the interface the firmware is provisioned on.
"""

from __future__ import annotations

import re
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import __version__, inside_scope, tls_session
from ..config import load_port_encryption
from ..identity import names_by_address, report_as
from ..inside_scope import MAX_HOSTS
from ..model import CryptoAsset
from ..plaintext import CLEARTEXT, PortTable, apply_posture, lookup
from ..util import ERROR_PREFIX, is_ipv6_literal, now_date, run, scan_address
from . import tls_scan

SOURCE = "intel_amt"
#: The ``scan_targets`` (and ``authorisation``) key for this probe.
TARGET_KEY = "intel_amt"
AMT_PORTS: tuple[tuple[str, str], ...] = (("16992", "http"), ("16993", "https"))
TLS_PORT = "16993"

SOURCE_NAME = "Intel AMT firmware answer probe (curl) — inside the network"
ROLE = ("Out-of-band management interface (Intel AMT) — controls the machine below "
        "the operating system")

#: Written by curl's ``-w`` after the headers: curl's exit code and the address reached.
PROBE_MARKER = "__takestock_probe__"
CURL_FLAGS = ("-sS", "-o", "/dev/null", "-D", "-", "-A", f"takestock/{__version__}",
              "--connect-timeout", "10", "-m", "20",
              "-w", rf"\n{PROBE_MARKER} exit=%{{exitcode}} connected=%{{remote_ip}}\n")
RUN_TIMEOUT = 30
INTER_HOST_SECONDS = 2.0

AMT_SERVER = re.compile(
    r"^(?:Intel\(R\) Active Management Technology(?: [\w._-]+)?"
    r"|Intel\(R\) Standard Manageability(?: [\w._-]+)?"
    r"|AMT)$")

#: ``extra.amt_instrument`` on the TLS row.
TLS_INSTRUMENT = "tls_scan measurement (nmap ssl-enum-ciphers, openssl, ssl-cert)"

AMT_ANSWERED = "amt-answered"
OTHER_HTTP = "other-http"
NO_HTTP_ANSWER = "no-http-answer"
NO_CONNECTION = "no-connection"
NO_ANSWER = "no-answer"

CONFIRMED, NOT_CONFIRMED, UNMEASURED = "confirmed", "not-confirmed", "unmeasured"

_STATUS = re.compile(r"^HTTP/([\d.]+)\s+(\d{3})")
_TRAILER = re.compile(rf"^{PROBE_MARKER} exit=(\d+) connected=(\S*)\s*$")
_CURL_ERR = re.compile(r"^curl: \((\d+)\)\s*(.*)$")
_KEPT_HEADERS = ("server", "www-authenticate", "location")


@dataclass
class Answer:
    """What one curl invocation showed."""

    exit_code: int | None = None
    connected: str = ""
    status: int | None = None
    http_version: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""


def parse_curl(out: str) -> Answer:
    """Read curl's header dump and the ``-w`` trailer; the last status block wins."""
    ans = Answer()
    if out.startswith(ERROR_PREFIX):
        ans.error = out.strip()[:200]
        return ans
    for line in out.replace("\r\n", "\n").split("\n"):
        s = line.strip()
        m = _STATUS.match(s)
        if m:
            ans.http_version, ans.status, ans.headers = f"HTTP/{m.group(1)}", int(m.group(2)), {}
            continue
        t = _TRAILER.match(s)
        if t:
            ans.exit_code, ans.connected = int(t.group(1)), t.group(2)
            continue
        e = _CURL_ERR.match(s)
        if e:
            ans.error = f"curl ({e.group(1)}) {e.group(2)}".strip()
            continue
        name, sep, value = s.partition(":")
        if sep and ans.status is not None and name.lower() in _KEPT_HEADERS:
            ans.headers.setdefault(name.lower(), value.strip())
    return ans


def classify(ans: Answer, port: str) -> tuple[str, str]:
    """(outcome, evidence sentence) for one port."""
    if ans.status is not None:
        server = ans.headers.get("server", "")
        if AMT_SERVER.match(server):
            return AMT_ANSWERED, (
                f"Measured: {port}/tcp answered an unauthenticated GET / with "
                f"{ans.http_version} {ans.status} and `Server: {server}`, the header nmap's "
                "service database identifies as Intel AMT firmware. The firmware interface "
                "answers on this port from where the probe ran. No login was attempted.")
        return OTHER_HTTP, (
            f"Measured: {port}/tcp answered GET / with {ans.http_version} {ans.status} and "
            f"`Server: {server or '(none sent)'}`, which is not a header Intel AMT sends. "
            "Something other than AMT firmware answers on this port.")
    if ans.exit_code == 7:
        return NO_CONNECTION, (
            f"No connection on {port}/tcp ({ans.error or 'curl exit 7'}): refused or no "
            "route, and curl does not say which. AMT firmware did not answer here from "
            "where the probe ran; that is narrower than 'AMT is off'.")
    if ans.connected:
        return NO_HTTP_ANSWER, (
            f"A connection to {port}/tcp was made and no HTTP response came back "
            f"({ans.error or 'no response'}). Something listens; it did not answer as AMT "
            "firmware answers, and what it is is not measured.")
    return NO_ANSWER, (
        f"No answer on {port}/tcp ({ans.error or 'no response'}). Whether AMT firmware "
        "listens here is NOT measured: a coverage gap, not a clean result.")


def listener_finding(outcome: str) -> str:
    """How this outcome bears on a listener inventory's claim of AMT on this host."""
    if outcome == AMT_ANSWERED:
        return CONFIRMED
    if outcome in (OTHER_HTTP, NO_CONNECTION, NO_HTTP_ANSWER):
        return NOT_CONFIRMED
    return UNMEASURED


def _url(host: str, port: str, scheme: str) -> str:
    address = scan_address(host)
    netloc = f"[{address}]" if is_ipv6_literal(host) else address
    return f"{scheme}://{netloc}:{port}/"


def curl_command(host: str, port: str) -> list[str]:
    """The one request sent to ``port``; refuses a port that is not an AMT port."""
    scheme = dict(AMT_PORTS).get(port)
    if scheme is None:
        raise inside_scope.InsideRefused(f"{port}/tcp is not an AMT port this probe sends to")
    insecure = ["-k"] if scheme == "https" else []
    return ["curl", *CURL_FLAGS, *insecure, _url(host, port, scheme)]


def tls_enum_command(host: str) -> list[str]:
    """nmap's suite enumeration on 16993, as :mod:`tls_scan` runs it on 443."""
    family = ["-6"] if is_ipv6_literal(host) else []
    return ["nmap", "-Pn", *family, "-p", TLS_PORT, "--script", "ssl-enum-ciphers",
            scan_address(host)]


def tls_asset(host: str, enum_out: str, probed: dict[str, tls_session.TlsSession],
              ref_time: datetime | None = None) -> CryptoAsset:
    """The TLS row for 16993; the caller attaches the negotiation and certificate."""
    a = CryptoAsset(
        name=f"Intel AMT TLS {host}:{TLS_PORT}", role=ROLE, data_state="in-transit",
        protocol="tls", host=host, port=TLS_PORT, source=SOURCE, internet_facing=False,
        source_class="private", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        extra={"amt_instrument": TLS_INSTRUMENT,
               "version_probe": tls_session.describe(probed)})
    parsed = tls_scan.parse_enum_ciphers(enum_out) if "ssl-enum-ciphers" in enum_out else None
    offered = tls_session.versions_in_state(probed, tls_session.OFFERED)
    refused = tls_session.versions_in_state(probed, tls_session.REFUSED)
    if parsed is None and not offered and not refused:
        a.verdict = "unknown"
        a.notes = (f"TLS on {TLS_PORT}/tcp is NOT measured: neither nmap's enumeration nor the "
                   "per-version handshake could run, so nothing is known either way.")
        return a
    if parsed is None and not offered:
        a.verdict = "unknown"
        a.notes = (f"Something answered on {TLS_PORT}/tcp, completed no TLS handshake at "
                   "TLS 1.0-1.3, and nmap enumerated no TLS suites there. The TLS strength "
                   "of this port is not measured; the identification row says what answered.")
        return a
    versions, version_note, version_flags = tls_scan.merge_versions(
        parsed["versions"] if parsed else [], probed)
    notes = [f"nmap least-strength grade {parsed['grade']}"] if parsed and parsed["grade"] else []
    if parsed is None:
        notes.append("nmap's ssl-enum-ciphers returned nothing although a handshake completed, "
                     "so the suites shown are what each pinned handshake chose, not the full "
                     "accepted set")
    if version_note:
        notes.append(version_note)
    a.protocol_versions = versions
    a.key_exchange = parsed["key_exchange"] if parsed else []
    a.symmetric = parsed["suites"] if parsed else sorted(
        {probed[v].cipher for v in offered if probed[v].cipher})
    a.flags = sorted(version_flags)
    a.notes = "; ".join(notes)
    a.extra.update({"nmap_grade": parsed["grade"] if parsed else None,
                    "versions_enumerated": ", ".join(parsed["versions"]) if parsed else ""})
    return a


def measure_tls(host: str, raw_dir: Path | None, ref_time: datetime | None) -> CryptoAsset:
    """The :mod:`tls_scan` measurement on 16993."""
    out = run(tls_enum_command(host), timeout=180)
    if raw_dir:
        (raw_dir / f"intel-amt-nmap-tls-{scan_address(host)}-{TLS_PORT}.txt").write_text(out)
    probed = tls_scan.probe_versions(host, int(TLS_PORT), host, raw_dir)
    a = tls_asset(host, out, probed, ref_time)
    if a.protocol_versions:
        tls_scan.attach_negotiation(a, host, int(TLS_PORT), host, raw_dir)
        tls_scan.attach_cert_detail(a, host, int(TLS_PORT), raw_dir, ref_time)
    return a


def build_plan(target: dict) -> list[str]:
    """The authorised hosts, or :class:`~takestock.inside_scope.InsideRefused`."""
    where = f"`scan_targets.{TARGET_KEY}`"
    hosts = [inside_scope.entry_address(entry, f"{where}[{i}]")[0]
             for i, entry in enumerate(inside_scope.entries(target, TARGET_KEY))]
    inside_scope.check_unique(((h,) for h in hosts), where)
    inside_scope.check_ceiling(len(hosts), MAX_HOSTS, where)
    return hosts


def budget_lines(hosts: list[str]) -> list[str]:
    """Every host and what will be sent to it, printed before anything runs."""
    ports = ", ".join(f"{p}/tcp ({s})" for p, s in AMT_PORTS)
    return [f"[{SOURCE}] probe budget — {len(hosts)} host(s) (ceiling {MAX_HOSTS}), "
            f"ports {ports}, fixed in code",
            f"  method   : one unauthenticated `GET /` per port with curl, hosts one at a "
            f"time, {INTER_HOST_SECONDS:g}s between them",
            f"  on {TLS_PORT}: where GET / reached something, tls_scan's TLS measurement "
            "(nmap ssl-enum-ciphers, one openssl handshake per version, one negotiation, "
            "nmap ssl-cert)",
            "  never    : a credential, a login, or any vulnerability test",
            *(f"  host     : {h}" for h in hosts)]


def asset_for(host: str, port: str, out: str, table: PortTable,
              ref_time: datetime | None = None) -> CryptoAsset:
    """One identification row from one curl result."""
    ans = parse_curl(out)
    outcome, evidence = classify(ans, port)
    row = lookup(port, "tcp", table) or {}
    scheme = dict(AMT_PORTS)[port]
    protocol = scheme if outcome == OTHER_HTTP else row.get("protocol", "")
    a = CryptoAsset(
        name=f"Intel AMT probe {host}:{port}", role=ROLE, data_state="in-transit",
        protocol=protocol, host=host, port=port, source=SOURCE, internet_facing=False,
        source_class="private", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        extra={"amt_outcome": outcome, "amt_listener_finding": listener_finding(outcome),
               "amt_instrument": "curl GET /", "http_status": ans.status,
               "http_server": ans.headers.get("server", ""),
               "http_www_authenticate": ans.headers.get("www-authenticate", ""),
               "http_location": ans.headers.get("location", ""),
               "connected_address": ans.connected, "curl_exit": ans.exit_code})
    if outcome == AMT_ANSWERED and row.get("posture") == CLEARTEXT:
        apply_posture(a, table, "tcp", evidence=evidence)
    else:
        a.verdict = "unknown"
        a.notes = evidence
    return a


def _reached(ans: Answer) -> bool:
    return ans.status is not None or bool(ans.connected)


def _settle() -> None:
    time.sleep(INTER_HOST_SECONDS)


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def collect(target: dict, raw_dir: Path | None = None, ref_time: datetime | None = None,
            announce: Callable[[str], None] | None = None
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Probe every authorised host; return (assets, failures)."""
    try:
        hosts = build_plan(target)
    except inside_scope.InsideRefused as exc:
        return [], [inside_scope.refusal(SOURCE, exc)]
    if not hosts:
        return [], []
    say = _announce if announce is None else announce
    lines = budget_lines(hosts)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "intel-amt-budget.txt").write_text("\n".join(lines) + "\n")
    if not shutil.which("curl"):
        return [], [f"{SOURCE}: curl is not on PATH, so none of the {len(hosts)} planned "
                    "host(s) was probed. This run holds no evidence about AMT."]
    table = load_port_encryption()
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    tls_missing = sorted(t for t in ("nmap", "openssl") if not shutil.which(t))
    if tls_missing:
        failures.append(f"{SOURCE}: {', '.join(tls_missing)} not on PATH, so TLS on "
                        f"{TLS_PORT}/tcp was not measured on any host; the curl rows stand.")
    for n, host in enumerate(hosts):
        if n:
            _settle()
        for port, _scheme in AMT_PORTS:
            out = run(curl_command(host, port), timeout=RUN_TIMEOUT)
            if raw_dir:
                (raw_dir / f"intel-amt-{scan_address(host)}-{port}.txt").write_text(out)
            if "curl: (6)" in out:
                failures.append(f"{SOURCE} {host}: the name did not resolve, so {port}/tcp "
                                "was not probed")
                continue
            assets.append(asset_for(host, port, out, table, ref_time))
            if port == TLS_PORT and not tls_missing and _reached(parse_curl(out)):
                assets.append(measure_tls(host, raw_dir, ref_time))
    names = names_by_address(target)
    return [report_as(a, names) for a in assets], failures
