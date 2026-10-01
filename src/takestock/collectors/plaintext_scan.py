"""Active cleartext check of named ports on the authorised hosts.

This collector answers one question per (host, port): is a service listening
here that carries its traffic in clear? It never sweeps ports. Every host
and every port it touches comes from the target's own files, and the whole
plan is printed (and written beside the observation) before anything is
contacted.

**Where the plan comes from.** In order:

1. a ``probe_list:`` in the ``<profile>.derived-ports.yaml`` overlay beside
   the target profile. It is a mapping of named sections, each with
   ``hosts_from:`` (one ``scan_targets.<group>`` the profile already
   authorises), ``ports:`` (single ``<port>/<transport>`` strings) and a
   ``basis:`` saying why those ports. It must also declare a ``budget:``
   (``hosts``, ``tcp_pairs``, ``udp_pairs``) that matches what the plan
   computes, so a host list edited without redoing the arithmetic is
   caught;
2. otherwise the profile's own ``plaintext_ports:`` list, applied to every
   published host.

**What it refuses** (nothing is contacted, and the refusal is a failure):
ranges, comma lists or wildcards in a port; more than
:data:`MAX_PORTS_PER_HOST` ports on a host, :data:`~takestock.inside_scope.MAX_HOSTS`
hosts, or :data:`MAX_PROBE_PAIRS` pairs in all (refused, never truncated); a
section with no basis or no TCP port; a host claimed by two sections; a
budget that does not match; and a derived plan that would stop probing a
pair the profile's own list authorises.

**How it measures.** One ``nmap -sT`` connect scan per host, slowly, with
the ``http-title`` script. Where that reads a page on an HTTP port, one
explicit ``curl http://`` request confirms it, because nmap retries over TLS
by itself and a title alone does not prove cleartext.

The plan checks refuse rather than warning, because a probe that has left
the machine cannot be recalled.
"""

from __future__ import annotations

import re
import shutil
import sys
import time
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import inside_scope, roles
from ..config import load_derived_ports, load_port_encryption
from ..inside_scope import MAX_HOSTS
from ..model import NA_VERDICT, CryptoAsset, register_informational_prefixes
from ..plaintext import CLEARTEXT, ENCRYPTED, OPPORTUNISTIC, PortTable, apply_posture, lookup
from ..util import ERROR_PREFIX, is_ipv6_literal, now_date, run, scan_address
from . import hsts

SOURCE = "plaintext_scan"
SOURCE_NAME = "Active cleartext check (nmap) — internet-facing endpoint"

#: The target profile's own port list.
TARGET_KEY = "plaintext_ports"

PROBE_LIST_KEY = "probe_list"
BUDGET_KEY = "budget"

HOST_SOURCE_PREFIX = "scan_targets."

PORT_SPEC = re.compile(r"^(\d{1,5})/(tcp|udp)$")

MAX_PORTS_PER_HOST = 12
MAX_PROBE_PAIRS = 400

#: Ports in a plan that another collector measures properly, and why.
MEASURED_ELSEWHERE: dict[str, str] = {
    "25/tcp": "smtp_starttls measures whether this gateway upgrades to TLS in band "
              "(RFC 3207), which a TCP connection cannot establish",
}

# Protocols that answer HTTP although their name does not say so.
HTTP_BEARING_PROTOCOLS = ("upnp", "wsd")


def _speaks_http(protocol: str) -> bool:
    p = (protocol or "").strip().lower()
    return "http" in p or p in HTTP_BEARING_PROTOCOLS


NMAP_FLAGS = ("-sT", "-Pn", "--max-retries", "1", "--scan-delay", "200ms",
              "--max-rate", "10", "--host-timeout", "120s")
NMAP_SCRIPT = "http-title"
RUN_TIMEOUT = 300

INTER_HOST_SECONDS = 2.0

# Outcomes, one per probed (host, port).
CLEARTEXT_SERVED = "cleartext-served"
CLEARTEXT_LISTENING = "cleartext-listening"
REDIRECT_HTTPS = "redirect-to-https"
UPGRADABLE_LISTENING = "upgradable-listening"
NOT_LISTENING = "not-listening"
FILTERED_NO_ANSWER = "filtered-no-answer"
UNREACHED = "unreached"
INCONCLUSIVE = "inconclusive"

REDIRECT_FLAG = "http-redirect:"
INCONCLUSIVE_FLAG = "plaintext-scan-inconclusive:"
UNREACHED_FLAG = "plaintext-scan-unreached:"

register_informational_prefixes(REDIRECT_FLAG, INCONCLUSIVE_FLAG, UNREACHED_FLAG)


def no_answer(state: str) -> bool:
    """True for an nmap port state that means nothing came back (``filtered``, ``open|filtered``)."""
    s = (state or "").strip().lower()
    return s == "filtered" or s.endswith("|filtered")


_PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(\S+)\s*(\S*)")
_TITLE_LINE = re.compile(r"^\|_?\s*http-title:\s*(.*)$")
_REDIRECT = re.compile(r"^Did not follow redirect to\s+(\S+)", re.IGNORECASE)

_REDIRECT_QUERY_IN_LINE = re.compile(
    r"(Did not follow redirect to\s+[^?#\s]+)([?#]\S*)", re.IGNORECASE)


def _redact_redirect_queries(nmap_output: str) -> str:
    """Drop the query string from redirect targets: it can carry session tokens."""
    return _REDIRECT_QUERY_IN_LINE.sub(
        lambda m: m.group(1) + " [query string redacted]", nmap_output)


class PortListRefused(ValueError):
    """The probe plan is refused; the message says why, and nothing was contacted."""


@dataclass(frozen=True)
class PortObservation:
    """One port line from nmap, with the page title if ``http-title`` read one."""

    port: str
    transport: str
    state: str
    service: str = ""
    title: str = ""

    @property
    def spec(self) -> str:
        return f"{self.port}/{self.transport}"


@dataclass(frozen=True)
class ProbeStep:
    """One host and the ports to probe on it (``deferred`` are the non-TCP ones)."""

    host: str
    section: str
    ports: tuple[str, ...]
    deferred: tuple[str, ...] = ()
    basis: str = ""


@dataclass(frozen=True)
class ProbePlan:
    """Every host and port this run will touch, and where the plan came from."""

    steps: tuple[ProbeStep, ...]
    source: str
    derived_on: str = ""
    authority: str = ""

    @property
    def hosts(self) -> int:
        return len(self.steps)

    @property
    def tcp_pairs(self) -> int:
        return sum(len(s.ports) for s in self.steps)

    @property
    def udp_pairs(self) -> int:
        return sum(len(s.deferred) for s in self.steps)


@dataclass
class HostScan:
    """nmap's answer for one host."""

    ports: dict[str, PortObservation] = field(default_factory=dict)
    reached: bool = False
    detail: str = ""


def _port_specs(raw: object, where: str) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise PortListRefused(
            f"{where}: `ports:` must be a non-empty list of `<port>/<transport>` strings. "
            "An empty or missing list is not 'probe nothing quietly' — it is a section "
            "nobody finished writing")
    specs = [str(p).strip() for p in raw]
    if len(set(specs)) != len(specs):
        raise PortListRefused(f"{where}: `ports:` repeats a port: {specs}")
    for spec in specs:
        if not PORT_SPEC.match(spec):
            raise PortListRefused(
                f"{where}: port {spec!r} is not a single `<port>/<transport>`. Ranges, "
                "comma lists, wildcards and nmap's own port syntax are refused by "
                "construction, so a port sweep cannot be expressed here at all")
    if len(specs) > MAX_PORTS_PER_HOST:
        raise PortListRefused(
            f"{where}: names {len(specs)} ports per host; the ceiling is "
            f"{MAX_PORTS_PER_HOST}. This run is REFUSED rather than shortened — a "
            "truncated probe under-reports, and absence has to keep meaning absence")
    return specs


def _hosts_from(target: dict, path: object, where: str) -> list[str]:
    ref = str(path or "").strip()
    if not ref.startswith(HOST_SOURCE_PREFIX):
        raise PortListRefused(
            f"{where}: `hosts_from:` is {ref!r}; it must name a group under "
            f"`{HOST_SOURCE_PREFIX}` in the target profile. A probe plan may point at a "
            "host list the authorisation already covers; it may not introduce one of "
            "its own")
    group = ref[len(HOST_SOURCE_PREFIX):]
    if not group or "." in group:
        raise PortListRefused(f"{where}: `hosts_from:` {ref!r} does not name one group")
    entries = (target.get("scan_targets", {}) or {}).get(group)
    if entries is None:
        raise PortListRefused(
            f"{where}: the target profile has no `scan_targets.{group}:` group, so this "
            "section names hosts that do not exist. Refused rather than skipped: a "
            "section that silently probes nothing reads as a section that found nothing")
    if not isinstance(entries, list):
        raise PortListRefused(f"{where}: `scan_targets.{group}:` is not a list")
    hosts: list[str] = []
    for entry in entries:
        host = (str(entry.get("ip") or entry.get("host") or "").strip()
                if isinstance(entry, dict) else str(entry or "").strip())
        if host:
            hosts.append(host)
    if not hosts:
        raise PortListRefused(
            f"{where}: `scan_targets.{group}:` is empty, so this section would contact "
            "nothing. An empty group is a target that has not been set up, not a clean "
            "result")
    return hosts


def _check_declared_budget(declared: object, plan: ProbePlan, where: str) -> None:
    if not isinstance(declared, dict):
        raise PortListRefused(
            f"{where}: `{PROBE_LIST_KEY}:` declares no `{BUDGET_KEY}:`. A run must be able "
            "to name every host and every port it will touch before it runs; a plan with "
            "no stated budget has not been counted by anybody")
    for field_name, computed in (("hosts", plan.hosts),
                                 ("tcp_pairs", plan.tcp_pairs),
                                 ("udp_pairs", plan.udp_pairs)):
        if field_name not in declared:
            raise PortListRefused(
                f"{where}: `{BUDGET_KEY}:` does not state `{field_name}:`")
        stated = declared[field_name]
        if not isinstance(stated, int) or stated != computed:
            raise PortListRefused(
                f"{where}: the declared budget says {field_name}={stated!r} and this plan "
                f"computes {computed}. One of the two is wrong and neither is authorised, "
                "so nothing was contacted. This is what a host list edited without "
                "redoing the arithmetic looks like — fix the overlay's budget, or the "
                "section that changed")


def _fallback_plan(target: dict) -> ProbePlan:
    raw = target.get(TARGET_KEY)
    if raw is None:
        raise PortListRefused(
            f"the target profile declares no `{TARGET_KEY}:` list and has no "
            "`.derived-ports.yaml` overlay beside it. There is no default: active "
            "probing of a port has to be authorised in the target's own files, port by "
            "port")
    if not isinstance(raw, list):
        raise PortListRefused(f"`{TARGET_KEY}:` must be a list of `<port>/<transport>` "
                              f"strings, not {type(raw).__name__}")
    ports = _port_specs(raw, f"`{TARGET_KEY}:`")
    hosts = scan_hosts(target)
    steps = tuple(ProbeStep(host=h, section=TARGET_KEY,
                            ports=tuple(p for p in ports if p.endswith("/tcp")),
                            deferred=tuple(p for p in ports if not p.endswith("/tcp")),
                            basis="the target profile's own authorised port list")
                  for h in hosts)
    plan = ProbePlan(steps=steps, source=f"target profile `{TARGET_KEY}:`")
    _check_ceilings(plan, f"`{TARGET_KEY}:`")
    return plan


def _check_ceilings(plan: ProbePlan, where: str) -> None:
    if plan.hosts > MAX_HOSTS:
        raise PortListRefused(
            f"{where}: the plan names {plan.hosts} hosts; the ceiling is {MAX_HOSTS}. "
            "This run is REFUSED rather than cut down to the first "
            f"{MAX_HOSTS} — a truncated probe reports the hosts it skipped as though "
            "nothing were listening on them")
    if plan.tcp_pairs > MAX_PROBE_PAIRS:
        raise PortListRefused(
            f"{where}: the plan is {plan.tcp_pairs} (host, port) pairs; the ceiling is "
            f"{MAX_PROBE_PAIRS}. Host count and per-host port count are each inside "
            "their own limit, and the product is not — which is the shape neither of "
            "them can see. REFUSED, not truncated")


def build_plan(target: dict, derived: dict | None = None) -> ProbePlan:
    """The probe plan for ``target``, or :class:`PortListRefused` saying why not.

    ``derived`` is the overlay's ``derived_ports:`` mapping; by default it is
    loaded from beside the profile.
    """
    derived = load_derived_ports(target) if derived is None else derived
    where = derived.get("_path") or "the derived-ports overlay"
    sections = derived.get(PROBE_LIST_KEY)
    if not sections:
        return _fallback_plan(target)
    if not isinstance(sections, dict):
        raise PortListRefused(f"{where}: `{PROBE_LIST_KEY}:` must be a mapping of "
                              f"named sections, not {type(sections).__name__}")

    steps: list[ProbeStep] = []
    seen: dict[str, str] = {}
    for name, section in sections.items():
        if name == BUDGET_KEY:
            continue
        label = f"{where} `{PROBE_LIST_KEY}.{name}`"
        if not isinstance(section, dict):
            raise PortListRefused(f"{label}: must be a mapping with `hosts_from:`, "
                                  "`ports:` and `basis:`")
        if not str(section.get("basis") or "").strip():
            raise PortListRefused(
                f"{label}: names no `basis:`. Every port in this plan has to be "
                "justified before it runs — a section with no stated basis is a guess")
        specs = _port_specs(section.get("ports"), label)
        tcp = tuple(s for s in specs if s.endswith("/tcp"))
        udp = tuple(s for s in specs if not s.endswith("/tcp"))
        if not tcp:
            raise PortListRefused(
                f"{label}: names only non-TCP ports {list(udp)}. This collector speaks "
                "one scan type — an ordinary TCP connection — so a section with no TCP "
                "port would contact nothing while reading as though it had")
        for host in _hosts_from(target, section.get("hosts_from"), label):
            if host in seen:
                raise PortListRefused(
                    f"{label}: host {host!r} is already claimed by section "
                    f"{seen[host]!r}. Two sections naming one host means two different "
                    "port profiles for it and no way to say which was authorised — and "
                    "the declared budget would count it twice")
            seen[host] = str(name)
            steps.append(ProbeStep(host=host, section=str(name), ports=tcp,
                                   deferred=udp, basis=str(section["basis"]).strip()))

    if not steps:
        raise PortListRefused(f"{where}: `{PROBE_LIST_KEY}:` names no probe sections")
    plan = ProbePlan(steps=tuple(steps), source=str(where),
                     derived_on=str(derived.get("derived_on") or ""),
                     authority=str(derived.get("authority") or "").strip())
    _check_ceilings(plan, where)
    _check_declared_budget(sections.get(BUDGET_KEY), plan, where)
    _check_nothing_lost(target, plan, where)
    return plan


def _check_nothing_lost(target: dict, plan: ProbePlan, where: str) -> None:
    """Refuse a derived plan that drops a pair the profile's own list authorises.

    A host that used to be probed and now is not would read as a host with
    nothing listening, and a comparison of two runs would read that as a fix.
    """
    raw = target.get(TARGET_KEY)
    if not isinstance(raw, list) or not raw:
        return
    profile_ports = {str(p).strip() for p in raw if str(p).strip().endswith("/tcp")}
    planned = {(s.host, p) for s in plan.steps for p in s.ports}
    lost = sorted(f"{h} {p}" for h in scan_hosts(target)
                  for p in profile_ports if (h, p) not in planned)
    if lost:
        raise PortListRefused(
            f"{where}: this plan would stop probing {len(lost)} (host, port) pair(s) the "
            f"target profile's own `{TARGET_KEY}:` authorises — {', '.join(lost[:6])}"
            f"{' …' if len(lost) > 6 else ''}. A derived plan may widen the profile's "
            "list and may never narrow it: a host that used to be probed and now is not "
            "reads as a host with nothing listening")


def scan_hosts(target: dict) -> list[str]:
    """Gateways, published hosts and SSH hosts from the profile, de-duplicated."""
    st = target.get("scan_targets", {}) or {}
    hosts: list[str] = []
    for gw in st.get("vpn_gateways", []) or []:
        hosts.append(gw.get("ip") or gw["host"])
    hosts += roles.published_hosts(target)
    hosts += [str((e.get("ip") or e.get("host") or "") if isinstance(e, dict) else e or "")
              for e in st.get("ssh_22") or []]
    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        if host and host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


def budget_lines(plan: ProbePlan, table: PortTable | None = None) -> list[str]:
    """The plan in full, for the console and the raw directory, before anything runs."""
    out = [
        "plaintext_scan: PROBE BUDGET — every host and every port, before anything runs",
        f"  plan source     : {plan.source}"
        + (f" (derived {plan.derived_on})" if plan.derived_on else ""),
    ]
    if plan.authority:
        out.append(f"  authority       : {plan.authority}")
    out += [
        f"  hosts           : {plan.hosts} (ceiling {MAX_HOSTS})",
        f"  TCP pairs       : {plan.tcp_pairs} (ceiling {MAX_PROBE_PAIRS}); at most "
        f"{max((len(s.ports) for s in plan.steps), default=0)} ports on any one host "
        f"(ceiling {MAX_PORTS_PER_HOST})",
        f"  method          : one `nmap {' '.join(NMAP_FLAGS)}` per host, hosts probed "
        f"one at a time, {INTER_HOST_SECONDS:g}s between them",
        "  then            : where http-title read an answer that would grade as cleartext, "
        "ONE plain `curl http://<host>:<port>/` on that port (no TLS fallback, no "
        "credentials, redirects not followed) to confirm it",
    ]
    if plan.udp_pairs:
        deferred = sorted({p for s in plan.steps for p in s.deferred})
        out.append(
            f"  NOT probed here : {plan.udp_pairs} UDP pair(s) ({', '.join(deferred)}). "
            "This collector speaks TCP only")
    if table is not None:
        silent = _ports_producing_no_row(plan, table)
        if silent:
            out.append("  contacted, but producing no row of their own:")
            out += [f"      {spec:<10} {reason}" for spec, reason in silent]
    out.append("  the enumeration:")
    for step in plan.steps:
        out.append(f"      {step.host}  ->  {', '.join(step.ports)}   [{step.section}]")
    return out


def _ports_producing_no_row(plan: ProbePlan, table: PortTable) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for spec in sorted({p for s in plan.steps for p in s.ports},
                       key=lambda s: int(s.split("/")[0])):
        port, _, transport = spec.partition("/")
        row = lookup(port, transport, table)
        if spec in MEASURED_ELSEWHERE:
            out.append((spec, MEASURED_ELSEWHERE[spec]))
        elif row is not None and row.get("posture") == ENCRYPTED:
            out.append((spec, f"{row.get('protocol', '')} — encryption is inherent on this "
                              "port; its strength is a capability scanner's to grade"))
    return out


def _nmap_command(host: str, ports: list[str] | tuple[str, ...]) -> list[str]:
    numbers = []
    for spec in ports:
        m = PORT_SPEC.match(spec)
        if not m:
            raise PortListRefused(f"refusing to build an nmap port list from {spec!r}")
        if m.group(2) != "tcp":
            raise PortListRefused(f"{spec} is not TCP; this collector probes TCP only")
        numbers.append(m.group(1))
    family = ["-6"] if is_ipv6_literal(host) else []
    return ["nmap", *NMAP_FLAGS, *family, "-p", ",".join(numbers),
            "--script", NMAP_SCRIPT, scan_address(host)]


def parse_nmap(out: str) -> HostScan:
    """Port states and ``http-title`` lines from one nmap run."""
    scan = HostScan()
    if out.startswith(ERROR_PREFIX):
        scan.detail = out.strip()[:200]
        return scan
    current: str | None = None
    for line in out.splitlines():
        pm = _PORT_LINE.match(line.strip())
        if pm:
            port, transport, state, service = pm.groups()
            obs = PortObservation(port=port, transport=transport, state=state, service=service)
            scan.ports[obs.spec] = obs
            current = obs.spec
            continue
        tm = _TITLE_LINE.match(line.strip())
        if tm and current:
            prev = scan.ports[current]
            scan.ports[current] = PortObservation(prev.port, prev.transport, prev.state,
                                                  prev.service, tm.group(1).strip())
            continue
        if not line.startswith("|"):
            current = None
    scan.reached = bool(scan.ports)
    if not scan.reached:
        for marker in ("Failed to resolve", "skipping host", "Note: Host seems down"):
            if marker in out:
                scan.detail = next(ln.strip() for ln in out.splitlines() if marker in ln)[:200]
                break
        else:
            scan.detail = scan.detail or "nmap produced no port table"
    return scan


def classify(obs: PortObservation, row: Mapping[str, str] | None = None,
             host_unreached: bool = False) -> tuple[str, str]:
    """(outcome, evidence sentence) for one port.

    ``host_unreached`` says every planned port on the host went unanswered,
    which makes a silent port unmeasured rather than filtered.
    """
    if obs.state != "open":
        if no_answer(obs.state) and host_unreached:
            return UNREACHED, (
                f"nmap reported {obs.spec} {obs.state}, and every other port probed on "
                "this host went unanswered too: the host did not answer this probe on "
                "any port. A firewall dropping everything from outside and a security "
                "control cutting the probe off look identical from here, so whether a "
                "cleartext service listens on this port is NOT measured. This row is "
                "a coverage gap, not a clean result, and not a finding against the host.")
        if no_answer(obs.state):
            return FILTERED_NO_ANSWER, (
                f"nmap reported {obs.spec} {obs.state}: the probe got no answer on this "
                "port, while the same host answered on at least one other port in the "
                "same run. So nothing on this port is reachable from where the probe ran. "
                "Whether a service listens behind the filter is not measured — this row "
                "says 'not reachable from outside', which is narrower than 'not listening'. "
                "Not a finding.")
        return NOT_LISTENING, (
            f"nmap reported {obs.spec} {obs.state}: the host answered and refused the "
            "connection, so nothing is listening on this port and there is no cleartext "
            "service here to report. Not a finding.")

    posture = (row or {}).get("posture", CLEARTEXT)
    protocol = (row or {}).get("protocol", "")

    if posture == OPPORTUNISTIC:
        return UPGRADABLE_LISTENING, (
            f"Actively probed: {obs.spec} is OPEN — a TCP connection completed. What was "
            f"measured is the listener; whether {protocol or 'this protocol'} upgrades "
            "the session to TLS in band is NOT measured here, because this collector "
            "makes an ordinary connection and reads no protocol banner. That is a "
            "coverage gap on this port, not a finding against it.")

    if not obs.title or obs.title.upper().startswith("ERROR"):
        if protocol and not _speaks_http(protocol):
            return CLEARTEXT_LISTENING, (
                f"Actively probed: {obs.spec} is OPEN — a TCP connection completed, so "
                f"something is listening. What it speaks is NOT measured: nmap's HTTP "
                f"probe does not run on this port, and the finding that it carries "
                f"{protocol} in clear rests on the port table's convention rather than "
                "on a banner. The listener is measured; the protocol is inferred.")
        return INCONCLUSIVE, (
            f"nmap found {obs.spec} OPEN but the http-title probe got no readable HTTP "
            f"response ({obs.title or 'no script output'}). Something is listening and "
            "this check could not tell cleartext from TLS-on-this-port, a web firewall "
            "that drops unrecognised requests, or a non-HTTP service. Nothing is concluded "
            "either way.")

    redirect = _REDIRECT.match(obs.title)
    if redirect:
        url = redirect.group(1)
        if url.lower().startswith("https://"):
            return REDIRECT_HTTPS, (
                f"{obs.spec} is open and answers by redirecting to {url}: the client is sent "
                "to HTTPS, so this is NOT a cleartext finding — it is how a correctly "
                "configured site handles port 80. Two limits, stated rather than assumed: "
                "the redirect and the request that triggers it do travel in clear, so they "
                "can be stripped on-path (HSTS is what removes that first unencrypted "
                "request; this check does not observe it, and the hsts collector does, "
                "on the target's published web endpoints), and the evidence covers the "
                "path '/' only.")
        return CLEARTEXT_SERVED, (
            f"Actively probed: {obs.spec} is open and redirects to {url} — still cleartext, "
            "so the redirect does not remove the exposure. Measured, not inferred from the "
            "port number.")

    return CLEARTEXT_SERVED, (
        f"Actively probed: {obs.spec} is open and served an HTTP response over an "
        f"unencrypted connection (page title: {obs.title!r}). Measured, not inferred from "
        "the port number.")


def _asset(host: str, obs: PortObservation, outcome: str, evidence: str,
           table: PortTable, ref_time: datetime | None, role: str = "",
           host_filtered: tuple[str, ...] = ()) -> CryptoAsset:
    row = lookup(obs.port, obs.transport, table)
    protocol = (row or {}).get("protocol", "")
    extra: dict[str, object] = {"nmap_state": obs.state, "nmap_service": obs.service,
                                "http_title": obs.title, "plaintext_outcome": outcome}
    if host_filtered:
        extra["host_filtered_ports"] = list(host_filtered)
    asset = CryptoAsset(
        name=f"{protocol or 'port'} {host}:{obs.port}", role=role,
        data_state="in-transit", protocol=protocol, host=host, port=obs.port,
        source=SOURCE, internet_facing=True,
        source_class="public", source_name=SOURCE_NAME, collected_at=now_date(ref_time),
        extra=extra,
    )
    if outcome in (CLEARTEXT_SERVED, CLEARTEXT_LISTENING, UPGRADABLE_LISTENING):
        apply_posture(asset, table, obs.transport, evidence=evidence)
    elif outcome == REDIRECT_HTTPS:
        asset.verdict = NA_VERDICT
        asset.flags = [f"{REDIRECT_FLAG}https"]
        asset.notes = evidence
    elif outcome in (NOT_LISTENING, FILTERED_NO_ANSWER):
        asset.verdict = NA_VERDICT
        asset.notes = evidence
    elif outcome == UNREACHED:
        asset.verdict = "unknown"
        asset.flags = [f"{UNREACHED_FLAG}{protocol or obs.port}"]
        asset.notes = evidence
    else:
        asset.flags = [f"{INCONCLUSIVE_FLAG}{protocol or obs.port}"]
        asset.notes = evidence
    return asset


def _settle() -> None:
    time.sleep(INTER_HOST_SECONDS)


def _announce(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


VERIFY_INSTRUMENT = "curl http:// (explicit plain HTTP, no TLS fallback)"
_HTTP_STATUS = re.compile(r"^HTTP/[\d.]+\s+(\d{3})[^\n]*", re.M)
_HTTP_LOCATION = re.compile(r"^location:\s*(\S+)", re.M | re.I)


def verify_command(host: str, port: str) -> list[str]:
    """The single plain-HTTP request that confirms a cleartext page."""
    addr = scan_address(host)
    netloc = f"[{addr}]" if is_ipv6_literal(host) else addr
    return ["curl", *hsts.CURL_FLAGS, "-m", str(hsts.REQUEST_TIMEOUT),
            f"http://{netloc}:{port}/"]


def parse_http_answer(out: str) -> tuple[str, int | None, str]:
    """(status line, status code, Location) of the last response in curl's header dump."""
    matches = list(_HTTP_STATUS.finditer(out or ""))
    if not matches:
        return "", None, ""
    last = matches[-1]
    loc = _HTTP_LOCATION.search(out, last.start())
    return last.group(0).strip(), int(last.group(1)), (loc.group(1) if loc else "")


def _last_curl_line(out: str) -> str:
    lines = [ln for ln in (out or "").splitlines()
             if ln.strip() and hsts.CONNECTED_MARKER not in ln]
    return lines[-1].strip()[:160] if lines else ""


def verified_outcome(spec: str, title: str, curl_out: str) -> tuple[str, str]:
    """(outcome, evidence) once the plain-HTTP request has answered.

    No HTTP answer, or a 400, is inconclusive: a TLS server commonly answers
    a plain request on its TLS port that way.
    """
    status, code, location = parse_http_answer(curl_out)
    seen = f" (nmap's http-title had read {title!r}, which it may have fetched over TLS)"
    if code is None:
        return INCONCLUSIVE, (
            f"{spec} is OPEN and nmap's http-title read a page, but an explicit plain "
            f"http:// request got no HTTP answer in clear (curl: {_last_curl_line(curl_out)!r})"
            f"{seen}. nmap retries over TLS by itself, so the page was most likely served "
            "over TLS. Not concluded as cleartext; nothing is concluded either way.")
    if code == 400:
        return INCONCLUSIVE, (
            f"{spec} is OPEN and an explicit plain http:// request was answered `{status}`"
            f"{seen}. A TLS server commonly answers a plain request on its TLS port this "
            "way, so a 400 is not taken as a cleartext service.")
    if 300 <= code < 400 and location.lower().startswith("https://"):
        return REDIRECT_HTTPS, (
            f"{spec} is open and an explicit plain http:// request was answered `{status}` "
            f"with a redirect to {location}: the client is sent to HTTPS. The redirect "
            "itself travels in clear, and the evidence covers the path '/' only.")
    what = (f" and a redirect to {location} — still cleartext, so the redirect does not "
            "remove the exposure" if location else "")
    return CLEARTEXT_SERVED, (
        f"Actively probed: {spec} is open and an explicit plain http:// request was "
        f"answered `{status}`{what}, over an unencrypted connection"
        + (f" (nmap's http-title read {title!r})" if title else "")
        + ". Measured with a request that cannot fall back to TLS, not inferred from the "
        "page title or the port number.")


def _needs_verification(outcome: str, row: Mapping[str, str] | None) -> bool:
    return outcome == CLEARTEXT_SERVED and _speaks_http((row or {}).get("protocol", ""))


def _run_verify(host: str, port: str, raw_dir: Path | None) -> str:
    out = run(verify_command(host, port), timeout=hsts.RUN_TIMEOUT)
    if raw_dir:
        (raw_dir / f"plaintext-verify-{scan_address(host)}-{port}.txt").write_text(out)
    return out


def verify_cleartext_http(asset: CryptoAsset, raw_dir: Path | None = None,
                          ref_time: datetime | None = None) -> CryptoAsset:
    """Re-check a stored cleartext-HTTP row with one plain request; return an updated copy.

    Rows that are not cleartext HTTP come back unchanged (as a copy). The
    note says when the port was scanned and when the request was sent.
    """
    extra = dict(asset.extra or {})
    spec = f"{asset.port}/tcp"
    table = load_port_encryption()
    row = lookup(str(asset.port), "tcp", table)
    if not _needs_verification(str(extra.get("plaintext_outcome", "")), row):
        return deepcopy(asset)
    address = asset.ip or asset.host
    curl_out = _run_verify(address, str(asset.port), raw_dir)
    title = str(extra.get("http_title", ""))
    outcome, evidence = verified_outcome(spec, title, curl_out)
    today = now_date(ref_time)
    obs = PortObservation(port=str(asset.port), transport="tcp",
                          state=str(extra.get("nmap_state", "open")),
                          service=str(extra.get("nmap_service", "")), title=title)
    fresh = _asset(asset.host, obs, outcome, evidence, table, ref_time, asset.role)
    out = deepcopy(asset)
    out.verdict, out.flags = fresh.verdict, list(fresh.flags)
    out.extra = {**extra, "plaintext_outcome": outcome,
                 "cleartext_verified_by": VERIFY_INSTRUMENT,
                 "cleartext_verified_on": today,
                 "cleartext_verify_status": parse_http_answer(curl_out)[0]}
    out.notes = (f"{fresh.notes} [Port state and page title scanned {asset.collected_at}; "
                 f"plain http:// request sent {today}.]")
    return out


def _scan_host(step: ProbeStep, table: PortTable, raw_dir: Path | None,
               ref_time: datetime | None,
               role: str = "") -> tuple[list[CryptoAsset], list[str]]:
    host = step.host
    out = _redact_redirect_queries(run(_nmap_command(host, step.ports), timeout=RUN_TIMEOUT))
    if raw_dir:
        (raw_dir / f"nmap-plaintext-{host}.txt").write_text(out)
    scan = parse_nmap(out)
    if not scan.reached:
        return [], [f"plaintext_scan {host}: no cleartext evidence — nmap produced no port "
                    f"table ({scan.detail}). The {len(step.ports)} planned port(s) were NOT "
                    "checked on this host, so this run says nothing about cleartext "
                    "services there."]

    assets: list[CryptoAsset] = []
    failures: list[str] = []
    planned = [scan.ports[s] for s in step.ports if s in scan.ports]
    host_filtered = tuple(o.spec for o in planned if no_answer(o.state))
    host_unreached = bool(planned) and len(host_filtered) == len(planned)
    for spec in step.ports:
        port, _, transport = spec.partition("/")
        row = lookup(port, transport, table)
        if row is None:
            failures.append(f"plaintext_scan {host}: {spec} is in the probe plan but "
                            "the port-encryption table has no row for it, so its result "
                            "cannot be classified — add a row with its citation")
            continue
        if row.get("posture") == ENCRYPTED or spec in MEASURED_ELSEWHERE:
            continue
        obs = scan.ports.get(spec)
        if obs is None:
            failures.append(f"plaintext_scan {host}: nmap returned no line for {spec}, so "
                            "the port was not checked — absence here is not evidence that "
                            "nothing is listening")
            continue
        outcome, evidence = classify(obs, row, host_unreached=host_unreached)
        verified = False
        if _needs_verification(outcome, row):
            if shutil.which("curl"):
                outcome, evidence = verified_outcome(spec, obs.title,
                                                     _run_verify(host, port, raw_dir))
                verified = True
            else:
                outcome, evidence = INCONCLUSIVE, (
                    f"{spec} is OPEN and nmap's http-title read {obs.title!r}, but curl is "
                    "not on PATH, so the plain http:// request that separates cleartext "
                    "from TLS was not sent. nmap retries over TLS by itself, so the title "
                    "alone is not evidence of cleartext. Nothing is concluded.")
        a = _asset(host, obs, outcome, evidence, table, ref_time, role,
                   host_filtered=host_filtered)
        if verified:
            a.extra["cleartext_verified_by"] = VERIFY_INSTRUMENT
        assets.append(a)
    return assets, failures


def collect(target: dict, raw_dir: Path | None = None,
            ref_time: datetime | None = None,
            announce: Callable[[str], None] | None = None
            ) -> tuple[list[CryptoAsset], list[str]]:
    """Run the plan; return (assets, failures). A refused plan contacts nothing."""
    say = _announce if announce is None else announce
    try:
        plan = build_plan(target)
    except (PortListRefused, ValueError) as exc:
        return [], [f"plaintext_scan: REFUSED to probe — {exc}. No ports were contacted."]

    if not plan.steps:
        return [], []
    refused = inside_scope.scan_refusal(SOURCE, target)
    if refused:
        return [], [refused]

    table = load_port_encryption()
    lines = budget_lines(plan, table)
    for line in lines:
        say(line)
    if raw_dir:
        (raw_dir / "nmap-plaintext-budget.txt").write_text("\n".join(lines) + "\n")

    if not shutil.which("nmap"):
        return [], ["plaintext_scan: nmap is not on PATH, so the enumerated port probe did "
                    f"not run against any of the {plan.hosts} planned host(s). This run "
                    "holds NO evidence about cleartext services."]

    role_by_host = roles.scan_target_roles(target)
    assets: list[CryptoAsset] = []
    failures: list[str] = []
    for n, step in enumerate(plan.steps):
        if n:
            _settle()
        a, f = _scan_host(step, table, raw_dir, ref_time, role_by_host.get(step.host, ""))
        assets += a
        failures += f
    for line in reach_summary(plan, assets):
        say(line)
    return assets, failures


def reach_summary(plan: ProbePlan, assets: list[CryptoAsset]) -> list[str]:
    """How many planned hosts answered, and which answered on no port at all."""
    unreached = sorted({a.host for a in assets
                        if a.extra.get("plaintext_outcome") == UNREACHED})
    answered = len({a.host for a in assets} - set(unreached))
    out = [f"plaintext_scan: {answered} of {plan.hosts} planned host(s) answered on at "
           "least one probed port"]
    if unreached:
        out.append(f"plaintext_scan: UNREACHED — no probed port answered on "
                   f"{', '.join(unreached)}. Unmeasured, not clean: nothing in this run "
                   "says whether a cleartext service listens there")
    return out
