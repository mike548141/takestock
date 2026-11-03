"""CrowdStrike Falcon: plain HTTP requests the endpoint sensor recorded, by destination.

The sensor's ``HttpRequest`` event carries an HTTP request's ``Host`` header
in readable form. A request sent inside TLS does not expose its headers on
the connection, so this reader takes each event as evidence that the request
crossed the network unencrypted, where a port number is only a convention.
That is an inference from what the event carries: the public sources read
for this reader (``docs/COLLECTORS.md``) do not say when the sensor writes
the event. The ``Host`` header also names the destination, and so says
which services the machines speak plain HTTP to by name.

**The input** (``input:``) is a CSV written by a LogScale query over
``HttpRequest`` events, grouped by machine, Host header, destination port and
(optionally) sending program, and counted. ``docs/COLLECTORS.md`` gives the
query. The fields read, and their default headings (``settings: columns:``
names others):

===============  =================  ========================================
field            default heading    what it holds
===============  =================  ========================================
``agent_id``     ``aid``            the sensor's ID for the machine
``machine``      ``ComputerName``   the machine's name, used when there is no ID
``host_header``  ``HttpHost``       the request's Host header
``port``         ``RemotePort``     the destination port connected to
``program``      ``ImageFileName``  the sending program's path (optional)
``count``        ``_count``         requests in the group
===============  =================  ========================================

The request path is not read, and the query does not group it: a path can
carry tokens and identifiers.

**Each request is placed in one of four kinds:**

* *tunnel*: the Host names port 443 on a connection to another port. That
  is the form a ``CONNECT`` request to a forward web proxy takes, after which
  the page travels inside TLS. The export carries no request method, so this
  rests on the form of the target alone: a ``CONNECT`` to any other port is
  not recognised, and a plain request whose Host happens to name 443 is
  misread as a tunnel.
* *loopback*: the Host is ``localhost``, a name under ``.localhost``
  (reserved for loopback by RFC 6761) or a loopback address. The request
  never reached a network interface.
* *no Host*: no Host header was recorded, so the destination cannot be
  named.
* *cleartext*: everything else, a readable request to a named destination.
  A link-local destination (IPv4's link-local block, RFC 3927, or IPv6's,
  RFC 4291) is flagged ``http-link-local``: it does not cross a router.

**Graded once, on the port.** These requests are a subset of the outbound
connections ``falcon_connections`` grades by destination port. So:

* a port takestock's port-encryption table calls cleartext is graded there,
  and gets no second grade here;
* a port the table does not call cleartext gets one ``weak`` row here,
  ``Cleartext HTTP on <port>/tcp``, flagged ``cleartext-http:<port>`` and
  ``cleartext-exposure:content``, listing its destinations;
* every destination gets an ``n/a`` detail row, ``Cleartext HTTP to
  <host>:<port>``, flagged ``cleartext-http-detail:<port>``, naming the row
  that carries its grade.

The rule reads the port table, not ``falcon_connections``' rows: a port the
table calls cleartext but that the connection export does not hold is graded
by neither reader, and the scope row says so.

**Further rows.** On each port that carried a tunnel, one ``n/a`` row
(``http-proxy``, flagged ``http-connect-tunnel:<port>``) splits its requests
into tunnels, plain requests, requests with no Host and loopback. One ``n/a``
row counts loopback requests (``http-loopback``), one ``unknown`` row counts
requests with no Host (``http-host-unrecorded``), and one ``n/a`` scope row
(``scope-observed-not-enumerated``) says what the export cannot support.
Machines are counted, never named.

**Cannot see.** Any share of all web traffic (the export counts no
encrypted request, so there is no denominator); where a destination is (the query groups
no address, so a name that resolves to the sending machine looks like any
other); and what a request carried (no path).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from .. import coverage, plaintext, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_traffic as _ft

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_http"

CLEARTEXT_HTTP_FLAG = "cleartext-http:"
DETAIL_FLAG = "cleartext-http-detail:"
TUNNEL_FLAG = "http-connect-tunnel:"
LOOPBACK_FLAG = "http-loopback"
LINK_LOCAL_FLAG = "http-link-local"
NO_HOST_FLAG = "http-host-unrecorded"
SCOPE_FLAG = "scope-observed-not-enumerated"

register_informational_prefixes(DETAIL_FLAG, TUNNEL_FLAG, LOOPBACK_FLAG, LINK_LOCAL_FLAG,
                                NO_HOST_FLAG, SCOPE_FLAG)

TUNNEL, LOOPBACK, NO_HOST, CLEARTEXT = "tunnel", "loopback", "no-host", "cleartext"
KINDS = (TUNNEL, LOOPBACK, NO_HOST, CLEARTEXT)
#: The port a forward proxy's ``CONNECT`` target names for an HTTPS page.
TUNNEL_PORT = "443"

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "agent_id": "aid",
    "machine": "ComputerName",
    "host_header": "HttpHost",
    "port": "RemotePort",
    "program": "ImageFileName",
    "count": _ft.COUNT_HEADING,
}

OBSERVED = ("Read from the request, not from the port: the sensor's event carries the request's "
            "Host header in readable form, which a request inside TLS does not expose on the "
            "connection, so takestock reads it as sent unencrypted.")

SCOPE_NOTE = (
    "The export holds only the HTTP requests the sensor recorded, and counts no encrypted "
    "request, so it has no denominator: it says how much readable web traffic there was, "
    "never what share of all web traffic that is. It carries no request method, so a proxy "
    "tunnel is recognised by the form of its target alone; no path, by design; and no "
    "destination address, so a name that resolves to the sending machine itself looks like "
    "any other")


# ── placing one request ─────────────────────────────────────────────────────

def split_host(value: str) -> tuple[str, str]:
    """``(host, port)`` from a Host header value, the host lower-cased; port "" when none is named.

    Reads ``name``, ``name:port``, ``[v6]`` and ``[v6]:port``. A bare IPv6
    address (more than one colon, no brackets) is returned whole, with no port.
    """
    v = value.strip()
    if not v:
        return "", ""
    if v.startswith("["):
        close = v.find("]")
        if close != -1:
            rest = v[close + 1:]
            port = rest[1:] if rest.startswith(":") and rest[1:].isdigit() else ""
            return v[1:close].lower(), port
    if v.count(":") == 1:
        name, _, port = v.partition(":")
        if port.isdigit():
            return name.lower().rstrip("."), port
    return v.lower().rstrip("."), ""


def _address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_loopback(host: str) -> bool:
    """``localhost``, a name under ``.localhost``, or a loopback address."""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    addr = _address(host)
    return bool(addr and addr.is_loopback)


def is_link_local(host: str) -> bool:
    """A link-local address, IPv4 (RFC 3927) or IPv6 (RFC 4291)."""
    addr = _address(host)
    return bool(addr and addr.is_link_local)


def classify(host_header: str, port: str) -> str:
    """Which of the four kinds a request is: ``tunnel``, ``loopback``, ``no-host`` or ``cleartext``."""
    host, named_port = split_host(host_header)
    if not host:
        return NO_HOST
    if named_port == TUNNEL_PORT and port != TUNNEL_PORT:
        return TUNNEL
    if is_loopback(host):
        return LOOPBACK
    return CLEARTEXT


# ── tallies ─────────────────────────────────────────────────────────────────

def _tally() -> dict:
    return {"requests": 0, "machines": set(), "programs": {}, "ports": {}, "named_ports": set(),
            "targets": {}}


def _add(t: dict, n: int, machine: str, program: str, port: str, named_port: str = "") -> None:
    t["requests"] += n
    if machine:
        t["machines"].add(machine)
    if program:
        t["programs"][program] = t["programs"].get(program, 0) + n
    t["ports"][port] = t["ports"].get(port, 0) + n
    if named_port:
        t["named_ports"].add(named_port)


def _missing_gap(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of plain HTTP requests recorded by the endpoint sensor was read"
        + (f" ({why})" if why else "")
        + ": which destinations the estate's machines send unencrypted web requests to, by "
        "name, and whether a proxy port carries readable pages or encrypted tunnels",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, cleartext web traffic is judged from the port number alone: a "
                "proxy port reads as cleartext even where it carries encrypted tunnels, and no "
                "service spoken to in plain HTTP can be named."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_http) and name its CSV "
                 "with input:."),
        nature=coverage.NO_DATA)


# ── reading ─────────────────────────────────────────────────────────────────

def read(path: Path, port_table: plaintext.PortTable,
         headings: dict[str, str] | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    h = headings or dict(HEADINGS)
    rows, unreadable = _ft.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon HTTP request export, "
                   + (f"file dated {when}" if when else "file date unavailable"))

    machines: set[str] = set()
    destinations: dict[tuple[str, str], dict] = {}
    by_kind = {k: _tally() for k in (TUNNEL, LOOPBACK, NO_HOST)}
    per_port: dict[str, dict[str, dict]] = {}
    for r in rows:
        port = _ft.cell(r, h["port"])
        if not port:
            continue
        n = _ft.count(_ft.cell(r, h["count"]))
        machine = _ft.cell(r, h["agent_id"]) or _ft.cell(r, h["machine"])
        if machine:
            machines.add(machine)
        header = _ft.cell(r, h["host_header"])
        program = _ft.program(_ft.cell(r, h["program"]))
        kind = classify(header, port)
        host, named_port = split_host(header)
        split = per_port.setdefault(port, {k: _tally() for k in KINDS})
        _add(split[kind], n, machine, program, port)
        if kind == TUNNEL:
            targets = split[TUNNEL]["targets"]
            targets[host] = targets.get(host, 0) + n
        if kind == CLEARTEXT:
            _add(destinations.setdefault((host, port), _tally()), n, machine, program, port,
                 named_port if named_port != port else "")
        else:
            _add(by_kind[kind], n, machine, program, port)

    seen = len(machines)
    base: dict[str, Any] = {"data_state": "in-transit", "source": NAME, "source_class": "private",
            "source_name": source_name, "collected_at": when}

    def graded_elsewhere(port: str) -> bool:
        row = plaintext.lookup(port, "tcp", port_table) or {}
        return row.get("posture") == plaintext.CLEARTEXT

    out: list[CryptoAsset] = []

    # One weak row per port the port table does not already call cleartext.
    by_port: dict[str, dict] = {}
    for (host, port), t in destinations.items():
        p = by_port.setdefault(port, _tally())
        p["requests"] += t["requests"]
        p["machines"] |= t["machines"]
        for prog, k in t["programs"].items():
            p["programs"][prog] = p["programs"].get(prog, 0) + k
        p["targets"][host] = p["targets"].get(host, 0) + t["requests"]
    for port, p in sorted(by_port.items(), key=lambda kv: (-kv[1]["requests"], kv[0])):
        if graded_elsewhere(port):
            continue
        n, req, dests = len(p["machines"]), p["requests"], p["targets"]
        programs = _ft.top(p["programs"])
        out.append(CryptoAsset(
            name=f"Cleartext HTTP on {port}/tcp", protocol="http", port=port,
            role=roles.cleartext_web_port(port, n), verdict="weak",
            flags=[f"{CLEARTEXT_HTTP_FLAG}{port}", f"{plaintext.EXPOSURE_FLAG}content"],
            usage_count=req, hosts_count=n,
            notes=(f"{_ft.plural(n, 'machine')} of the {seen:,} in this export sent "
                   f"{_ft.plural(req, 'HTTP request')} on port {port}/tcp that the sensor "
                   f"recorded as plain HTTP, to {_ft.plural(len(dests), 'destination')}: "
                   f"{_ft.top(dests, 5)}. "
                   "Anyone on the network path can read each request line and its headers. "
                   f"Sending programs: {programs or 'none recorded'}. The port-encryption "
                   "table does not call this port cleartext, so this is the one row grading "
                   f"this traffic. {OBSERVED}"),
            extra={"requests": str(req), "hosts": str(n), "estate_hosts": str(seen),
                   "programs": programs, "destinations": str(len(dests)),
                   "destinations_top": _ft.top(dests, 10), "kind": CLEARTEXT,
                   "direction": "outbound"},
            **base))

    # One detail row per destination, never graded.
    for (host, port), t in sorted(destinations.items(),
                                  key=lambda kv: (-kv[1]["requests"], kv[0])):
        n, req = len(t["machines"]), t["requests"]
        flags = [f"{DETAIL_FLAG}{port}"]
        link_local = is_link_local(host)
        if link_local:
            flags.append(LINK_LOCAL_FLAG)
        programs = _ft.top(t["programs"])
        named_ports = ", ".join(sorted(t["named_ports"]))
        graded_on = (f"the outbound-connection row for port {port}/tcp (falcon_connections)"
                     if graded_elsewhere(port) else f"the row \"Cleartext HTTP on {port}/tcp\"")
        notes = (f"{_ft.plural(n, 'machine')} of the {seen:,} in this export sent "
                 f"{_ft.plural(req, 'HTTP request')} to {host} on port {port}/tcp that the "
                 "sensor recorded as plain HTTP; anyone on the network path can read each "
                 f"request line and its headers. Sending programs: {programs or 'none recorded'}. This row "
                 f"is detail only: the traffic is graded on {graded_on}.")
        if named_ports:
            notes += (f" The Host header names port {named_ports}, not the port connected to, "
                      "as when a front end or proxy relays the request on.")
        if link_local:
            notes += (" The destination is a link-local address, so the request does not cross "
                      "a router; it is still readable on the local link.")
        out.append(CryptoAsset(
            # ``host`` stays empty: elsewhere it names the machine a row sits on, and this
            # row's destination is the far end. The destination is in ``name`` and ``extra``.
            name=f"Cleartext HTTP to {host}:{port}", protocol="http", port=port,
            role=roles.cleartext_web_destination(host, port, n), verdict="n/a", flags=flags,
            usage_count=req, hosts_count=n, notes=f"{notes} {OBSERVED}",
            extra={"destination": host, "requests": str(req), "hosts": str(n),
                   "estate_hosts": str(seen), "programs": programs,
                   "host_header_port": named_ports, "kind": CLEARTEXT,
                   "graded_on": graded_on, "direction": "outbound"},
            **base))

    # The split, on each port that carried a tunnel.
    for port in sorted(per_port, key=lambda p: (-per_port[p][TUNNEL]["requests"], p)):
        split = per_port[port]
        t = split[TUNNEL]["requests"]
        if not t:
            continue
        c, nh, lo = (split[CLEARTEXT]["requests"], split[NO_HOST]["requests"],
                     split[LOOPBACK]["requests"])
        total = t + c + nh + lo
        everyone: set[str] = set().union(*(k["machines"] for k in split.values()))
        tunnel_machines = len(split[TUNNEL]["machines"])
        plain_machines = len(split[CLEARTEXT]["machines"])
        notes = (f"Of {_ft.plural(total, 'request')} the sensor read on port {port}/tcp, from "
                 f"{_ft.plural(len(everyone), 'machine')}: {t:,} ({_ft.share(t, total)}, "
                 f"{_ft.plural(tunnel_machines, 'machine')}) name a host:443 target, the form "
                 "a CONNECT request to a forward proxy takes before an encrypted tunnel, so the "
                 "proxy and the path see the destination's name and not the page; "
                 f"{c:,} ({_ft.share(c, total)}, {_ft.plural(plain_machines, 'machine')}) are "
                 "plain requests to a named destination, each on its own row; "
                 f"{nh:,} ({_ft.share(nh, total)}) had no Host header"
                 + (f"; {lo:,} ({_ft.share(lo, total)}) stayed on the loopback interface"
                    if lo else "")
                 + ". The export carries no request method, so the tunnel reading rests on "
                 "the form of the target. Whether a tunnel is strongly encrypted is not in "
                 "this export (falcon_tls_clienthello reads handshakes). Nothing on this row is "
                 "graded.")
        out.append(CryptoAsset(
            name=f"Proxy traffic on {port}/tcp — tunnelled against plain requests",
            protocol="http-proxy", port=port, role=roles.web_proxy_split(port), verdict="n/a",
            flags=[f"{TUNNEL_FLAG}{port}"], usage_count=total, hosts_count=len(everyone),
            notes=notes,
            extra={"requests": str(total), "tunnel_requests": str(t),
                   "tunnel_share": _ft.share(t, total), "tunnel_hosts": str(tunnel_machines),
                   "tunnel_targets_top": _ft.top(split[TUNNEL]["targets"], 5),
                   "plain_requests": str(c), "plain_share": _ft.share(c, total),
                   "plain_hosts": str(plain_machines), "no_host_requests": str(nh),
                   "no_host_share": _ft.share(nh, total), "loopback_requests": str(lo)},
            **base))

    lb = by_kind[LOOPBACK]
    if lb["requests"]:
        n = len(lb["machines"])
        out.append(CryptoAsset(
            name="HTTP on the loopback interface", protocol="http",
            role=roles.loopback_web_requests(n), verdict="n/a", flags=[LOOPBACK_FLAG],
            usage_count=lb["requests"], hosts_count=n,
            notes=(f"{_ft.plural(lb['requests'], 'request')} from {_ft.plural(n, 'machine')} "
                   "named localhost or a loopback address, so they never reached a network "
                   f"interface. Recorded, not graded. By destination port: "
                   f"{_ft.top(lb['ports'], 6)}."),
            extra={"requests": str(lb["requests"]), "hosts": str(n),
                   "ports_top": _ft.top(lb["ports"], 6), "kind": LOOPBACK},
            **base))
    nh_t = by_kind[NO_HOST]
    if nh_t["requests"]:
        n = len(nh_t["machines"])
        out.append(CryptoAsset(
            name="HTTP requests with no Host recorded", protocol="http",
            role=roles.unnamed_web_requests(n), verdict="unknown", flags=[NO_HOST_FLAG],
            usage_count=nh_t["requests"], hosts_count=n,
            notes=(f"{_ft.plural(nh_t['requests'], 'request')} from "
                   f"{_ft.plural(n, 'machine')}, across "
                   f"{_ft.plural(len(nh_t['ports']), 'destination port')}, were recorded with "
                   "no Host header, so their destination cannot be named. Unmeasured, not "
                   f"graded. Largest ports: {_ft.top(nh_t['ports'], 6)}."),
            extra={"requests": str(nh_t["requests"]), "hosts": str(n),
                   "ports": str(len(nh_t["ports"])), "ports_top": _ft.top(nh_t["ports"], 6),
                   "kind": NO_HOST},
            **base))

    out.append(CryptoAsset(
        name="HTTP request export scope", protocol="http", role=roles.web_requests_scope(),
        verdict="n/a", flags=[SCOPE_FLAG], hosts_count=seen,
        notes=(f"{SCOPE_NOTE}. It covers {_ft.plural(seen, 'machine')}, only those whose sensor "
               "recorded a readable request: compare that with the estate's machine count "
               "before reading a figure here as the estate's. A port the port-encryption table "
               "calls cleartext is graded by falcon_connections, not here; if that reader's "
               "export does not hold the port, no row grades its traffic."),
        extra={"machines": str(seen), "destinations": str(len(destinations)),
               "rows": str(len(rows))},
        **base))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    assets, gaps = read(ctx.input, ctx.port_table, _ft.headings(ctx, HEADINGS))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon plain HTTP requests, by destination",
                gap_prefix=False)
