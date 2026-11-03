"""CrowdStrike Falcon: outbound connections by destination port, read from the endpoint sensor.

A list of the services that listen on an estate says what is offered. It
does not say what is used. This reader answers the second question: which
destination ports the estate's own machines connect out to, how many
machines do so and how often, and so which unencrypted protocols are in
daily use rather than merely present. It also counts traffic to services no
listener inventory holds, such as one outside the estate.

**The input** (``input:``) is a CSV written by a LogScale query over the
sensor's outbound connection events (``NetworkConnectIP4`` and
``NetworkConnectIP6``), grouped by machine and destination port and counted.
``docs/COLLECTORS.md`` gives the query. The fields read, and their default
headings (``settings: columns:`` names others):

==============  ================  ==========================================
field           default heading   what it holds
==============  ================  ==========================================
``agent_id``    ``aid``           the sensor's ID for the machine
``machine``     ``ComputerName``  the machine's name, used when there is no ID
``port``        ``RemotePort``    the destination port
``count``       ``_count``        connections in the group
==============  ================  ==========================================

**One row per destination port, never per machine.** A machine is counted,
not named: the finding is how many machines speak a protocol in clear and
how much, and a row per machine would bury it. Each port is looked up in
takestock's port-encryption table (``port-encryption.csv``) over TCP:

* cleartext: ``weak``, flagged ``cleartext-egress:<protocol>`` and, where
  the table classes what the protocol exposes, ``cleartext-exposure:<what>``;
* opportunistic (the protocol can upgrade to encryption in band, as STARTTLS
  does): ``unknown``, flagged ``unverified-egress:<protocol>``, because the
  export cannot say whether the upgrade happened;
* encrypted by convention: ``n/a``;
* a port the table has no row for: ``unknown``, flagged
  ``ungraded:port-encryption:<port>``, kept so the table's gap stays in view.

The flag family is ``cleartext-egress:``, not ``plaintext:``. ``plaintext:``
counts listening services; adding outbound flows to it would count two
different things under one name.

**A scope row**, ``Outbound connection scope`` (``n/a``, flagged
``scope-cleartext-ports-only``), says what the export cannot support: where
the query selected destination ports (the published one does), there is no
denominator and no share of all traffic; the event's remote address is not grouped, so
an internal service and one on the internet look the same here; and the
grade is the port's convention, not a measurement of the traffic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import coverage, plaintext, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_traffic as _ft

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_connections"

EGRESS_FLAG = "cleartext-egress:"
UNVERIFIED_EGRESS_FLAG = "unverified-egress:"
SCOPE_FLAG = "scope-cleartext-ports-only"

register_informational_prefixes(UNVERIFIED_EGRESS_FLAG, SCOPE_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "agent_id": "aid",
    "machine": "ComputerName",
    "port": "RemotePort",
    "count": _ft.COUNT_HEADING,
}

SCOPE_NOTE = (
    "If the query that wrote this export selected destination ports, as the one in "
    "docs/COLLECTORS.md does, the export has no denominator: it says how much traffic reached "
    "those ports, never what share of all traffic that is. It groups no remote address, so a "
    "connection to an internal service and one to the internet look the same here. Each grade "
    "is the port's convention, from the port-encryption table, not a reading of the traffic "
    "itself")


def _missing_gap(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of outbound connections by destination port was read"
        + (f" ({why})" if why else "")
        + ": which unencrypted protocols the estate's own machines actually use, and how "
        "often. A list of listening services says what exists; only this says what is used",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, an unencrypted service nobody connects to cannot be told apart "
                "from one every machine uses all day, and traffic to services outside any "
                "listener inventory is not seen at all."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_connections) and name "
                 "its CSV with input:."),
        nature=coverage.NO_DATA)


def read(path: Path, port_table: plaintext.PortTable,
         headings: dict[str, str] | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    h = headings or dict(HEADINGS)
    rows, unreadable = _ft.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon outbound connection export, "
                   + (f"file dated {when}" if when else "file date unavailable"))

    by_port: dict[str, dict] = {}
    machines: set[str] = set()
    for r in rows:
        port = _ft.cell(r, h["port"])
        if not port:
            continue
        key = _ft.cell(r, h["agent_id"]) or _ft.cell(r, h["machine"])
        agg = by_port.setdefault(port, {"connections": 0, "machines": set()})
        agg["connections"] += _ft.count(_ft.cell(r, h["count"]))
        if key:
            machines.add(key)
            agg["machines"].add(key)

    seen = len(machines)
    base: dict[str, Any] = {"data_state": "in-transit", "source": NAME, "source_class": "private",
            "source_name": source_name, "collected_at": when}
    out: list[CryptoAsset] = []
    for port, agg in sorted(by_port.items(), key=lambda kv: (-kv[1]["connections"], kv[0])):
        entry = plaintext.lookup(port, "tcp", port_table) or {}
        protocol = entry.get("protocol", "") or f"port-{port}"
        posture = entry.get("posture", "")
        exposure = entry.get("exposure", "")
        n = len(agg["machines"])
        conns = agg["connections"]
        host_share = f"{n * 100 // seen}%" if seen else "unknown"
        who = f"{_ft.plural(n, 'machine')} of the {seen:,} in this export"
        flags: list[str] = []
        if posture == plaintext.CLEARTEXT:
            verdict = "weak"
            flags.append(f"{EGRESS_FLAG}{protocol}")
            if exposure and exposure != plaintext.EXPOSURE_NOT_APPLICABLE:
                flags.append(f"{plaintext.EXPOSURE_FLAG}{exposure}")
            finding = (f"{who} ({host_share}) made {conns:,} connections out over {protocol}, "
                       "a protocol with no encryption of its own: anyone on the network path "
                       "can read that traffic.")
        elif posture == plaintext.OPPORTUNISTIC:
            verdict = "unknown"
            flags.append(f"{UNVERIFIED_EGRESS_FLAG}{protocol}")
            finding = (f"{who} made {conns:,} connections out over {protocol}, which can "
                       "upgrade to encryption within the connection but need not. The export "
                       "cannot say whether it did, so this is unmeasured, not a finding.")
        elif not posture:
            verdict = "unknown"
            flags.append(f"ungraded:port-encryption:{port}")
            finding = (f"{who} made {conns:,} connections to port {port}/tcp. The "
                       "port-encryption table has no row for this port, so nothing here is "
                       "graded.")
        else:
            verdict = "n/a"
            finding = (f"{who} made {conns:,} connections to port {port}/tcp, which carries "
                       "encryption by convention.")
        out.append(CryptoAsset(
            name=f"Outbound {protocol} ({port}/tcp)", protocol=protocol, port=port,
            role=roles.outbound_connections(protocol, n, seen), verdict=verdict, flags=flags,
            usage_count=conns, hosts_count=n,
            notes=f"{finding} {plaintext.CONVENTION_BASIS}",
            extra={"connections": str(conns), "hosts": str(n), "estate_hosts": str(seen),
                   "host_share": host_share, "direction": "outbound",
                   "posture": posture or "unclassified"},
            **base))

    out.append(CryptoAsset(
        name="Outbound connection scope", protocol="egress",
        role=roles.outbound_connections_scope(), verdict="n/a", flags=[SCOPE_FLAG],
        hosts_count=seen,
        notes=(f"{SCOPE_NOTE}. It covers {_ft.plural(seen, 'machine')}: compare that with the "
               "estate's own machine count before reading a figure here as the estate's."),
        extra={"machines": str(seen), "ports": str(len(by_port))},
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
                title="CrowdStrike Falcon outbound connections by destination port",
                gap_prefix=False)
