"""CrowdStrike Falcon: the network services listening on each sensor's machine.

**The input** is a CSV of listening sockets, one row per machine, port and
the way the socket was bound, written by a CrowdStrike Query Language (CQL)
query over the sensor's ``NetworkListenIP4`` and ``NetworkListenIP6``
events in Falcon's event search. ``docs/COLLECTORS.md`` gives the query.
Three further exports are optional, each named in ``settings:``:

* ``accepts``: inbound connections accepted, per machine, port and program,
  from the ``NetworkReceiveAcceptIP4`` and ``NetworkReceiveAcceptIP6``
  events. It counts how much each service is used, and it names the program
  behind a port when the listener export does not.
* ``hosts``: one row per sensor (its ID, machine name, operating system and
  machine type), such as the sensors' host list. It says what kind of
  machine each listener is on, and it is an independent count of the
  machines, so the reader can say which machines produced no listener rows.
* ``host_types``: further exports that type each sensor's machine (a list).
  Where every one of them gives a sensor the same type (compared ignoring
  case) and it differs from ``hosts``, theirs is kept.

**Fields.** Each export's fields are read under the headings in
:data:`LISTENER_HEADINGS`, :data:`ACCEPT_HEADINGS`, :data:`HOST_HEADINGS` and
:data:`HOST_TYPE_HEADINGS`. ``aid`` (the sensor ID), ``ComputerName``,
``LocalAddressIP4``, ``LocalAddressIP6``, ``ProductType`` and ``Version`` are
CrowdStrike's own field names, as its public query examples use them; the
other headings are the ones the queries in ``docs/COLLECTORS.md`` write. An
export written with other headings is read by naming them:
``settings: {columns: {listeners: {port: <heading>}, ...}}``. A field may
name a list of headings, and the first one holding a value is read.
Headings match ignoring case, spaces and hyphens.

**Which listeners become rows.** A listening port is a row when the reader
can say something about it: the port has a row in takestock's port
encryption table (``port-encryption.csv``), so its protocol and whether it
encrypts are known; or the program behind it is named. A port with neither
is counted, not listed: one ``n/a`` row gives the total and how many
machines it spans. A program that holds more unrecognised ports on one
machine than ``settings: dynamic_port_run`` (default 20) is read as
handing each session a port of its own, and its ports become one row
saying how many, with no cryptographic claim about them.

**The program behind a port**, in order of evidence: the listener row's own
``program``; the accept export's program for the same machine and port; and,
when the accept export names exactly one program for that port across all
machines, that one, unless the daemon dictionary marks it ``ambiguous`` (a
runtime such as ``java`` names no service).

**Grades.** Each row's protocol and grade come from the port encryption
table through :func:`takestock.plaintext.apply_posture`, as a host listener:
a cleartext protocol is ``weak`` and flagged ``plaintext:<protocol>``; an
out-of-band management port seen only on the host is recorded as unmeasured
exposure, since a host's listener list cannot see the management
controller. The program's product, from the daemon dictionary (with any
profile overlay), names the row.

**Bind scope.** ``bind_scope`` is ``all-interfaces`` (the wildcard address),
``interface`` (one address), ``localhost`` (loopback only, flagged
``loopback-only``) or ``unknown`` (the row carried no address the query
could read). The query writes it; failing that, the reader works it out
from ``bind_address``, or from ``LocalAddressIP4`` or ``LocalAddressIP6``,
reading only the address field of the row's own address family. A listener
seen several ways keeps the widest scope, with ``unknown`` ranked above
``localhost``, so an unread address never reads as the least exposed.

**Loopback.** When no listener in the export is bound to loopback only, one
``n/a`` row says so, since a service reachable only from its own machine
would then be missing rather than absent. ``settings:
loopback_binds_reported: false`` records that the operator has established
that their sensors do not report loopback binds; the row then says the
blind spot is the source's, and is written even when the export holds
loopback rows. ``true`` records that they do report them; the row, written
only when none is in the export, then says none was seen.

**Truncation.** A CQL ``groupBy()`` that reaches its limit (20,000 groups
unless ``limit`` raises it) may return incomplete results. An export whose
row count equals ``settings: row_limit`` (default 20,000), or is a whole
multiple of 10,000 at or above it, is read as cut short.

**Coverage gaps.** No listener export: one gap. A listener export cut short,
rows with no readable address, no address family, or IPv4 only: one gap
each. No accept export, one cut short, or one with no machine column: one
gap. Machines in ``hosts`` with no listener row: one gap. No ``hosts``
export: one optional gap.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plaintext import apply_posture, lookup, register_host_listener_source
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra, _table

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon"

#: Where this reader's own detail begins in a row's notes, after the posture note.
NOTES_MARKER = "service="
register_host_listener_source(NAME, NOTES_MARKER)

LOOPBACK_FLAG = "loopback-only"
register_informational_prefixes(LOOPBACK_FLAG)

GROUPBY_URL = "https://library.humio.com/crowdstrike-query-language/functions-groupby.html"
#: CQL ``groupBy()``'s default group limit (its documentation, :data:`GROUPBY_URL`).
ROW_LIMIT = 20000
#: More distinct unrecognised ports than this, held by one program on one machine, are one row.
DYNAMIC_PORT_RUN = 20

#: Listener export: each field and the heading it is read from.
LISTENER_HEADINGS: dict[str, Any] = {
    "host": "ComputerName",
    "sensor_id": "aid",
    "port": "port",
    "transport": "transport",
    "program": "program",
    "bind_scope": "bind_scope",
    "address_family": "address_family",
    "bind_address": "bind_address",
    "bound_v4": "LocalAddressIP4",
    "bound_v6": "LocalAddressIP6",
    "events": "events",
}
#: Accept export: each field and the heading it is read from.
ACCEPT_HEADINGS: dict[str, Any] = {
    "host": "ComputerName",
    "sensor_id": "aid",
    "port": "port",
    "transport": "transport",
    "program": "program",
    "events": "events",
}
#: Host export: each field and the heading it is read from.
HOST_HEADINGS: dict[str, Any] = {
    "sensor_id": "aid",
    "host": "ComputerName",
    "os": "Version",
    "machine_type": "ProductType",
}
#: Each further machine-type export: each field and the heading it is read from.
HOST_TYPE_HEADINGS: dict[str, Any] = {"sensor_id": "aid", "machine_type": "ProductType"}

_TABLES = {"listeners": LISTENER_HEADINGS, "accepts": ACCEPT_HEADINGS, "hosts": HOST_HEADINGS,
           "host_types": HOST_TYPE_HEADINGS}

#: ``ProductType`` codes and CrowdStrike's names for them (its public value mappings).
PRODUCT_TYPES = {"1": "Desktop", "2": "Domain Controller", "3": "Server"}

#: ``Protocol`` numbers (IANA's assigned internet protocol numbers) and the transport each names.
TRANSPORTS = {"6": "tcp", "17": "udp"}

SCOPE_ALL = "all-interfaces"
SCOPE_LOCAL = "localhost"
SCOPE_IFACE = "interface"
SCOPE_UNKNOWN = "unknown"
#: Widest exposure first: a listener seen several ways keeps the first of these it was seen as.
SCOPE_RANK = (SCOPE_ALL, SCOPE_IFACE, SCOPE_UNKNOWN, SCOPE_LOCAL)

IPV4 = "ipv4"
IPV6 = "ipv6"
DUAL_STACK = "dual-stack"
_FAMILY_WORDS = {"ipv4": IPV4, "4": IPV4, "v4": IPV4, "ip4": IPV4,
                 "networklistenip4": IPV4,
                 "ipv6": IPV6, "6": IPV6, "v6": IPV6, "ip6": IPV6,
                 "networklistenip6": IPV6}

SCOPE_NOTES = {
    SCOPE_ALL: "bound on every interface",
    SCOPE_LOCAL: "bound on loopback only — not reachable from the network",
    SCOPE_IFACE: "bound on a specific interface address",
    SCOPE_UNKNOWN: ("bind address not recorded by the export, so whether this is exposed to the "
                    "network or only to the machine itself is UNKNOWN — not assumed either way"),
}
FAMILY_NOTES = {
    IPV4: "IPv4",
    IPV6: "IPv6 — this listener was seen only on the IPv6 stack",
    DUAL_STACK: "dual-stacked — seen on both IPv4 and IPv6",
}

#: The ``extra`` key the loopback row names its scope under.
LOOPBACK_ROW_SCOPE = "unobservable_scope"


# ── reading ──

def _headings(ctx: Context) -> dict[str, dict[str, Any]]:
    """Each export's field-to-heading map, with ``settings: columns:`` applied."""
    named = (ctx.settings or {}).get("columns") or {}
    out = {table: dict(heads) for table, heads in _TABLES.items()}
    if not isinstance(named, Mapping):
        return out
    for table, fields in named.items():
        if table not in out or not isinstance(fields, Mapping):
            continue
        for field, heading in fields.items():
            if field not in out[table]:
                continue
            if isinstance(heading, str) and heading.strip():
                out[table][field] = heading
            elif isinstance(heading, list) and all(isinstance(h, str) for h in heading):
                out[table][field] = [h for h in heading if h.strip()]
    return out


def _value(row: Mapping[str, str], heading: Any) -> str:
    """The field's value: under its heading, or the first of its headings holding one."""
    if isinstance(heading, list):
        for h in heading:
            v = _table.value(row, h).strip()
            if v:
                return v
        return ""
    return _table.value(row, str(heading)).strip()


def _rows(path: Path | None) -> tuple[list[dict[str, str]], str]:
    """The file's rows and, when it could not be read, why ("" when it was read or not named)."""
    if path is None:
        return [], ""
    if not path.exists():
        return [], f"{path.name} was named and not found"
    try:
        return _table.read(path), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], f"{path.name} could not be read ({exc})"


def _number(text: str) -> int:
    try:
        return int(text or 0)
    except ValueError:
        return 0


def looks_cut_short(rows: int, limit: int = ROW_LIMIT) -> bool:
    """Whether a row count looks like a query limit rather than an answer.

    Exactly the limit is the plain case. A grouped count rarely lands on a
    round number, so a whole multiple of 10,000 at or above the limit is read
    the same way: it catches a limit raised to 50,000 or 100,000 and reached.
    """
    return rows == limit or (rows >= limit and rows % 10000 == 0)


def split_port(service: str, transport: str = "") -> tuple[str, str]:
    """``"443/tcp"`` → ``("443", "tcp")``; a bare ``"443"`` takes ``transport``.

    A protocol number (``6``, ``17``) is read as the transport it names. A
    value that is not a port number gives ``("", "")``.
    """
    port, _, trans = service.partition("/")
    port = port.strip()
    if not port.isdigit():
        return "", ""
    trans = (trans or transport).strip().lower()
    return port, TRANSPORTS.get(trans, trans)


def _service(row: Mapping[str, str], heads: Mapping[str, Any]) -> str:
    """A listener's ``port/transport``, as the export writes it or built from two fields."""
    service = _value(row, heads["port"])
    if not service or "/" in service:
        return service
    transport = _value(row, heads["transport"]).lower()
    transport = TRANSPORTS.get(transport, transport)
    return f"{service}/{transport}" if transport else service


def address_scope(addr: str) -> str:
    """A bind address's scope. The literals are RFC 4291's and RFC 1122's, not anyone's address."""
    addr = addr.strip().lower()
    if not addr:
        return ""
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    if addr.startswith("::ffff:"):
        addr = addr[len("::ffff:"):]   # an IPv4 address carried on an IPv6 socket
    if addr in ("::1", "0:0:0:0:0:0:0:1") or addr.startswith("127."):
        return SCOPE_LOCAL
    if addr in ("::", "0:0:0:0:0:0:0:0", "0.0.0.0"):
        return SCOPE_ALL
    return SCOPE_IFACE


def _family(row: Mapping[str, str], heads: Mapping[str, Any]) -> str:
    """The row's address family: its own label, else whichever family's address it carries."""
    label = _value(row, heads["address_family"]).lower()
    if label in _FAMILY_WORDS:
        return _FAMILY_WORDS[label]
    if _value(row, heads["bound_v6"]):
        return IPV6
    if _value(row, heads["bound_v4"]):
        return IPV4
    addr = _value(row, heads["bind_address"])
    if addr:
        return IPV6 if ":" in addr else IPV4
    return ""


def _scope(row: Mapping[str, str], heads: Mapping[str, Any]) -> str:
    """The row's bind scope: its own label, else from the address of its own family.

    Only the address field of the row's own family is read, so an IPv4
    address on an IPv6 row is never taken for the IPv6 socket's address.
    """
    label = _value(row, heads["bind_scope"]).lower()
    if label in SCOPE_RANK:
        return label
    family = _family(row, heads)
    if family == IPV6:
        addr = _value(row, heads["bound_v6"]) or (
            _value(row, heads["bind_address"]) if ":" in _value(row, heads["bind_address"])
            else "")
    elif family == IPV4:
        addr = _value(row, heads["bound_v4"]) or _value(row, heads["bind_address"])
    else:
        addr = (_value(row, heads["bind_address"]) or _value(row, heads["bound_v4"])
                or _value(row, heads["bound_v6"]))
    if not addr:
        # Knowing the family, or the export having a scope or family column
        # at all, and still finding no address is a reading that failed; an
        # export with none of them simply does not record scope.
        said = family or label or _value(row, heads["address_family"])
        return SCOPE_UNKNOWN if said else ""
    return address_scope(addr)


def _widest(scopes: set[str]) -> str:
    return next((s for s in SCOPE_RANK if s in scopes), "")


def _families(families: set[str]) -> str:
    known = families & {IPV4, IPV6}
    if len(known) > 1:
        return DUAL_STACK
    return next(iter(known), "")


def _machine_type(raw: str) -> str:
    return PRODUCT_TYPES.get(raw.strip(), raw.strip())


def host_types(paths: list[Path], heads: Mapping[str, Any]) -> dict[str, list[str]]:
    """Every machine type the further exports give each sensor ID, in the order read."""
    out: dict[str, list[str]] = {}
    for path in paths:
        rows, _why = _rows(path)
        for r in rows:
            sid = _value(r, heads["sensor_id"])
            kind = _machine_type(_value(r, heads["machine_type"]))
            if sid and kind:
                out.setdefault(sid, []).append(kind)
    return out


def resolve_type(sid: str, reported: str, others: Mapping[str, list[str]]) -> str:
    """The machine type kept for a sensor: the further exports' one type where they agree on one
    and it differs from ``reported`` (compared ignoring case), else ``reported``."""
    seen = others.get(sid) or []
    if len({k.casefold() for k in seen}) != 1 or seen[0].casefold() == reported.casefold():
        return reported
    return seen[0]


# ── gaps ──

def _harvest_listeners() -> str:
    return ("Run the listener query in docs/COLLECTORS.md (section falcon) in Falcon's event "
            "search, download the results as CSV and name the file in the profile.")


def _no_listeners_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon listener export was read: which network services each machine "
        "with a sensor is running" + (f"; {why}" if why else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, what services the machines run is not measured, so anything said "
                "about encryption inside the network rests on what could be reached from "
                "outside: a sample, not a total."),
        harvest=_harvest_listeners(),
        nature=coverage.NO_DATA)


def _cut_short_listeners_gap(rows: int) -> coverage.Gap:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"the CrowdStrike Falcon listener export holds {rows:,} rows, the query limit or a "
        "round multiple of it, so it was probably cut short and an unknown number of "
        "listeners are missing. Raise or narrow every limit in the query (join()'s "
        "subquery is capped at 200,000 rows, so shorten the period if programs come back "
        "blank).",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Every count of services is a floor, by an amount not known: read each as "
                "'at least this many'."),
        harvest="Re-run the listener query with its limits raised, then re-run takestock.",
        nature=coverage.NO_DATA)


def _no_address_gap(rows: int, total: int) -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"{rows:,} of {total:,} CrowdStrike Falcon listener rows carry no bind address the "
        "query could read, so whether each is reachable from the network or only from its own "
        "machine is not known. Check that the query reads LocalAddressIP6 for IPv6 events.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("For these services an exposure cannot be told from a local detail, which "
                "decides whether one needs fixing, so they cannot be ranked."),
        harvest=("Re-run the listener query with the address field of each family read, "
                 "then re-run takestock."),
        nature=coverage.LOW_FIDELITY)


def _no_family_gap() -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        "the CrowdStrike Falcon listener export says no row's address family, so IPv6 "
        "listeners cannot be told from IPv4 ones and IPv6 exposure is not measured",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("If services can also be reached over IPv6, that route is not graded here, so "
                "'no weak service found' cannot be read as 'none exists'."),
        harvest=("Re-run the listener query, which labels each row's address family, then "
                 "re-run takestock."),
        nature=coverage.LOW_FIDELITY)


def _ipv4_only_gap(rows: int) -> coverage.Gap:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"all {rows:,} CrowdStrike Falcon listener rows are IPv4 and none is IPv6. Either the "
        "machines listen on IPv4 only, or the query left the NetworkListenIP6 events out or "
        "mislabelled them; check the query before reading the estate as IPv4 only.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("If the machines also listen over IPv6, the exposure figures here cover one of "
                "two routes to these services."),
        harvest=("Confirm that the query reads NetworkListenIP6 events, then re-run it and "
                 "takestock."),
        nature=coverage.NO_DATA)


def _no_accepts_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon accept export was read: how many inbound connections each "
        "listening service accepted, and which program accepted them"
        + (f"; {why}" if why else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("A service someone uses cannot be told from one nobody has used, which is the "
                "difference between switching it off and upgrading it; and a port's program "
                "is named only where the listener export names it."),
        harvest=("Run the accept query in docs/COLLECTORS.md (section falcon), download the "
                 "results as CSV and name the file under settings: accepts:."),
        nature=coverage.NO_DATA)


def _cut_short_accepts_gap(rows: int) -> coverage.Gap:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"the CrowdStrike Falcon accept export holds {rows:,} rows, the query limit or a "
        "round multiple of it, so it was probably cut short. Raise the query's limits or "
        "narrow it, and re-run.",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Use counts rest on part of the traffic, so a service can look unused and be "
                "busy. The encryption findings do not depend on them."),
        harvest="Re-run the accept query with its limits raised, then re-run takestock.",
        nature=coverage.NO_DATA)


def _accepts_without_host_gap() -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        "the CrowdStrike Falcon accept export has no machine column (aid or ComputerName), so "
        "a program is named for a listener only where one program serves that port across "
        "every machine, and no per-machine use count is given",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Use is known for the estate as a whole, not machine by machine. It slows "
                "planning a change and alters no grade."),
        harvest="Re-run the accept query grouped by machine, then re-run takestock.",
        nature=coverage.LOW_FIDELITY)


def _blind_hosts_gap(blind: int, total: int, kinds: list[str], cut_short: bool) -> coverage.Gap:
    reading = ("they were never returned, which is the likelier reading, because the "
               "listener export looks cut short." if cut_short else
               "they were switched off for the period. The listener export does not look cut "
               "short, so this is the likelier reading.")
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{blind:,} of {total:,} machines in the CrowdStrike Falcon host export produced no "
        f"listener row ({', '.join(kinds)}). Either they listen on no port the query keeps, or "
        + reading + " This is measured against an independent count of the machines, not "
        "inferred from the listener export.",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("These machines contributed nothing to the service inventory, so per-machine "
                "figures cover the machines named, not every machine. Nothing here says these "
                "machines are clean."),
        harvest=("A re-run of the listener query with its limits raised, or confirmation that "
                 "these machines run no network service."),
        nature=coverage.NO_DATA)


def _no_hosts_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon host export was read: what kind of machine each listener is on, "
        "and which machines produced no listener row" + (f"; {why}" if why else ""),
        required=False,
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Listeners are listed without their machine's type, and a machine that "
                "produced no listener row cannot be told from one that does not exist."),
        harvest=("Run the host query in docs/COLLECTORS.md (section falcon) and name the file "
                 "under settings: hosts:."),
        nature=coverage.NO_DATA)


# ── reading the exports into rows ──

def read(listeners_path: Path, *, accepts: Path | None = None, hosts: Path | None = None,
         type_paths: list[Path] | None = None, dictionary: Mapping[str, Mapping] | None = None,
         port_table: Mapping | None = None, headings: Mapping[str, Mapping[str, Any]] | None = None,
         row_limit: int = ROW_LIMIT, dynamic_port_run: int = DYNAMIC_PORT_RUN,
         loopback_binds_reported: bool | None = None,
         ) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows and gaps for one listener export and its optional companions."""
    heads = headings or _TABLES
    lh, ah, hh, th = (heads["listeners"], heads["accepts"], heads["hosts"], heads["host_types"])
    words: Mapping[str, Mapping] = dictionary or {}
    table = port_table or {}
    gaps: list[coverage.Gap] = []

    listeners, why = _rows(listeners_path)
    if not listeners:
        return [], [_no_listeners_gap(why or "the file named holds no rows")]
    accept_rows, accept_why = _rows(accepts)
    host_rows, host_why = _rows(hosts)

    when = file_mtime_date(listeners_path) or ""
    source_name = ("CrowdStrike Falcon listener export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}

    # The machines, by sensor ID: the sensor ID is stable where a machine name can be
    # renamed, left blank or shared.
    others = host_types(type_paths or [], th)
    machines: dict[str, dict[str, str]] = {}
    for r in host_rows:
        sid = _value(r, hh["sensor_id"])
        if sid:
            reported = _machine_type(_value(r, hh["machine_type"]))
            machines[sid] = {"name": _value(r, hh["host"]), "os": _value(r, hh["os"]),
                             "type": resolve_type(sid, reported, others)}

    # The accept export, indexed by machine and port, and by port alone. A port's
    # estate-wide total is never written as one machine's use: it would multiply
    # one stream of traffic by the number of machines listening on that port.
    used_on: dict[tuple[str, str], int] = {}
    program_on: dict[tuple[str, str], str] = {}
    programs_for: dict[str, set[str]] = {}
    used_port: dict[str, int] = {}
    used_program: dict[tuple[str, str], int] = {}
    per_machine = False
    for r in accept_rows:
        program = _value(r, ah["program"])
        service = _service(r, ah)
        who = _value(r, ah["sensor_id"]) or _value(r, ah["host"])
        n = _number(_value(r, ah["events"]))
        used_program[(program, service)] = used_program.get((program, service), 0) + n
        used_port[service] = used_port.get(service, 0) + n
        if program:
            programs_for.setdefault(service, set()).add(program)
        if who:
            per_machine = True
            used_on[(who, service)] = used_on.get((who, service), 0) + n
            if program:
                program_on[(who, service)] = program

    # A machine name shared by several sensors is shown with the start of each sensor ID.
    sensors_named: dict[str, set[str]] = {}
    for r in listeners:
        sensors_named.setdefault(_value(r, lh["host"]), set()).add(_value(r, lh["sensor_id"]))
    shared_names = {n for n, ids in sensors_named.items() if len(ids) > 1}

    def label(host: str, sid: str) -> str:
        return f"{host} [{sid[:8]}]" if host in shared_names and sid else host

    # One listener per machine, sensor and port, however many rows the export split it
    # into: the address family and the bind scope are properties of the addresses a
    # listener was seen on, not of the listener.
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    no_address = 0
    per_family = {IPV4: 0, IPV6: 0}
    for r in listeners:
        scope = _scope(r, lh)
        if scope == SCOPE_UNKNOWN:
            no_address += 1
        family = _family(r, lh)
        if family in per_family:
            per_family[family] += 1
        key = (_value(r, lh["host"]), _value(r, lh["sensor_id"]), _service(r, lh))
        g = grouped.setdefault(key, {"row": r, "events": 0, "families": set(), "scopes": set()})
        g["events"] += _number(_value(r, lh["events"]))
        if family:
            g["families"].add(family)
        if scope:
            g["scopes"].add(scope)

    def program_of(r: Mapping[str, str], who: str, service: str) -> tuple[str, str]:
        """The program behind a listener and where its name came from ("" when none)."""
        program = _value(r, lh["program"])
        if program:
            return program, "listener event"
        program = program_on.get((who, service), "")
        if program:
            return program, "accept export, same machine and port"
        candidates = programs_for.get(service, set())
        if len(candidates) == 1:
            only = next(iter(candidates))
            if (words.get(only) or {}).get("confidence") != "ambiguous":
                return only, "accept export, one program across every machine on this port"
        return "", ""

    # How many distinct unrecognised ports each program holds on each machine.
    held: dict[tuple[str, str], int] = {}
    for (host, sid, service), g in grouped.items():
        port, transport = split_port(service)
        if lookup(port, transport, table) is not None:
            continue
        program, _basis = program_of(g["row"], sid or host, service)
        if program:
            held[(host, program)] = held.get((host, program), 0) + 1

    out: list[CryptoAsset] = []
    runs: dict[tuple[str, str], dict[str, Any]] = {}
    uncounted = 0
    uncounted_hosts: set[str] = set()
    for (host, sid, service), g in grouped.items():
        port, transport = split_port(service)
        who = sid or host
        program, basis = program_of(g["row"], who, service)
        known = lookup(port, transport, table)
        entry = words.get(program) or {}
        machine = machines.get(sid, {})

        used = used_on.get((who, service))
        if used is None and basis == "listener event":
            used = used_program.get((program, service))
        estate_used = used_port.get(service)

        if not (known or program):
            uncounted += 1
            if host:
                uncounted_hosts.add(host)
            continue
        if known is None and program and held.get((host, program), 0) > dynamic_port_run:
            run = runs.setdefault((host, program), {"ports": 0, "events": 0, "used": 0,
                                                    "sid": sid})
            run["ports"] += 1
            run["events"] += g["events"]
            run["used"] += used or 0
            continue

        scope = _widest(g["scopes"])
        family = _families(g["families"])
        flags = [LOOPBACK_FLAG] if scope == SCOPE_LOCAL else []
        notes = [f"{NOTES_MARKER}{service}"]
        if entry.get("category"):
            notes.append(f"category={entry['category']}")
        if basis:
            notes.append(f"program named from the {basis}")
        if scope:
            notes.append(SCOPE_NOTES[scope])
        if family:
            notes.append(FAMILY_NOTES[family])
        if used is None and estate_used:
            notes.append(f"{estate_used:,} connections accepted on this port across every "
                         "machine (the accept export does not say how many were to this one)")
        where = label(host, sid)
        asset = CryptoAsset(
            name=f"{entry.get('product', program) or 'listener'} on {where}:{service}",
            role=roles.listening_service(entry.get("product", ""), where,
                                         roles.machine_kind(machine.get("os", ""),
                                                            machine.get("type", ""))),
            data_state="in-transit", protocol=known["protocol"] if known else "", host=where,
            port=port, software=entry.get("product", program), software_binary=program,
            usage_count=used, flags=flags, notes="; ".join(notes),
            extra={"service": service, "confidence": entry.get("confidence", ""),
                   "bind_scope": scope, "address_family": family,
                   "bind_scopes_seen": ",".join(sorted(g["scopes"])),
                   "binds": str(g["events"]), "aid": sid,
                   "os": machine.get("os", ""), "host_type": machine.get("type", ""),
                   "estate_connections": str(estate_used) if estate_used else ""},
            **base)
        apply_posture(asset, table, transport, host_listener=True)
        out.append(asset)

    if looks_cut_short(len(listeners), row_limit):
        gaps.append(_cut_short_listeners_gap(len(listeners)))
    if no_address:
        gaps.append(_no_address_gap(no_address, len(listeners)))
    if not any(per_family.values()):
        gaps.append(_no_family_gap())
    elif per_family[IPV4] and not per_family[IPV6]:
        gaps.append(_ipv4_only_gap(per_family[IPV4]))

    if not accept_rows:
        gaps.append(_no_accepts_gap(accept_why))
    elif looks_cut_short(len(accept_rows), row_limit):
        gaps.append(_cut_short_accepts_gap(len(accept_rows)))
    elif not per_machine:
        gaps.append(_accepts_without_host_gap())

    for (host, program), run in runs.items():
        entry = words.get(program) or {}
        product = entry.get("product", program)
        where = label(host, run["sid"])
        out.append(CryptoAsset(
            name=f"{product} on {where} — {run['ports']:,} dynamically allocated ports",
            role=roles.dynamic_port_run(entry.get("product", ""), where, run["ports"]),
            data_state="in-transit", host=where, software=product, software_binary=program,
            usage_count=run["used"] or None,
            notes=(f"{run['ports']:,} distinct ports, none of them in the port table, all held "
                   "by this one program on this machine: the pattern of a program that gives "
                   "each session a port of its own rather than serving on a fixed one. One "
                   "row, because the count is the fact. No cryptographic claim is made about "
                   "these ports: a probe of a sample would settle what they carry."),
            extra={"dynamic_ports": str(run["ports"]), "binds": str(run["events"]),
                   "aid": run["sid"], "confidence": entry.get("confidence", "")},
            **base))

    if machines:
        seen = {sid for (_h, sid, _s) in grouped}
        blind = [m for sid, m in machines.items() if sid not in seen]
        if blind:
            kinds = sorted({f"{m.get('os', '?')} {m.get('type', '?')}" for m in blind})
            gaps.append(_blind_hosts_gap(len(blind), len(machines), kinds,
                                         looks_cut_short(len(listeners), row_limit)))
    elif not host_rows:
        gaps.append(_no_hosts_gap(host_why))

    if uncounted:
        out.append(CryptoAsset(
            name=(f"Unclassified listener binds ({uncounted:,} across "
                  f"{len(uncounted_hosts):,} computers)"),
            role=roles.unclassified_binds(uncounted, len(uncounted_hosts)),
            data_state="discovery", verdict="n/a",
            notes=("Not listed one by one: the port is not in the port table, and no program "
                   "was named for it. Most are likely short-lived binds rather than services. "
                   "Counted here so that a listener left out still leaves a trace."),
            extra={"unclassified_binds": str(uncounted),
                   "unclassified_hosts": str(len(uncounted_hosts))},
            **base))

    sensors = len({sid for (_h, sid, _s) in grouped if sid})
    if loopback_binds_reported is False:
        out.append(CryptoAsset(
            name="Loopback-only listeners are not observable through CrowdStrike",
            role=roles.loopback_listeners_unseen(sensors, reported=False),
            data_state="discovery", verdict="n/a",
            notes=("The profile records that these sensors do not report listeners bound to "
                   "the loopback address (settings: loopback_binds_reported: false). So no row "
                   f"here carries bind_scope {SCOPE_LOCAL}, and that is the source's blind "
                   "spot, not an estate with no such services: anything listening on loopback "
                   "only is outside this reader's view."),
            extra={LOOPBACK_ROW_SCOPE: SCOPE_LOCAL, "hosts_in_scope": str(sensors)},
            **base))
    elif not any(SCOPE_LOCAL in g["scopes"] for g in grouped.values()):
        out.append(CryptoAsset(
            name="Loopback-only listeners: none in the CrowdStrike export",
            role=roles.loopback_listeners_unseen(sensors, reported=loopback_binds_reported),
            data_state="discovery", verdict="n/a",
            notes=(("No listener in this export is bound to the loopback address only. The "
                    "profile records that these sensors report listeners bound to the loopback "
                    "address (settings: loopback_binds_reported: true), so none was seen."
                    ) if loopback_binds_reported else
                   ("No listener in this export is bound to the loopback address only. Whether "
                    "the sensors report such listeners was not established here, so a service "
                    "reachable only from its own machine may be missing rather than absent.")),
            extra={LOOPBACK_ROW_SCOPE: SCOPE_LOCAL, "hosts_in_scope": str(sensors)},
            **base))
    return out, gaps


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the listener export's rows and gaps, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_no_listeners_gap("")])
    settings = ctx.settings or {}
    reported = settings.get("loopback_binds_reported")
    assets, gaps = read(
        ctx.input, accepts=_entra.newest(ctx, "accepts"), hosts=_entra.newest(ctx, "hosts"),
        type_paths=_entra.paths(ctx, "host_types"), dictionary=ctx.dictionary,
        port_table=ctx.port_table, headings=_headings(ctx),
        row_limit=int(_entra.setting_number(ctx, "row_limit", ROW_LIMIT)),
        dynamic_port_run=int(_entra.setting_number(ctx, "dynamic_port_run", DYNAMIC_PORT_RUN)),
        loopback_binds_reported=reported if isinstance(reported, bool) else None)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon listening ports, inbound use and machine types",
                gap_prefix=False)
