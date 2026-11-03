"""CrowdStrike Falcon: the TLS version the estate's own software asks for when it connects out.

Most in-transit readings measure what a listening service offers to whoever
connects in. This reader measures the other direction: what the estate's own
programs ask for when they open a TLS connection, read from the endpoint
sensor's ``TlsClientHello`` event. That is the question behind raising a
minimum TLS version anywhere on the path: which programs would stop working.

**The input** (``input:``) is a CSV written by a LogScale query over
``TlsClientHello`` events, grouped by machine, destination name, destination
port, TLS version value and (optionally) program, and counted.
``docs/COLLECTORS.md`` gives the query. The fields read, and their default
headings (``settings: columns:`` names others):

===============  =================  ========================================
field            default heading    what it holds
===============  =================  ========================================
``machine``      ``ComputerName``   the machine's name
``agent_id``     ``aid``            the sensor's ID, used when there is no name
``server_name``  ``DomainName``     the destination name the client asked for
``port``         ``RemotePort``     the destination port
``version``      ``TlsVersion``     the TLS version value, a number
``program``      ``ImageFileName``  the program's full path (optional)
``count``        ``_count``         handshakes in the group
===============  =================  ========================================

**The version is a number, and this reader names no TLS version for it
unless told to.** ``settings: values:`` lists the values the reader places,
lowest first (default ``0``, ``1``, ``2``, ``3``). The last is the *upper*
value; every other listed value is *lower*; a value not listed is counted on
the scope row and placed nowhere. CrowdStrike's community content repository
on GitHub (``CrowdStrike/logscale-community-content``) publishes a query
transform (``TlsVersion.logscale``) and a mappings table that read 0 to 3 as
TLS 1.0 to 1.3, and that repository says its content is not a replacement for
the official documentation. So the reader does not adopt that reading by
itself: ``settings: version_names:`` maps values to names, and only then do
the rows name a version. Without it, the reader raises a gap saying the
versions are unnamed.

**Rows.** One ``n/a`` row per program that asked for a lower value,
``Outbound handshakes — <program>`` (``software`` is the program), flagged
``outbound-tls-lower-tier:<handshakes>`` and, when the program asked for
nothing at the upper value, ``outbound-tls-lower-tier-only``. Programs that
asked only for the upper value get no row of their own. A program is keyed
by its full path, so two copies of one program in different places are two
rows. One ``n/a`` scope row, ``Outbound handshake scope``, gives the totals
and is flagged ``scope-enum-unnamed`` while no names are set. No row is
graded: the export says what clients asked for, not what was agreed.

**Further exports, each optional, named in** ``settings:``:

* ``distribution``: the same events grouped by version value alone, with no
  other grouping, read with the same headings. Its total is compared with
  the main export's: within 2 per cent, the main export holds the whole
  event population (every machine that produced the event, not a selection),
  and the scope row is flagged ``scope-reconciled-to-whole-event-population``;
  otherwise the scope row says what share the main export holds.
* ``platforms``: ``{file: <csv>, os_column: <heading>, host_column:
  <heading or list>}``, any export with one row per machine naming its
  operating system. ``host_column`` defaults to the ``machine`` heading.
  Machine names are matched ignoring case, in full or by the first label of
  a dotted name, and the scope row gives the operating systems of the
  machines in the export. The main export needs its ``machine`` column for
  this: a row keyed by ``aid`` matches only a column of agent IDs. With no
  ``os_column`` the file is not read.

Each setting naming a file may be a path, a list of paths or a pattern; the
last match in name order is read.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_traffic as _ft

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_tls_clienthello"

LOWER_FLAG = "outbound-tls-lower-tier:"
LOWER_ONLY_FLAG = "outbound-tls-lower-tier-only"
SCOPE_FLAG = "scope-enum-unnamed"
POPULATION_FLAG = "scope-reconciled-to-whole-event-population"

register_informational_prefixes(SCOPE_FLAG, POPULATION_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "machine": "ComputerName",
    "agent_id": "aid",
    "server_name": "DomainName",
    "port": "RemotePort",
    "version": "TlsVersion",
    "program": "ImageFileName",
    "count": _ft.COUNT_HEADING,
}

#: The version values placed by default, lowest first: the values CrowdStrike's
#: community content maps (``TlsVersion.logscale``).
VALUES: tuple[str, ...] = ("0", "1", "2", "3")

#: The source of the mapping a user may adopt with ``settings: version_names:``.
COMMUNITY_MAPPING_URL = ("https://github.com/CrowdStrike/logscale-community-content/blob/main/"
                         "Log-Sources/CrowdStrike/FLTR/standalone-content/transforms/"
                         "TlsVersion.logscale")

NO_PROGRAM = "(program not recorded)"
#: The main export's total within this fraction of the distribution's counts as the whole.
RECONCILE_TOLERANCE = 0.02


# ── settings ────────────────────────────────────────────────────────────────

def placed_values(ctx: Context) -> tuple[str, ...]:
    """``settings: values:``, lowest first, or :data:`VALUES`."""
    raw = (ctx.settings or {}).get("values")
    if isinstance(raw, Sequence) and not isinstance(raw, str):
        vals = tuple(str(v).strip() for v in raw if str(v).strip())
        if vals:
            return vals
    return VALUES


def version_names(ctx: Context) -> dict[str, str]:
    """``settings: version_names:`` as value -> name; empty when not set."""
    raw = (ctx.settings or {}).get("version_names") or {}
    if not isinstance(raw, Mapping):
        return {}
    return {str(k).strip(): str(v).strip() for k, v in raw.items() if str(v).strip()}


def _first(row: Mapping[str, str], columns: Sequence[str]) -> str:
    for c in columns:
        v = _ft.cell(row, c)
        if v:
            return v
    return ""


def platforms(path: Path | None, host_columns: Sequence[str], os_column: str,
              machines: set[str]) -> dict[str, int]:
    """The operating systems of ``machines`` (lower-cased names), counted, from a platform export.

    A machine is matched by its full name or by the first label of a dotted
    name. Machines the export does not match are counted under
    ``(no operating system recorded)``. Empty when the file holds no rows.
    """
    rows, _ = _ft.load(path)
    if not rows:
        return {}
    out: dict[str, int] = {}
    matched: set[str] = set()
    for r in rows:
        name = _first(r, host_columns).lower()
        if not name:
            continue
        short = name.split(".")[0]
        hit = name if name in machines else short if short in machines else ""
        if not hit or hit in matched:
            continue
        matched.add(hit)
        os_name = _ft.cell(r, os_column) or "unknown"
        out[os_name] = out.get(os_name, 0) + 1
    if len(machines) > len(matched):
        out["(no operating system recorded)"] = len(machines) - len(matched)
    return out


# ── gaps ────────────────────────────────────────────────────────────────────

def _missing_gap(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of outbound TLS handshakes was read"
        + (f" ({why})" if why else "")
        + ": what the estate's own software asks for when it makes an encrypted connection "
        "out, as opposed to what its services offer to whoever connects in",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, what the estate's services offer is known but not what its own "
                "software asks for, and the second decides which programs would stop working "
                "if a minimum TLS version were raised on the path."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_tls_clienthello) and "
                 "name its CSV with input:."),
        nature=coverage.NO_DATA)


def _unnamed_gap() -> str:
    return coverage.gap(
        coverage.NOT_MEASURED,
        "The TLS version each client asked for is recorded by the endpoint sensor as a number, "
        "and no TLS version is named for those numbers here (settings: version_names is not "
        "set), so the rows compare programs by value, lower against upper, not by version",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("The rows cannot be measured against a control that names a minimum TLS "
                "version. What they do show is which programs ask for a lower value than the "
                "highest placed, which is the set a raised minimum would affect first."),
        harvest=("Set version_names from a mapping you can stand behind. CrowdStrike's "
                 "community content repository on GitHub publishes one, reading 0 to 3 as TLS "
                 f"1.0 to 1.3 ({COMMUNITY_MAPPING_URL}), and says its content is not a "
                 "replacement for the official documentation."),
        nature=coverage.LOW_FIDELITY)


# ── reading ─────────────────────────────────────────────────────────────────

def _label(value: str, names: Mapping[str, str]) -> str:
    return f"{names[value]} (value {value})" if value in names else f"value {value}"


def read(path: Path, *, headings: dict[str, str] | None = None,
         values: Sequence[str] = VALUES, names: Mapping[str, str] | None = None,
         distribution: Path | None = None, platform_file: Path | None = None,
         platform_hosts: Sequence[str] = (), platform_os: str = "",
         ) -> tuple[list[CryptoAsset], list[str]]:
    """The rows for one export and the reader's gaps, or a gap when it cannot be read or is empty."""
    h = headings or dict(HEADINGS)
    names = dict(names or {})
    rows, unreadable = _ft.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon outbound TLS handshake export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    upper = values[-1]
    lower_values = set(values[:-1])

    per_value: dict[str, int] = {}
    unplaced: dict[str, int] = {}
    machines: set[str] = set()
    dest_names: set[str] = set()
    unnamed = 0
    software: dict[str, dict[str, Any]] = {}
    for r in rows:
        machine = (_ft.cell(r, h["machine"]) or _ft.cell(r, h["agent_id"])).lower()
        if machine:
            machines.add(machine)
        value = _ft.cell(r, h["version"])
        n = _ft.count(_ft.cell(r, h["count"]))
        server = _ft.cell(r, h["server_name"]).lower()
        if server:
            dest_names.add(server)
        else:
            unnamed += n
        if value not in values:
            unplaced[value or "(blank)"] = unplaced.get(value or "(blank)", 0) + n
            continue
        per_value[value] = per_value.get(value, 0) + n
        prog = _ft.cell(r, h["program"]) or NO_PROGRAM
        e = software.setdefault(prog, {"machines": set(), "values": {}, "names": set()})
        if machine:
            e["machines"].add(machine)
        e["values"][value] = e["values"].get(value, 0) + n
        if server:
            e["names"].add(server)

    total = sum(per_value.values()) + sum(unplaced.values())
    lower = sum(n for v, n in per_value.items() if v in lower_values)
    base: dict[str, Any] = {"data_state": "in-transit", "protocol": "tls", "source": NAME,
            "source_class": "private", "source_name": source_name, "collected_at": when}

    def lower_of(e: dict) -> int:
        return sum(n for v, n in e["values"].items() if v in lower_values)

    out: list[CryptoAsset] = []
    lower_programs = sorted(((p, e) for p, e in software.items() if lower_of(e)),
                            key=lambda kv: (-lower_of(kv[1]), kv[0]))
    for prog, e in lower_programs:
        n_lower, n_upper = lower_of(e), e["values"].get(upper, 0)
        asked = ", ".join(f"{_label(v, names)}: {e['values'][v]:,}"
                          for v in values if v in lower_values and e["values"].get(v))
        flags = [f"{LOWER_FLAG}{n_lower}"]
        if not n_upper:
            flags.append(LOWER_ONLY_FLAG)
        dests = sorted(e["names"])
        notes = (f"{_ft.plural(n_lower, 'handshake')} from {_ft.plural(len(e['machines']), 'machine')} "
                 f"asked for a lower version value than the upper one ({_label(upper, names)}): "
                 f"{asked}. "
                 + ("The program asked for nothing else. " if not n_upper else
                    f"It also made {n_upper:,} at the upper value, so where it asks for less, "
                    "the machine or the destination decides, not the program alone. ")
                 + (f"It reached {_ft.plural(len(dests), 'named destination')}"
                    + (f": {', '.join(dests)}. " if len(dests) <= 6 else ". ")
                    if dests else
                    "No destination name was recorded, so what it reached is not named here. ")
                 + ("The version names come from settings: version_names."
                    if names else
                    "No TLS version is named for these values; see the reader's gap."))
        out.append(CryptoAsset(
            name=f"Outbound handshakes — {prog}", software=prog,
            role=roles.outbound_tls_program(prog, len(e["machines"])), verdict="n/a",
            flags=flags, hosts_count=len(e["machines"]), notes=notes,
            extra={"program": prog, "lower_tier_handshakes": str(n_lower),
                   "upper_tier_handshakes": str(n_upper),
                   "machines": str(len(e["machines"])),
                   "named_destinations": str(len(e["names"]))},
            **base))

    dist_rows, _ = _ft.load(distribution)
    dist_total = sum(_ft.count(_ft.cell(r, h["count"])) for r in dist_rows)
    whole = bool(dist_total) and abs(total / dist_total - 1) <= RECONCILE_TOLERANCE
    if dist_total:
        ratio = total / dist_total
        if whole:
            population = (f"The distribution export, the same events grouped by version value "
                          f"alone, totals {dist_total:,} handshakes against {total:,} here, so "
                          "this export holds the whole event population: every machine that "
                          "produced the event, not a selection. A difference this small can come "
                          "from the two queries being run at different times.")
        else:
            population = (f"The distribution export, the same events grouped by version value "
                          f"alone, totals {dist_total:,} handshakes against {total:,} here, so "
                          f"this export holds {ratio:.0%} of the events and is a selection; "
                          "every figure here is short by the rest.")
    else:
        population = ("No distribution export was read, so whether these machines are every "
                      "machine that produced the event, or a selection, is not checked here.")

    if platform_file is not None and platform_os:
        spread = platforms(platform_file, platform_hosts or (h["machine"],), platform_os,
                           machines)
        if spread:
            listed = ", ".join(f"{k}: {v:,}" for k, v in
                               sorted(spread.items(), key=lambda kv: (-kv[1], kv[0])))
            platform_note = f"By the platform export, the machines here run: {listed}."
        else:
            platform_note = "The platform export named in the settings held no rows."
    else:
        platform_note = "No platform export was read, so the machines' operating systems are not given."

    flags = ([SCOPE_FLAG] if not names else []) + ([POPULATION_FLAG] if whole else [])
    lower_share = f"{lower / total:.0%}" if total else "unknown"
    out.append(CryptoAsset(
        name="Outbound handshake scope", role=roles.outbound_tls_scope(), verdict="n/a",
        flags=flags, hosts_count=len(machines),
        notes=(f"{_ft.plural(total, 'handshake')} from {_ft.plural(len(machines), 'machine')} "
               f"to {_ft.plural(len(dest_names), 'named destination')}, in "
               f"{_ft.plural(len(rows), 'row')}. {lower:,} of them ({lower_share}) asked for a "
               f"lower version value than the upper one ({_label(upper, names)}), from "
               f"{len(lower_programs):,} of the {len(software):,} programs seen. "
               f"{platform_note} {population}"
               + (f" {unnamed:,} handshakes carry no destination name." if unnamed else "")
               + (f" {sum(unplaced.values()):,} handshakes carry a value this reader does not "
                  f"place ({', '.join(sorted(unplaced))}) and are counted in neither group."
                  if unplaced else "")
               + (" The version names come from settings: version_names." if names else
                  " No TLS version is named for the values; see the reader's gap.")),
        extra={"handshakes": str(total), "machines": str(len(machines)), "rows": str(len(rows)),
               "named_destinations": str(len(dest_names)),
               "lower_tier_handshakes": str(lower),
               "upper_tier_handshakes": str(per_value.get(upper, 0)),
               "programs": str(len(software)),
               "programs_in_lower_tier": str(len(lower_programs)),
               "unfiltered_export_handshakes": str(dist_total)},
        **base))
    return out, ([] if names else [_unnamed_gap()])


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows and gaps, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    conf = (ctx.settings or {}).get("platforms") or {}
    if isinstance(conf, str):
        conf = {"file": conf}
    hosts = conf.get("host_column") or ()
    platform_file = None
    if conf.get("file"):
        found = _entra.paths(_ctx_with(ctx, {"file": conf["file"]}), "file")
        platform_file = found[-1] if found else None
    assets, gaps = read(
        ctx.input, headings=_ft.headings(ctx, HEADINGS), values=placed_values(ctx),
        names=version_names(ctx), distribution=_entra.newest(ctx, "distribution"),
        platform_file=platform_file,
        platform_hosts=(hosts,) if isinstance(hosts, str) else tuple(str(c) for c in hosts),
        platform_os=str(conf.get("os_column") or ""))
    return StepResult(records=assets, gaps=gaps)


def _ctx_with(ctx: Context, settings: dict) -> Context:
    """``ctx`` with other settings, to resolve a nested file setting as a top-level one is."""
    return dataclasses.replace(ctx, settings=settings)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon outbound TLS handshakes: what clients ask for",
                gap_prefix=False)
