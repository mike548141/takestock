"""CrowdStrike Falcon: SHA-1 in the signing data of software loaded on Windows machines.

The Falcon sensor records an event, ``ModuleCertificateInfo2``, with the
signing details of software modules loaded on a Windows machine. A LogScale
search for the text ``sha1RSA`` (the name Windows gives the SHA-1 with RSA
signature algorithm) in those events, grouped by machine, says which machines
load software whose signing data carries SHA-1 somewhere. No public source
found shows which of the event's fields hold the certificates' algorithm
names, so an empty result is not evidence that no SHA-1 is present.

**The input** (``input:``) is a CSV with one row per machine and a count of
matching events, written by the LogScale query in ``docs/COLLECTORS.md``.
The fields read, and their default headings (``settings: columns:`` names
another heading, or a list tried in order):

==============  ================  ==========================================
field           default heading   what it holds
==============  ================  ==========================================
``machine``     ``ComputerName``  the machine's name
``agent_id``    ``aid``           the sensor's ID, used when a row names no machine
``count``       ``_count``        the matching events on that machine
==============  ================  ==========================================

A blank or unreadable count is read as 1, since a grouped row stands for one
event or more. Machines are matched by name ignoring case and any domain
suffix (the first label of a dotted name).

**One row for the whole export**, ``Software signed with SHA-1, loaded on
the machines``, never one per machine: the export names no module, publisher
or certificate, so the one thing it can say is about the population. The row
carries the primitive (``hashes: sha1``), so the baseline grades SHA-1 as it
does anywhere else; it is flagged ``sha1-signing-position-unresolved``, and
a coverage gap says why. A module's signing data holds a chain of
certificates, and the text search matches SHA-1 anywhere in it, so three
cases look the same here: the module's own signature is SHA-1 (the case that
matters); the module is signed twice, with SHA-1 kept beside SHA-2 for older
verifiers; or a certificate higher in the chain is signed with SHA-1, such
as a root certificate's signature over itself, which no verifier relies on.
``extra`` names the busiest machines (``settings: top_machines:``, default
10) with their counts.

**A platform export.** ``settings: platforms:`` names a CSV of the sensored
machines and their operating systems (``file``; ``host_column``, default
``hostname``; ``os_column``, default ``os_version``). The row then says how
many of these machines run Windows, how many run something else, how many the
platform export does not list, and how many Windows machines it lists, so
how much of the Windows estate the reading reaches is measured on each run.
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_platform as _fp
from . import _falcon_traffic as _ft

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_sha1_signed_modules"

POSITION_FLAG = "sha1-signing-position-unresolved"

register_informational_prefixes(POSITION_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "machine": "ComputerName",
    "agent_id": "aid",
    "count": _ft.COUNT_HEADING,
}

TOP_MACHINES = 10


def short_name(name: str) -> str:
    """A machine's name lower-cased, without any domain suffix."""
    return name.strip().lower().split(".")[0]


def platforms(ctx: Context, machines: set[str]) -> tuple[int, int, int, int]:
    """(of ``machines``: Windows, other, not listed; Windows machines the platform export lists).

    All four are 0 except "not listed", which is every machine, when no
    platform export is read.
    """
    conf = _fp.nested(ctx, "platforms")
    rows, _, _ = _fp.load(_fp.file_setting(ctx, conf))
    if not rows:
        return 0, 0, len(machines), 0
    hosts = _fp.heading_list(conf.get("host_column"), ("hostname",))
    os_cols = _fp.heading_list(conf.get("os_column"), ("os_version",))
    windows: set[str] = set()
    other: set[str] = set()
    fleet_windows: set[str] = set()
    for r in rows:
        name = short_name(_fp.first(r, hosts))
        if not name:
            continue
        is_windows = _fp.first(r, os_cols).lower().startswith("windows")
        if is_windows:
            fleet_windows.add(name)
        if name in machines and name not in windows | other:
            (windows if is_windows else other).add(name)
    return len(windows), len(other), len(machines) - len(windows | other), len(fleet_windows)


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of module-signature events carrying SHA-1 was read"
        + (f" ({why})" if why else "")
        + ": which machines load software whose signing data carries SHA-1",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it SHA-1 is graded where it appears in network protocols and nothing "
                "is said about the signatures on the software the machines run, which is "
                "where a forged signature would be used."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_sha1_signed_modules) "
                 "and name its CSV with input:."),
        nature=coverage.NO_DATA)


def _position_gap(machines: int) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_MEASURED,
        f"where SHA-1 sits in the signing data of software loaded on "
        f"{_fp.plural(machines, 'machine')} is not established: a module's own SHA-1 "
        "signature, the older half of a module signed twice, and a root certificate's "
        "signature over itself all match the same text search",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Only the first is software trusted on a SHA-1 signature, and it is the only "
                "one that needs action. Until the chain is read, the reading shows that SHA-1 "
                "is present in software signing, not that any machine runs software trusted "
                "on SHA-1 alone, and it cannot name the software to replace."),
        harvest=("The same events read with each certificate's subject, issuer and algorithm "
                 "parsed out of the signing data, grouped by module."),
        nature=coverage.LOW_FIDELITY)


def read(path: Path, headings: Mapping[str, Sequence[str]], ctx: Context,
         top: int) -> tuple[list[CryptoAsset], list]:
    """The row and gap for one export, or no row and a gap when it cannot be read or is empty."""
    rows, header, unreadable = _fp.load(path)
    if rows and not _fp.has_column(header, (*headings["machine"], *headings["agent_id"])):
        rows, unreadable = [], "the header has no column for the machine or its sensor"
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon module-signature export, "
                   + (f"file dated {when}" if when else "file date unavailable"))

    per_machine: dict[str, int] = {}
    for r in rows:
        name = short_name(_fp.first(r, headings["machine"]) or _fp.first(r, headings["agent_id"]))
        if name:
            per_machine[name] = per_machine.get(name, 0) + _ft.count(
                _fp.first(r, headings["count"]))
    if not per_machine:
        return [], [_missing_gap("no row names a machine")]
    events = sum(per_machine.values())
    counts = sorted(per_machine.values())
    median = int(statistics.median(counts))
    busiest = sorted(per_machine.items(), key=lambda kv: (-kv[1], kv[0]))
    machines = set(per_machine)
    windows, other, unlisted, fleet_windows = platforms(ctx, machines)
    if fleet_windows:
        population = (f"By the platform export, {windows:,} of these machines run Windows, "
                      f"{other:,} run something else and {unlisted:,} are not listed there. It "
                      f"lists {_fp.plural(fleet_windows, 'Windows machine')}, so this reading "
                      f"reaches {windows:,} of them.")
    else:
        population = ("No platform export was read, so which machines these are is not "
                      "checked.")

    row = CryptoAsset(
        name="Software signed with SHA-1, loaded on the machines", data_state="certificate",
        protocol="code-signing", role=roles.sha1_signed_software(len(machines)),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        hashes=["sha1"], verdict="unknown", flags=[POSITION_FLAG],
        hosts_count=len(machines), usage_count=events,
        notes=(f"{events:,} module-signature events on {_fp.plural(len(machines), 'machine')} "
               f"carry SHA-1 (sha1RSA) somewhere in the signing data: {median:,} on the "
               f"median machine and {counts[-1]:,} on the busiest. {population} An event is "
               "one signature reading by the sensor, not one distinct module, and the export "
               "names no module or publisher. The text search cannot tell whether SHA-1 is the "
               "module's own signature, the older half of a module signed twice, or a "
               "certificate higher in the chain such as a root's signature over itself, which "
               "no verifier relies on. So this row records that SHA-1 is present in signing "
               "data, not that any module is trusted on SHA-1 alone. The export carries no "
               "dates; the period is the query's."),
        extra={"machines": str(len(machines)), "events": str(events),
               "median_events_per_machine": str(median),
               "max_events_per_machine": str(counts[-1]),
               "machines_windows": str(windows), "machines_other_platform": str(other),
               "machines_not_in_census": str(unlisted),
               "census_windows_machines": str(fleet_windows),
               "busiest_machines": "; ".join(f"{m}={n}" for m, n in busiest[:top]),
               "match": "substring sha1RSA anywhere in ModuleCertificateInfo2"})
    return [row], [_position_gap(len(machines))]


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's row and gap, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    try:
        top = int((ctx.settings or {}).get("top_machines") or TOP_MACHINES)
    except (TypeError, ValueError):
        top = TOP_MACHINES
    assets, gaps = read(ctx.input, _fp.columns(ctx, HEADINGS), ctx, top)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon software signed with SHA-1",
                gap_prefix=False)
