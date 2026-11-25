"""Re-read named plug-ins into a copy of an earlier observation.

``takestock rerun <target> --from <observation> --plugin <name> ...`` makes a
new observation that holds everything the earlier one holds, except the rows
of the named plug-ins, which are read again from their inputs as they stand
now. Nothing is looked up and nothing is probed: only the named plug-ins read
their supplied files, and the plug-ins that read the rest of the observation
(late steps, coverage checks and annotations) run again over the rows. It
suits a plug-in whose reader has changed, or whose export has been supplied
again, when the rest of the observation is still current and taking a full
one would cost a scan or a network read.

The result is called a *derived* observation, and it says so in its own
record, so it is never mistaken for a full run.

What is carried, and what is read again
---------------------------------------

* **Rows.** Every row of the earlier observation whose ``source`` is not a
  re-run plug-in's or a late step's is copied exactly as it was stored: its
  grade, its notes, its ``collected_at`` and its ``source`` are untouched.
  The re-run plug-ins' old rows are dropped, and their new rows take their
  place in the row order (a plug-in that wrote no rows before has its rows
  placed after those of the nearest plug-in before it in the profile's
  ``plugins:`` list).
* **Late steps and coverage checks** (plug-ins declared ``late``, and the
  ``coverage-check`` kind) run again, as a full observation runs them: after
  the readers, over every row but the late steps' own, in the order a full
  run would hold them. ``Context.run`` gives the earlier observation's
  collectors, each plug-in's status from its record or from this pass, and
  ``offline`` true, since this pass looks nothing up.
  Their earlier rows are dropped and their new rows take their place (one
  that wrote none before puts its rows last). So a late step's rows and a
  check's gaps describe the rows this observation holds, not the ones it was
  derived from. Built-in collectors' late steps (zone files, CAA, WinRM
  listeners) are not run again: their rows are carried, like every other
  built-in collector's.
* **Grading.** The new rows are graded together with the carried ones, as a
  full observation grades every row at once, because some readings compare a
  row with the rest of the population. The carried rows are then written as
  they were stored, not as this pass left them. Where this pass would have
  stored a carried row differently (the tool has changed since, a new row
  changes a reading across rows, or an annotation would now label it
  differently), that is counted in the record, by source and by field, and
  not applied.
* **Annotations** (plug-ins of the ``annotation`` kind) run again over every
  graded row, so each new row carries the labels a full run would give it.
  A carried row keeps the labels it was stored with.
* **Gaps.** An observation records beside each gap the step it is about
  (``gap_origins``; see :class:`takestock.coverage.Gap`): the collector or
  plug-in that filed it, or, for a gap about one row, the step that wrote the
  row. An earlier gap whose origin is a re-run plug-in, a late step, a
  coverage check or an annotation is dropped, whether or not its text names
  the plug-in, and this pass's gaps from those steps are added. A new gap
  with the same text as one kept is not added twice, and is counted as
  repeated. For an earlier gap with no recorded origin (an observation
  written before origins were recorded), two tests stand in: a gap that names
  a re-run plug-in (``plug-in `<name>```) is dropped, and so is one the
  earlier observation's own late steps, coverage checks and annotations file
  again when run over its stored rows, together with the not-measured gaps of
  the rows the re-run plug-ins and late steps wrote (that replay writes
  nothing); and so is one whose first clause, figures masked, is the same as
  that of a gap a step run again files now or filed in the replay, since it
  is that step's earlier wording of the same gap ("3 hosts were not read"
  beside "5 hosts were not read"). An earlier gap that matches none of these
  is kept, and the record counts the gaps kept without an origin.
* **The summary** is worked out again from the rows and gaps written: counts,
  findings, dispensations and the rest. The plug-in records of the steps run
  again are this pass's; every other plug-in's record, and any other key the
  earlier summary holds (a carry record, a certificate-transparency record),
  is copied.
* **Dispositions.** The ``observation`` block keeps the earlier
  ``dispositions_digest``, because the carried rows were judged under that
  set; the record holds the digest of the set the new rows were judged
  under, so a report can tell when the two differ.
* **Raw files.** The earlier ``raw/`` is copied, except the folders under
  ``raw/plugins/`` of the plug-ins run again, which they write afresh.

The record
----------

``summary.json`` gains a ``rerun`` block (:data:`SUMMARY_KEY`): the
observation it was derived from and when that was taken, the plug-ins re-run,
the plug-ins run again over the rows, the rows carried, the rows dropped (by
source) and added (by plug-in), the gaps carried, dropped (and by which test),
added and repeated, the gaps kept without an origin, the digest of the
dispositions the new rows were judged under, the raw files copied, and the
carried-row comparison above. The
``observation`` block records ``offline: true`` and ``scan: false``, so an
active-probe carry (:mod:`takestock.carry`) never treats a derived
observation as a fresh measurement, and a certificate-transparency answer
copied into it is never reused as a recent one (:mod:`takestock.ctcache`).
The CycloneDX metadata carries a ``takestock:derived_from`` property.

Refusals
--------

Each is raised as :class:`RerunRefused`, and leaves nothing behind:

* no plug-in is named, or one is named twice;
* the earlier observation cannot be found, has not finished, carries no run
  record (``summary.json["observation"]``), or was taken of another target;
* a named plug-in is not declared in the profile, cannot be loaded, is a
  built-in collector, a late step, a coverage check or an annotation (each
  reads the rest of the observation, and every rerun runs it again);
* a named plug-in's or a late step's rows carry a source that another
  declared plug-in (named or not) or a built-in collector also writes, so
  its rows cannot be told apart, and neither can the two plug-ins' new rows;
* a stored row was merged from a re-run plug-in's or late step's row and
  another source's, so it cannot be split; or a new row describes the same
  thing as a carried row, or a late step's new row the same thing as another
  row, so a full run would merge them;
* a named plug-in did not run (its input is missing, or its step stopped
  with an error), so its earlier rows would go with nothing in their place;
* the profile's daemon-dictionary overlay is malformed
  (:func:`takestock.config.load_dictionary_overlay`);
* the new observation's directory already exists.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import (
    __version__,
    carry,
    collectors,
    config,
    coverage,
    ctcache,
    dispensation,
    normalise,
    plugin_kinds,
    plugins,
    sge,
)
from .disposition import load_dispositions_for_target, set_digest
from .model import CryptoAsset, dump_assets, load_assets, to_cyclonedx, write_json
from .observe import Options as ObserveOptions
from .observe import Result, _metadata, _organisation, _point_latest, stamp_for
from .policy import Policy

#: The ``summary.json`` key holding the record of a derived observation.
SUMMARY_KEY = "rerun"

#: The CycloneDX metadata property naming the observation this one was derived from.
DERIVED_PROPERTY = "takestock:derived_from"

_ISO = "%Y-%m-%dT%H:%M:%SZ"

#: How many row references the carried-row comparison lists, at most.
SAMPLE = 20

_GAP_LISTS = ("gap_kinds", "gap_required", "gap_impacts", "gap_impact_kinds",
              "gap_harvests", "gap_natures")
#: The ``summary.json`` list naming each gap's origin (:attr:`takestock.coverage.Gap.origin`).
_ORIGINS = "gap_origins"


class RerunRefused(Exception):
    """The derived observation will not be made. ``code`` is a short machine name."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Options:
    """How to make one derived observation."""

    #: The plug-ins to read again, by the names the profile declares them under.
    plugins: tuple[str, ...] = ()
    now: datetime | None = None
    announce: Callable[[str], None] = field(default=lambda _line: None)


# ── reading the earlier observation ──

def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _parses(path: Path) -> bool:
    try:
        _read_json(path)
    except (OSError, ValueError):
        return False
    return True


def _base(ref: str | Path, target: dict, observations: Path) -> tuple[Path, dict, list[dict]]:
    """The earlier observation: its directory, summary and stored rows. Refuses as the module says."""
    try:
        obs = carry.resolve(ref, observations)
    except carry.CarryRefused as exc:
        raise RerunRefused("rerun-not-found", str(exc)) from exc
    markers = ctcache.completion_markers()
    if not any(_parses(obs / name) for name in markers):
        raise RerunRefused("rerun-unfinished", f"{obs.name} has not finished: none of "
                                               f"{', '.join(markers)} is there and readable")
    try:
        summary = _read_json(obs / "summary.json")
        rows = _read_json(obs / "assets.json")
        if not isinstance(summary, dict) or not isinstance(rows, list):
            raise ValueError("summary.json must hold an object and assets.json a list")
    except (OSError, ValueError) as exc:
        raise RerunRefused("rerun-unreadable",
                           f"{obs.name} is not a readable observation: {exc}") from exc
    block = summary.get("observation")
    if not isinstance(block, dict):
        raise RerunRefused("rerun-no-record",
                           f"{obs.name}/summary.json has no `observation` block, so nothing says "
                           "which target it was taken of or how it ran")
    held_org = str(block.get("organisation") or "")
    held_target = Path(str(block.get("target") or "")).stem
    this_target = Path(str(target.get("_path") or "")).stem
    if held_org != _organisation(target) or held_target != this_target:
        raise RerunRefused("rerun-other-target",
                           f"{obs.name} was taken of target {held_target!r} ({held_org!r}); this "
                           f"run is {this_target!r} ({_organisation(target)!r})")
    return obs, summary, rows


# ── which plug-ins, and which rows are theirs ──

def _declared(target: dict) -> dict[str, plugins.Declared]:
    return {d.name: d for d in plugins.resolve(target)[0]}


def _source(p: plugins.Plugin) -> str:
    """The source a plug-in's rows carry; "" for a kind that writes no rows."""
    if p.kind in (plugin_kinds.ANNOTATION, plugin_kinds.COVERAGE_CHECK):
        return ""
    return plugin_kinds.fixed_source(p.kind) or p.name


def _check_plugins(names: tuple[str, ...], declared: dict[str, plugins.Declared]) -> dict[str, str]:
    """{plug-in name: the source its rows carry}, for the plug-ins to re-run. Refuses as the module says."""
    if not names:
        raise RerunRefused("rerun-nothing-named", "name at least one plug-in to read again")
    twice = sorted(n for n, k in Counter(names).items() if k > 1)
    if twice:
        raise RerunRefused("rerun-named-twice", f"named more than once: {', '.join(twice)}")
    builtin = set(collectors.REGISTRY)
    sources: dict[str, str] = {}
    for name in names:
        d = declared.get(name)
        if d is None:
            why = ("is a built-in collector; only plug-ins are read again, because built-in "
                   "collectors read the network or the profile's own inputs" if name in builtin
                   else "is not declared in the target profile's `plugins:` list")
            raise RerunRefused("rerun-not-declared", f"{name!r} {why}")
        if d.plugin is None:
            raise RerunRefused("rerun-not-loaded", f"{name!r} cannot be run: {d.problem}")
        p = d.plugin
        if p.kind in (plugin_kinds.ANNOTATION, plugin_kinds.COVERAGE_CHECK) or p.late:
            what = ("an annotation" if p.kind == plugin_kinds.ANNOTATION else
                    "a coverage check" if p.kind == plugin_kinds.COVERAGE_CHECK else "a late step")
            raise RerunRefused("rerun-reads-the-observation",
                               f"{name!r} is {what}: it reads the rest of the observation, so "
                               "every rerun runs it again over the rows it writes; name only "
                               "the plug-ins whose inputs are to be read again")
        sources[name] = _source(p)
    _unshared(sources, declared)
    return sources


def _later(declared: dict[str, plugins.Declared]) -> tuple[dict[str, str], list[str], list[str]]:
    """The plug-ins that read the rest of the observation, each in the profile's order.

    Returns the late steps that write rows (``{name: the source they carry}``),
    the coverage checks and the annotations.
    """
    late: dict[str, str] = {}
    checks: list[str] = []
    notes: list[str] = []
    for n, d in declared.items():
        p = d.plugin
        if p is None:
            continue
        if p.kind == plugin_kinds.ANNOTATION:
            notes.append(n)
        elif p.kind == plugin_kinds.COVERAGE_CHECK:
            checks.append(n)
        elif p.late:
            late[n] = _source(p)
    return late, checks, notes


def _unshared(sources: dict[str, str], declared: dict[str, plugins.Declared]) -> None:
    """Refuse when a plug-in in ``sources`` writes rows another plug-in or a built-in also writes."""
    builtin = set(collectors.REGISTRY)
    others = {_source(d.plugin): n for n, d in declared.items()
              if d.plugin is not None and n not in sources and _source(d.plugin)}
    others.update({collectors.REGISTRY[n].module: n for n in builtin})
    # Two named plug-ins sharing a source are refused too: their rows could not
    # be credited to either, so the record could not say which wrote what.
    for name, src in sources.items():
        named = [n for n, s in sources.items() if s == src and n != name]
        if named:
            others.setdefault(src, named[0])
    for name, src in sources.items():
        if src in others and others[src] != name:
            raise RerunRefused("rerun-shared-source",
                               f"{name!r} writes rows with source {src!r}, which {others[src]!r} "
                               "also writes, so its rows cannot be told apart")


def _merged_sources(row: dict) -> list[str]:
    extra = row.get("extra") or {}
    return [str(s) for s in extra.get(normalise.MERGED_SOURCES_KEY) or []]


def _split(rows: list[dict], sources: set[str]) -> list[bool]:
    """For each stored row, True when it is a re-run plug-in's. Refuses a row merged across the line."""
    out = []
    for n, row in enumerate(rows):
        theirs = str(row.get("source") or "") in sources
        merged = set(_merged_sources(row))
        if merged and (merged & sources) and (merged - sources):
            raise RerunRefused("rerun-merged-row",
                               f"stored row {n + 1} ({row.get('name')!r}) was merged from "
                               f"{', '.join(sorted(merged))}, which mixes a re-run plug-in's "
                               "rows with another source's, so it cannot be split")
        out.append(theirs)
    return out


# ── gaps ──

def _stored_gaps(summary: dict) -> list[coverage.Gap]:
    """The earlier observation's gaps, rebuilt with their classifications.

    A gap's origin is the one recorded beside it (``gap_origins``), or None
    when the observation recorded none, or a list of another length.
    """
    texts = [str(g) for g in summary.get("gaps") or []]
    lists = {k: list(summary.get(k) or []) for k in _GAP_LISTS}
    held = summary.get(_ORIGINS)
    origins = held if isinstance(held, list) and len(held) == len(texts) else [None] * len(texts)

    def at(key: str, n: int, default: Any) -> Any:
        values = lists[key]
        return values[n] if n < len(values) else default

    return [coverage.Gap(at("gap_kinds", n, coverage.COULD_NOT_TEST), text,
                         at("gap_required", n, True) is not False,
                         impact=str(at("gap_impacts", n, "")),
                         impact_kind=str(at("gap_impact_kinds", n, coverage.IMPACT_UNWRITTEN)),
                         harvest=str(at("gap_harvests", n, "")),
                         nature=str(at("gap_natures", n, coverage.NATURE_UNSTATED)),
                         origin=origins[n] if isinstance(origins[n], str) else None)
            for n, text in enumerate(texts)]


def _names_plugin(gap: str, names: tuple[str, ...]) -> bool:
    return any(f"plug-in `{n}`" in gap for n in names)


# ── placing the new rows ──

def _placed(stored: list[dict], theirs: list[bool], new: dict[str, list[Any]],
            order: list[str], source_of: dict[str, str], *, tail: frozenset[str] = frozenset(),
            items: list[Any] | None = None) -> list[Any]:
    """The stored rows kept, with each re-run plug-in's new rows where a full run would put them.

    ``order`` is the profile's row-writing plug-ins (ordinary, then late), in
    the order an observation runs them, and ``source_of`` the source each
    writes. A re-run plug-in that had rows takes the place of its first old
    row. One that had none goes at the end when it is in ``tail`` (a late
    step, whose rows a full run adds after everything else); otherwise after
    the rows of the nearest plug-in before it in ``order`` that has rows, else
    before the rows of the nearest one after it that has, else at the end.
    ``items``, parallel to ``stored``, is what is placed for each kept row
    (default: the stored row itself).
    """
    payload = stored if items is None else items
    by_source: dict[str, list[int]] = {}
    for n, row in enumerate(stored):
        by_source.setdefault(str(row.get("source") or ""), []).append(n)

    def rows_of(name: str) -> list[int]:
        return by_source.get(source_of.get(name, ""), [])

    keyed: list[tuple[tuple[int, int, int], list[Any]]] = [
        ((n, 1, 0), [payload[n]]) for n in range(len(stored)) if not theirs[n]]
    for rank, name in enumerate(order):
        if name not in new:
            continue
        key = (len(stored), 0, rank)
        if rows_of(name):
            key = (rows_of(name)[0], 0, rank)
        elif name in tail:
            pass
        else:
            before = [n for n in reversed(order[:rank]) if rows_of(n)]
            after = [n for n in order[rank + 1:] if rows_of(n)]
            if before:
                at = rows_of(before[0])
                key = (at[0], 0, rank) if before[0] in new else (at[-1], 2, rank)
            elif after:
                key = (rows_of(after[0])[0], 0, rank)
        keyed.append((key, new[name]))
    out: list[Any] = []
    for _key, rows in sorted(keyed, key=lambda item: item[0]):
        out += rows
    return out


# ── comparing what grading would have changed ──

def _as_stored(asset: CryptoAsset) -> dict:
    """One row as ``assets.json`` stores it."""
    return json.loads(json.dumps(dump_assets([asset])[0], default=str))


def _compare(carried: list[tuple[CryptoAsset, dict]], survivors: set[int]) -> dict:
    """What the grading pass would have stored differently for the carried rows."""
    by_source: Counter[str] = Counter()
    by_field: Counter[str] = Counter()
    refs: list[str] = []
    folded = 0
    for asset, stored in carried:
        if id(asset) not in survivors:
            folded += 1
            continue
        now = _as_stored(asset)
        changed = sorted(k for k in set(now) | set(stored) if now.get(k) != stored.get(k))
        if not changed:
            continue
        by_source[str(stored.get("source") or "")] += 1
        by_field.update(changed)
        if len(refs) < SAMPLE:
            refs.append(asset.bom_ref())
    return {"rows": sum(by_source.values()), "by_source": dict(sorted(by_source.items())),
            "by_field": dict(sorted(by_field.items())), "sample": refs, "merged_away": folded}


# ── the derived observation ──

def _copy_raw(base: Path, raw: Path, names: tuple[str, ...]) -> int:
    src = base / "raw"
    if not src.is_dir():
        raw.mkdir(parents=True)
        return 0
    skip = {(src / "plugins" / n).resolve() for n in names}

    def ignore(folder: str, entries: list[str]) -> set[str]:
        return {e for e in entries if (Path(folder) / e).resolve() in skip}

    shutil.copytree(src, raw, ignore=ignore, symlinks=False)
    return sum(1 for p in raw.rglob("*") if p.is_file())


def _run_info(block: dict, offline: bool) -> plugins.RunInfo:
    return plugins.RunInfo(collectors=tuple(collectors.names()),
                           ran=tuple(block.get("collectors_run") or ()),
                           skipped=dict(block.get("collectors_skipped") or {}),
                           failed=tuple(block.get("failed_collectors") or ()),
                           carried=tuple(block.get("collectors_carried") or ()),
                           scan=bool(block.get("scan")), offline=offline)


def _ordinary(declared: dict[str, plugins.Declared]) -> dict[str, str]:
    """{name: source} for each declared plug-in that writes rows in the ordinary phase, in order."""
    return {n: _source(d.plugin) for n, d in declared.items()
            if d.plugin is not None and not d.plugin.late
            and d.plugin.kind not in (plugin_kinds.ANNOTATION, plugin_kinds.COVERAGE_CHECK)}


def _refuse_after_writing(obs: Path, code: str, message: str) -> RerunRefused:
    shutil.rmtree(obs, ignore_errors=True)
    return RerunRefused(code, message)


def _replayed(target: dict, stored: list[dict], theirs: list[bool], later: list[str],
              block: dict, records: dict, ref_time: datetime) -> set[str]:
    """The gaps the earlier observation's later steps filed, worked out again from its rows.

    Used when the earlier observation recorded no gap origins. The late
    steps, coverage checks and annotations in ``later`` are run over the
    stored rows (the late steps' own rows left out, as a full run's late
    steps never see them), and the not-measured gaps of the rows the re-run
    plug-ins wrote (``theirs``) are taken again. Each is a gap the earlier
    pass filed from the earlier inputs, so an earlier gap with the same text
    is theirs. Nothing is kept: their raw files go to a folder that is then
    removed.
    """
    try:
        rows = load_assets([dict(r) for r in stored])
    except TypeError:
        return set()
    steps = set(later)
    inputs = [a for a in rows if normalise.row_origin(a) not in steps]
    entries = [e for e in target.get(plugins.PROFILE_KEY) or []
               if (e if isinstance(e, str) else str(e.get("name") or "")) in steps]
    scratch = Path(tempfile.mkdtemp(prefix="takestock-rerun-"))
    try:
        host = plugins.Host(dict(target, **{plugins.PROFILE_KEY: entries}), scratch, ref_time,
                            earlier={n: r for n, r in records.items() if n not in steps})
        info = _run_info(block, offline=True)
        _rows, gaps = host.run(late=True, assets=inputs, run=info)
        gaps += host.annotate(rows, run=info)
        gaps += host.summarise(rows)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    gaps += normalise.not_measured_gaps(a for a, mine in zip(rows, theirs, strict=True) if mine)
    return {str(g) for g in gaps}


#: A figure in a gap's text: digits, with any thousands or decimal separators.
_FIGURE = re.compile(r"\d[\d,.]*")

#: A gap's shape shorter than this says too little to tell one step's gap from another's.
_SHAPE_MIN = 24


def _shape(text: str) -> str:
    """A gap's first clause with every figure masked: what stays when only its counts change.

    The clause ends at the first ``": "`` or ``". "``, so a list after a
    colon (names, samples) does not count. "" when the clause is too short
    to be told apart from another step's.
    """
    masked = _FIGURE.sub("#", " ".join(text.split()))
    ends = [i for i in (masked.find(": "), masked.find(". ")) if i > 0]
    clause = masked[:min(ends)] if ends else masked
    return clause if len(clause) >= _SHAPE_MIN else ""


def _earlier_is_replaced(g: coverage.Gap, replaced: set[str], replayed: set[str],
                         shapes: set[str]) -> str:
    """Why an earlier gap gives way to this pass's, or "" when it is kept.

    With a recorded origin, by that alone. Without one: it names a step run
    again; or it is a gap the earlier pass's later steps file again over the
    stored rows (``replayed``); or it is the same first clause, figures aside,
    as a gap a step run again files now or filed then (``shapes``), so it is
    that step's earlier wording.
    """
    origin = coverage.origin_of(g)
    if origin is not None:
        return "origin" if origin in replaced else ""
    if _names_plugin(g, tuple(replaced)):
        return "named"
    if str(g) in replayed:
        return "replayed"
    shape = _shape(str(g))
    if shape and shape in shapes:
        return "reworded"
    return ""


def rerun(target: dict, base_ref: str | Path, options: Options | None = None) -> Result:
    """Derive a new observation of ``target`` from ``base_ref``, reading ``options.plugins`` again.

    Writes it into the workspace's ``observations/`` under the current
    stamp and points ``latest`` at it, as :func:`takestock.observe.observe`
    does. Raises :class:`RerunRefused` as the module says; a refusal leaves
    nothing behind.
    """
    options = options or Options()
    options.now = options.now or datetime.now(UTC)
    say = options.announce
    try:
        config.load_dictionary(target)
    except ValueError as exc:
        raise RerunRefused("rerun-dictionary", str(exc)) from exc
    observations = config.observations_dir()
    base, summary, stored = _base(base_ref, target, observations)
    declared = _declared(target)
    names = tuple(options.plugins)
    sources = _check_plugins(names, declared)
    late_sources, checks, notes = _later(declared)
    late = list(late_sources)
    _unshared(late_sources, declared)
    writers = {**sources, **late_sources}
    theirs = _split(stored, set(writers.values()))
    carried_rows = [row for row, mine in zip(stored, theirs, strict=True) if not mine]
    try:
        carried_assets = load_assets([dict(r) for r in carried_rows])
    except TypeError as exc:
        raise RerunRefused("rerun-unreadable",
                           f"{base.name}/assets.json holds a row this version cannot read: "
                           f"{exc}") from exc
    stamp = stamp_for(options.now)
    obs = observations / stamp
    if obs.exists() or obs.is_symlink():
        raise RerunRefused("rerun-exists", f"{obs} already exists. Observations are named to the "
                                           "minute; wait for the next minute")

    rerun_all = (*names, *late, *checks, *notes)
    raw = obs / "raw"
    obs.mkdir(parents=True)
    copied = _copy_raw(base, raw, rerun_all)
    say(f"deriving {config.display_path(obs)} from {base.name}, reading again: {', '.join(names)}")
    if late or checks:
        say(f"  and running again over the rows: {', '.join((*late, *checks))}")

    # Only the named plug-ins and the plug-ins reading the rest are declared to this host.
    keep = set(rerun_all)
    entries = [e for e in target.get(plugins.PROFILE_KEY) or []
               if (e if isinstance(e, str) else str(e.get("name") or "")) in keep]
    earlier_records = dict(summary.get(plugins.SUMMARY_KEY) or {})
    host = plugins.Host(dict(target, **{plugins.PROFILE_KEY: entries}), raw, options.now,
                        announce=say,
                        earlier={n: r for n, r in earlier_records.items() if n not in keep})
    new_rows, step_gaps = host.run(late=False, assets=[])
    fresh_records = host.summary()
    not_run = {n: fresh_records.get(n, {}).get("reason", "") for n in names
               if fresh_records.get(n, {}).get("status") != "ran"}
    if not_run:
        raise _refuse_after_writing(
            obs, "rerun-not-run", "; ".join(f"{n!r} did not run: {why or 'no reason given'}"
                                            for n, why in not_run.items())
            + ". Its earlier rows would be dropped and nothing put in their place")
    carried_refs = {a.bom_ref() for a in carried_assets}
    clash = {a.bom_ref() for a in new_rows} & carried_refs
    if clash:
        raise _refuse_after_writing(
            obs, "rerun-merged-row",
            f"{len(clash)} new row(s) describe the same thing as a carried row "
            f"(first: {sorted(clash)[0]}), so a full run would merge them")

    block = dict(summary["observation"])
    info = _run_info(block, offline=True)
    ordinary = _ordinary(declared)
    order = [*ordinary, *late]
    source_of = {**ordinary, **late_sources}
    plugin_of = {src: n for n, src in writers.items()}

    # The late steps and coverage checks read the rows a full run would hand
    # them: every row but their own, in the order it would hold them.
    items: list[Any] = [None] * len(stored)
    for i, a in zip([i for i, mine in enumerate(theirs) if not mine], carried_assets,
                    strict=True):
        items[i] = a
    new_assets: dict[str, list[Any]] = {n: [] for n in names}
    for a in new_rows:
        new_assets[plugin_of[a.source]].append(a)
    inputs = _placed(stored, theirs, new_assets, order, source_of, items=items)
    late_rows, late_gaps = host.run(late=True, assets=inputs, run=info)
    clash = {a.bom_ref() for a in late_rows} & (carried_refs | {a.bom_ref() for a in new_rows})
    if clash:
        raise _refuse_after_writing(
            obs, "rerun-merged-row",
            f"{len(clash)} late step row(s) describe the same thing as another row "
            f"(first: {sorted(clash)[0]}), so a full run would merge them")
    step_gaps += late_gaps
    fresh_ids = {id(a) for a in (*new_rows, *late_rows)}

    baseline = config.load_baseline()
    policy = Policy(baseline)
    rules = load_dispositions_for_target(target)
    # The passes an observation's grading makes, in the same order, over every row.
    graded, passes = normalise.finalise([*carried_assets, *new_rows, *late_rows], policy,
                                        config.load_dictionary(target), dispositions=rules,
                                        lifecycle=target.get("lifecycle") or {})
    step_gaps += host.annotate(graded, run=info)
    step_gaps += host.summarise(graded)
    fresh = [a for a in graded if id(a) in fresh_ids]
    step_gaps += normalise.not_measured_gaps(fresh)
    email_domains = [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]
    sge.apply_conformance(graded, email_domains, bulk_mail_domains=sge.bulk_mail_domains(target),
                          parked=sge.parked_domains(target))
    regraded = _compare(list(zip(carried_assets, carried_rows, strict=True)),
                        {id(a) for a in graded})

    new_by_plugin: dict[str, list[dict]] = {n: [] for n in (*names, *late)}
    for a in fresh:
        new_by_plugin[plugin_of[a.source]].append(_as_stored(a))
    rows_out = _placed(stored, theirs, new_by_plugin, order, source_of, tail=frozenset(late))
    assets = load_assets([dict(r) for r in rows_out])

    # An earlier gap gives way when it is about a step this pass ran again:
    # by its recorded origin, or, where none was recorded, by the tests in
    # `_earlier_is_replaced`.
    earlier = _stored_gaps(summary)
    replaced = set(rerun_all)
    replayed: set[str] = set()
    if any(coverage.origin_of(g) is None for g in earlier):
        replayed = _replayed(target, stored, theirs, [*late, *checks, *notes], block,
                             earlier_records, options.now)
    shapes = {_shape(t) for t in (*replayed, *(str(g) for g in step_gaps))} - {""}
    why = [_earlier_is_replaced(g, replaced, replayed, shapes) for g in earlier]
    kept = [g for g, reason in zip(earlier, why, strict=True) if not reason]
    seen = {str(g) for g in kept}
    added = []
    repeated = 0
    for g in step_gaps:
        if str(g) in seen:
            repeated += 1
            continue
        seen.add(str(g))
        added.append(g)
    gaps = [*kept, *added]
    failures = [str(f) for f in summary.get("collector_failures") or []]
    found = normalise.findings(assets, rules.out_of_cycle)
    dispensations = dispensation.payload(assets, baseline, dispensation.records_for_target(target),
                                         asof=options.now.date(), rules=rules)
    complete = not failures and not coverage.required_gaps(gaps)

    record: dict[str, Any] = {
        "from_observation": base.name,
        "from_collected_at": str(block.get("collected_at") or ""),
        "plugins": list(names),
        "run_over_rows": [*late, *checks, *notes],
        "rows_carried": len(carried_rows),
        "rows_dropped": dict(sorted(Counter(str(r.get("source") or "")
                                            for r, mine in zip(stored, theirs, strict=True)
                                            if mine).items())),
        "rows_added": {n: len(rows) for n, rows in new_by_plugin.items()},
        "gaps_carried": len(kept),
        "gaps_dropped": len(earlier) - len(kept),
        "gaps_dropped_by": dict(sorted(Counter(r for r in why if r).items())),
        "gaps_added": [str(g) for g in added],
        "gaps_repeated": repeated,
        "gaps_without_origin": sum(1 for g in kept if coverage.origin_of(g) is None),
        "dispositions_digest": set_digest(rules),
        "raw_files_copied": copied,
        "carried_rows_graded_differently": regraded,
    }
    if isinstance(summary.get(SUMMARY_KEY), dict):
        record["from_rerun"] = summary[SUMMARY_KEY]

    records = dict(earlier_records)
    fresh_summaries = host.summary()
    for n in rerun_all:
        records[n] = fresh_summaries[n]

    out = dict(summary)
    out.update(normalise.summarise(assets, gaps, rules))
    rel, _absolute = config.recorded_target_paths(str(target.get("_path") or ""))
    block.update({"stamp": stamp, "collected_at": options.now.strftime(_ISO),
                  "tool_version": __version__, "organisation": _organisation(target),
                  "target": rel, "scan": False, "offline": True})
    out.update({
        "observation": block,
        "complete": complete,
        "collector_failures": failures,
        "findings": found,
        "standards_marked": sum(1 for a in assets if a.standards_verdict == sge.NON_CONFORMANT),
        "dispensations": dispensations,
        "normalise": passes,
        plugins.SUMMARY_KEY: records,
        SUMMARY_KEY: record,
    })

    write_json(rows_out, obs / "assets.json")
    write_json(out, obs / "summary.json")
    meta = _metadata(target, stamp, ObserveOptions(scan=False, offline=True, now=options.now),
                     complete)
    meta["properties"].append({"name": DERIVED_PROPERTY, "value": base.name})
    write_json(to_cyclonedx(assets, meta), obs / "bom.cdx.json")
    _point_latest(observations, stamp)
    say(f"  carried {len(carried_rows)} row(s); read again: "
        + ", ".join(f"{n} {len(r)}" for n, r in new_by_plugin.items()))
    return Result(observation=obs, assets=assets, summary=out, failures=failures, findings=found)
