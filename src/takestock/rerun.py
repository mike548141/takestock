"""Re-read named plug-ins into a copy of an earlier observation.

``takestock rerun <target> --from <observation> --plugin <name> ...`` makes a
new observation that holds everything the earlier one holds, except the rows
of the named plug-ins, which are read again from their inputs as they stand
now. Nothing is looked up and nothing is probed: only the named plug-ins read
their supplied files, and the profile's annotations label the new rows. It
suits a plug-in whose reader has changed, or whose export has been supplied
again, when the rest of the observation is still current and taking a full
one would cost a scan or a network read.

The result is called a *derived* observation, and it says so in its own
record, so it is never mistaken for a full run.

What is carried, and what is read again
---------------------------------------

* **Rows.** Every row of the earlier observation whose ``source`` is not a
  re-run plug-in's is copied exactly as it was stored: its grade, its notes,
  its ``collected_at`` and its ``source`` are untouched. The re-run plug-ins'
  old rows are dropped, and their new rows take their place in the row order
  (a plug-in that wrote no rows before has its rows placed after those of the
  nearest plug-in before it in the profile's ``plugins:`` list).
* **Grading.** The new rows are graded together with the carried ones, as a
  full observation grades every row at once, because some readings compare a
  row with the rest of the population. The carried rows are then written as
  they were stored, not as this pass left them. Where this pass would have
  stored a carried row differently (the tool has changed since, or a new row
  changes a reading across rows), that is counted in the record, by source
  and by field, and not applied.
* **Annotations** (plug-ins of the ``annotation`` kind) are applied to the
  new rows, so each carries the labels a full run would give it. Their
  records and summaries, like every other plug-in's, are the earlier ones.
* **Gaps.** The earlier gaps are kept, except those that name a re-run
  plug-in (``plug-in `<name>```), which are dropped; the re-run plug-ins' new
  gaps are added. A plug-in declared with ``gap_prefix=False`` writes gaps
  that do not name it, so its earlier gaps cannot be told apart and are kept;
  a new gap with the same text is not added twice, and is counted as
  repeated. An earlier gap such a plug-in would now word differently stays
  beside the new wording.
* **The summary** is worked out again from the rows and gaps written: counts,
  findings, dispensations and the rest. Any other key the earlier summary
  holds (a carry record, a certificate-transparency record) is copied.
* **Dispositions.** The ``observation`` block keeps the earlier
  ``dispositions_digest``, because the carried rows were judged under that
  set; the record holds the digest of the set the new rows were judged
  under, so a report can tell when the two differ.
* **Raw files.** The earlier ``raw/`` is copied, except the re-run plug-ins'
  own folders under ``raw/plugins/``, which they write afresh.

The record
----------

``summary.json`` gains a ``rerun`` block (:data:`SUMMARY_KEY`): the
observation it was derived from and when that was taken, the plug-ins re-run,
the rows carried, the rows dropped (by source) and added (by plug-in), the
gaps dropped, added and repeated, the digest of the dispositions the new rows
were judged under, the raw files copied, and the carried-row comparison
above. The
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
  reads the rest of the observation, so re-running it alone is not a
  re-read of its input);
* a named plug-in's rows carry a source that another declared plug-in
  (named or not) or a built-in collector also writes, so its rows cannot be
  told apart, and neither can the two plug-ins' new rows;
* a stored row was merged from a re-run plug-in's row and another source's,
  so it cannot be split; or a new row describes the same thing as a carried
  row, so a full run would merge them;
* a named plug-in did not run (its input is missing, or its step stopped
  with an error), so its earlier rows would go with nothing in their place;
* the new observation's directory already exists.
"""

from __future__ import annotations

import json
import shutil
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
                               "running it alone is not a re-read of its input. Take a full "
                               "observation instead")
        sources[name] = _source(p)
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
    return sources


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
    """The earlier observation's gaps, rebuilt with their classifications."""
    texts = [str(g) for g in summary.get("gaps") or []]
    lists = {k: list(summary.get(k) or []) for k in _GAP_LISTS}

    def at(key: str, n: int, default: Any) -> Any:
        values = lists[key]
        return values[n] if n < len(values) else default

    return [coverage.Gap(at("gap_kinds", n, coverage.COULD_NOT_TEST), text,
                         at("gap_required", n, True) is not False,
                         impact=str(at("gap_impacts", n, "")),
                         impact_kind=str(at("gap_impact_kinds", n, coverage.IMPACT_UNWRITTEN)),
                         harvest=str(at("gap_harvests", n, "")),
                         nature=str(at("gap_natures", n, coverage.NATURE_UNSTATED)))
            for n, text in enumerate(texts)]


def _names_plugin(gap: str, names: tuple[str, ...]) -> bool:
    return any(f"plug-in `{n}`" in gap for n in names)


# ── placing the new rows ──

def _placed(stored: list[dict], theirs: list[bool], new: dict[str, list[dict]],
            order: list[str], source_of: dict[str, str]) -> list[dict]:
    """The stored rows kept, with each re-run plug-in's new rows where a full run would put them.

    ``order`` is the profile's ordinary plug-ins (neither late nor reading
    the rows), in the order an observation runs them, and ``source_of`` the
    source each writes. A re-run plug-in that had rows takes the place of its
    first old row. One that had none goes after the rows of the nearest
    plug-in before it in ``order`` that has rows, else before the rows of the
    nearest one after it that has, else at the end.
    """
    by_source: dict[str, list[int]] = {}
    for n, row in enumerate(stored):
        by_source.setdefault(str(row.get("source") or ""), []).append(n)

    def rows_of(name: str) -> list[int]:
        return by_source.get(source_of.get(name, ""), [])

    keyed: list[tuple[tuple[int, int, int], list[dict]]] = [
        ((n, 1, 0), [row]) for n, row in enumerate(stored) if not theirs[n]]
    for rank, name in enumerate(order):
        if name not in new:
            continue
        key = (len(stored), 0, rank)
        if rows_of(name):
            key = (rows_of(name)[0], 0, rank)
        else:
            before = [n for n in reversed(order[:rank]) if rows_of(n)]
            after = [n for n in order[rank + 1:] if rows_of(n)]
            if before:
                at = rows_of(before[0])
                key = (at[0], 0, rank) if before[0] in new else (at[-1], 2, rank)
            elif after:
                key = (rows_of(after[0])[0], 0, rank)
        keyed.append((key, new[name]))
    out: list[dict] = []
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
    observations = config.observations_dir()
    base, summary, stored = _base(base_ref, target, observations)
    declared = _declared(target)
    names = tuple(options.plugins)
    sources = _check_plugins(names, declared)
    theirs = _split(stored, set(sources.values()))
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

    raw = obs / "raw"
    obs.mkdir(parents=True)
    copied = _copy_raw(base, raw, names)
    say(f"deriving {config.display_path(obs)} from {base.name}, reading again: {', '.join(names)}")

    # Only the named plug-ins and the annotations are declared to this host.
    keep = set(names) | {n for n, d in declared.items()
                         if d.plugin is not None and d.plugin.kind == plugin_kinds.ANNOTATION}
    entries = [e for e in target.get(plugins.PROFILE_KEY) or []
               if (e if isinstance(e, str) else str(e.get("name") or "")) in keep]
    host = plugins.Host(dict(target, **{plugins.PROFILE_KEY: entries}), raw, options.now,
                        announce=say)
    new_rows, step_gaps = host.run(late=False, assets=[])
    fresh_records = host.summary()
    not_run = {n: fresh_records.get(n, {}).get("reason", "") for n in names
               if fresh_records.get(n, {}).get("status") != "ran"}
    if not_run:
        raise _refuse_after_writing(
            obs, "rerun-not-run", "; ".join(f"{n!r} did not run: {why or 'no reason given'}"
                                            for n, why in not_run.items())
            + ". Its earlier rows would be dropped and nothing put in their place")
    clash = {a.bom_ref() for a in new_rows} & {a.bom_ref() for a in carried_assets}
    if clash:
        raise _refuse_after_writing(
            obs, "rerun-merged-row",
            f"{len(clash)} new row(s) describe the same thing as a carried row "
            f"(first: {sorted(clash)[0]}), so a full run would merge them")
    new_ids = {id(a) for a in new_rows}

    block = dict(summary["observation"])
    baseline = config.load_baseline()
    policy = Policy(baseline)
    rules = load_dispositions_for_target(target)
    # The passes an observation's grading makes, in the same order, over every row.
    graded, passes = normalise.finalise([*carried_assets, *new_rows], policy,
                                        config.load_dictionary(), dispositions=rules,
                                        lifecycle=target.get("lifecycle") or {})
    later = host.annotate(graded, run=_run_info(block, offline=True))
    later += host.summarise(graded)
    fresh = [a for a in graded if id(a) in new_ids]
    step_gaps += [g for g in later if _names_plugin(g, names)]
    step_gaps += normalise.not_measured_gaps(fresh)
    email_domains = [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]
    sge.apply_conformance(graded, email_domains, bulk_mail_domains=sge.bulk_mail_domains(target),
                          parked=sge.parked_domains(target))
    regraded = _compare(list(zip(carried_assets, carried_rows, strict=True)),
                        {id(a) for a in graded})

    plugin_of = {src: n for n, src in sources.items()}
    new_by_plugin: dict[str, list[dict]] = {n: [] for n in names}
    for a in fresh:
        new_by_plugin[plugin_of[a.source]].append(_as_stored(a))
    ordinary = _ordinary(declared)
    rows_out = _placed(stored, theirs, new_by_plugin, list(ordinary), ordinary)
    assets = load_assets([dict(r) for r in rows_out])

    earlier = _stored_gaps(summary)
    kept = [g for g in earlier if not _names_plugin(g, names)]
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
        "rows_carried": len(carried_rows),
        "rows_dropped": dict(sorted(Counter(str(r.get("source") or "")
                                            for r, mine in zip(stored, theirs, strict=True)
                                            if mine).items())),
        "rows_added": {n: len(rows) for n, rows in new_by_plugin.items()},
        "gaps_carried": len(kept),
        "gaps_dropped": len(earlier) - len(kept),
        "gaps_added": [str(g) for g in added],
        "gaps_repeated": repeated,
        "annotation_gaps_not_carried": [str(g) for g in later
                                        if not _names_plugin(g, names) and str(g) not in seen],
        "dispositions_digest": set_digest(rules),
        "raw_files_copied": copied,
        "carried_rows_graded_differently": regraded,
    }
    if isinstance(summary.get(SUMMARY_KEY), dict):
        record["from_rerun"] = summary[SUMMARY_KEY]

    records = dict(summary.get(plugins.SUMMARY_KEY) or {})
    fresh_summaries = host.summary()
    for n in names:
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
