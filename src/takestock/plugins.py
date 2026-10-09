"""Plug-in collectors: readers for exports takestock has no built-in reader for.

A **plug-in** lives in its own package, outside takestock. It declares itself
with a :class:`Plugin`: a name, a **kind** (one of the record schemas in
:mod:`takestock.plugin_kinds`, the ``general`` kind for finished rows that fit
no schema, or one of the two kinds that write no rows), the input it reads,
and a **step** function. takestock calls the step during
an observation with a :class:`Context` carrying what a built-in ingest
collector gets, checks what comes back, and turns valid records into graded
rows.

**Finding a plug-in.** Two ways, which may be mixed:

* an installed package names it under the entry-point group
  ``takestock.collectors``;
* the target profile names a module (``module: package.module``, optionally
  ``package.module:attribute``) or a Python file in the workspace
  (``path: plugins/reader.py``).

Either way the target profile's ``plugins:`` list decides what runs: an
installed plug-in the profile does not name never runs, and a named plug-in
that cannot be found, has no input, or fails is recorded as a coverage gap.
An absent plug-in never reads as a clean result.

**What a step may return** is a :class:`StepResult` (or a plain list of
records). Records are mappings checked against the kind's fields; a plug-in
may also return finished :class:`~takestock.model.CryptoAsset` rows, checked
against the kind's row constraints. A ``general`` plug-in returns finished
rows only. Invalid records are left out and counted in a gap. A step that
raises becomes a gap carrying the error; it never stops the observation.

**When steps run.** Ordinary steps run after the built-in collectors' early
steps; ``late`` steps run after every built-in step and see the rows already
collected (``Context.assets``, as copies) and how the run went so far
(``Context.run``, a :class:`RunInfo`). A ``coverage-check`` plug-in is
always late and returns gaps only. An ``annotation`` plug-in runs after
grading and returns ``extra`` keys to add to other rows, keyed by each row's
``bom_ref()``; it can add a key but never change one. The keys it declares in
``annotation_keys`` are cleared from every row before it runs, so a row
carried from an earlier observation never keeps an earlier run's label.
"""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from importlib import import_module, metadata
from pathlib import Path
from typing import Any

from . import config, coverage, identity, plaintext, plugin_kinds
from .model import CryptoAsset
from .policy import Policy
from .util import file_mtime_date, now_date

#: The entry-point group an installed package names its plug-ins under.
ENTRY_POINT_GROUP = "takestock.collectors"
#: The target-profile key listing the plug-ins an organisation runs.
PROFILE_KEY = "plugins"
#: The ``summary.json`` key holding each declared plug-in's record.
SUMMARY_KEY = "plugins"
#: The ``summary.json`` key listing installed plug-ins the profile does not declare.
UNDECLARED_KEY = "plugins_installed_not_declared"
#: The attribute a profile ``module:`` without ``:attribute`` is read from.
DEFAULT_ATTRIBUTE = "PLUGIN"

_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
#: The ``extra`` key naming the plug-in that wrote a row.
_OWN_KEY = "plugin"
_DATA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
#: How many invalid-record problems a gap and the summary quote.
PROBLEM_SAMPLE = 5

Step = Callable[["Context"], Any]
Summarise = Callable[["Context", list[CryptoAsset]], Mapping]


@dataclass(frozen=True)
class Plugin:
    """One plug-in's declaration.

    ``name`` is lower case (letters, digits, ``-`` and ``_``) and is the
    ``source`` of the rows it writes, unless its kind fixes one. ``input`` is
    the path the step reads, as a target profile would write it
    (``inbox/<file>``); the profile may override it, and when it names
    nothing that exists the step is not called. ``title`` describes the input
    to a reader and becomes each row's ``source_name``. ``data_files`` names
    the plug-in's own reference files, found in ``data_dir`` (default: the
    directory of the module defining ``step``). ``summarise``, when given, is
    called after grading with the plug-in's own graded rows and returns its
    contribution to ``summary.json``. ``gap_prefix`` (default true) starts
    each gap the step returns with ``plug-in `<name>`:``; false files the
    step's gaps exactly as written, for a plug-in whose gap sentences are
    written for the report's reader. Gaps takestock writes about the plug-in
    always name it. ``annotation_keys``, for an annotation only, names the
    ``extra`` keys it writes; takestock removes them from every row before
    the annotation runs.
    """

    name: str
    kind: str
    step: Step
    input: str = ""
    late: bool = False
    title: str = ""
    data_files: tuple[str, ...] = ()
    data_dir: str = ""
    summarise: Summarise | None = None
    gap_prefix: bool = True
    annotation_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.match(self.name):
            raise ValueError(f"plug-in name {self.name!r}: lower-case letters, digits, '-' and "
                             "'_', starting with a letter")
        if self.kind not in plugin_kinds.kinds():
            raise ValueError(f"plug-in {self.name!r}: kind {self.kind!r} is not one of "
                             f"{list(plugin_kinds.kinds())}")
        if not callable(self.step):
            raise TypeError(f"plug-in {self.name!r}: step must be callable")
        if self.summarise is not None and not callable(self.summarise):
            raise TypeError(f"plug-in {self.name!r}: summarise must be callable")
        if not isinstance(self.gap_prefix, bool):
            raise TypeError(f"plug-in {self.name!r}: gap_prefix must be true or false")
        if self.kind == plugin_kinds.ANNOTATION and self.late:
            raise ValueError(f"plug-in {self.name!r}: an annotation runs after grading; it "
                             "cannot also be late")
        if self.kind == plugin_kinds.COVERAGE_CHECK:
            object.__setattr__(self, "late", True)
        keys = (self.annotation_keys,) if isinstance(self.annotation_keys, str) \
            else tuple(self.annotation_keys)
        if keys and self.kind != plugin_kinds.ANNOTATION:
            raise ValueError(f"plug-in {self.name!r}: only an annotation declares annotation_keys")
        for k in keys:
            if not isinstance(k, str) or not k.strip():
                raise ValueError(f"plug-in {self.name!r}: annotation key {k!r} is not text")
            if k == _OWN_KEY:
                raise ValueError(f"plug-in {self.name!r}: {_OWN_KEY!r} is takestock's own key on "
                                 "every plug-in row, so an annotation cannot clear it")
        object.__setattr__(self, "annotation_keys", keys)
        files = tuple(self.data_files)
        for f in files:
            if not isinstance(f, str) or not _DATA_NAME.match(f):
                raise ValueError(f"plug-in {self.name!r}: data file {f!r} must be a plain file "
                                 "name, not a path")
        object.__setattr__(self, "data_files", files)
        if not self.title:
            object.__setattr__(self, "title", f"Plug-in {self.name}")
        if not self.data_dir:
            try:
                where = str(Path(inspect.getfile(self.step)).resolve().parent)
            except TypeError:
                where = ""
            object.__setattr__(self, "data_dir", where)
        if self.data_dir and Path(self.data_dir).resolve() == config.BUNDLED_DATA_DIR.resolve():
            raise ValueError(f"plug-in {self.name!r}: its data directory cannot be takestock's own")


@dataclass
class StepResult:
    """What a step returns.

    ``records`` holds mappings of the kind's fields, or finished rows.
    ``gaps`` holds :func:`takestock.coverage.gap` results (a plain string is
    filed as a could-not-test gap). ``summary`` is written under the
    plug-in's name in ``summary.json`` and must be expressible as JSON.
    ``annotations`` is for the ``annotation`` kind only: ``{bom_ref: {key:
    value}}``, each value anything expressible as JSON (text, a number, true
    or false, or a list or mapping of those).
    """

    records: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RunInfo:
    """How the observation has gone so far, for a late step, a coverage check or an annotation.

    ``collectors`` names every registered built-in collector; ``ran`` those
    that ran; ``skipped`` those that did not, each with the reason;
    ``failed`` those that reported a real failure or stopped with an error;
    ``carried`` the active collectors whose rows were carried from an earlier
    observation instead of probing again (see :mod:`takestock.carry`).
    ``plugins`` gives each declared plug-in's status so far: ``ran``,
    ``not-run`` (its record in ``summary.json`` says why) or ``pending`` (its
    turn has not come, which includes the plug-in reading it). ``scan`` and
    ``offline`` are the observation's options. A coverage check can so tell
    a collector that was never built into the run from one skipped, and both
    from one that ran and found nothing.
    """

    collectors: tuple[str, ...] = ()
    ran: tuple[str, ...] = ()
    skipped: Mapping[str, str] = field(default_factory=dict)
    failed: tuple[str, ...] = ()
    carried: tuple[str, ...] = ()
    plugins: Mapping[str, str] = field(default_factory=dict)
    scan: bool = False
    offline: bool = False


@dataclass
class Context:
    """Everything a step receives. Rows and the profile are copies: changing them changes nothing.

    ``run`` is filled for a late step, a coverage check and an annotation
    when the caller supplies it (an observation always does); it is None for
    an ordinary step, which runs before the run's picture is complete.
    """

    plugin: Plugin
    target: dict
    settings: dict
    input: Path | None
    ref_time: datetime
    raw_dir: Path
    policy: Policy
    baseline: dict
    dictionary: dict
    port_table: dict
    collected_on: str
    assets: tuple[CryptoAsset, ...] = ()
    run: RunInfo | None = None

    @property
    def name(self) -> str:
        return self.plugin.name

    @property
    def kind(self) -> str:
        return self.plugin.kind

    def inbox_path(self, rel: str | Path) -> Path:
        """Resolve a further input path the way a target profile's paths are resolved."""
        return config.inbox_path(rel)

    def data_file(self, name: str) -> Path:
        """One of the plug-in's own declared data files. takestock's data files are never returned."""
        if name not in self.plugin.data_files:
            raise KeyError(f"plug-in {self.plugin.name!r} declares no data file {name!r}")
        if not self.plugin.data_dir:
            raise FileNotFoundError(f"plug-in {self.plugin.name!r} has no data directory")
        return Path(self.plugin.data_dir) / name


@dataclass
class Declared:
    """One entry of the profile's ``plugins:`` list, and what it resolved to."""

    name: str
    module: str = ""
    path: str = ""
    input: str | None = None
    required: bool = True
    settings: dict = field(default_factory=dict)
    plugin: Plugin | None = None
    origin: str = ""
    problem: str = ""


@dataclass
class _Record:
    kind: str = ""
    status: str = "not-run"
    reason: str = ""
    origin: str = ""
    input: str = ""
    records: int = 0
    rows: int = 0
    invalid: int = 0
    problems: list[str] = field(default_factory=list)
    annotated: int = 0
    summary: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        out: dict[str, Any] = {"kind": self.kind, "status": self.status}
        if self.reason:
            out["reason"] = self.reason
        out.update({"origin": self.origin, "input": self.input, "records": self.records,
                    "rows": self.rows, "invalid": self.invalid})
        if self.problems:
            out["problems"] = self.problems
        if self.kind == plugin_kinds.ANNOTATION:
            out["annotated"] = self.annotated
        if self.summary:
            out["summary"] = self.summary
        return out


# ── finding plug-ins ──

def _as_plugins(obj: Any) -> list[Plugin]:
    """The plug-ins an entry point or module attribute names: one, a list, or a callable giving either."""
    if callable(obj) and not isinstance(obj, Plugin):
        obj = obj()
    items = obj if isinstance(obj, (list, tuple)) else [obj]
    out = []
    for item in items:
        if not isinstance(item, Plugin):
            raise TypeError(f"expected a takestock Plugin, got {type(item).__name__}")
        out.append(item)
    return out


def installed() -> tuple[dict[str, Plugin], dict[str, str]]:
    """Plug-ins named under the entry-point group: (by name, entry points that failed to load)."""
    found: dict[str, Plugin] = {}
    broken: dict[str, str] = {}
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            for p in _as_plugins(ep.load()):
                found.setdefault(p.name, p)
        except Exception as exc:  # noqa: BLE001 - a broken package must not stop the others
            broken[ep.name] = f"{type(exc).__name__}: {exc}"
    return found, broken


def _from_module(spec: str) -> list[Plugin]:
    module, _, attr = spec.partition(":")
    return _as_plugins(getattr(import_module(module.strip()), attr.strip() or DEFAULT_ATTRIBUTE))


def _from_path(rel: str, name: str) -> list[Plugin]:
    path = Path(rel).expanduser()
    if not path.is_absolute():
        path = config.workspace_root() / path
    if not path.is_file():
        raise FileNotFoundError(f"{config.display_path(path)} does not exist")
    module_name = f"takestock_plugin_{name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{config.display_path(path)} cannot be loaded as a module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return _as_plugins(getattr(module, DEFAULT_ATTRIBUTE))


def declarations(target: Mapping) -> list[Declared]:
    """The profile's ``plugins:`` entries, each parsed; a malformed entry carries its problem."""
    raw = target.get(PROFILE_KEY) or []
    if not isinstance(raw, list):
        return [Declared(name="(plugins)", problem=f"`{PROFILE_KEY}:` must be a list")]
    out: list[Declared] = []
    seen: set[str] = set()
    for n, entry in enumerate(raw, 1):
        if isinstance(entry, str):
            entry = {"name": entry}
        if not isinstance(entry, Mapping) or not str(entry.get("name") or "").strip():
            out.append(Declared(name=f"(entry {n})", problem="each entry needs a `name:`"))
            continue
        d = Declared(name=str(entry["name"]).strip(), module=str(entry.get("module") or ""),
                     path=str(entry.get("path") or ""),
                     input=None if entry.get("input") is None else str(entry["input"]),
                     settings=dict(entry.get("settings") or {}))
        required = entry.get("required", True)
        if not isinstance(required, bool):
            d.problem = "`required:` must be true or false"
        d.required = required is not False
        if d.module and d.path:
            d.problem = "give `module:` or `path:`, not both"
        if d.name in seen:
            d.problem = "declared twice"
        seen.add(d.name)
        out.append(d)
    return out


def resolve(target: Mapping) -> tuple[list[Declared], list[str]]:
    """Each declaration with its plug-in found; also installed plug-ins the profile does not name."""
    decls = declarations(target)
    if not decls:
        return [], []
    found, broken = installed()
    for d in decls:
        if d.problem:
            continue
        try:
            if d.module:
                candidates, d.origin = _from_module(d.module), f"module {d.module}"
            elif d.path:
                candidates, d.origin = _from_path(d.path, d.name), f"path {d.path}"
            else:
                candidates = [found[d.name]] if d.name in found else []
                d.origin = "entry point"
        except Exception as exc:  # noqa: BLE001 - a plug-in that cannot load must not stop the run
            d.problem = f"could not be loaded: {type(exc).__name__}: {exc}"
            continue
        match = [p for p in candidates if p.name == d.name]
        if match:
            d.plugin = match[0]
        elif d.module or d.path:
            d.problem = f"{d.origin} defines no plug-in named {d.name!r}"
        elif broken:
            d.problem = ("is not installed (entry points that failed to load: "
                         + "; ".join(f"{k}: {v}" for k, v in sorted(broken.items())) + ")")
        else:
            d.problem = f"is not installed under the entry-point group {ENTRY_POINT_GROUP}"
    named = {d.name for d in decls}
    return decls, sorted(n for n in found if n not in named)


# ── running them ──

def _as_gap(g: Any) -> coverage.Gap:
    """A plug-in's gap exactly as written, as a classified Gap."""
    if isinstance(g, coverage.Gap):
        return g
    return coverage.gap(coverage.COULD_NOT_TEST, str(g), nature=coverage.NATURE_UNSTATED)


def _prefixed(name: str, g: Any) -> coverage.Gap:
    """A plug-in's gap, with the plug-in named, as a classified Gap."""
    if not isinstance(g, coverage.Gap):
        return coverage.gap(coverage.COULD_NOT_TEST, f"plug-in `{name}`: {g}",
                            nature=coverage.NATURE_UNSTATED)
    if f"`{name}`" in g:
        return g
    return coverage.Gap(g.kind, f"plug-in `{name}`: {g}", g.required, impact=g.impact,
                        impact_kind=g.impact_kind, harvest=g.harvest, nature=g.nature)


def _not_run_gap(d: Declared, why: str, kind: str, missing_input: bool = False) -> coverage.Gap:
    what = f"plug-in `{d.name}`" + (f" ({kind})" if kind else "")
    if missing_input:
        return coverage.gap(
            coverage.NOT_COLLECTED, f"{what} not run: {why}", d.required,
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact=("Nothing this plug-in would have read is in this observation, so an absent "
                    "finding there means the question was not asked."),
            harvest="Supply the input the plug-in reads and run the observation again.",
            nature=coverage.NO_DATA)
    return coverage.gap(
        coverage.COULD_NOT_TEST, f"{what} not run: {why}", d.required,
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Nothing this plug-in would have read is in this observation, so an absent "
                "finding there means the question was not asked."),
        harvest="Install or fix the plug-in, then run the observation again.",
        nature=coverage.NO_DATA)


def _invalid_gap(name: str, kind: str, bad: int, total: int, problems: list[str]) -> coverage.Gap:
    what = ("row(s) did not meet the constraints every row shares" if kind == plugin_kinds.GENERAL
            else "record(s) did not match the kind's schema")
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"plug-in `{name}` ({kind}): {bad} of {total} {what} "
        f"and were left out. First problems: {'; '.join(problems[:PROBLEM_SAMPLE])}",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Whatever those records described is missing from this observation. Every "
                "record that matched stands."),
        harvest="Correct the plug-in or its input so every record carries the kind's fields.",
        nature=coverage.NO_DATA)


def _problem_gap(name: str, what: str, problems: list[str]) -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"plug-in `{name}`: {what}: {'; '.join(problems[:PROBLEM_SAMPLE])}",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact="What the plug-in returned here was not used, so this observation lacks it.",
        harvest="Correct the plug-in.",
        nature=coverage.NO_DATA)


def _json_ok(value: Any) -> str:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        return str(exc)
    return ""


class Host:
    """Runs the declared plug-ins of one observation and keeps their records."""

    def __init__(self, target: Mapping, raw: Path, ref_time: datetime | None = None,
                 announce: Callable[[str], None] = lambda _line: None) -> None:
        self.target = target
        self.raw = raw
        self.ref_time = ref_time or datetime.now(UTC)
        self.say = announce
        self.declared, self.undeclared = resolve(target)
        self.records: dict[str, _Record] = {}
        self.gaps: list[coverage.Gap] = []
        self._rows: dict[str, list[str]] = {}
        self._contexts: dict[str, Context] = {}
        self._loaded = False
        self._reported = 0
        for d in self.declared:
            rec = self.records.setdefault(d.name, _Record(origin=d.origin))
            if d.plugin is not None:
                rec.kind = d.plugin.kind
                if d.plugin.kind == "host-listener":
                    plaintext.register_host_listener_source(
                        plugin_kinds.fixed_source(d.plugin.kind) or d.plugin.name,
                        plugin_kinds.LISTENER_MARKER)
            elif d.problem:
                rec.reason = d.problem
                self.gaps.append(_not_run_gap(d, d.problem, ""))

    def _drain(self) -> list[coverage.Gap]:
        """The gaps recorded since the last call, so each is handed over once."""
        out = self.gaps[self._reported:]
        self._reported = len(self.gaps)
        return out

    def _reference(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self.baseline = config.load_baseline()
        self.policy = Policy(self.baseline)
        self.dictionary = config.load_dictionary()
        self.port_table = config.load_port_encryption()

    def _runnable(self, phase: str) -> list[Declared]:
        out = []
        for d in self.declared:
            p = d.plugin
            if p is None:
                continue
            if phase == "annotate":
                if p.kind == plugin_kinds.ANNOTATION:
                    out.append(d)
            elif p.kind != plugin_kinds.ANNOTATION and p.late == (phase == "late"):
                out.append(d)
        return out

    def _statuses(self) -> dict[str, str]:
        """Each declared plug-in's status so far: ran, not-run, or pending."""
        return {name: "ran" if rec.status == "ran" else "not-run" if rec.reason else "pending"
                for name, rec in self.records.items()}

    def _context(self, d: Declared, assets: Iterable[CryptoAsset],
                 run: RunInfo | None = None) -> Context | None:
        p = d.plugin
        assert p is not None
        rec = self.records[d.name]
        rel = d.input if d.input is not None else p.input
        path = config.inbox_path(rel) if rel else None
        rec.input = config.display_path(path) if path is not None else ""
        if path is not None and not path.exists():
            rec.reason = f"its input {rec.input} was not supplied"
            self.gaps.append(_not_run_gap(d, rec.reason, p.kind, missing_input=True))
            return None
        self._reference()
        raw_dir = self.raw / "plugins" / p.name
        raw_dir.mkdir(parents=True, exist_ok=True)
        mtime = file_mtime_date(path) if path is not None and path.is_file() else None
        ctx = Context(
            plugin=p, target=copy.deepcopy(dict(self.target)), settings=copy.deepcopy(d.settings),
            input=path, ref_time=self.ref_time, raw_dir=raw_dir, policy=self.policy,
            baseline=copy.deepcopy(self.baseline), dictionary=copy.deepcopy(self.dictionary),
            port_table=copy.deepcopy(self.port_table),
            collected_on=mtime or now_date(self.ref_time),
            assets=tuple(copy.deepcopy(list(assets))),
            run=None if run is None else replace(run, skipped=dict(run.skipped),
                                                 plugins=self._statuses()))
        self._contexts[d.name] = ctx
        return ctx

    def _call(self, d: Declared, ctx: Context) -> StepResult | None:
        rec = self.records[d.name]
        try:
            out = d.plugin.step(ctx) if d.plugin else None
        except Exception as exc:  # noqa: BLE001 - a plug-in that raises must not end the run
            rec.reason = f"stopped with {type(exc).__name__}: {exc}"
            self.gaps.append(_not_run_gap(d, rec.reason, ctx.kind))
            return None
        if out is None:
            out = StepResult()
        elif isinstance(out, list):
            out = StepResult(records=out)
        if not isinstance(out, StepResult):
            rec.reason = f"its step returned {type(out).__name__}, not a StepResult or a list"
            self.gaps.append(_not_run_gap(d, rec.reason, ctx.kind))
            return None
        rec.status = "ran"
        own = d.plugin is None or d.plugin.gap_prefix
        for g in out.gaps:
            self.gaps.append(_prefixed(d.name, g) if own else _as_gap(g))
        problem = _json_ok(out.summary) if isinstance(out.summary, dict) else "not a mapping"
        if problem:
            self.gaps.append(_problem_gap(d.name, "its summary was not written", [problem]))
        else:
            rec.summary.update(out.summary)
        return out

    def run(self, late: bool, assets: list[CryptoAsset],
            run: RunInfo | None = None) -> tuple[list[CryptoAsset], list]:
        """Run the early (or late) plug-ins; return their rows and gaps.

        ``run`` describes the observation so far; late steps and coverage
        checks receive it as ``Context.run`` (with each plug-in's status
        filled in), and ordinary steps never do.
        """
        rows_out: list[CryptoAsset] = []
        for d in self._runnable("late" if late else "early"):
            p = d.plugin
            assert p is not None
            self.say(f"  · plug-in {p.name} ({p.kind})")
            ctx = self._context(d, assets if late else (), run if late else None)
            if ctx is None:
                continue
            out = self._call(d, ctx)
            if out is None:
                continue
            if p.kind == plugin_kinds.COVERAGE_CHECK:
                if out.records:
                    self.gaps.append(_problem_gap(
                        p.name, "a coverage check returns gaps only, so its rows were not written",
                        [f"{len(out.records)} row(s) returned"]))
                continue
            rows_out += self._rows_from(d, ctx, out)
        return rows_out, self._drain()

    def _rows_from(self, d: Declared, ctx: Context, out: StepResult) -> list[CryptoAsset]:
        p = d.plugin
        assert p is not None
        rec = self.records[p.name]
        records: list[dict] = []
        finished: list[CryptoAsset] = []
        problems: list[str] = []
        bad = 0
        mappings = 0
        for n, item in enumerate(out.records, 1):
            if p.kind == plugin_kinds.GENERAL and not isinstance(item, CryptoAsset):
                mappings += 1
                continue
            if isinstance(item, CryptoAsset):
                found = plugin_kinds.check_asset(p.kind, item)
                if found:
                    bad += 1
                    problems += [f"row {n}: {x}" for x in found]
                else:
                    finished.append(item)
                continue
            clean, found = plugin_kinds.validate(p.kind, item)
            if clean is None:
                bad += 1
                problems += [f"record {n}: {x}" for x in found]
            else:
                records.append(clean)
        rec.records = len(out.records)
        rec.invalid = bad + mappings
        refused = [f"{mappings} record mapping(s): the general kind has no record schema"]
        rec.problems = ((refused if mappings else []) + problems)[:PROBLEM_SAMPLE]
        if mappings:
            self.gaps.append(_problem_gap(
                p.name, "a general plug-in returns finished rows only, so its record mappings "
                "were not written", [f"{mappings} record mapping(s) returned"]))
        if bad:
            self.gaps.append(_invalid_gap(p.name, p.kind, bad, len(out.records) - mappings,
                                          problems))
        if not out.records:
            # A general plug-in says for itself what an empty result means, and
            # a step that returned a gap of its own has already said it.
            if p.kind != plugin_kinds.GENERAL and not out.gaps:
                self.gaps.append(plugin_kinds.scope_gap(p.name, p.kind, rec.input or "its input"))
            return []
        build = plugin_kinds.Build(
            plugin=p.name, kind=p.kind, title=p.title, policy=self.policy,
            port_table=self.port_table, target=ctx.target, collected_on=ctx.collected_on,
            shown=rec.input or p.title,
            names=identity.names_by_address(ctx.target))
        rows: list[CryptoAsset] = []
        if records:
            try:
                built, gaps = plugin_kinds.build_rows(p.kind, records, build)
            except Exception as exc:  # noqa: BLE001 - rows takestock cannot build are a gap, not a crash
                self.gaps.append(_problem_gap(p.name, "its records could not be turned into rows",
                                              [f"{type(exc).__name__}: {exc}"]))
                built, gaps = [], []
            rows += built
            self.gaps += [_prefixed(p.name, g) for g in gaps]
        for a in finished:
            rows.append(build.stamp(replace(a, extra=dict(a.extra)), {}, finished=True))
        rec.rows = len(rows)
        self._rows[p.name] = [a.bom_ref() for a in rows]
        return rows

    def annotate(self, assets: list[CryptoAsset], run: RunInfo | None = None) -> list:
        """Run the annotation plug-ins over the graded rows; return their gaps.

        Each annotation's declared ``annotation_keys`` are removed from every
        row first, whether or not its step then runs, so no row keeps a label
        from an earlier observation it was carried or re-read from.
        """
        for d in self._runnable("annotate"):
            p = d.plugin
            assert p is not None
            self.say(f"  · plug-in {p.name} (annotation)")
            for a in assets:
                for key in p.annotation_keys:
                    a.extra.pop(key, None)
            ctx = self._context(d, assets, run)
            if ctx is None:
                continue
            out = self._call(d, ctx)
            if out is None:
                continue
            if out.records:
                self.gaps.append(_problem_gap(
                    p.name, "an annotation adds keys to rows and writes none, so its rows were "
                    "not written", [f"{len(out.records)} row(s) returned"]))
            self.records[p.name].annotated = self._apply(p.name, out.annotations, assets)
        return self._drain()

    def _apply(self, name: str, annotations: Any, assets: list[CryptoAsset]) -> int:
        if not isinstance(annotations, Mapping):
            self.gaps.append(_problem_gap(name, "its annotations were not applied",
                                          ["annotations must map a row's bom_ref to its keys"]))
            return 0
        by_ref = {a.bom_ref(): a for a in assets}
        problems: list[str] = []
        stamped = 0
        for ref, keys in annotations.items():
            target = by_ref.get(ref)
            if target is None:
                problems.append(f"no row has bom_ref {ref!r}")
                continue
            if not isinstance(keys, Mapping):
                problems.append(f"{ref}: expected a mapping of key to value")
                continue
            changed = False
            for key, value in keys.items():
                if not isinstance(key, str) or not key.strip():
                    problems.append(f"{ref}: key {key!r} is not text")
                elif value is None or _json_ok(value):
                    problems.append(f"{ref}: {key} holds {type(value).__name__}; a value is "
                                    "anything expressible as JSON except null")
                elif key in target.extra and target.extra[key] != value:
                    problems.append(f"{ref}: {key} is already {target.extra[key]!r}, and an "
                                    "annotation adds keys, never changes them")
                else:
                    target.extra[key] = copy.deepcopy(value)
                    changed = True
            stamped += changed
        if problems:
            self.gaps.append(_problem_gap(name, f"{len(problems)} annotation(s) not applied",
                                          problems))
        return stamped

    def summarise(self, assets: list[CryptoAsset]) -> list:
        """Call each plug-in's ``summarise`` with its own graded rows; return any gaps."""
        by_ref = {a.bom_ref(): a for a in assets}
        for d in self.declared:
            p, ctx = d.plugin, self._contexts.get(d.name)
            if p is None or p.summarise is None or ctx is None:
                continue
            if self.records[d.name].status != "ran":
                continue
            own = [copy.deepcopy(by_ref[r]) for r in self._rows.get(d.name, []) if r in by_ref]
            try:
                extra = p.summarise(ctx, own)
            except Exception as exc:  # noqa: BLE001 - a broken summary must not end the run
                self.gaps.append(_problem_gap(d.name, "its summary was not written",
                                              [f"{type(exc).__name__}: {exc}"]))
                continue
            problem = _json_ok(extra) if isinstance(extra, Mapping) else "not a mapping"
            if problem:
                self.gaps.append(_problem_gap(d.name, "its summary was not written", [problem]))
                continue
            self.records[d.name].summary.update(dict(extra))
        return self._drain()

    def summary(self) -> dict:
        """Each declared plug-in's record, by name, for ``summary.json``."""
        return {name: rec.as_dict() for name, rec in self.records.items()}
