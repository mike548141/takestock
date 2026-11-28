"""The declared estate against the instruments that ran: one row per declared class.

A ``general`` plug-in that runs late (``docs/PLUGINS.md``). Every other check
in an observation notices an instrument that exists: one that failed, was not
run, or returned less than before. None can notice a class of equipment that
no instrument was ever pointed at, because such a class writes no rows and
fails nothing. This plug-in closes that hole by reading a **declaration** and
checking it against the run.

**The declaration** is a list in the target profile, by default under
``asset_classes:`` (``settings: key:`` names another profile key)::

    asset_classes:
      - name: Edge firewalls
        crypto: [IPsec VPN, TLS management interface]
        collect: ike_scan/tls_scan
      - name: Backup appliances
        crypto: [data at rest]
        collect: none

``name`` is the class. ``crypto`` lists the cryptography it is expected to
hold (shown, never graded). ``collect`` names the instruments meant to serve
the class, separated by ``/``: each is the ``source`` its rows carry, which
for a built-in collector is its module name (``tls_scan``) and for a plug-in
its name. ``none``, ``-`` or a blank say a person looked and no instrument
serves the class. A hyphen reads as an underscore, and an advisory
``(planned)`` marker is ignored: what the build contains decides, never what
the declaration says is coming.

**A row.** One row per class, ``data_state`` ``estate``, source ``estate``,
undated (a declaration is not an observation). It holds no cryptographic
primitive and says nothing about the class's security; it answers one
question, whether an instrument is pointed at the class and produced
anything this run. ``extra.estate_state`` holds the answer:

* ``no-instrument``: the declaration names no instrument, or only ones this
  run does not have;
* ``instrument-not-run``: every named instrument exists and did not run: a
  collector the run skipped, or a declared plug-in that was not run (its
  input was not supplied, or it stopped) or was given no input to read and
  wrote nothing;
* ``instrument-unmeasured``: every named instrument ran but sent no probe (it
  had no scanner), so it wrote only placeholder rows;
* ``instrument-silent``: every named instrument exists and produced nothing;
* ``instrument-partial``: some named instruments produced rows and others did
  not;
* ``instrumented``: every named instrument produced rows.

The first five carry the verdict ``unknown`` (a record the policy could not
grade) and a coverage gap; ``instrumented`` carries ``n/a``, since the row only
points at evidence held on other rows. A placeholder row (one whose
``source_class`` is ``unknown``) is never counted as output: the plug-in
that wrote it measured nothing.

**Attribution is derived, never guessed.** An instrument's rows belong to a
class only where the declaration proves it: an instrument named by exactly
one class is *exclusive* to it, and its row count is the class's
``estate-evidenced`` count. An instrument named by several classes is
*shared*; the row says so (``instrument-shared``) and claims no count.
Nothing here reads a host name, address or vendor string to place a row in a
class.

**What ran.** ``Context.run`` says which built-in collectors exist, ran and
were skipped, and which plug-ins are declared. An instrument is *built* if it
is a registered collector's module or a declared plug-in. It is *skipped* if
the run skipped its module and no other registered name for the same module
ran, or if it is a declared plug-in that did not run (:func:`plugins_not_run`):
an instrument that never ran has not "produced nothing". Without a run record,
the registered collectors' modules are built and none is skipped.

**The other direction.** A vendor seen on the network that no class names is
a class the declaration is missing. ``collect`` takes an optional mapping of
vendor to device count (``settings: discovered_vendors:`` in the profile
supplies one); with none, a gap says the declaration was not checked
against what is on the network.

**Summary.** :func:`summarise` returns counts (``declared_classes``, ``dark``,
``by_state``, ``stale_declarations``, ``not_run``), which takestock files under
this plug-in's record in ``summary.json``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .. import collectors, coverage, plugin_kinds, plugins
from ..model import NA_VERDICT, CryptoAsset
from ..plugins import Context, Plugin, RunInfo, StepResult

NAME = "estate"
DATA_STATE = "estate"
SOURCE = "estate"
#: The profile key holding the declaration, unless ``settings: key:`` names another.
PROFILE_KEY = "asset_classes"
#: ``settings:`` key naming a mapping of vendor to device count seen on the network.
DISCOVERED_SETTING = "discovered_vendors"

#: The ``source_class`` a row carries when its writer measured nothing.
UNMEASURED_SOURCE_CLASS = "unknown"

#: Advisory markers stripped from an instrument name before it is compared.
_ANNOTATIONS = ("(planned)",)
#: A ``collect`` value meaning that a person looked and no instrument serves the class.
_NONE = {"none", "", "-", "n/a"}

#: Plug-in kinds that write no rows by design, so writing none says nothing.
_WRITES_NO_ROWS = (plugin_kinds.COVERAGE_CHECK, plugin_kinds.ANNOTATION)

#: States in which the class produced no evidence at all.
DARK_STATES = ("no-instrument", "instrument-silent", "instrument-not-run",
               "instrument-unmeasured")


def _module(name: str) -> str:
    """The module a registered collector name runs; any other name is its own."""
    entry = collectors.REGISTRY.get(name)
    return str(entry.module) if entry is not None else name


def instruments(run: RunInfo | None,
                target: Mapping | None = None) -> tuple[set[str], set[str]]:
    """``(built, skipped)`` instrument names for this run, as rows' ``source`` spells them.

    Built: each registered collector's module, and each declared plug-in.
    Skipped: each skipped collector's module, less any module another
    registered name for it ran under (a module may have an input-reading
    entry beside a probing one), and each declared plug-in that did not run
    (see :func:`plugins_not_run`; ``target`` is the profile, which says what
    input each was given). Without a run record the registry's modules are
    built and none is skipped.
    """
    if run is None:
        return {c.module for c in collectors.REGISTRY.values()}, set()
    built = {_module(n) for n in run.collectors} | set(run.plugins)
    ran = {_module(n) for n in run.ran}
    return built, ({_module(n) for n in run.skipped} - ran) | set(plugins_not_run(run, target))


#: Why a declared plug-in did not run. The first is the host's own record (its
#: input file was not supplied, or its step stopped); the second is a plug-in
#: the host did call, given no input to read.
NOT_RUN = "not-run"
NO_INPUT = "no-input"


def plugins_not_run(run: RunInfo | None, target: Mapping | None = None) -> dict[str, str]:
    """Declared plug-ins that did not run, each with why: ``{name: NOT_RUN or NO_INPUT}``.

    * ``NOT_RUN``: the run records the plug-in as ``not-run`` (the file named
      as its input was not supplied, or its step stopped).
    * ``NO_INPUT``: the run records it as ``ran``, but the profile gave it no
      input and the plug-in has no default one, so its step was called with
      nothing to read. Only takestock's own readers and plug-ins that write
      rows are judged this way (a coverage check or an annotation writes none
      by design), and a plug-in the profile names by ``module:`` or ``path:``
      is not judged, since its default input is not known here. Whether the
      plug-in then wrote rows decides the class's state (:func:`collect`), so
      one that read its settings and wrote rows is unaffected.

    A plug-in whose turn has not come (``pending``) is in neither: it has not
    been asked to run yet, which says nothing about whether it will.
    """
    if run is None:
        return {}
    out = {n: NOT_RUN for n, status in run.plugins.items() if status == "not-run"}
    if target is None:
        return out
    from . import library  # imported here: this module is itself part of the library
    held = library()
    for d in plugins.declarations(target):
        known = held.get(d.name)
        if (run.plugins.get(d.name) != "ran" or d.problem or d.module or d.path
                or known is None or known.kind in _WRITES_NO_ROWS):
            continue
        if not str(d.input if d.input is not None else known.input).strip():
            out[d.name] = NO_INPUT
    return out


def _token(raw: str) -> str:
    tok = raw.strip().lower()
    for marker in _ANNOTATIONS:
        tok = tok.replace(marker, "")
    tok = tok.strip()
    # Checked before the hyphen folds, or a lone "-" would become the name "_".
    return "" if tok in _NONE else tok.replace("-", "_")


def parse_collect(spec: object) -> tuple[list[str], bool]:
    """``(instrument names, marked planned)`` from one ``collect`` value.

    ``"ike_scan/tls_scan"`` gives ``(["ike_scan", "tls_scan"], False)``;
    ``"vendor-export (planned)"`` gives ``(["vendor_export"], True)``;
    ``"none"`` gives ``([], False)``. A list is read as its items joined by ``/``.
    """
    if isinstance(spec, (list, tuple)):
        spec = "/".join(str(s) for s in spec)
    text = str(spec or "")
    planned = any(m in text.lower() for m in _ANNOTATIONS)
    return [t for t in (_token(p) for p in text.split("/")) if t], planned


def _exclusive(entries: Sequence[Mapping]) -> set[str]:
    """Instruments named by exactly one declared class."""
    counts: dict[str, int] = {}
    for e in entries:
        for name in set(parse_collect(e.get("collect", ""))[0]):
            counts[name] = counts.get(name, 0) + 1
    return {n for n, c in counts.items() if c == 1}


def _role(name: str, crypto: Sequence[str], state: str) -> str:
    """The row's plain-language line: what the class is and whether anything examined it."""
    what = f"A kind of equipment in the estate: {name}."
    if state == "no-instrument":
        return (f"{what} Nothing in this report has examined it, because no check for this "
                "kind of equipment exists in this run, so its encryption is unknown, not absent.")
    if state == "instrument-not-run":
        return (f"{what} The check for it was not run in this observation, so the equipment "
                "is unexamined here.")
    if state == "instrument-silent":
        return (f"{what} The check for it ran and found nothing, so the equipment is "
                "unexamined here.")
    if state == "instrument-unmeasured":
        return (f"{what} The check for it ran without the scanner it needs, so nothing was "
                "tested and the equipment is unexamined here.")
    if state == "instrument-partial":
        return (f"{what} Part of it was examined and part was not, and this run cannot say "
                "which part went unchecked.")
    listed = f" Expected: {', '.join(crypto)}." if crypto else ""
    return f"{what}{listed} Examined here; the findings are the other rows."


def _notes(crypto: Sequence[str], named: Sequence[str], live: Sequence[str],
           silent: list[str], missing: list[str], state: str, attributed: int,
           unprobed: Sequence[str]) -> str:
    what = f"declared crypto: {', '.join(crypto) or 'unstated'}"
    if state == "no-instrument" and not named:
        return f"NO INSTRUMENT: none is named for this class. {what}"
    if state == "no-instrument":
        return (f"NO INSTRUMENT: {', '.join(sorted(missing))} named, none present in this "
                f"run. {what}")
    if state == "instrument-not-run":
        return f"NOT RUN: {', '.join(sorted(silent))} was not run this observation. {what}"
    if state == "instrument-unmeasured":
        return (f"NO PROBE SENT: {', '.join(sorted(unprobed or silent))} ran without its "
                f"scanner and wrote placeholder rows only. {what}")
    if state == "instrument-silent":
        return f"DARK THIS RUN: {', '.join(sorted(silent))} produced nothing. {what}"
    if state == "instrument-partial":
        return (f"PARTLY INSTRUMENTED: {', '.join(sorted(live))} produced rows; "
                f"{', '.join(sorted(silent + missing))} produced none. {what}")
    if attributed:
        return (f"Instrumented: {attributed} row(s) attributable to this class via "
                f"{', '.join(sorted(live))}. {what}")
    return (f"Instrumented: {', '.join(sorted(live))} produced rows, none provably this "
            f"class's (each instrument is shared with another declared class). {what}")


def _class_row(entry: Mapping, *, built: set[str], produced: Mapping[str, int],
               exclusive: set[str], skipped: set[str], unmeasured: Mapping[str, int],
               unrun_plugins: Mapping[str, str] | None = None) -> tuple[CryptoAsset, list[str]]:
    """One declared class as a row, and the texts of the gaps it owes."""
    name = str(entry.get("name", "")).strip() or "(unnamed class)"
    crypto = [str(c) for c in (entry.get("crypto") or [])]
    named, planned = parse_collect(entry.get("collect", ""))

    missing = [n for n in named if n not in built]
    present = [n for n in named if n in built]
    live = [n for n in present if produced.get(n)]
    silent = [n for n in present if not produced.get(n)]
    # Present, wrote rows, but none of them a measurement: no probe was sent.
    unprobed = [n for n in silent if unmeasured.get(n)]

    def dark_flag(instrument: str) -> str:
        # An instrument the run skipped is the operator's decision and outranks
        # what its rows look like, because it never got to write any.
        if instrument in skipped:
            return f"instrument-not-run:{instrument}"
        if unmeasured.get(instrument):
            return f"instrument-unmeasured:{instrument}"
        return f"instrument-silent:{instrument}"

    crypto_text = ", ".join(crypto) or "unstated"
    flags: set[str] = set()
    texts: list[str] = []
    attributed = sum(produced.get(n, 0) for n in live if n in exclusive)
    shared_live = [n for n in live if n not in exclusive]

    if not named:
        state, reason = "no-instrument", "none-declared"
        flags.add("no-instrument:none-declared")
        texts.append(f"{name}: declared with no instrument named, so nothing in this run can "
                     f"produce a row for it. Its crypto ({crypto_text}) stays unmeasured until "
                     "one exists")
    elif not present:
        state, reason = "no-instrument", "unbuilt"
        flags.add("no-instrument:unbuilt")
        flags.update(f"collector-unbuilt:{n}" for n in missing)
        texts.append(f"{name}: declared, and every instrument it names is absent from this "
                     f"run ({', '.join(sorted(missing))}). Its crypto ({crypto_text}) is "
                     "unmeasured, and no failure will report it because nothing exists to fail")
    elif not live and all(n in skipped for n in present):
        state, reason = "instrument-not-run", "not-run"
        flags.update(f"instrument-not-run:{n}" for n in silent)
        flags.update(f"collector-unbuilt:{n}" for n in missing)
        # A collector is skipped by the run's choice; a plug-in that did not run
        # lacked its input or stopped, which is nobody's choice.
        reasons = {(unrun_plugins or {})[n] for n in present if n in (unrun_plugins or {})}
        why = ("dark because it did not run" if reasons else "dark by this run's choice")
        if reasons == {NO_INPUT}:
            ran_how = " (it was given no input to read)"
        elif reasons:
            ran_how = " (its input was not supplied, it stopped, or it was given no input)"
        else:
            ran_how = ""
        texts.append(f"{name}: its only instrument ({', '.join(sorted(present))}) was not run "
                     f"in this observation{ran_how}, so the class is {why}. Its "
                     f"crypto ({crypto_text}) would be measured by running it")
    elif not live and all(n in skipped or n in unprobed for n in present):
        state, reason = "instrument-unmeasured", "placeholders-only"
        flags.update(dark_flag(n) for n in silent)
        flags.update(f"collector-unbuilt:{n}" for n in missing)
        not_run = sorted(n for n in silent if n in skipped)
        why = f"{', '.join(sorted(unprobed))} ran but sent no probe and wrote placeholder rows"
        if not_run:
            why += f", and {', '.join(not_run)} was not run"
        texts.append(f"{name}: unmeasured, because {why}. Its crypto ({crypto_text}) has no "
                     "evidence here; installing the missing scanner would measure it")
    elif not live:
        state, reason = "instrument-silent", "produced-nothing"
        flags.update(dark_flag(n) for n in silent)
        flags.update(f"collector-unbuilt:{n}" for n in missing)
        ran_silent = sorted(n for n in silent if n not in skipped and n not in unprobed)
        not_run = sorted(n for n in silent if n in skipped)
        parts = []
        if ran_silent:
            parts.append(f"{', '.join(ran_silent)} produced nothing")
        if unprobed:
            parts.append(f"{', '.join(sorted(unprobed))} sent no probe")
        if not_run:
            parts.append(f"{', '.join(not_run)} was not run")
        texts.append(f"{name}: dark in this observation ({'; '.join(parts)}). Its crypto "
                     f"({crypto_text}) is unmeasured here. This limits what was measured and "
                     "is not evidence that the class is absent")
    elif silent or missing:
        state, reason = "instrument-partial", "some-silent"
        flags.update(dark_flag(n) for n in silent)
        flags.update(f"collector-unbuilt:{n}" for n in missing)
        texts.append(f"{name}: partly instrumented. {', '.join(sorted(live))} produced rows; "
                     f"{', '.join(sorted(silent + missing))} produced none. Which part of the "
                     f"class's crypto ({crypto_text}) went unmeasured is not established")
    else:
        state, reason = "instrumented", ""

    if shared_live:
        flags.update(f"instrument-shared:{n}" for n in sorted(shared_live))
    if attributed:
        flags.add(f"estate-evidenced:{attributed}")
    if planned and present:
        # The declaration's marker disagrees with the build: reported, never believed.
        flags.update(f"declaration-stale:planned-but-built:{n}" for n in sorted(present))

    asset = CryptoAsset(
        name=f"Declared asset class: {name}",
        role=_role(name, crypto, state),
        data_state=DATA_STATE,
        protocol="",
        source=SOURCE,
        source_class="private",
        source_name=f"{name} (declared in the target profile)",
        # No collected_at: a declaration is not an observation.
        verdict="unknown" if state != "instrumented" else NA_VERDICT,
        flags=sorted(flags),
        notes=_notes(crypto, named, live, silent, missing, state, attributed, unprobed),
        extra={
            "estate_class": name,
            "estate_state": state,
            "estate_reason": reason,
            "declared_crypto": crypto,
            "collectors_declared": named,
            "collectors_built": sorted(present),
            "collectors_live": sorted(live),
            "collectors_silent": sorted(silent),
            "collectors_unbuilt": sorted(missing),
            "collectors_unprobed": sorted(unprobed),
            "attributed_assets": attributed,
            "attribution": "exclusive-collector" if attributed else "none",
            "declared_planned": planned,
            "dark": state in DARK_STATES,
        },
    )
    return asset, texts


# What a dark class costs the reader, keyed on the state that made it dark:
# (impact kind, impact, how to close it). Keyed on the state, not written per
# class, so a class added to a profile arrives with the right sentences.
_IMPACT: dict[str, tuple[str, str, str]] = {
    "no-instrument": (
        coverage.CHANGES_CONCLUSION,
        "Nothing has measured the encryption on this equipment, and nothing in this run "
        "could. Read every coverage figure as excluding it: a clean result on the equipment "
        "that was measured says nothing about this, and traffic crossing it is unassessed, "
        "not sound.",
        "An export from whoever administers the equipment, or an instrument built for it. "
        "Folded in when it exists."),
    "instrument-silent": (
        coverage.CHANGES_CONCLUSION,
        "The instrument ran and this equipment gave it nothing, so it contributed no "
        "evidence. Silence is an unanswered question, not a clean result; estate-wide "
        "statements should be read as not covering this class.",
        "Obtain the export from the team that runs the equipment; the instrument already "
        "exists, so the answer appears in the next observation."),
    "instrument-not-run": (
        coverage.CHANGES_CONCLUSION,
        "This equipment can be measured and this run did not measure it, so there is no "
        "evidence about it either way.",
        "Run the observation again with the instrument enabled."),
    "instrument-unmeasured": (
        coverage.CHANGES_CONCLUSION,
        "The instrument ran without the scanner it needs, so the rows for this equipment "
        "are placeholders. Anything resembling a result for this class records that a "
        "probe was intended, not a finding.",
        "Install the missing scanner on the machine that runs the observation and run it "
        "again."),
    "instrument-partial": (
        coverage.CHANGES_CONCLUSION,
        "Part of this equipment's encryption was measured and part was not, for example "
        "data in transit but not at rest. A verdict shown for the class covers the "
        "measured part and is not the class's overall protection.",
        "The missing export from the source that supplied the other part."),
}
_IMPACT_DEFAULT = (
    coverage.CHANGES_CONCLUSION,
    "This equipment produced no evidence in this run, so nothing here describes its "
    "encryption. Treat it as unassessed, not sound.",
    "Establish who administers it and what it can export.")

# What is missing, by state. A declaration that a class exists is an input, not a
# measurement, so a class never measured is `no-data`. Only `instrument-partial`
# holds a real measurement answering a narrower question, which is `low-fidelity`.
_NATURE: dict[str, str] = {
    "no-instrument": coverage.NO_DATA,
    "instrument-silent": coverage.NO_DATA,
    "instrument-not-run": coverage.NO_DATA,
    "instrument-unmeasured": coverage.NO_DATA,
    "instrument-partial": coverage.LOW_FIDELITY,
}


def _gap_kind(state: str) -> str:
    # `instrument-unmeasured` is on the not-collected side: the scanner was
    # absent, so nothing was asked, and filing it as could-not-test would claim
    # a question was put and went unanswered.
    return (coverage.COULD_NOT_TEST
            if state in ("instrument-silent", "instrument-partial", "instrument-not-run")
            else coverage.NOT_COLLECTED)


def collect(target: Mapping, assets: Sequence[CryptoAsset], *,
            discovered_vendors: Mapping[str, int] | None = None,
            skipped: set[str] | None = None,
            built: set[str] | None = None,
            unrun_plugins: Mapping[str, str] | None = None,
            key: str = PROFILE_KEY) -> tuple[list[CryptoAsset], list]:
    """The declared classes checked against ``assets``: ``(rows, gaps)``.

    ``assets`` is every row the run produced so far, so this can only run late.
    ``skipped`` is what the run deliberately did not invoke; it is passed in,
    never inferred, because only the caller knows what it chose not to do.
    ``built`` is the instrument set the run is made of (see :func:`instruments`);
    without it, the registry's modules. ``unrun_plugins`` is the part of
    ``skipped`` that is declared plug-ins that did not run, with why (see
    :func:`plugins_not_run`); it only changes the wording of the gap, since a
    plug-in lacking its input was not left out by choice. ``key`` is the profile
    key that holds the declaration.
    """
    raw = target.get(key) or []
    entries = [e for e in raw if isinstance(e, Mapping)]
    gaps: list = []
    odd = len(raw) - len(entries)
    if odd:
        gaps.append(coverage.gap(
            coverage.COULD_NOT_TEST,
            f"{odd} entry/entries under `{key}:` in the target profile are not mappings with "
            "a `name` and were skipped, so those classes were not checked for an instrument",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="A class the profile meant to declare is not in this check, so it cannot "
                   "show as unmeasured.",
            harvest="Correct the entries in the target profile.",
            nature=coverage.NO_DATA))
    if not entries:
        return [], gaps + [coverage.gap(
            coverage.NOT_COLLECTED,
            f"The target profile declares no classes under `{key}:`, so no class can be "
            "checked for an instrument. Every class the organisation runs is invisible to "
            "this check; that is not evidence it is absent",
            impact_kind=coverage.CHANGES_CONCLUSION,
            impact="Nobody has written down what equipment runs, so the report cannot say "
                   "what it did not look at, and a reader cannot judge how much of the "
                   "estate the findings cover.",
            harvest="A list of the equipment classes in service (servers, network gear, "
                    "storage, cloud platforms) added to the target profile.",
            nature=coverage.NO_DATA)]

    have = built if built is not None else instruments(None)[0]
    # A row is not evidence: rows whose writer measured nothing are counted apart,
    # or an instrument that sent no probe would make its class read `instrumented`.
    produced: dict[str, int] = {}
    unmeasured: dict[str, int] = {}
    for a in assets:
        if not a.source:
            continue
        bucket = unmeasured if a.source_class == UNMEASURED_SOURCE_CLASS else produced
        bucket[a.source] = bucket.get(a.source, 0) + 1
    exclusive = _exclusive(entries)

    rows: list[CryptoAsset] = []
    for entry in entries:
        row, texts = _class_row(entry, built=have, produced=produced, exclusive=exclusive,
                                skipped=set(skipped or ()), unmeasured=unmeasured,
                                unrun_plugins=unrun_plugins)
        rows.append(row)
        state = row.extra["estate_state"]
        impact_kind, impact, harvest = _IMPACT.get(state, _IMPACT_DEFAULT)
        if state == "instrument-not-run" and set(unrun_plugins or ()) & set(
                row.extra["collectors_built"]):
            harvest = ("Give each plug-in that did not run its input, or fix what stopped it, "
                       "and run the observation again.")
        nature = _NATURE.get(state, coverage.NATURE_UNSTATED)
        gaps += [coverage.gap(_gap_kind(state), t, impact=impact, impact_kind=impact_kind,
                              harvest=harvest, nature=nature) for t in texts]
    gaps += _undeclared_vendor_gaps(entries, discovered_vendors)
    return rows, gaps


def _undeclared_vendor_gaps(entries: Sequence[Mapping],
                            discovered: Mapping[str, int] | None) -> list:
    """Vendors seen on the network that no declared class mentions, or a gap saying
    the comparison was not made."""
    if discovered is None:
        return [coverage.gap(
            coverage.NOT_COLLECTED,
            "The declared classes were not checked against the devices discovered on the "
            "network: no vendor evidence was supplied to this run. A vendor present on the "
            "network and absent from the declaration cannot be detected, so the declaration "
            "can go stale unnoticed",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="Nothing compared the declared list of equipment with what is on "
                   "the network, so a class nobody wrote down would not be noticed. Findings "
                   "about the declared equipment stand; whether the list is complete is "
                   "unknown.",
            harvest="A discovered-device export that names each device's manufacturer, "
                    "counted per vendor, supplied as `settings: discovered_vendors:`.",
            nature=coverage.NO_DATA)]
    declared = " ".join(str(e.get("name", "")).lower() for e in entries)
    undeclared = sorted((v, n) for v, n in discovered.items()
                        if v and not any(w in declared for w in _vendor_words(v)))
    if not undeclared:
        return []
    return [coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{len(undeclared)} vendor(s) discovered on the network appear in no declared class: "
        + ", ".join(f"{v} ({n})" for v, n in undeclared)
        + ". Each is a class of device the declaration does not know, so nothing has been "
        "pointed at it. This is a floor, not a census: the counts are of devices seen by "
        "discovery, which is not an inventory, and a device whose manufacturer was not "
        "recorded cannot be compared at all",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact="There is equipment on the network that the declaration does not mention, so "
               "nothing has measured its encryption. Estate-wide coverage statements are "
               "over the declared equipment, and the real estate is larger by at least this "
               "much.",
        harvest="Go through the list with whoever maintains the declaration: add each "
                "vendor, or explain it.",
        nature=coverage.NO_DATA)]


def _vendor_words(vendor: str) -> list[str]:
    """The distinctive words of a vendor string, corporate suffixes dropped."""
    drop = {"inc", "ltd", "corp", "corporation", "co", "llc", "gmbh", "limited",
            "technologies", "technology", "systems", "networks", "the", "and", "&"}
    words = [w.strip(" ,.()").lower() for w in str(vendor).split()]
    return [w for w in words if w and w not in drop] or [str(vendor).lower()]


def summarise(assets: Sequence[CryptoAsset]) -> dict:
    """The plug-in's contribution to ``summary.json``, derived from its own rows."""
    rows = [a for a in assets if a.data_state == DATA_STATE]
    if not rows:
        return {}

    def cls(a: CryptoAsset) -> str:
        return str(a.extra.get("estate_class", a.name))

    by_state: dict[str, list[str]] = {}
    for a in rows:
        by_state.setdefault(str(a.extra.get("estate_state", "unknown")), []).append(cls(a))
    dark = sorted(cls(a) for a in rows if a.extra.get("dark"))
    return {
        "declared_classes": len(rows),
        "dark": dark,
        "dark_count": len(dark),
        "by_state": {k: sorted(v) for k, v in sorted(by_state.items())},
        "stale_declarations": sorted(
            cls(a) for a in rows if any(f.startswith("declaration-stale:") for f in a.flags)),
        # The one dark state an operator clears by running again, not by chasing an export.
        "not_run": sorted(cls(a) for a in rows if a.extra.get("estate_state") == "instrument-not-run"),
    }


def step(ctx: Context) -> StepResult:
    built, skipped = instruments(ctx.run, ctx.target)
    key = str(ctx.settings.get("key") or PROFILE_KEY)
    found = ctx.settings.get(DISCOVERED_SETTING)
    vendors = {str(k): int(v) for k, v in found.items()} if isinstance(found, Mapping) else None
    rows, gaps = collect(ctx.target, list(ctx.assets), discovered_vendors=vendors,
                         skipped=skipped, built=built, key=key,
                         unrun_plugins=plugins_not_run(ctx.run, ctx.target))
    return StepResult(records=list(rows), gaps=list(gaps))


def _summary(_ctx: Context, rows: list) -> dict:
    return summarise(rows)


#: The declaration. Late, so it sees every other row; its rows are undated.
PLUGIN = Plugin(name=NAME, kind="general", step=step, late=True, gap_prefix=False,
                summarise=_summary, date_rows=False,
                title="declared asset classes against the instruments that ran")
