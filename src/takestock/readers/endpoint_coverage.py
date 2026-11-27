"""Endpoint control families no instrument reaches, and how many devices each reaches.

A ``coverage-check`` plug-in (``docs/PLUGINS.md``): it reads every row the
observation has produced and returns coverage gaps only. It writes no rows, so
no verdict, count or denominator elsewhere moves.

Every collector notices that its own input is short. None notices a *control*
that no collector reads at all, because that writes nothing and fails
nothing. This check keeps a short working list of endpoint control families
and says, for each one, whether anything in the run produced evidence of it,
and for how many of the devices the run did reach.

**What it will say.** Only that nothing looked: a family with no instrument is
a statement about the run's coverage, and a device outside a family's reach is
a device with no reading, not a device that failed. It never judges a device,
and a list of controls is not a compliance assessment. Every gap carries its
population (``covered of total``) so "nothing looked" is bounded.

**The family list** (:data:`FAMILIES`) is takestock's own working list, not
any framework's. It is a judgement, so it can be changed from the profile::

    endpoint_control_families:
      exclude: [removable-media]            # a family this organisation does not operate
      evidence:
        configuration-baseline: [mdm_compliance]   # instruments that evidence a family

* ``exclude`` drops families. An id that names no family is reported, since a
  typo would otherwise suppress nothing and read as a clean answer.
* ``evidence`` adds instruments (the ``source`` their rows carry) to a
  family's own list, for a reader takestock does not ship. An id that names
  no family is reported the same way. Its rows then count as readings of
  devices.
* A family left with no instrument at all is the point of the list.

**Devices.** A row counts as a reading of a device only if its ``source`` is
one a family names and it carries a machine: ``extra.aid`` (a sensor
identifier) and/or ``host``. Aggregate rows (a fleet count, a product total)
carry neither and are not devices. Two identifiers on one row are one
machine, merged transitively: two exports that name a machine differently
would otherwise double the population and make every coverage figure read
worse than the truth.

**Gaps raised.** *unreached* (no rows for the family), *fleet-level only*
(rows exist, none names a device), *partly reached* (``n`` of ``N`` devices),
*support horizon* (devices with no support status for the operating system
they run), *management record* (devices a sensor reached that no
device-management export lists; silent when no such export ran), and
*profile* (an unknown id in the block above).

**Support status** is declared in the profile (``lifecycle: support_status:``)
or derived from the bundled Windows table, both of which an observation
applies after late steps run. This check applies the same two steps to copies
of the rows, so the gap reads what the finished rows will carry.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from .. import config, coverage, lifecycle
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult

NAME = "endpoint_coverage"
#: The profile block that excludes families and adds evidence to them.
PROFILE_KEY = "endpoint_control_families"

#: Each gap sentence begins with one of these, so a search for this check's
#: gaps cannot match another collector's.
TOKEN_PREFIX = "Endpoint coverage"
FAMILY_TOKEN = f"{TOKEN_PREFIX} — control family unreached:"
POPULATION_TOKEN = f"{TOKEN_PREFIX} — control family partly reached:"
AGGREGATE_TOKEN = f"{TOKEN_PREFIX} — control family fleet-level only:"
SUPPORT_TOKEN = f"{TOKEN_PREFIX} — support horizon:"
MANAGEMENT_TOKEN = f"{TOKEN_PREFIX} — management record:"
PROFILE_TOKEN = f"{TOKEN_PREFIX} — profile:"

#: Instruments whose rows are a record held by a device-management platform,
#: as opposed to a security sensor. Comparing the two populations is the only
#: way to see a machine one knows and the other does not.
MANAGEMENT_SOURCES = ("m365_bitlocker",)


@dataclass(frozen=True)
class ControlFamily:
    """One endpoint control, and which instruments evidence it.

    ``evidence`` names instruments by the ``source`` their rows carry. An empty
    tuple says nothing in takestock reaches the family.
    """

    slug: str
    name: str
    question: str
    impact: str
    harvest: str
    evidence: tuple[str, ...] = field(default=())


#: The working list, in the order a reader meets the controls: is there an
#: agent on the device, what it can say about the device, then the controls
#: that shape what the device may do.
FAMILIES: tuple[ControlFamily, ...] = (
    ControlFamily(
        slug="agent-coverage",
        name="Whether a management or security agent is on the device at all",
        question="How many devices carry an agent, against how many devices exist",
        evidence=("falcon_estate_coverage",),
        impact="Without this, every endpoint percentage is a numerator with no "
               "denominator: it describes the machines that report in and cannot say "
               "how many do not.",
        harvest="The platform's count of managed devices beside its count of all "
                "devices it can see."),
    ControlFamily(
        slug="platform-integrity",
        name="Secure start-up and in-memory credential protection",
        question="Does the device verify what it loads at start-up, and protect "
                 "credentials while running",
        evidence=("falcon_zta",),
        impact="Without this, a device that would resist tampering cannot be told from "
               "one that would not, so nothing can be said about device hardening.",
        harvest="A platform-integrity assessment from the endpoint platform."),
    ControlFamily(
        slug="disk-encryption",
        name="Disk encryption at rest",
        question="Are the device's drives encrypted",
        evidence=("falcon_disk_encryption", "m365_bitlocker"),
        impact="Without this, a lost or stolen device cannot be treated as a "
               "non-event, and nothing says how many devices that applies to.",
        harvest="A drive-encryption export from the endpoint or management platform."),
    ControlFamily(
        slug="key-escrow",
        name="Recovery-key custody for encrypted drives",
        question="Is an encrypted drive's recovery key held somewhere the "
                 "organisation can reach",
        evidence=("m365_bitlocker",),
        impact="Without this, an encrypted drive whose key was never escrowed looks the "
               "same as one whose key was, and the first is a data-loss risk.",
        harvest="The device-management platform's recovery-key report."),
    ControlFamily(
        slug="software-inventory",
        name="What software is installed on the device",
        question="Which products and versions are in service across the fleet",
        evidence=("falcon_software",),
        impact="Without this, nobody can say which devices carry a given version, so no "
               "upgrade can be sized and no exposure scoped to a set of machines.",
        harvest="A per-device installed-software export."),
    ControlFamily(
        slug="patch-state",
        name="Open defects and patch state",
        question="Which known defects are open on the fleet, and for how long",
        evidence=("falcon_vulnerabilities",),
        impact="Without this, a fleet that is current cannot be told from one that is "
               "years behind.",
        harvest="A vulnerability export from the endpoint platform."),
    ControlFamily(
        slug="remote-management",
        name="How the device is administered remotely",
        question="Does remote administration of the device require encryption",
        evidence=("winrm_config",),
        impact="Without this, an open remote-administration service proves neither "
               "exposure nor its absence, so nothing says whether administrative "
               "sessions are protected.",
        harvest="A remote-management configuration export."),
    ControlFamily(
        slug="fleet-trend",
        name="Whether the fleet is getting better or worse over time",
        question="Which way has each endpoint measure moved across recent periods",
        impact="Without this, every endpoint figure is a point with no direction, so a "
               "problem being fixed cannot be told from one getting worse.",
        harvest="Periodic exports of the same endpoint measures, kept so they can be "
                "compared."),
    # Families with no instrument in takestock. Each is a real endpoint control that
    # no reader here writes a row for; a profile adds one with `evidence:`.
    ControlFamily(
        slug="configuration-baseline",
        name="Whether devices match a configured security baseline",
        question="Does a baseline exist, and how many devices currently meet it",
        impact="Without this, individual controls are described but nothing says whether "
               "devices are configured to an agreed standard, which is what a reader "
               "usually means by asking whether endpoints are managed.",
        harvest="A compliance-policy report from the device-management platform."),
    ControlFamily(
        slug="application-control",
        name="Whether devices restrict what software may run",
        question="Is code execution limited to approved software, and on how many "
                 "devices",
        impact="Without this, nothing bounds what one compromised device could execute.",
        harvest="An application-control policy export from the endpoint platform."),
    ControlFamily(
        slug="removable-media",
        name="Whether devices restrict removable media",
        question="Can data be copied onto removable storage, and on how many devices",
        impact="Without this, at-rest encryption findings stop at the device: an "
               "encrypted drive says nothing about what may be copied off it in clear.",
        harvest="A removable-media policy export from the device-management platform."),
    ControlFamily(
        slug="device-retirement",
        name="Whether a lost or retired device can be wiped",
        question="Can the organisation erase a device it no longer controls, and for "
                 "how many devices",
        impact="Without this, a lost device is an open question, and nothing says how "
               "many devices could be dealt with if one went missing.",
        harvest="A device-management report of wipe capability and recent actions."),
)


def resolve(target: Mapping) -> tuple[tuple[ControlFamily, ...], frozenset[str], list[str]]:
    """``(families, excluded, unknown)`` for this profile.

    ``families`` is every family with the profile's ``evidence:`` added;
    ``excluded`` is the ids the profile leaves out of the report; ``unknown``
    is every id in the block that names no family. An excluded family is
    still in ``families``: leaving a control out of the report does not make
    its instrument's rows any less a reading of a device, so the population
    does not shrink with it. A block that is not a mapping is ignored.
    """
    block = target.get(PROFILE_KEY) or {}
    if not isinstance(block, Mapping):
        return FAMILIES, frozenset(), []
    known = {f.slug for f in FAMILIES}
    listed = [str(x).strip() for x in (block.get("exclude") or []) if str(x).strip()]
    added = block.get("evidence") or {}
    added = added if isinstance(added, Mapping) else {}
    unknown = [x for x in listed if x not in known] + [str(k) for k in added if str(k) not in known]
    families = []
    for fam in FAMILIES:
        more = tuple(str(s).strip() for s in (added.get(fam.slug) or []) if str(s).strip())
        families.append(replace(fam, evidence=fam.evidence + tuple(
            s for s in more if s not in fam.evidence)))
    return tuple(families), frozenset(x for x in listed if x in known), unknown


def evidence_sources(families: Sequence[ControlFamily] = FAMILIES) -> frozenset[str]:
    """Every instrument whose rows count as a reading of a device.

    Derived from the families, so a family added later brings its instruments
    into the population without a second list to update.
    """
    return frozenset(s for f in families for s in f.evidence) | frozenset(MANAGEMENT_SOURCES)


def _identifiers(asset: CryptoAsset, sources: frozenset[str]) -> list[str]:
    """Every key identifying the machine a row is about, or ``[]``.

    A row from an instrument no family names is not a device reading, and a row
    carrying neither a sensor identifier nor a host is an aggregate, which would
    put a denominator in the report that no machine corresponds to.
    """
    if asset.source not in sources:
        return []
    aid = str(asset.extra.get("aid") or "").strip()
    host = (asset.host or "").strip().casefold()
    return [k for k in (aid, host) if k]


def _canonical(assets: Sequence[CryptoAsset], sources: frozenset[str]) -> dict[str, str]:
    """Every identifier seen, mapped to one canonical key per machine.

    Two identifiers on one row are one machine, merged transitively (union-find).
    Keying on "identifier, else host" would file a machine under two keys when
    one export carries both and another only the host, and inflate the population.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in assets:
        keys = _identifiers(a, sources)
        for k in keys:
            find(k)
        for k in keys[1:]:
            ra, rb = find(keys[0]), find(k)
            if ra != rb:
                parent[rb] = ra
    return {k: find(k) for k in parent}


def device_population(assets: Sequence[CryptoAsset],
                      families: Sequence[ControlFamily] = FAMILIES) -> set[str]:
    """The distinct devices the endpoint instruments reached, one key per machine."""
    return set(_canonical(assets, evidence_sources(families)).values())


def collect(target: Mapping, assets: Sequence[CryptoAsset]) -> tuple[list[CryptoAsset], list]:
    """Coverage gaps over what every other step read: ``([], gaps)``.

    The empty row list is deliberate: this check must not move any count, and
    producing nothing that anything counts is the only way to guarantee it.
    """
    families, excluded, unknown = resolve(target)
    sources = evidence_sources(families)
    gaps: list = _profile_gaps(unknown, [f.slug for f in FAMILIES])

    canonical = _canonical(assets, sources)
    population = set(canonical.values())
    # Devices each instrument reached, and separately whether it wrote any row.
    # An instrument with only fleet-level rows has reached the family at a coarser
    # grain; calling that "nothing reaches it" would send a reader after an export
    # they already hold.
    reached: dict[str, set[str]] = {}
    rows: dict[str, int] = {}
    for a in assets:
        if a.source not in sources:
            continue
        rows[a.source] = rows.get(a.source, 0) + 1
        for k in _identifiers(a, sources):
            reached.setdefault(a.source, set()).add(canonical[k])

    for fam in families:
        if fam.slug in excluded:
            continue
        covered: set[str] = set()
        produced = 0
        for source in fam.evidence:
            covered |= reached.get(source, set())
            produced += rows.get(source, 0)
        if not fam.evidence or not produced:
            gaps.append(_unreached_gap(fam, len(population)))
        elif not covered:
            gaps.append(_aggregate_only_gap(fam, produced))
        elif population and covered < population:
            gaps.append(_population_gap(fam, len(covered), len(population)))

    graded = _graded_support(target, assets, sources)
    gaps += _support_gaps(graded, _canonical(graded, sources), sources)
    gaps += _management_gaps(population, reached)
    return [], gaps


def _graded_support(target: Mapping, assets: Sequence[CryptoAsset],
                    sources: frozenset[str]) -> list[CryptoAsset]:
    """Copies of the device rows carrying the support status the finished rows will.

    A late step sees rows before the profile's declared ``lifecycle:
    support_status:`` block and the bundled Windows table are applied, so
    counting them as handed in would read "none have a status" however much
    the profile declares. The two steps are applied to copies, in the order an
    observation applies them; the rows handed in are never changed.
    """
    rows = [copy.deepcopy(a) for a in assets if a.source in sources]
    lifecycle.apply_support_status(
        rows, dict(target.get("lifecycle") or {}).get("support_status") or {})
    lifecycle.derive_windows_support(rows, config.load_windows_lifecycle())
    return rows


def support_gaps(assets: Sequence[CryptoAsset], target: Mapping | None = None) -> list:
    """The support-horizon gap over finished rows, for a reader of a stored observation.

    The rows are read, never changed, and must already carry whatever status
    they will have (derive it again first if the table has changed). ``target``
    supplies any profile-added evidence; without it the shipped families are used.
    """
    sources = evidence_sources(resolve(target or {})[0])
    canonical = _canonical(assets, sources)
    return _support_gaps(assets, canonical, sources)


def _profile_gaps(unknown: Sequence[str], valid: Sequence[str]) -> list:
    if not unknown:
        return []
    return [coverage.gap(
        coverage.COULD_NOT_TEST,
        f"{PROFILE_TOKEN} the `{PROFILE_KEY}` block names family id(s) this build does not "
        f"recognise: {', '.join(sorted(unknown))}. They had no effect. If they were meant "
        f"to name a real family, that family is being reported as the profile did not "
        f"intend. Valid ids: {', '.join(valid)}.",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact="A line meant to say that a control is not operated, or that an instrument "
               "evidences it, matches nothing and does nothing. Nothing in the report is "
               "wrong because of it; it is not doing what its author intended.",
        harvest="Correct the id in the target profile, or delete the line.",
        nature=coverage.NO_DATA)]


def _unreached_gap(fam: ControlFamily, total: int) -> str:
    scope = (f"none of the {total:,} device(s) this observation reached has "
             if total else "no device has ")
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"{FAMILY_TOKEN} {fam.name}. {fam.question}? No instrument in this run wrote a row "
        f"for it, so {scope}been looked at for this control. This limits what was measured "
        f"and is not evidence that the control is absent.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=fam.impact,
        harvest=fam.harvest,
        nature=coverage.NO_DATA)


def _aggregate_only_gap(fam: ControlFamily, produced: int) -> str:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{AGGREGATE_TOKEN} {fam.name} is measured for the fleet as a whole ({produced:,} "
        f"row(s)) and for no individual device. The fleet figure stands; what is missing is "
        f"which machines it is true of, so it cannot be joined to any other fact about a "
        f"device.",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=f"{fam.impact} The fleet-level reading is usable; it cannot be broken down "
               "to say which machines are covered.",
        harvest=f"The same source at per-device grain. {fam.harvest}",
        nature=coverage.LOW_FIDELITY)


def _population_gap(fam: ControlFamily, covered: int, total: int) -> str:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{POPULATION_TOKEN} {fam.name} is evidenced for {covered:,} of the {total:,} "
        f"device(s) this observation reached. The other {total - covered:,} carry no "
        f"reading for it, so any figure for this control describes the smaller set. They "
        f"are not devices that failed the control; nothing measured it on them.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=fam.impact,
        harvest=fam.harvest,
        nature=coverage.NO_DATA)


def _support_gaps(assets: Sequence[CryptoAsset], canonical: Mapping[str, str],
                  sources: frozenset[str]) -> list:
    """Devices held with no support status against their operating system."""
    population = set(canonical.values())
    if not population:
        return []
    dated = {canonical[k] for a in assets if (a.support_status or "").strip()
             for k in _identifiers(a, sources)}
    missing = population - dated
    if not missing:
        return []
    return [coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{SUPPORT_TOKEN} {len(dated):,} of {len(population):,} device(s) carry a support "
        f"status for the operating system they run; {len(missing):,} do not. Those devices "
        f"are in the report and their operating system is recorded; what is missing is how "
        f"long it stays supported, so nothing says whether they can still be patched.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact="For part of the fleet the report says what each device runs and not how long "
               "it stays supported, so any estimate of how much must be replaced before it "
               "becomes unpatchable is made over a fraction of the fleet and can only "
               "understate it.",
        harvest="A support-lifecycle table for the operating systems in the fleet, declared "
                "under `lifecycle: support_status:` in the target profile. It is a mapping "
                "to write, not an export to obtain.",
        nature=coverage.LOW_FIDELITY)]


def _management_gaps(population: set[str], reached: Mapping[str, set[str]]) -> list:
    """Devices a sensor reached that no device-management record lists.

    Silent when no management export ran: that is a different gap, which the
    reader of that export raises, and a subtraction against nothing measures
    nothing. It fires only where a management export did arrive.
    """
    managed: set[str] = set()
    for source in MANAGEMENT_SOURCES:
        managed |= reached.get(source, set())
    if not managed or not population:
        return []
    missing = population - managed
    if not missing:
        return []
    return [coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{MANAGEMENT_TOKEN} {len(managed):,} of {len(population):,} device(s) this "
        f"observation reached appear in a device-management export; {len(missing):,} "
        f"appear only in other instruments' data. Whether those devices are enrolled in "
        f"management, and what policy they should meet, is not recorded here. A device "
        f"absent from one export is not necessarily unmanaged: another platform may manage "
        f"it.",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=f"{len(missing):,} of {len(population):,} device(s) are missing from the "
               "management export. Anything the report says about policy, baselines or "
               "enrolment covers only the devices listed, and a plan sized on it may be "
               "sized for the wrong estate.",
        harvest="A device inventory from each management platform in use, so the "
                "populations can be compared.",
        nature=coverage.NO_DATA)]


def step(ctx: Context) -> StepResult:
    _, gaps = collect(ctx.target, list(ctx.assets))
    return StepResult(gaps=list(gaps))


#: The declaration: a coverage check, so always late, gaps only.
PLUGIN = Plugin(name=NAME, kind="coverage-check", step=step, gap_prefix=False,
                title="endpoint control families against the devices reached")
