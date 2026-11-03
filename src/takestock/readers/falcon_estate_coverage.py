"""CrowdStrike Falcon: how much of the estate the sensor covers, and how well.

Every inside-out reading takestock takes from the Falcon sensor describes the
machines that carry it. This reader says how many machines that is against
everything discovery can see, and how much the "covered" count can be
trusted: which sensor versions run, which sensors are in reduced
functionality mode, which have stopped reporting, and which discovered
devices cannot take the sensor at all.

**The input** (``input:``) is the sensor-managed host list, one row per
sensor, such as the console's host management list exported as CSV or the
API's host records flattened to CSV. Further exports, each optional, are
named in ``settings:``:

* ``discovered``: every asset discovery reports, sensored or not (the
  denominator), such as the console's discovered asset list;
* ``rfm``: a host list carrying each sensor's reduced functionality mode,
  when the main host list does not carry it;
* ``heartbeats``: each sensor's latest ``SensorHeartbeat`` event, from the
  LogScale query in ``docs/COLLECTORS.md``;
* ``unsupported``: the discovered devices the console classes as unable to
  run the sensor.

Each may be a path, a list of paths or a pattern (the last match in name
order is read).

**Headings.** ``settings: columns: {<export>: {<field>: <heading>}}`` names
another heading, or a list of which the first holding a value is read, for
the exports ``hosts``, ``discovered``, ``rfm``, ``heartbeats`` and
``unsupported`` (:data:`TABLES` lists each export's fields and defaults).
The host list's defaults are the field names of the API's host record
(Elastic's CrowdStrike integration shows them in a sample record), except
``groups`` and ``criticality``: that record's ``groups`` holds group IDs,
not names, and it carries no criticality, so those two defaults are plain
names of takestock's own. The heartbeat defaults are the event's own field
names and LogScale's ``_count``. No public description of the console's
discovered and unsupported asset lists was found, so their defaults are
plain names of takestock's own. A cell holding ``--`` is read as blank.

**Rows**, all ``n/a`` (data state ``discovery``, protocol ``inventory``):

* ``Estate coverage``: discovered assets against sensored machines, with a
  gap when some discovered assets carry no sensor. An asset without the
  sensor is one nothing here has looked inside: a limit on what is known,
  never a finding against the asset.
* ``Discovered device vendors``: the manufacturers discovery names, folded
  across spellings (``Example Ltd`` and ``Example Ltd.``), with the rows
  that name none; every vendor count is therefore a floor.
* ``Sensor version spread``: the sensor versions running, and how many
  sensors are not on the newest present, with the machine types and
  platforms.
* ``Asset criticality assignment``: the console's criticality values;
  ``criticality-unassigned:<n>`` counts values listed in ``settings:
  criticality_unset:`` (no default: no public source gives the console's
  word for an unset value).
* ``Environment labelling``, when ``settings: environment:`` names words:
  how many machines the host groups place on each side of the production
  line (see *Environments* below).
* ``Sensor reduced-functionality mode``: the sensors whose mode value is in
  ``settings: rfm_yes:`` (default ``yes``; Elastic's sample host record shows
  ``reduced_functionality_mode`` ``no``, and ``yes`` is read as its
  opposite). Such a machine counts as covered in every coverage figure; what
  the sensor still does in that mode is not in the export.
* ``Sensor heartbeat recency``: sensors whose latest heartbeat is more than
  ``settings: silent_days:`` (default 7) before the newest in the file, and
  sensors that sent heartbeats but are not in the host list.
* ``Discovered devices that cannot take the sensor``: the unsupported asset
  list, with its vendors, confidence values and, when ``settings:
  unreviewed:`` names the review status words meaning not yet reviewed,
  how many were reviewed.

A gap is written for each of ``rfm``, ``heartbeats`` and ``unsupported``
that is not read, and one when neither the host list nor the discovered
list is read.

**Environments.** ``settings: environment: {production: [...],
non_production: [...]}`` names the words that mark a host group as
production or not. A group name is compared as lower-case words (anything
not a letter or digit separates words), and a setting's word or phrase
matches whole words only. Non-production phrases are matched first and
taken out, so a phrase such as ``pre production`` can mark a group
non-production without its word ``production`` then counting. A machine in
groups on both sides resolves to production and is marked contested:
labelling a live machine non-production would move it down a remediation
queue, which costs more than the opposite error. The groups are whatever
names the console's operators chose, so the label is inferred, never
reported. The ``falcon_environment`` annotation reads the same setting to
put each machine's label on the other readers' rows.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_estate_coverage"

COVERAGE_FLAG = "estate-coverage:"
VENDOR_FLAG = "vendor-unattributed:"
VERSIONS_FLAG = "sensor-versions:"
CRITICALITY_FLAG = "criticality-unassigned:"
ENVIRONMENT_FLAG = "environment-census:"
CONTESTED_FLAG = "environment-contested:"
RFM_FLAG = "sensor-rfm:"
SILENT_FLAG = "sensor-silent:"
UNSUPPORTED_FLAG = "unsupported-discovered:"

register_informational_prefixes(COVERAGE_FLAG, VENDOR_FLAG, VERSIONS_FLAG, ENVIRONMENT_FLAG,
                                CONTESTED_FLAG, RFM_FLAG, SILENT_FLAG, UNSUPPORTED_FLAG)

#: Each export's fields and default headings (``settings: columns:`` names others).
TABLES: dict[str, dict[str, Any]] = {
    "hosts": {"machine": "hostname", "sensor_id": "device_id",
              "sensor_version": "agent_version", "machine_type": "product_type_desc",
              "platform": "platform_name", "groups": "host_groups",
              "criticality": "criticality", "rfm": "reduced_functionality_mode"},
    "discovered": {"manufacturer": "manufacturer"},
    "rfm": {"machine": "hostname", "sensor_id": "device_id",
            "rfm": "reduced_functionality_mode"},
    "heartbeats": {"sensor_id": "aid", "timestamp": "@timestamp", "count": "_count"},
    "unsupported": {"name": "name", "manufacturer": "manufacturer",
                    "confidence": "confidence", "review_status": "review_status",
                    "last_seen": "last_seen"},
}

SILENT_DAYS = 7
RFM_YES: tuple[str, ...] = ("yes",)
#: How many vendors the vendor row's ``extra`` names, busiest first.
TOP_VENDORS = 12
#: How many the unsupported row's ``extra`` names.
TOP_UNSUPPORTED_VENDORS = 10


# ── vendors ──────────────────────────────────────────────────────────────────

_SUFFIX = re.compile(
    r"[,.]?\s*\b(inc|inc\.|incorporated|corp|corporation|co|co\.|company|ltd|"
    r"limited|llc|gmbh|technologies|technology|electronics|systems)\b\.?",
    re.IGNORECASE)


def normalise_vendor(raw: str) -> str:
    """One key per vendor across spellings (company suffixes and punctuation folded); "" for none."""
    v = re.sub(r"\s+", " ", str(raw or "").strip())
    if not v or v in ("--", "-"):
        return ""
    v = _SUFFIX.sub("", v).strip(" ,.")
    return v or str(raw).strip()


def _key(text: str) -> str:
    return text.lower().replace(" ", "_")


# ── environments ─────────────────────────────────────────────────────────────

PRODUCTION = "production"
NON_PRODUCTION = "non-production"
#: The configuration register's ``absence_reason`` codes (``cmdb-schema.yaml``):
#: a machine in no group gives the source nothing to answer from; a machine in
#: groups that name no environment gave an answer without this attribute.
NO_GROUP = "could-not-test"
GROUP_SILENT = "not-measured"

_WORDS = re.compile(r"[^a-z0-9]+")


def _normalise(text: str) -> str:
    return _WORDS.sub(" ", text.casefold()).strip()


def groups_of(cell: str) -> list[str]:
    """The group names in one host-groups cell (comma-separated, spaces around each trimmed)."""
    return [g.strip() for g in cell.split(",") if g.strip()]


@dataclass(frozen=True)
class Words:
    """The words that mark a group production or not (``settings: environment:``)."""

    production: tuple[re.Pattern[str], ...] = ()
    non_production: tuple[re.Pattern[str], ...] = ()

    @property
    def any(self) -> bool:
        return bool(self.production or self.non_production)


def environment_words(settings: Mapping[str, Any] | None) -> Words:
    """The ``environment`` setting's words, as whole-word patterns; empty when not set."""
    conf = (settings or {}).get("environment") or {}
    if not isinstance(conf, Mapping):
        return Words()

    def patterns(raw: Any) -> tuple[re.Pattern[str], ...]:
        values = [raw] if isinstance(raw, str) else list(raw or [])
        out = []
        for v in values:
            phrase = _normalise(str(v))
            if phrase:
                out.append(re.compile(rf"\b{re.escape(phrase)}\b"))
        return tuple(out)

    return Words(patterns(conf.get("production")), patterns(conf.get("non_production")))


@dataclass(frozen=True)
class EnvironmentLabel:
    """What one machine's host groups say about its environment."""

    value: str = ""          # PRODUCTION, NON_PRODUCTION, or "" when absent
    absence: str = ""        # an absence_reason code when value is ""
    note: str = ""
    contested: bool = False  # groups on both sides; resolved to production

    def payload(self, valid_at: str, source: str, source_name: str) -> dict[str, str]:
        """The label as it travels on another reader's row (``extra.environment``).

        It carries its own date and source because the row it sits on was
        read by another reader, at another time.
        """
        return {"value": self.value, "absent": self.absence, "note": self.note,
                "contested": "yes" if self.contested else "",
                "valid_at": valid_at, "source": source, "source_name": source_name}


def classify(cell: str, words: Words) -> EnvironmentLabel:
    """One machine's environment, from the groups it is in."""
    groups = groups_of(cell)
    if not groups:
        return EnvironmentLabel(
            absence=NO_GROUP,
            note="the machine is in no host group, so the host list says nothing about "
                 "its environment")
    prod = nonprod = False
    for group in groups:
        rest = _normalise(group)
        for pattern in words.non_production:
            if pattern.search(rest):
                nonprod = True
                rest = pattern.sub(" ", rest)
        if any(p.search(rest) for p in words.production):
            prod = True
    if prod and nonprod:
        return EnvironmentLabel(
            value=PRODUCTION, contested=True,
            note="in host groups on both sides of the production line (" + ", ".join(groups)
                 + "); resolved to production, since labelling a live machine "
                   "non-production would move it down a remediation queue")
    if prod:
        return EnvironmentLabel(value=PRODUCTION, note="a host group names it production")
    if nonprod:
        return EnvironmentLabel(value=NON_PRODUCTION,
                                note="a host group names it non-production")
    return EnvironmentLabel(
        absence=GROUP_SILENT,
        note=f"the machine is in {len(groups)} host group(s) and none of them names an "
             "environment: " + ", ".join(groups))


@dataclass
class EnvironmentIndex:
    """Every machine in the host list, keyed by sensor ID and by lower-cased name."""

    by_key: dict[str, EnvironmentLabel] = field(default_factory=dict)
    rows: int = 0
    production: int = 0
    non_production: int = 0
    contested: int = 0
    group_silent: int = 0
    no_group: int = 0
    #: the groups the machines with no environment are in, with their member counts
    silent_groups: dict[str, int] = field(default_factory=dict)
    #: names worn by several sensors whose labels disagree; such a name resolves to nothing
    ambiguous_hostnames: int = 0

    @property
    def resolved(self) -> int:
        """Machines carrying a label, contested ones included."""
        return self.production + self.non_production + self.contested

    @property
    def labelled_production(self) -> int:
        """Machines the label puts in production: the agreed ones and the contested ones."""
        return self.production + self.contested


def environment_index(rows: Sequence[Mapping[str, str]], heads: Mapping[str, Any],
                      words: Words) -> EnvironmentIndex:
    """The index over already-read host-list rows."""
    index = EnvironmentIndex()
    by_name: dict[str, list[EnvironmentLabel]] = {}
    for row in rows:
        index.rows += 1
        cell = _fi.value(row, heads["groups"])
        label = classify(cell, words)
        if label.contested:
            index.contested += 1
        elif label.value == PRODUCTION:
            index.production += 1
        elif label.value == NON_PRODUCTION:
            index.non_production += 1
        elif label.absence == NO_GROUP:
            index.no_group += 1
        else:
            index.group_silent += 1
            for group in groups_of(cell):
                index.silent_groups[group] = index.silent_groups.get(group, 0) + 1
        sensor = _fi.value(row, heads["sensor_id"])
        name = _fi.value(row, heads["machine"])
        if sensor:
            index.by_key[sensor] = label
        if name:
            by_name.setdefault(name.casefold(), []).append(label)
    # A name is not unique to one sensor; a sensor ID is. Where the sensors
    # sharing a name agree, the name still answers; where they disagree it
    # cannot say which machine is which, so it resolves to nothing.
    for name, labels in by_name.items():
        if len({(lb.value, lb.absence) for lb in labels}) == 1:
            index.by_key[name] = labels[0]
        else:
            index.ambiguous_hostnames += 1
    return index


# ── reading ──────────────────────────────────────────────────────────────────

def _file(ctx: Context, key: str) -> Path | None:
    return _entra.newest(ctx, key)


def _read(path: Path | None) -> tuple[list[dict[str, str]], str]:
    if path is None:
        return [], ""
    return _fi.rows(path)


def _named(label: str, path: Path | None) -> str:
    return _fi.source_name(label, file_mtime_date(path) if path is not None else None)


def _gap_missing(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon host list (`input:`) or discovered asset list "
        "(`settings: discovered:`) was read" + (f" ({why})" if why else "")
        + ": how many assets exist against how many carry the sensor",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without the pair, every coverage figure is a count of the machines that "
                "were seen with nothing to divide it by, so nobody can say what share of "
                "the estate the inside-out readings describe."),
        harvest=("Export the console's host list and its discovered asset list as CSV; "
                 "name the first with input: and the second with settings: discovered:."),
        nature=coverage.NO_DATA)


def _gap_optional(what: str, setting: str, why: str, impact: str, harvest: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no {what} was read (`settings: {setting}:`)" + (f" ({why})" if why else ""),
        impact_kind=coverage.NARROWS_CONFIDENCE, impact=impact, harvest=harvest,
        nature=coverage.NO_DATA)


def _version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in version.split("."))


def _epoch_ms(raw: str) -> int | None:
    """A ``@timestamp`` as milliseconds since 1970 (UTC): integer milliseconds, or ISO 8601."""
    s = (raw or "").strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def _day(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).date().isoformat()


def _words(raw: Any, default: Sequence[str] = ()) -> tuple[str, ...]:
    if raw is None:
        return tuple(default)
    values = [raw] if isinstance(raw, str) else list(raw)
    return tuple(str(v).strip().lower() for v in values if str(v).strip())


def _row(name: str, role: str, source_name: str, when: str, flags: list[str],
         hosts: int, notes: str, extra: dict[str, str]) -> CryptoAsset:
    return CryptoAsset(name=name, data_state="discovery", protocol="inventory", role=role,
                       source=NAME, source_class="private", source_name=source_name,
                       collected_at=when, verdict="n/a", flags=flags, hosts_count=hosts,
                       notes=notes, extra=extra)


def read(ctx: Context) -> tuple[list[CryptoAsset], list]:
    """Every row and gap for one run."""
    s = ctx.settings or {}
    heads = _fi.headings(ctx, TABLES)
    h = heads["hosts"]
    hosts_path = ctx.input
    disc_path = _file(ctx, "discovered")
    hosts, hosts_err = _read(hosts_path)
    disc, disc_err = _read(disc_path)
    assets: list[CryptoAsset] = []
    gaps: list = []
    if not hosts and not disc:
        gaps.append(_gap_missing("; ".join(e for e in (hosts_err, disc_err) if e)))
        return assets, gaps

    main_path = hosts_path if hosts else disc_path
    when = (file_mtime_date(main_path) if main_path is not None else None) or ""
    source_name = _fi.source_name("asset inventory", when)

    def ident(r: Mapping[str, str], hd: Mapping[str, Any]) -> str:
        return _fi.value(r, hd["sensor_id"]) or _fi.value(r, hd["machine"])

    managed = len({ident(r, h) for r in hosts if ident(r, h)})
    total = len(disc)
    vendors: dict[str, int] = {}
    unattributed = 0
    for r in disc:
        v = normalise_vendor(_fi.value(r, heads["discovered"]["manufacturer"]))
        if v:
            vendors[v] = vendors.get(v, 0) + 1
        else:
            unattributed += 1
    vendors = dict(sorted(vendors.items(), key=lambda kv: (-kv[1], kv[0])))

    # 1 · discovered against sensored
    if total:
        share = managed / total
        unmanaged = total - managed
        assets.append(_row(
            "Estate coverage", roles.estate_coverage(), source_name, when,
            [f"{COVERAGE_FLAG}{round(share * 100)}"], total,
            (f"{total:,} assets are visible to discovery and {managed:,} machines carry the "
             f"sensor, {share:.0%}. Every reading taken from inside a machine describes "
             f"that {share:.0%}, not the estate."
             + (f" The other {unmanaged:,} have not been looked inside: a limit on what is "
                "known, and none of them is called unprotected." if unmanaged > 0 else "")
             + (" The host list holds more machines than the discovered list, so the "
                "discovered list does not include every sensored machine." if unmanaged < 0
                else "")),
            {"discovered": str(total), "sensor_managed": str(managed),
             "unmanaged": str(unmanaged), "coverage_share": f"{share:.3f}",
             "unattributed_vendor_rows": str(unattributed)}))
        if unmanaged > 0:
            gaps.append(coverage.gap(
                coverage.EXTENT_UNKNOWN,
                f"{unmanaged:,} of {total:,} discovered assets carry no CrowdStrike Falcon "
                f"sensor, so no inside-out reading has looked at them: their posture is "
                f"unknown rather than absent, and the {managed:,}-machine figures are not "
                "estate-wide",
                impact_kind=coverage.CHANGES_CONCLUSION,
                impact=(f"Every endpoint figure read from the sensor describes {managed:,} of "
                        f"{total:,} assets. Read none of them as estate-wide, and treat the "
                        "unsensored assets as unexamined, not as passing."),
                harvest=("Decide what each unsensored asset is (a server, a printer, a "
                         "personal device) and whether it should carry the sensor: a piece "
                         "of work, not a data request."),
                nature=coverage.NO_DATA))

    # 2 · vendors, a floor
    if vendors:
        top = list(vendors.items())[:TOP_VENDORS]
        assets.append(_row(
            "Discovered device vendors", roles.discovered_vendors(), source_name, when,
            [f"{VENDOR_FLAG}{unattributed}"], len(vendors),
            (f"{len(vendors)} distinct manufacturers across {total:,} discovered assets, and "
             f"{unattributed:,} rows name no manufacturer, so every count here is a floor, "
             "never a census. Discovery lists what it saw; it does not say which devices "
             "belong to the organisation."),
            {"vendors": str(len(vendors)), "unattributed": str(unattributed),
             **{f"vendor_{_key(k)}": str(v) for k, v in top}}))

    if hosts:
        # 3 · the sensor's own currency
        versions: dict[str, int] = {}
        types: dict[str, int] = {}
        platforms: dict[str, int] = {}
        crit: dict[str, int] = {}
        for r in hosts:
            for value, tally in ((_fi.value(r, h["sensor_version"]), versions),
                                 (_fi.value(r, h["machine_type"]), types),
                                 (_fi.value(r, h["platform"]), platforms),
                                 (_fi.value(r, h["criticality"]), crit)):
                if value:
                    tally[value] = tally.get(value, 0) + 1
        newest = max(versions, key=_version_key, default="")
        behind = sum(n for v, n in versions.items() if v != newest)
        assets.append(_row(
            "Sensor version spread", roles.sensor_version_spread(), source_name, when,
            [f"{VERSIONS_FLAG}{len(versions)}"], managed,
            (f"{managed:,} sensors run {len(versions)} distinct versions, and {behind:,} are "
             "not on the newest version present. This is the measuring instrument's own "
             "currency, not a cryptographic finding; it bears on how far the other readings "
             "can be trusted."),
            {"versions": str(len(versions)), "newest": newest, "not_newest": str(behind),
             **{f"type_{_key(k)}": str(v) for k, v in types.items()},
             **{f"platform_{k.lower()}": str(v) for k, v in platforms.items()}}))

        # 4 · criticality
        if crit:
            unset_words = _words(s.get("criticality_unset"))
            unset = sum(n for k, n in crit.items() if k.lower() in unset_words)
            counted = sum(crit.values())
            assets.append(_row(
                "Asset criticality assignment", roles.asset_criticality(), source_name,
                when, [f"{CRITICALITY_FLAG}{unset}"] if unset else [], counted,
                (f"{unset:,} of {counted:,} machines with a criticality value carry one "
                 "meaning unset" + (", all of them" if unset and unset == counted else "")
                 + ". " + ("A remediation queue ordered by what each machine is worth has "
                           "nothing to order those machines by. " if unset else "")
                 + "This is the console's own field, not an inference."
                 + ("" if unset_words else " No value is treated as unset until "
                    "settings: criticality_unset: names one.")),
                {f"criticality_{_key(k)}": str(v) for k, v in crit.items()}))

        # 5 · environments
        words = environment_words(s)
        if words.any:
            env = environment_index(hosts, h, words)
            widest = max(env.silent_groups.items(), key=lambda kv: kv[1], default=("", 0))
            if widest[0]:
                members = (f", all of them in the group '{widest[0]}'"
                           if widest[1] == env.group_silent else
                           f", {widest[1]:,} of them in the group '{widest[0]}'")
            else:
                members = ""
            assets.append(_row(
                "Environment labelling", roles.environment_label(),
                _fi.source_name("host group", when), when,
                [f"{ENVIRONMENT_FLAG}{env.resolved}"]
                + ([f"{CONTESTED_FLAG}{env.contested}"] if env.contested else []),
                env.rows,
                (f"{env.resolved:,} of {env.rows:,} machines in the host list can be placed "
                 f"on one side of the production line from their host groups: "
                 f"{env.production:,} production, {env.non_production:,} non-production, "
                 f"and {env.contested:,} in groups on both sides, resolved to production and "
                 "flagged. The groups are names the console's operators chose, not a "
                 "register of live systems, so the label is inferred, never reported. "
                 f"{env.no_group:,} machines are in no group, so the host list says nothing "
                 f"about them, and {env.group_silent:,} are in groups that name no "
                 f"environment{members}. An unlabelled machine is one the groups do not "
                 "describe, never a machine that failed anything."),
                {"hosts_in_export": str(env.rows),
                 "environment_resolved": str(env.resolved),
                 "environment_production": str(env.production),
                 "environment_non_production": str(env.non_production),
                 "environment_contested": str(env.contested),
                 "environment_labelled_production": str(env.labelled_production),
                 "environment_group_silent": str(env.group_silent),
                 "environment_no_group": str(env.no_group),
                 "environment_widest_silent_group": widest[0],
                 "environment_widest_silent_group_hosts": str(widest[1])}))

    # 6 · reduced functionality mode
    assets_rfm, gaps_rfm = _rfm(ctx, heads, hosts, hosts_path)
    assets += assets_rfm
    gaps += gaps_rfm
    # 7 · heartbeats
    sensor_ids = {_fi.value(r, h["sensor_id"]) for r in hosts} - {""}
    assets_hb, gaps_hb = _heartbeats(ctx, heads["heartbeats"], sensor_ids)
    assets += assets_hb
    gaps += gaps_hb
    # 8 · devices that cannot take the sensor
    assets_un, gaps_un = _unsupported(ctx, heads["unsupported"])
    assets += assets_un
    gaps += gaps_un
    return assets, gaps


def _rfm(ctx: Context, heads: Mapping[str, Any], hosts: list[dict[str, str]],
         hosts_path: Path | None) -> tuple[list[CryptoAsset], list]:
    path = _file(ctx, "rfm")
    hd = heads["rfm"]
    rows, err = _read(path)
    if path is None and hosts and any(_fi.value(r, heads["hosts"]["rfm"]) for r in hosts):
        path, rows, hd = hosts_path, hosts, heads["hosts"]
    if not rows:
        return [], [_gap_optional(
            "host list carrying each sensor's reduced functionality mode", "rfm", err,
            ("Every coverage figure counts a sensor in reduced functionality mode as "
             "covered, so without this the covered count may include machines whose sensor "
             "is not running fully, and nobody can say how many."),
            ("Export the host list with its reduced functionality mode column and name it "
             "with settings: rfm:, or use a host list that carries the column as input:."))]
    yes = _words((ctx.settings or {}).get("rfm_yes"), RFM_YES)
    when = (file_mtime_date(path) if path is not None else None) or ""
    machines = {(_fi.value(r, hd["sensor_id"]) or _fi.value(r, hd["machine"])): r
                for r in rows if _fi.value(r, hd["sensor_id"]) or _fi.value(r, hd["machine"])}
    in_rfm = sorted(_fi.value(r, hd["machine"]) for r in rows
                    if _fi.value(r, hd["rfm"]).lower() in yes)
    return [_row(
        "Sensor reduced-functionality mode", roles.sensor_rfm(),
        _fi.source_name("reduced functionality mode", when), when,
        [f"{RFM_FLAG}{len(in_rfm)}"], len(machines),
        (f"{len(in_rfm)} of {len(machines):,} sensored machines report reduced functionality "
         "mode. Such a machine counts as covered in every coverage figure; what its sensor "
         "still does in that mode is not in the export"
         + (f": {', '.join(in_rfm)}." if in_rfm else ".")),
        {"hosts_in_export": str(len(machines)), "in_rfm": str(len(in_rfm)),
         **({"rfm_hosts": ", ".join(in_rfm)} if in_rfm else {})})], []


def _heartbeats(ctx: Context, hd: Mapping[str, Any],
                sensor_ids: set[str]) -> tuple[list[CryptoAsset], list]:
    path = _file(ctx, "heartbeats")
    rows, err = _read(path)
    if not rows:
        return [], [_gap_optional(
            "export of each sensor's latest heartbeat", "heartbeats", err,
            ("A sensor that has stopped reporting still counts as covered in every coverage "
             "figure, so without this the covered count includes machines nothing has heard "
             "from lately, and nobody can say how many."),
            ("Run the heartbeat query in docs/COLLECTORS.md (falcon_estate_coverage), "
             "download the result as CSV and name it with settings: heartbeats:."))]
    silent_days = int(_entra.setting_number(ctx, "silent_days", SILENT_DAYS))
    last: dict[str, int] = {}
    beats: dict[str, int] = {}
    for r in rows:
        sensor = _fi.value(r, hd["sensor_id"])
        ts = _epoch_ms(_fi.value(r, hd["timestamp"]))
        if not sensor or ts is None:
            continue
        last[sensor] = max(last.get(sensor, ts), ts)
        beats[sensor] = beats.get(sensor, 0) + _fi.number(_fi.value(r, hd["count"]))
    if not last:
        return [], []
    newest, earliest = max(last.values()), min(last.values())
    silent = {a for a, t in last.items() if newest - t > silent_days * 86_400_000}
    unlisted = set(last) - sensor_ids if sensor_ids else set()
    silent_unlisted = silent & unlisted
    no_beat = sensor_ids - set(last)
    when = (file_mtime_date(path) if path is not None else None) or ""
    listing = (
        f" {len(unlisted):,} of the sensors that sent a heartbeat are not in the host list "
        f"the other figures count, and {len(silent_unlisted):,} of those are among the "
        "silent ones; a sensor record kept after its machine was retired or rebuilt looks "
        f"like this. {len(no_beat):,} machine(s) in the host list sent no heartbeat in the "
        "file." if sensor_ids else
        " No host list was read, so these sensors cannot be matched to the machines the "
        "other figures count.")
    return [_row(
        "Sensor heartbeat recency", roles.sensor_heartbeat(),
        _fi.source_name("sensor heartbeat", when), when,
        [f"{SILENT_FLAG}{len(silent)}"], len(last),
        (f"{len(last):,} sensors sent a heartbeat in the period this export covers; each "
         f"one's latest falls between {_day(earliest)} and {_day(newest)}. "
         f"{len(silent):,} went quiet more than {silent_days} days before the newest "
         "heartbeat in the file. A machine switched off or away from the network does that, "
         "and so does one retired or rebuilt while its sensor record was kept; the export "
         "cannot tell them apart, and neither is a machine that failed a control." + listing
         + " The file holds each sensor's latest heartbeat only, so the query's start is "
           "not in it and the period is at least the span above."),
        {"sensors": str(len(last)), "silent": str(len(silent)),
         "silent_days": str(silent_days), "earliest_last_heartbeat": _day(earliest),
         "newest_heartbeat": _day(newest), "not_in_host_list": str(len(unlisted)),
         "silent_not_in_host_list": str(len(silent_unlisted)),
         "host_list_without_heartbeat": str(len(no_beat)),
         "beats_total": str(sum(beats.values()))})], []


def _blank(v: str) -> bool:
    return (v or "").strip() in ("", "-", "--")


def _unsupported(ctx: Context, hd: Mapping[str, Any]) -> tuple[list[CryptoAsset], list]:
    path = _file(ctx, "unsupported")
    rows, err = _read(path)
    if not rows:
        return [], [_gap_optional(
            "list of discovered devices that cannot take the sensor", "unsupported", err,
            ("Without it, every discovered device without the sensor reads as one that "
             "could be given it, so the work of extending coverage cannot be sized."),
            ("Export the console's list of unsupported discovered assets as CSV and name "
             "it with settings: unsupported:."))]
    unreviewed = _words((ctx.settings or {}).get("unreviewed"))
    named = sum(1 for r in rows if not _blank(_fi.value(r, hd["name"])))
    vendors: dict[str, int] = {}
    unattributed = 0
    confidence: dict[str, int] = {}
    reviewed = 0
    seen: list[str] = []
    for r in rows:
        v = normalise_vendor(_fi.value(r, hd["manufacturer"]))
        if v:
            vendors[v] = vendors.get(v, 0) + 1
        else:
            unattributed += 1
        c = _fi.value(r, hd["confidence"]) or "(not recorded)"
        confidence[c] = confidence.get(c, 0) + 1
        status = _fi.value(r, hd["review_status"]).lower()
        if status and status not in unreviewed:
            reviewed += 1
        last_seen = _fi.value(r, hd["last_seen"])
        if not _blank(last_seen):
            seen.append(last_seen[:10])
    top = sorted(vendors.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_UNSUPPORTED_VENDORS]
    when = (file_mtime_date(path) if path is not None else None) or ""
    span = f" They were last seen between {min(seen)} and {max(seen)}." if seen else ""
    review = (f" {reviewed:,} have been reviewed in the console." if unreviewed else
              " Whether any has been reviewed is not counted until settings: unreviewed: "
              "names the review status meaning not yet reviewed.")
    extra = {"rows": str(len(rows)), "named": str(named),
             "unattributed_vendor_rows": str(unattributed), "vendors": str(len(vendors))}
    if unreviewed:
        extra["reviewed"] = str(reviewed)
    extra.update({f"confidence_{_key(k)}": str(v) for k, v in confidence.items()})
    extra.update({f"vendor_{_key(k)}": str(v) for k, v in top})
    return [_row(
        "Discovered devices that cannot take the sensor", roles.unsupported_devices(),
        _fi.source_name("unsupported asset", when), when,
        [f"{UNSUPPORTED_FLAG}{len(rows)}"], len(rows),
        (f"{len(rows):,} discovered devices are ones the console classes as unable to run "
         "the sensor, so no reading taken through the sensor can be made on them. "
         f"{named:,} carry a name; {len(rows) - unattributed:,} name a manufacturer, across "
         f"{len(vendors):,} manufacturers, and {unattributed:,} name none, so any vendor "
         f"count is a floor.{review}{span} This count is read on its own; it is not "
         "subtracted from the discovered total."),
        extra)], []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the rows, or a gap saying no host or discovered list was read."""
    assets, gaps = read(ctx)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs, reads whatever ``settings:`` names, and records what is missing in gaps.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon estate coverage",
                gap_prefix=False)
