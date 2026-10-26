"""The configuration register: a draft CMDB built from one observation.

A configuration management database (CMDB) holds the things an organisation
runs (configuration items), what is known about each, and how they connect.
This module builds a draft of one from an observation's ``assets.json``,
shaped by the schema in ``data/cmdb-schema.yaml``.

The model, in brief:

* Every **item** has a surrogate key (``CI-000001``) that carries no meaning
  and never changes. Every name it was seen under is kept as an alias, and
  items are matched on aliases in the schema's ``alias_kind`` order.
* Every fact is an **assertion**: an attribute value with its evidence
  strength, the date it was true (``valid_at``), the date it was recorded
  (``recorded_at``) and the named actor that made it. Keeping both dates
  makes the log bitemporal, in the sense of the SQL:2011 temporal features.
* Where assertions disagree, :func:`resolve` publishes one by a stated rule
  and marks the attribute **contested**, keeping every assertion.
* A missing value is an :class:`Absence` with a reason from the schema's
  ``absence_reason`` vocabulary, never an empty cell.
* Every **relationship** must be declared in the schema; a relationship
  declared and not drawn is listed with its reason.

Entry points: :func:`build_register` returns the whole register as one dict
with the schema beside the data, and :func:`write_outputs` writes it as JSON,
one CSV per class, and a workbook. From a shell::

    python -m takestock.cmdb <observation_dir> [<out_dir>] [--keys keys.jsonl]
                             [--ip-plan <plan>.json]

What the builder reads from each row of ``assets.json``:

=====================  ===================================================
row                    becomes
=====================  ===================================================
``data_state`` estate  a Declared Asset Class (``extra``: ``estate_class``,
                       ``estate_state``, ``declared_crypto``,
                       ``collectors_live``, its live instruments by collector
                       id or display name)
``third-party``        a Vendor when ``extra.vendor`` names one, else an
                       Unattributed Dependency keyed on
                       ``extra.registrable_domain``
``certificate``        a Certificate keyed on its host
``key-material``       a Credential keyed on its name
``discovery`` or       a DNS Name keyed on its host, never a machine
``email-auth`` (port
or not), or a DNS-
layer protocol with
no port
anything else with a   a machine, keyed on host name and ``extra.agent_id``;
host or agent id       its class from ``extra.host_type``, else from
                       ``extra.netdev_device_class``. A port
                       (``extra.service`` as ``443/tcp``, or ``port``) adds a
                       Network Service, contained once however many rows name
                       it; ``software`` adds a Software Product and Release
                       installed on it
``software`` and no    a Software Product and Release, installed on each
host                   machine ``extra.installed_on`` names (a list, or names
                       separated by commas), or on nothing when it names none;
                       ``extra.hosts`` stands in only as a list of names
``extra.software_``    a Software Product for each name listed, with no
``products``           release: an inventory's list of every product it names
``extra.dns_names`` on a DNS Name for each name listed, such as a zone
a name row             file reader's list of every name the zones publish
``extra.releases``     a Software Product and Release for each entry, with its
                       versions, support dates and exploited defects (see
                       ``docs/CMDB.md``)
``technology_zone``    in ``extra``: the item's GEANZ technology zone, one
                       of the ``technology_zone`` vocabulary's codes
``technology_``        in ``extra``: the item's GEANZ technology location,
``location``           one of the ``technology_location`` vocabulary's codes
=====================  ===================================================

A row flagged ``version-spread:`` counts the versions of a product in
service; it is not an install and makes no release.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import depth, obsarchive
from .agility import SPREAD_FLAG
from .config import data_file, load_yaml_strict
from .exits import EXIT_CLEAN, guarded

MEASURED = "measured"
REPORTED = "reported"
DECLARED = "declared"
INFERRED = "inferred"

#: Evidence strengths, strongest first.
EVIDENCE_STRENGTH: tuple[str, ...] = (MEASURED, REPORTED, DECLARED, INFERRED)
_STRENGTH_RANK: dict[str, int] = {v: i for i, v in enumerate(EVIDENCE_STRENGTH)}

PROPOSED = "proposed"
DECIDED = "decided"
BASES: tuple[str, ...] = (PROPOSED, DECIDED)

PERSON = "person"
COLLECTOR = "collector"
ACTOR_KINDS: tuple[str, ...] = (PERSON, COLLECTOR)

LIFECYCLE_STATES: tuple[str, ...] = (
    "planned", "discovered", "live", "retiring", "retired", "disposed")

SCHEMA_FILE = "cmdb-schema.yaml"

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}$")


class SchemaError(ValueError):
    """The schema does not hold together, or the builder stepped outside it."""


# ── The schema ─────────────────────────────────────────────────────────────


@lru_cache(maxsize=4)
def _read_schema(path: str) -> dict[str, Any]:
    loaded = load_yaml_strict(Path(path))
    if not isinstance(loaded, dict):
        raise SchemaError(f"{path} did not parse as a mapping")
    return loaded


def raw_schema() -> dict[str, Any]:
    """The schema file as parsed YAML (workspace copy first, else the bundled one)."""
    return _read_schema(str(data_file(SCHEMA_FILE)))


class Schema:
    """The parsed schema, with a consistency check over it."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.version = str(raw.get("schema_version", ""))
        self.maturity = str(raw.get("maturity", ""))
        self.governance: dict[str, Any] = dict(raw.get("governance") or {})
        self.families: dict[str, Any] = dict(raw.get("families") or {})
        self.classes: dict[str, Any] = dict(raw.get("classes") or {})
        self.attributes: dict[str, Any] = dict(raw.get("attributes") or {})
        self.relationships: dict[str, Any] = dict(raw.get("relationships") or {})
        self.authorities: dict[str, Any] = dict(raw.get("authorities") or {})
        self.vocabularies: dict[str, dict[str, Any]] = {
            name: dict(body) for name, body in (raw.get("vocabularies") or {}).items()
            if isinstance(body, dict)}
        #: The file name of the schema overlay merged in, or "" for none.
        self.overlay = ""

    def problems(self) -> list[str]:
        """Every way the schema fails to hold together; empty when it is sound."""
        out: list[str] = []
        if not self.version:
            out.append("no schema_version")
        if "governance" not in self.raw:
            out.append("no governance block, so the register would not say who owns it")
        for name, spec in self.classes.items():
            if spec.get("family") not in self.families:
                out.append(f"class {name!r} names family {spec.get('family')!r}, "
                           "which is not declared")
            for attribute in spec.get("attributes") or []:
                if attribute not in self.attributes:
                    out.append(f"class {name!r} carries attribute {attribute!r}, "
                               "which is not declared")
        known = set(self.families) | set(self.classes)
        for name, spec in self.relationships.items():
            for end in ("from", "to"):
                if spec.get(end) not in known:
                    out.append(f"relationship {name!r} {end} {spec.get(end)!r} is neither "
                               "a declared family nor a declared class")
            if not spec.get("test"):
                out.append(f"relationship {name!r} has no one-sentence test")
            if "built" not in spec:
                out.append(f"relationship {name!r} does not say whether it is drawn")
            elif not spec["built"] and not spec.get("note"):
                out.append(f"relationship {name!r} is not drawn and does not say why")
        for name, spec in self.attributes.items():
            if "refresh_interval_days" not in spec:
                out.append(f"attribute {name!r} declares no refresh interval")
            if spec.get("expected_strength") not in _STRENGTH_RANK:
                out.append(f"attribute {name!r} has no valid expected_strength")
            if spec.get("vocabulary") and spec["vocabulary"] not in self.vocabularies:
                out.append(f"attribute {name!r} takes its values from vocabulary "
                           f"{spec['vocabulary']!r}, which is not declared")
        for vocab in ("evidence_strength", "basis", "lifecycle_state", "actor_kind"):
            declared = set(self.vocabularies.get(vocab, {}))
            expected = set({"evidence_strength": EVIDENCE_STRENGTH, "basis": BASES,
                            "lifecycle_state": LIFECYCLE_STATES,
                            "actor_kind": ACTOR_KINDS}[vocab])
            if declared != expected:
                out.append(f"vocabulary {vocab!r} declares {sorted(declared)}, "
                           f"the code uses {sorted(expected)}")
        out += [f"citation {key!r} on {where} resolves to no authority"
                for key, where in self.unresolved_citations()]
        return out

    def check(self) -> None:
        """Raise :class:`SchemaError` listing every problem, if there are any."""
        problems = self.problems()
        if problems:
            raise SchemaError("the configuration register schema does not hold together:\n  "
                              + "\n  ".join(problems))

    def unresolved_citations(self) -> list[tuple[str, str]]:
        """(key, where) for every ``cites:`` entry naming no authority."""
        out: list[tuple[str, str]] = []

        def walk(node: Any, where: str) -> None:
            if isinstance(node, dict):
                for key in node.get("cites") or []:
                    if key not in self.authorities:
                        out.append((str(key), where))
                for key, value in node.items():
                    if key != "cites":
                        walk(value, f"{where}.{key}" if where else str(key))
            elif isinstance(node, list):
                for item in node:
                    walk(item, where)

        walk(self.raw, "")
        return out

    def unassigned_roles(self) -> list[str]:
        """Governance roles with nobody named."""
        return sorted(k for k, v in self.governance.items()
                      if k != "cites" and v in (None, "", []))

    def declared_not_built(self) -> list[tuple[str, str]]:
        """(relationship, reason) for every relationship this build does not draw."""
        return sorted((k, str(v.get("note") or "")) for k, v in self.relationships.items()
                      if not v.get("built"))

    def class_attributes(self, item_class: str) -> list[str]:
        """The attributes ``item_class`` carries, in the schema's order."""
        return list((self.classes.get(item_class) or {}).get("attributes") or [])

    def allowed_values(self, attribute: str) -> frozenset[str] | None:
        """The codes ``attribute`` may take, or None when it is not a controlled one."""
        vocabulary = (self.attributes.get(attribute) or {}).get("vocabulary")
        return frozenset(self.vocabularies.get(str(vocabulary), {})) if vocabulary else None


def load_schema(overlay: Path | str | None = None) -> Schema:
    """The schema, checked. Raises :class:`SchemaError` if it does not hold together.

    ``overlay`` names a schema overlay file (:func:`apply_overlay`), whose
    wording is merged over the schema before the check.
    """
    raw = raw_schema()
    source = ""
    if overlay is not None:
        path = Path(overlay)
        raw = apply_overlay(raw, read_overlay(path), where=str(path))
        source = path.name
    schema = Schema(raw)
    schema.overlay = source
    schema.check()
    return schema


# ── A schema overlay: wording only ─────────────────────────────────────────
#
# An overlay rewords the schema for one organisation (an attribute's note, a
# class's question, a vocabulary code's definition, who holds a governance
# role) without copying the whole file. It never changes the model: a class,
# relationship, attribute, family or vocabulary code it names must already be
# declared, and only the text fields below may be given.

#: For each section, the text fields an overlay may set on an entry.
OVERLAY_FIELDS: dict[str, tuple[str, ...]] = {
    "families": ("answers", "definition", "note"),
    "classes": ("answers", "built_from", "note"),
    "attributes": ("note",),
    "relationships": ("asserts", "test", "wrong_if", "qualifier", "note"),
}
#: The text fields an overlay may set on one code of a vocabulary.
OVERLAY_CODE_FIELDS: tuple[str, ...] = ("definition", "note", "source")


class OverlayError(SchemaError):
    """A schema overlay tries to do more than reword the schema."""


def read_overlay(path: Path | str) -> dict[str, Any]:
    """A schema overlay file, parsed. Raises :class:`OverlayError` if it is not a mapping."""
    p = Path(path)
    if not p.is_file():
        raise OverlayError(f"no schema overlay at {p}")
    loaded = load_yaml_strict(p)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise OverlayError(f"{p}: a schema overlay is a mapping of section to entries")
    return loaded


def apply_overlay(raw: Mapping[str, Any], overlay: Mapping[str, Any], *,
                  where: str = "the overlay") -> dict[str, Any]:
    """``raw`` with the overlay's wording merged over it; ``raw`` is left unchanged.

    Each text field the overlay gives replaces the schema's. Sections and
    fields are those in :data:`OVERLAY_FIELDS`, plus ``vocabularies``
    (``<vocabulary>: {<code>: {definition, note, source}}``) and
    ``governance`` (``<role>: <who holds it>``). Anything else is refused
    with :class:`OverlayError`, which lists every refused entry at once: an
    entry naming something the schema does not declare (a class,
    relationship, attribute, family, vocabulary code or governance role),
    and a field that would change the model rather than its wording.
    """
    import copy

    out: dict[str, Any] = copy.deepcopy(dict(raw))
    problems: list[str] = []

    def text(value: Any, at: str) -> bool:
        if isinstance(value, str):
            return True
        problems.append(f"{at} must be text, not {type(value).__name__}")
        return False

    def entries(section: str) -> dict[str, Any]:
        body = overlay.get(section)
        if body is None:
            return {}
        if not isinstance(body, dict):
            problems.append(f"{section} must be a mapping of name to fields")
            return {}
        return body

    for section, fields in OVERLAY_FIELDS.items():
        declared = out.get(section) or {}
        for name, body in entries(section).items():
            at = f"{section}.{name}"
            if name not in declared:
                problems.append(f"{at} is not declared in the schema; an overlay may "
                                f"reword it, never add it")
                continue
            if not isinstance(body, dict):
                problems.append(f"{at} must be a mapping of field to text")
                continue
            for key, value in body.items():
                if key not in fields:
                    problems.append(f"{at}.{key} is not a wording field; an overlay may "
                                    f"set only {', '.join(fields)}")
                elif text(value, f"{at}.{key}"):
                    declared[name][key] = value

    vocabularies = out.get("vocabularies") or {}
    for vocab, codes in entries("vocabularies").items():
        if vocab not in vocabularies:
            problems.append(f"vocabularies.{vocab} is not declared in the schema; an overlay "
                            "may reword a vocabulary, never add one")
            continue
        if not isinstance(codes, dict):
            problems.append(f"vocabularies.{vocab} must be a mapping of code to fields")
            continue
        for code, body in codes.items():
            at = f"vocabularies.{vocab}.{code}"
            if code not in vocabularies[vocab]:
                problems.append(f"{at} is not a declared code; an overlay may reword a "
                                "code, never add one")
                continue
            held = vocabularies[vocab][code]
            if not isinstance(held, dict):
                problems.append(f"{at} has no wording fields to set")
                continue
            if not isinstance(body, dict):
                problems.append(f"{at} must be a mapping of field to text")
                continue
            for key, value in body.items():
                if key not in OVERLAY_CODE_FIELDS:
                    problems.append(f"{at}.{key} is not a wording field; an overlay may "
                                    f"set only {', '.join(OVERLAY_CODE_FIELDS)}")
                elif text(value, f"{at}.{key}"):
                    held[key] = value

    governance = out.get("governance") or {}
    for role, value in entries("governance").items():
        at = f"governance.{role}"
        if role == "cites" or role not in governance:
            problems.append(f"{at} is not a declared governance role")
        elif value is None or text(value, at):
            governance[role] = value

    for section in sorted(set(overlay) - set(OVERLAY_FIELDS)
                          - {"vocabularies", "governance"}):
        problems.append(f"{section} cannot be overlaid; an overlay may hold only "
                        f"{', '.join([*OVERLAY_FIELDS, 'vocabularies', 'governance'])}")
    if problems:
        raise OverlayError(f"{where} would change the configuration register schema, not "
                           "only its wording, so it is refused:\n  " + "\n  ".join(problems))
    return out


# ── Values, actors and assertions ──────────────────────────────────────────


@dataclass(frozen=True)
class Absence:
    """A value that is missing, and why: ``reason`` is an ``absence_reason`` code."""

    reason: str
    note: str = ""

    def __post_init__(self) -> None:
        known = absence_reasons()
        if self.reason not in known:
            raise ValueError(f"unknown absence reason {self.reason!r}: expected one of "
                             f"{sorted(known)} (see {SCHEMA_FILE}, absence_reason)")

    @property
    def definition(self) -> str:
        """The schema's definition of this reason."""
        return str(absence_reasons()[self.reason].get("definition", ""))


def absence_reasons() -> Mapping[str, Any]:
    """The schema's absence vocabulary: each code with its definition and source."""
    vocab = (raw_schema().get("vocabularies") or {}).get("absence_reason") or {}
    return vocab if isinstance(vocab, dict) else {}


def is_absent(value: object) -> bool:
    """True when ``value`` is an :class:`Absence` rather than a value."""
    return isinstance(value, Absence)


@dataclass(frozen=True)
class Actor:
    """Who or what made an assertion. A collector names the artefact it read."""

    kind: str
    name: str
    artefact: str = ""
    artefact_digest: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ACTOR_KINDS:
            raise ValueError(f"unknown actor kind {self.kind!r}: expected one of {list(ACTOR_KINDS)}")
        if not str(self.name).strip():
            raise ValueError("an actor must be named")

    def payload(self) -> dict[str, str]:
        return {"kind": self.kind, "name": self.name, "artefact": self.artefact,
                "artefact_digest": self.artefact_digest, "source": self.source}


def _check_date(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _ISO_DATE.match(value):
        raise ValueError(f"{field_name} must be an ISO 8601 date (YYYY-MM-DD), got {value!r}")
    return value


def _digest(payload: Any) -> str:
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _encode(value: Any) -> Any:
    if isinstance(value, Absence):
        return {"absent": value.reason, "note": value.note}
    return value


@dataclass(frozen=True)
class Assertion:
    """One fact about one item: a value, how strongly known, when, and by whom.

    ``valid_at`` is when the value was true; ``recorded_at`` is when the
    register learned it. ``retracts`` names the id of an assertion this one
    withdraws.
    """

    item: str
    attribute: str
    value: Any
    evidence_strength: str
    valid_at: str
    recorded_at: str
    actor: Actor
    basis: str = PROPOSED
    retracts: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.actor, Actor):
            raise TypeError(f"an assertion needs an Actor, got {type(self.actor).__name__}")
        if self.evidence_strength not in _STRENGTH_RANK:
            raise ValueError(f"unknown evidence strength {self.evidence_strength!r}: "
                             f"expected one of {list(EVIDENCE_STRENGTH)}")
        if self.basis not in BASES:
            raise ValueError(f"unknown basis {self.basis!r}: expected one of {list(BASES)}")
        _check_date(self.valid_at, "valid_at")
        _check_date(self.recorded_at, "recorded_at")

    @property
    def id(self) -> str:
        """A content digest identifying this assertion."""
        return _digest(self.payload())

    def payload(self) -> dict[str, Any]:
        return {"item": self.item, "attribute": self.attribute, "value": _encode(self.value),
                "evidence_strength": self.evidence_strength, "valid_at": self.valid_at,
                "recorded_at": self.recorded_at, "basis": self.basis,
                "actor": self.actor.payload(), "retracts": self.retracts,
                "reason": self.reason}


def retraction(target: Assertion, *, recorded_at: str, actor: Actor, reason: str) -> Assertion:
    """A new assertion withdrawing ``target``. Nothing is ever deleted."""
    if not reason.strip():
        raise ValueError("a retraction must state its reason")
    return Assertion(item=target.item, attribute=target.attribute,
                     value=Absence("could-not-test", note=reason),
                     evidence_strength=target.evidence_strength, valid_at=target.valid_at,
                     recorded_at=recorded_at, actor=actor, retracts=target.id, reason=reason)


def live(log: Sequence[Assertion]) -> list[Assertion]:
    """The assertions still standing: neither retractions nor retracted."""
    withdrawn = {a.retracts for a in log if a.retracts}
    return [a for a in log if not a.retracts and a.id not in withdrawn]


def as_of(log: Sequence[Assertion], recorded_at: str) -> list[Assertion]:
    """What the register knew on ``recorded_at``."""
    _check_date(recorded_at, "recorded_at")
    return live([a for a in log if a.recorded_at <= recorded_at])


def as_at(log: Sequence[Assertion], valid_at: str) -> list[Assertion]:
    """What is known, today, to have been true by ``valid_at``."""
    _check_date(valid_at, "valid_at")
    return [a for a in live(log) if a.valid_at <= valid_at]


@dataclass(frozen=True)
class Resolution:
    """The value published for one attribute, and whether it was contested."""

    attribute: str
    value: Any
    evidence_strength: str
    valid_at: str
    actor: str
    basis: str
    contested: bool
    tie: bool
    assertions: tuple[Assertion, ...]
    winner: Assertion | None = None

    def payload(self) -> dict[str, Any]:
        return {"value": _encode(self.value), "evidence_strength": self.evidence_strength,
                "valid_at": self.valid_at, "actor": self.actor, "basis": self.basis,
                "contested": self.contested, "tie": self.tie,
                "assertions": [{"value": _encode(a.value),
                                "evidence_strength": a.evidence_strength,
                                "valid_at": a.valid_at, "actor": a.actor.name,
                                "artefact": a.actor.artefact} for a in self.assertions]}


def _invert_date(value: str) -> str:
    # Sorting on this puts the newest date first.
    return "".join(str(9 - int(c)) if c.isdigit() else c for c in value)


def resolve(assertions: Sequence[Assertion], attribute: str = "") -> Resolution:
    """Publish one value from ``assertions`` by a fixed order of preference.

    A decided value beats a proposed one; a value beats an absence; stronger
    evidence beats weaker; within those, the most recent ``valid_at`` wins.
    The result is contested when the live assertions disagree, and a tie
    when the top two differ and nothing in that order separates them.
    """
    kept = live(assertions)
    if not kept:
        return Resolution(attribute=attribute, value=Absence("not-collected"),
                          evidence_strength=INFERRED, valid_at="", actor="", basis=PROPOSED,
                          contested=False, tie=False, assertions=())

    def rank(a: Assertion) -> tuple[int, int, int, str]:
        return (0 if a.basis == DECIDED else 1, 1 if is_absent(a.value) else 0,
                _STRENGTH_RANK[a.evidence_strength], _invert_date(a.valid_at))

    ordered = sorted(kept, key=rank)
    winner = ordered[0]
    contested = len({json.dumps(_encode(a.value), sort_keys=True, default=str)
                     for a in kept}) > 1
    runner = ordered[1] if len(ordered) > 1 else None
    tie = bool(runner is not None and contested and rank(winner) == rank(runner)
               and _encode(winner.value) != _encode(runner.value))
    return Resolution(attribute=attribute or winner.attribute, value=winner.value,
                      evidence_strength=winner.evidence_strength, valid_at=winner.valid_at,
                      actor=winner.actor.name, basis=winner.basis, contested=contested,
                      tie=tie, assertions=tuple(kept), winner=winner)


def capped_strength(schema: Schema, attribute: str, strength: str) -> str:
    """``strength``, lowered to the attribute's ``expected_strength`` if it claims more."""
    expected = str((schema.attributes.get(attribute) or {}).get("expected_strength") or "")
    if expected not in _STRENGTH_RANK or strength not in _STRENGTH_RANK:
        return strength
    return expected if _STRENGTH_RANK[strength] < _STRENGTH_RANK[expected] else strength


# ── Identity ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Alias:
    """One identifier an item has been seen under."""

    kind: str
    identifier: str
    source: str = ""
    first_seen: str = ""
    last_seen: str = ""


class KeyLedger:
    """Mints surrogate keys and matches identifiers to them.

    Feed it a previous build's :meth:`records` (``keys.jsonl``) and the same
    thing keeps the same key across builds.
    """

    prefix = "CI-"

    def __init__(self, schema: Schema | None = None) -> None:
        schema = schema or load_schema()
        self._by_alias: dict[tuple[str, str], str] = {}
        self._aliases: dict[str, list[Alias]] = {}
        self._redirects: dict[str, str] = {}
        self._next = 1
        self.merges: list[dict[str, str]] = []
        kinds = schema.vocabularies.get("alias_kind", {})
        self._rank = {k: int(v["rank"]) for k, v in kinds.items()
                      if isinstance(v, dict) and "rank" in v}
        self._refused = {k: dict(v) for k, v in
                         schema.vocabularies.get("refused_alias_kind", {}).items()
                         if isinstance(v, dict)}

    def aliases(self, key: str) -> list[Alias]:
        return list(self._aliases.get(self.redirect(key), []))

    def redirect(self, key: str) -> str:
        """The key ``key`` was merged into, or ``key`` itself."""
        seen: set[str] = set()
        while key in self._redirects and key not in seen:
            seen.add(key)
            key = self._redirects[key]
        return key

    def keys(self) -> list[str]:
        return sorted(self._aliases)

    def records(self) -> list[dict[str, Any]]:
        """The ledger as plain rows, for ``keys.jsonl``."""
        return [{"key": key, "aliases": [vars(a) for a in aliases]}
                for key, aliases in sorted(self._aliases.items())] + [
            {"redirect": old, "to": new} for old, new in sorted(self._redirects.items())]

    @classmethod
    def from_records(cls, records: Iterable[Mapping[str, Any]],
                     schema: Schema | None = None) -> KeyLedger:
        """A ledger rebuilt from :meth:`records` output."""
        ledger = cls(schema)
        for record in records:
            if "redirect" in record:
                ledger._redirects[str(record["redirect"])] = str(record["to"])
                continue
            key = str(record["key"])
            ledger._aliases[key] = [Alias(**a) for a in record.get("aliases", [])]
            for alias in ledger._aliases[key]:
                ledger._by_alias[(alias.kind, alias.identifier)] = key
            suffix = key.removeprefix(cls.prefix)
            if suffix.isdigit():
                ledger._next = max(ledger._next, int(suffix) + 1)
        for old in ledger._redirects:
            suffix = old.removeprefix(cls.prefix)
            if suffix.isdigit():
                ledger._next = max(ledger._next, int(suffix) + 1)
        return ledger

    def mint(self) -> str:
        """A new key, never used before in this ledger."""
        key = f"{self.prefix}{self._next:06d}"
        self._next += 1
        self._aliases.setdefault(key, [])
        return key

    def key_for(self, candidates: Sequence[tuple[str, str]], *, source: str = "",
                seen_at: str = "", merged_at: str = "", reason: str = "") -> str:
        """The key for an item seen under ``candidates`` (kind, identifier) pairs.

        Mints a key when none matches. When the identifiers match two or more
        existing keys they are merged, which needs ``merged_at`` and
        ``reason``: the merge is recorded and the retired key redirects.
        """
        pairs = [(str(k), str(v)) for k, v in candidates if str(v).strip()]
        for kind, _identifier in pairs:
            if kind in self._refused:
                raise ValueError(f"{kind!r} may never be an identifier: "
                                 f"{self._refused[kind].get('definition', '')}")
            if kind not in self._rank:
                raise ValueError(f"unknown alias kind {kind!r}: expected one of {sorted(self._rank)}")
        if not pairs:
            raise ValueError("an item needs at least one identifier")
        pairs.sort(key=lambda p: self._rank[p[0]])

        found = list(dict.fromkeys(self.redirect(self._by_alias[p])
                                   for p in pairs if p in self._by_alias))
        if not found:
            key = self.mint()
        elif len(found) == 1:
            key = found[0]
        else:
            key = self._merge(found, merged_at=merged_at, reason=reason)

        for kind, identifier in pairs:
            self._by_alias[(kind, identifier)] = key
            held = self._aliases[key]
            for i, alias in enumerate(held):
                if (alias.kind, alias.identifier) == (kind, identifier):
                    if seen_at:
                        held[i] = Alias(kind=kind, identifier=identifier,
                                        source=alias.source or source,
                                        first_seen=min(filter(None, (alias.first_seen, seen_at))),
                                        last_seen=max(alias.last_seen, seen_at))
                    break
            else:
                held.append(Alias(kind=kind, identifier=identifier, source=source,
                                  first_seen=seen_at, last_seen=seen_at))
        return key

    def _merge(self, keys: Sequence[str], *, merged_at: str, reason: str) -> str:
        if not merged_at or not reason.strip():
            raise ValueError(f"identifiers resolve to more than one item ({list(keys)}); "
                             "merging them needs merged_at= and reason=")
        _check_date(merged_at, "merged_at")
        winner = keys[0]
        for losing in keys[1:]:
            self._redirects[losing] = winner
            for alias in self._aliases.pop(losing, []):
                self._by_alias[(alias.kind, alias.identifier)] = winner
                if (alias.kind, alias.identifier) not in {
                        (a.kind, a.identifier) for a in self._aliases[winner]}:
                    self._aliases[winner].append(alias)
            self.merges.append({"at": merged_at, "reason": reason,
                                "kept": winner, "retired": losing})
        return winner


# ── The register ───────────────────────────────────────────────────────────


@dataclass
class ConfigurationItem:
    key: str
    item_class: str
    family: str
    lifecycle_state: str
    aliases: list[Alias] = field(default_factory=list)
    label: str = ""


@dataclass(frozen=True)
class Edge:
    """One drawn relationship. ``count`` and ``unit`` say how many, of what."""

    kind: str
    from_key: str
    to_key: str
    evidence_strength: str
    valid_at: str
    recorded_at: str
    actor: Actor
    count: int = 1
    qualifier: str = ""
    unit: str = ""


@dataclass(frozen=True)
class Population:
    """A count of things, by one instrument, held beside the others, never averaged."""

    population: str
    instrument: str
    count: int
    valid_at: str
    evidence_strength: str
    note: str = ""
    contested: bool = False
    unit: str = ""

    def payload(self) -> dict[str, Any]:
        return {"population": self.population, "instrument": self.instrument,
                "count": self.count, "unit": self.unit, "valid_at": self.valid_at,
                "evidence_strength": self.evidence_strength, "note": self.note,
                "contested": self.contested}


@dataclass
class Cmdb:
    """A built register: items, the assertion log, edges and population counts."""

    schema: Schema
    items: dict[str, ConfigurationItem]
    assertions: list[Assertion]
    edges: list[Edge]
    populations: list[Population]
    ledger: KeyLedger
    observation: str = ""
    recorded_at: str = ""
    #: The row sources and plug-ins whose host lists drew installed-on; None for every row.
    installed_on_from: tuple[str, ...] | None = None
    #: The date the observation's rows were read: a derived observation's full
    #: observation's date, otherwise the observation's own; empty when its
    #: directory is not named by a time stamp.
    read_on: str = ""
    #: Each plug-in a derived observation read again, with the date it last did.
    read_again: dict[str, str] = field(default_factory=dict)

    def resolved(self) -> dict[str, dict[str, Resolution]]:
        """The published value of every asserted attribute, per item."""
        by_item: dict[str, dict[str, list[Assertion]]] = {}
        for a in self.assertions:
            by_item.setdefault(a.item, {}).setdefault(a.attribute, []).append(a)
        return {item: {attr: resolve(group, attr) for attr, group in attrs.items()}
                for item, attrs in by_item.items()}

    def census(self) -> list[dict[str, Any]]:
        """Every declared class, with its item count and, when zero, why."""
        counted = _tally(i.item_class for i in self.items.values())
        out: list[dict[str, Any]] = []
        for name, spec in sorted(self.schema.classes.items()):
            n = counted.get(name, 0)
            source = spec.get("built_from")
            if n:
                reason = ""
            elif not source:
                reason = ("No observation row feeds this class; it is declared for the "
                          "organisation to populate. Not measured, rather than found empty.")
            else:
                reason = ("Rows of this kind feed the class and this observation held none. "
                          "That may mean the evidence was not gathered rather than that "
                          "nothing exists, so treat it as unmeasured, not clean.")
            out.append({"class": name, "family": str(spec.get("family") or ""), "items": n,
                        "source": str(source or ""), "answers": str(spec.get("answers") or ""),
                        "empty_because": reason})
        return out


def _tally(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


# ── Reading rows ───────────────────────────────────────────────────────────

# Which evidence strength a source's rows carry, when the row does not say.
# A collector that reads a management system's own records registers itself
# as "reported" with register_source_strength() when it is imported.
_SOURCE_STRENGTH: dict[str, str] = {}


def register_source_strength(source: str, strength: str) -> None:
    """Declare the evidence strength rows from ``source`` carry by default."""
    if strength not in _STRENGTH_RANK:
        raise ValueError(f"unknown evidence strength {strength!r}")
    _SOURCE_STRENGTH[source] = strength


def _strength_for(asset: Mapping[str, Any]) -> str:
    extra = asset.get("extra") or {}
    own = str(extra.get("evidence_strength") or "")
    if own in _STRENGTH_RANK:
        return own
    if _is_estate(asset):
        return DECLARED
    return _SOURCE_STRENGTH.get(str(asset.get("source") or ""), MEASURED)


# Host types as management tools spell them, folded to lower case, and the
# class each becomes. Anything else is a Host.
_HOST_TYPE_CLASS: dict[str, str] = {
    "server": "Server",
    "workstation": "Endpoint Device",
    "desktop": "Endpoint Device",
    "laptop": "Endpoint Device",
    "endpoint": "Endpoint Device",
    "domain controller": "Domain Controller",
    "network device": "Network Device",
    "router": "Network Device",
    "switch": "Network Device",
    "firewall": "Network Device",
    "virtual machine": "Virtual Machine",
}
# Equipment categories a network device export declares
# (``extra.netdev_device_class``), read when no host type is given. A link,
# a management processor, storage or "other" says nothing more about the
# machine, so it stays a Host.
_DEVICE_CLASS_CLASS: dict[str, str] = {
    "switch": "Network Device",
    "router": "Network Device",
    "firewall": "Network Device",
    "wireless": "Network Device",
    "vpn-gateway": "Network Device",
}
_UNTYPED_CLASS = "Host"
_DECLARED_CLASS = "Declared Asset Class"

_NAME_STATES = ("discovery", "email-auth")
_NAME_PROTOCOLS = ("dns", "dnssec")

_INSTALLED_ON_UNIT = "observation rows naming this release on this machine"

_TRANSPARENCY_QUALIFIER = (
    "Read from certificate transparency logs: the certificate was issued for this "
    "name. That does not show a server presents it.")


def _is_estate(asset: Mapping[str, Any]) -> bool:
    return asset.get("data_state") == "estate" or asset.get("source") == "estate"


def _is_name_row(asset: Mapping[str, Any]) -> bool:
    """True for a row about a DNS name rather than a machine.

    A discovery or mail-authentication row is about a name by its state. A
    DNS or DNSSEC reading is about a name too, unless it names a port: then
    it is a probe of a machine that answers DNS there, so the row is about
    that machine and its listener.
    """
    if asset.get("data_state") in _NAME_STATES:
        return True
    return asset.get("protocol") in _NAME_PROTOCOLS and not _service(asset)


_NOT_MACHINE_STATES = ("third-party", "certificate", "key-material")


def _is_machine_row(asset: Mapping[str, Any]) -> bool:
    """True for a row the register reads as about a machine, named or not."""
    return not (_is_estate(asset) or asset.get("data_state") in _NOT_MACHINE_STATES
                or _is_name_row(asset))


def _installed_software(asset: Mapping[str, Any]) -> tuple[str, str] | None:
    """(product, version) for a row naming installed software; None for a count of versions."""
    software = str(asset.get("software") or "").strip()
    if not software or any(str(f).startswith(SPREAD_FLAG) for f in asset.get("flags") or []):
        return None
    return software, str(asset.get("version") or "").strip()


def _names_in(raw: Any) -> list[str]:
    """The names in a list, or in a string of names separated by commas, each once."""
    if isinstance(raw, str):
        parts = raw.split(",")
    elif isinstance(raw, list):
        parts = [str(p) for p in raw]
    else:
        return []
    out: list[str] = []
    for part in parts:
        name = part.strip()
        if name and name.casefold() not in {n.casefold() for n in out}:
            out.append(name)
    return out


def _listed_hosts(asset: Mapping[str, Any]) -> list[str]:
    """The machines a row says carry its software.

    ``extra.installed_on`` holds them: a list of names, or names separated by
    commas. A name with a space in it cannot be one host name, so it is
    refused. ``extra.hosts`` is read only when there is no
    ``installed_on`` and it is a list of names: a plug-in reader may use
    ``hosts`` for a count of machines or a list joined by spaces, and reading
    either as a name would make a machine of it.
    """
    extra = asset.get("extra") or {}
    raw = extra.get("installed_on")
    if raw not in (None, "", []):
        names = _names_in(raw)
        spaced = [n for n in names if len(n.split()) > 1]
        if spaced or not isinstance(raw, (str, list)):
            who = str(asset.get("source_name") or asset.get("source") or "a row")
            raise ValueError(f"{who}: extra.installed_on is not a list of host names"
                             + (f" ({spaced[0]!r} holds a space)" if spaced else ""))
        return names
    legacy = extra.get("hosts")
    if (isinstance(legacy, list)
            and all(isinstance(n, str) and len(n.split()) == 1 for n in legacy)):
        return _names_in(legacy)
    return []


def _listed_names(asset: Mapping[str, Any]) -> list[str]:
    """The DNS names a name row lists in ``extra.dns_names``, without a trailing dot."""
    if not _is_name_row(asset):
        return []
    return _names_in([n.rstrip(".")
                      for n in _names_in((asset.get("extra") or {}).get("dns_names"))])


def _named_products(extra: Mapping[str, Any]) -> list[str]:
    """The product names a row lists in ``extra.software_products``."""
    return _names_in(extra.get("software_products"))


def _release_entries(asset: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The releases a row lists in ``extra.releases``, checked and normalised.

    Each entry names a ``product`` and either one version in ``versions`` or a
    vendor version ``line`` that the listed versions all belong to. A release
    covering several versions with no line would be a guess at what joins
    them, so it is refused, as is an entry with no product.
    """
    raw = (asset.get("extra") or {}).get("releases")
    if raw in (None, "", []):
        return []
    who = str(asset.get("source_name") or asset.get("source") or "a row")
    if not isinstance(raw, list):
        raise ValueError(f"{who}: extra.releases is not a list of releases")
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise ValueError(f"{who}: an entry of extra.releases is not a mapping")
        product = " ".join(str(entry.get("product") or "").split())
        if not product:
            raise ValueError(f"{who}: an entry of extra.releases names no product")
        line = " ".join(str(entry.get("line") or "").split())
        versions = _names_in(entry.get("versions"))
        if len(versions) > 1 and not line:
            raise ValueError(f"{who}: the {product} entry of extra.releases lists "
                             f"{len(versions)} versions and no version line joining them")
        label = (" ".join(str(entry.get("label") or "").split())
                 or f"{product} {line or (versions[0] if versions else '')}".strip())
        support = entry.get("support")
        exploited = entry.get("exploited")
        out.append({"product": product, "line": line, "versions": versions, "label": label,
                    "support": dict(support) if isinstance(support, Mapping) else {},
                    "exploited": dict(exploited) if isinstance(exploited, Mapping) else None})
    return out


_RUA = re.compile(r"(?:^|;)\s*rua\s*=\s*([^;]*)", re.IGNORECASE)


def _name_record_facts(asset: Mapping[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
    """A DNS name's name servers, from an ``ns`` row, or DMARC reporting address, from ``dmarc``.

    A name with neither row is left absent, which the register shows as
    *not collected*. A lookup that settled with nothing to report is
    *not applicable*, with a note saying what was read.
    """
    protocol = asset.get("protocol")
    if protocol == "ns":
        servers = [str(s) for s in extra.get("name_servers") or []]
        return {"name_servers": ", ".join(servers) if servers else Absence(
            "not-applicable", note="the NS lookup settled with no NS record: the name is not "
                                   "the top of its own zone, so its parent zone serves it")}
    if protocol == "dmarc":
        record = str(extra.get("record") or "")
        if not record:
            return {"dmarc_report_address": Absence(
                "not-applicable", note="the DMARC lookup settled and no record is published "
                                       "at this name")}
        rua = _RUA.search(record)
        address = rua.group(1).strip() if rua else ""
        return {"dmarc_report_address": address or Absence(
            "not-applicable", note="the DMARC record has no rua= tag, so receivers send this "
                                   "domain no aggregate reports (RFC 9989 §4.7)")}
    return {}


def _third_party_identity(extra: Mapping[str, Any]) -> tuple[str, str, str] | None:
    vendor = str(extra.get("vendor") or "").strip()
    if vendor:
        return "Vendor", f"vendor:{vendor}", vendor
    domain = str(extra.get("registrable_domain") or "").strip().lower()
    if domain:
        return "Unattributed Dependency", f"unattributed-domain:{domain}", domain
    return None


def _service(asset: Mapping[str, Any]) -> str:
    extra = asset.get("extra") or {}
    service = str(extra.get("service") or "").strip()
    if service:
        return service
    port = str(asset.get("port") or "").strip()
    if port:
        return f"{port}/{str(extra.get('transport') or 'tcp')}"
    return ""


def _host_class(extra: Mapping[str, Any]) -> str:
    """A machine's class from ``extra.host_type``, else ``extra.netdev_device_class``."""
    typed = _HOST_TYPE_CLASS.get(" ".join(str(extra.get("host_type") or "").lower().split()))
    if typed:
        return typed
    return _DEVICE_CLASS_CLASS.get(str(extra.get("netdev_device_class") or "").strip().lower(),
                                   _UNTYPED_CLASS)


_CURVE_BITS = {"P-256": 256, "P-384": 384, "P-521": 521}


def _key_length(pubkey: Mapping[str, Any]) -> str:
    bits = pubkey.get("bit_length")
    curve = str(pubkey.get("curve") or "")
    if isinstance(bits, int) and bits > 0:
        return f"{bits} bits" + (f" ({curve})" if curve else "")
    if curve in _CURVE_BITS:
        return f"{_CURVE_BITS[curve]} bits ({curve})"
    return curve


_CN = re.compile(r"(?:^|,)\s*CN=((?:\\.|[^,\\])*)")


def _issuing_ca(issuer_dn: str) -> str:
    """The common name in an issuer's distinguished name, or the whole name."""
    found = _CN.findall(issuer_dn)
    if not found:
        return issuer_dn.strip()
    return re.sub(r"\\(.)", r"\1", found[-1]).strip()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _address_or_absence(value: str) -> str | Absence:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if parts and all(_is_ip(p) for p in parts):
        return ", ".join(parts)
    return Absence("not-measured", note="this reading carries no address")


def _cert_first_seen(observations_root: Path, before: str) -> dict[str, str]:
    """Certificate fingerprint to the earliest date any earlier observation saw it."""
    index: dict[str, str] = {}
    for entry in obsarchive.observations(observations_root):
        if entry.name >= before or not entry.is_dir():
            continue
        try:
            rows = json.loads((entry / "assets.json").read_text())
        except (OSError, ValueError):
            continue
        for row in rows if isinstance(rows, list) else []:
            extra = row.get("extra") if isinstance(row, dict) else None
            if not isinstance(extra, dict):
                continue
            sha = str(extra.get("cert_sha256") or "")
            seen = str(row.get("collected_at") or "")
            if sha and _ISO_DATE.match(seen) and (sha not in index or seen < index[sha]):
                index[sha] = seen
    return index


_PLAN_EVIDENCE_REPORTED = ("observed", "named")
_NAME_NOTE = re.compile(r"[\s(\[]")


def _ip_sort(value: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(value)
    return ip.version, int(ip)


def plan_machines(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The machines an IP address plan names at an address, one entry per name.

    Reads the JSON ``takestock ipam`` writes: for each address, the names its
    sightings give as a ``machine`` that the plan counts as the address's
    current holder (``machine_names``). Aliases, labels and past holders are
    not machines, and an address only a superseded source lists is skipped.
    Each entry has the ``name`` as a source gave it, its ``addresses``, the
    evidence ``strength`` (reported when a source saw or named the address,
    declared when it is only documented) and the newest date, ``valid_at``.
    """
    from .ipam import _short

    out: dict[str, dict[str, Any]] = {}
    for subnet in plan.get("subnets") or []:
        for address in (subnet.get("addresses") or []) if isinstance(subnet, Mapping) else []:
            if not isinstance(address, Mapping) or address.get("only_in_superseded"):
                continue
            current = {str(n).lower() for n in address.get("machine_names") or []}
            ip = str(address.get("ip") or "")
            if not current or not _is_ip(ip):
                continue
            evidence = set(address.get("evidence") or [])
            strength = REPORTED if evidence & set(_PLAN_EVIDENCE_REPORTED) else DECLARED
            dates = [d for d in (str(address.get("last_observed") or ""),
                                 str(address.get("last_documented") or "")) if _ISO_DATE.match(d)]
            for sighting in address.get("sightings") or []:
                if not isinstance(sighting, Mapping) or sighting.get("name_is") != "machine":
                    continue
                name = _NAME_NOTE.split(str(sighting.get("name") or "").strip(), maxsplit=1)[0]
                if not name or _short(name) not in current:
                    continue
                entry = out.setdefault(name.casefold(), {"name": name, "addresses": [],
                                                         "strength": strength, "valid_at": ""})
                if ip not in entry["addresses"]:
                    entry["addresses"].append(ip)
                if _STRENGTH_RANK[strength] < _STRENGTH_RANK[entry["strength"]]:
                    entry["strength"] = strength
                entry["valid_at"] = max([entry["valid_at"], *dates])
    for entry in out.values():
        entry["addresses"].sort(key=_ip_sort)
    return [out[k] for k in sorted(out)]


_WHOLE_NUMBER = re.compile(r"[0-9]+")


def _whole_number(value: Any) -> int | None:
    """A count a row gives: a whole number, or one written as text (``"40"``,
    surrounding spaces ignored); None for anything else, which is not counted."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _WHOLE_NUMBER.fullmatch(value.strip()):
        return int(value.strip())
    return None


def _source_names(names: Sequence[str] | None) -> tuple[str, ...] | None:
    """``installed_on_from`` checked: None, or a list or tuple of non-blank names.

    Anything else (a string, a mapping, a set, a number, a blank or non-text
    name) is refused with :class:`ValueError`.
    """
    if names is None:
        return None
    if not isinstance(names, (list, tuple)) or not all(
            isinstance(n, str) and n.strip() for n in names):
        raise ValueError("installed_on_from must be a list or tuple of non-blank row "
                         "sources or plug-in names")
    return tuple(n.strip() for n in names)


def _default_recorded_at(observation: Path) -> str:
    if obsarchive.is_stamp(observation.name):
        return observation.name[:10]
    return date.today().isoformat()


#: The ``summary.json`` key a derived observation carries (``takestock.rerun.SUMMARY_KEY``).
DERIVED_KEY = "rerun"


@dataclass(frozen=True)
class ReadDates:
    """When the rows of a derived observation were read.

    ``held`` is the date of the full observation every carried row was read
    in; ``reread`` maps each plug-in read again to the date of the derived
    observation that last read it.
    """

    held: str
    reread: dict[str, str]

    def of(self, row: Mapping[str, Any]) -> str:
        """The date the observation that read ``row`` was taken."""
        plugin = str((row.get("extra") or {}).get("plugin") or "")
        return self.reread.get(plugin, self.held)


def read_dates(summary: Mapping[str, Any], stamp: str) -> ReadDates | None:
    """When a derived observation's rows were read; None for an observation that is not derived.

    ``stamp`` is the observation's own time stamp. A derived observation
    (``takestock rerun``) carries the record of the one it was derived from,
    which may be derived in turn, so the chain is followed back to the full
    observation: a row a plug-in wrote is dated by the latest observation
    that read that plug-in again, and every other row by the full one. A
    plug-in row names its plug-in in ``extra.plugin``. None too when the
    record names no earlier observation by a dated stamp.
    """
    record = summary.get(DERIVED_KEY)
    if not isinstance(record, Mapping):
        return None
    reread: dict[str, str] = {}
    day = stamp[:10]
    while isinstance(record, Mapping):
        if _ISO_DATE.match(day):
            for name in record.get("plugins") or []:
                reread.setdefault(str(name), day)
        day = str(record.get("from_observation") or "")[:10]
        record = record.get("from_rerun")
    return ReadDates(held=day, reread=reread) if _ISO_DATE.match(day) else None


# ── The builder ────────────────────────────────────────────────────────────


class _Builder:
    def __init__(self, observation: Path, ledger: KeyLedger | None, recorded_at: str,
                 ip_plan: Path | None = None, schema: Schema | None = None,
                 installed_on_from: Sequence[str] | None = None) -> None:
        self.dir = Path(observation)
        self.schema = schema or load_schema()
        self.installed_on_from = _source_names(installed_on_from)
        self.ledger = ledger or KeyLedger(self.schema)
        raw = (self.dir / "assets.json").read_bytes()
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{self.dir / 'assets.json'} is not a list of rows")
        self.assets: list[dict[str, Any]] = [r for r in rows if isinstance(r, dict)]
        summary_path = self.dir / "summary.json"
        summary: dict[str, Any] = {}
        if summary_path.is_file():
            loaded = json.loads(summary_path.read_text())
            summary = loaded if isinstance(loaded, dict) else {}
            total = summary.get("total_assets")
            if isinstance(total, int) and total != len(self.assets):
                raise ValueError(f"summary.json counts {total} assets and assets.json holds "
                                 f"{len(self.assets)}: the observation is incomplete")
        # A derived observation holds rows read on more than one date: each
        # row's facts are dated by the observation that read it (`_read_on`),
        # and what the build says of the whole by the full observation's date.
        block = summary.get("observation")
        stamp = str((block if isinstance(block, dict) else {}).get("stamp") or self.dir.name)
        self.read = read_dates(summary, stamp)
        self.read_on = (self.read.held if self.read
                        else stamp[:10] if obsarchive.is_stamp(stamp) else "")
        self._explicit = bool(recorded_at)
        default = self.read.held if self.read else _default_recorded_at(self.dir)
        self.recorded_at = _check_date(recorded_at or default, "recorded_at")
        # The recording date of the fact in hand: a row's while its facts are
        # asserted, the build's otherwise.
        self._recording = self.recorded_at
        self.artefact = f"{self.dir.name}/assets.json"
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.assertions: list[Assertion] = []
        self.edges: list[Edge] = []
        self.populations: list[Population] = []
        self._class: dict[str, str] = {}
        self._label: dict[str, str] = {}
        # Each instrument that saw a machine, as (collector id, display name).
        self._sources_by_machine: dict[str, set[tuple[str, str]]] = {}
        self._names: dict[str, str] = {}
        self._installs: dict[tuple[str, str], int] = {}
        # (machine, listener) -> (strength, valid_at, actor, recorded_at) of the contains edge.
        self._contains: dict[tuple[str, str], tuple[str, str, Actor, str]] = {}
        # A release, or a (release, machine) install -> the latest (read, recorded)
        # dates of the rows that name it (`_note_read`).
        self._edge_dates: dict[Any, tuple[str, str]] = {}
        self._release_of: dict[str, str] = {}
        self._environment_said: set[tuple[str, str]] = set()
        self._cert_history: dict[str, str] | None = None
        self._plan: list[dict[str, Any]] = []
        self._plan_actor: Actor | None = None
        if ip_plan is not None:
            self._read_plan(Path(ip_plan))

    def _read_plan(self, path: Path) -> None:
        raw = path.read_bytes()
        plan = json.loads(raw)
        if not isinstance(plan, dict) or not isinstance(plan.get("subnets"), list):
            raise ValueError(f"{path} is not an IP address plan: it has no list of subnets")
        self._plan = plan_machines(plan)
        self._plan_actor = Actor(kind=COLLECTOR, name=str(plan.get("title") or "IP address plan"),
                                 artefact=path.name,
                                 artefact_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                                 source="ipam")

    # Keys

    def _read_on(self, asset: Mapping[str, Any]) -> str:
        """The date of the observation that read ``asset``: the recording date,
        unless the observation is derived (:func:`read_dates`)."""
        return self.read.of(asset) if self.read else self.recorded_at

    def _recorded_on(self, asset: Mapping[str, Any]) -> str:
        """The date a row's facts are recorded: the date it was read, unless a
        recording date was given for the whole build."""
        return self.recorded_at if self._explicit else self._read_on(asset)

    def _seen_at(self, asset: Mapping[str, Any]) -> str:
        collected = str(asset.get("collected_at") or "")
        return collected if _ISO_DATE.match(collected) else self._read_on(asset)

    def _named_key(self, kind: str, identifier: str, asset: Mapping[str, Any]) -> str:
        return self.ledger.key_for(
            [(kind, identifier)], source=str(asset.get("source") or ""),
            seen_at=self._seen_at(asset), merged_at=self._recorded_on(asset),
            reason=f"one row named both identifiers ({self.artefact})")

    def _machine_key(self, asset: Mapping[str, Any]) -> str | None:
        host = str(asset.get("host") or "").strip()
        agent = str((asset.get("extra") or {}).get("agent_id") or "").strip()
        candidates = [(k, v) for k, v in (("hostname", host), ("agent-id", agent)) if v]
        if not candidates:
            return None
        return self.ledger.key_for(
            candidates, source=str(asset.get("source") or ""), seen_at=self._seen_at(asset),
            merged_at=self._recorded_on(asset),
            reason=f"one row named both identifiers ({self.artefact})")

    def _key_of(self, asset: Mapping[str, Any]) -> str | None:
        """The key of the item a row is about; None for a row about no item."""
        extra = asset.get("extra") or {}
        state = asset.get("data_state")
        host = str(asset.get("host") or "")
        name = str(asset.get("name") or "")
        if _is_estate(asset):
            return self._named_key("estate-name", f"estate:{name}", asset) if name else None
        if state == "third-party":
            identity = _third_party_identity(extra)
            return self._named_key("estate-name", identity[1], asset) if identity else None
        if state == "certificate":
            return self._named_key("estate-name", f"certificate:{host}", asset) if host else None
        if state == "key-material":
            return self._named_key("estate-name", f"credential:{name}", asset) if name else None
        if _is_name_row(asset):
            return self._named_key("estate-name", host, asset) if host else None
        return self._machine_key(asset)

    def _lists_hosts(self, asset: Mapping[str, Any]) -> bool:
        """Whether a row's host list may draw installed-on: always, unless
        ``installed_on_from`` names sources and the row's ``source`` and
        ``extra.plugin`` are neither of them."""
        if self.installed_on_from is None:
            return True
        plugin = str((asset.get("extra") or {}).get("plugin") or "")
        return bool({str(asset.get("source") or ""), plugin} & set(self.installed_on_from))

    def _listed_machines(self, asset: Mapping[str, Any]) -> list[tuple[str, str]]:
        """(name, key) for each machine an inventory row says carries its software.

        Only a row from a named source draws these when ``installed_on_from``
        names any: another row's host list is left unread, as if it held none.
        """
        if _installed_software(asset) is None or not self._lists_hosts(asset):
            return []
        return [(name, self.ledger.key_for(
                    [("hostname", name)], source=str(asset.get("source") or ""),
                    seen_at=self._seen_at(asset), merged_at=self._recorded_on(asset),
                    reason=f"one row named both identifiers ({self.artefact})"))
                for name in _listed_hosts(asset)]

    def _software_keys(self, asset: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
        """(product key, release key, product, release label) for installed software."""
        found = _installed_software(asset)
        if found is None:
            return None
        software, version = found
        label = f"{software} {version}".strip()
        return (self._named_key("estate-name", f"product:{software}", asset),
                self._named_key("estate-name", f"release:{label}", asset), software, label)

    def _entry_keys(self, asset: Mapping[str, Any], entry: Mapping[str, Any]) -> tuple[str, str]:
        """(product key, release key) for one entry of ``extra.releases``.

        The release is keyed on its label, as a machine row's release is, so an
        entry for one version and a row naming that software at that version
        are the same item.
        """
        return (self._named_key("estate-name", f"product:{entry['product']}", asset),
                self._named_key("estate-name", f"release:{entry['label']}", asset))

    def _plan_key(self, machine: Mapping[str, Any]) -> str:
        return self.ledger.key_for(
            [("hostname", str(machine["name"]))], source="ipam",
            seen_at=str(machine["valid_at"] or self.recorded_at), merged_at=self.recorded_at,
            reason="one IP address plan entry named both identifiers")

    def _listener_key(self, asset: Mapping[str, Any], service: str) -> str:
        return self._named_key("estate-name", f"{asset.get('host') or ''}:{service}", asset)

    def _set(self, key: str, item_class: str, label: str) -> None:
        current = self._class.get(key)
        if current is None or current == _UNTYPED_CLASS:
            self._class[key] = item_class
        if label and not self._label.get(key):
            self._label[key] = label

    # Pass 1: what items exist, and of which class

    def classify(self) -> None:
        for asset in self.assets:
            key = self._key_of(asset)
            for name in _listed_names(asset):
                listed = self._named_key("estate-name", name, asset)
                self._set(listed, "DNS Name", name)
                self._names.setdefault(name, listed)
            for entry in _release_entries(asset):
                product, release = self._entry_keys(asset, entry)
                self._set(product, "Software Product", entry["product"])
                self._set(release, "Software Release", entry["label"])
            if _is_machine_row(asset):
                self._classify_machine_row(asset, key)
                continue
            if key is None:
                continue
            extra = asset.get("extra") or {}
            state = asset.get("data_state")
            host = str(asset.get("host") or "")
            if _is_estate(asset):
                self._set(key, _DECLARED_CLASS,
                          str(extra.get("estate_class") or asset.get("name") or ""))
            elif state == "third-party":
                identity = _third_party_identity(extra)
                if identity:
                    self._set(key, identity[0], identity[2])
            elif state == "certificate":
                self._set(key, "Certificate", host)
            elif state == "key-material":
                self._set(key, "Credential", str(asset.get("name") or ""))
            elif _is_name_row(asset):
                self._set(key, "DNS Name", host)
                self._names[host] = key
        for machine in self._plan:
            self._set(self._plan_key(machine), _UNTYPED_CLASS, str(machine["name"]))

    def _classify_machine_row(self, asset: Mapping[str, Any], key: str | None) -> None:
        extra = asset.get("extra") or {}
        host = str(asset.get("host") or "")
        source = (str(asset.get("source") or ""), str(asset.get("source_name") or ""))
        if key is not None:
            self._set(key, _host_class(extra), host or str(extra.get("agent_id") or ""))
            self._sources_by_machine.setdefault(key, set()).add(source)
            service = _service(asset)
            if service and host:
                self._set(self._listener_key(asset, service), "Network Service",
                          f"{host} {service}")
        for name, machine in self._listed_machines(asset):
            self._set(machine, _UNTYPED_CLASS, name)
            self._sources_by_machine.setdefault(machine, set()).add(source)
        for name in _named_products(extra):
            self._set(self._named_key("estate-name", f"product:{name}", asset),
                      "Software Product", name)
        software = self._software_keys(asset)
        if software is not None:
            product, release, name, label = software
            self._set(product, "Software Product", name)
            self._set(release, "Software Release", label)

    # Pass 2: what is known about each

    def _actor(self, asset: Mapping[str, Any]) -> Actor:
        return Actor(kind=COLLECTOR,
                     name=str(asset.get("source_name") or asset.get("source") or "unnamed instrument"),
                     artefact=self.artefact, artefact_digest=self.digest,
                     source=str(asset.get("source") or ""))

    def _say(self, key: str, attribute: str, value: Any, strength: str,
             valid_at: str, actor: Actor) -> None:
        if attribute not in self.schema.attributes:
            raise SchemaError(f"attribute {attribute!r} is not declared in {SCHEMA_FILE}")
        self._check_code(attribute, value, actor)
        if attribute not in self.schema.class_attributes(self._class.get(key, "")):
            return
        if value == "" or value is None:
            value = Absence("not-measured", note=f"{actor.name} gave no value for this attribute")
        self.assertions.append(Assertion(
            item=key, attribute=attribute, value=value,
            evidence_strength=capped_strength(self.schema, attribute, strength),
            valid_at=valid_at, recorded_at=self._recording, actor=actor))

    def _check_code(self, attribute: str, value: Any, actor: Actor) -> None:
        """Refuse a value outside the attribute's vocabulary, if it has one."""
        allowed = self.schema.allowed_values(attribute)
        if (allowed is not None and value not in ("", None) and not is_absent(value)
                and value not in allowed):
            raise ValueError(f"{actor.name} gives {attribute} {value!r}, which is not one of "
                             f"its vocabulary's codes: {', '.join(sorted(allowed))}")

    def _check_codes(self, extra: Mapping[str, Any], actor: Actor) -> None:
        # A row's extra key named for a controlled attribute is checked on every
        # row, before anything decides whether the row names an item, so a
        # typing slip is never dropped silently.
        for attribute in self.schema.attributes:
            if extra.get(attribute) not in ("", None):
                self._check_code(attribute, str(extra[attribute]), actor)

    def _edge(self, kind: str, from_key: str, to_key: str, strength: str, valid_at: str,
              actor: Actor, count: int = 1, qualifier: str = "", unit: str = "",
              recorded_at: str = "") -> None:
        if kind not in self.schema.relationships:
            raise SchemaError(f"relationship {kind!r} is not declared in {SCHEMA_FILE}")
        self.edges.append(Edge(kind=kind, from_key=from_key, to_key=to_key,
                               evidence_strength=strength, valid_at=valid_at,
                               recorded_at=recorded_at or self._recording, actor=actor,
                               count=count, qualifier=qualifier, unit=unit))

    def assert_facts(self) -> None:
        for asset in self.assets:
            self._recording = self._recorded_on(asset)
            key = self._key_of(asset)
            extra = asset.get("extra") or {}
            seen = self._seen_at(asset)
            actor = self._actor(asset)
            strength = _strength_for(asset)
            self._check_codes(extra, actor)
            for name in _listed_names(asset):
                self._say(self._named_key("estate-name", name, asset), "name", name,
                          strength, seen, actor)
            for entry in _release_entries(asset):
                self._release_facts(asset, entry, strength, seen, actor)
            if key is None:
                if _is_machine_row(asset):
                    self._software_facts(None, asset, strength, seen, actor)
                continue
            for attribute, value in self._attributes(asset, extra).items():
                self._say(key, attribute, value, strength, seen, actor)
            self._say_environment(key, extra, self._read_on(asset))
            if asset.get("data_state") == "third-party" and str(extra.get("vendor") or "").strip():
                self._say(key, "vendor_name", str(extra["vendor"]).strip(),
                          DECLARED if extra.get("declared") is True else INFERRED, seen, actor)
            if self._class.get(key) == "Certificate":
                name_key = self._names.get(str(asset.get("host") or ""))
                if name_key:
                    self._edge("presents", name_key, key, strength, seen, actor,
                               qualifier=_TRANSPARENCY_QUALIFIER
                               if asset.get("source") == "ct_dns" else "")
            if self._is_hardware(key):
                self._machine_facts(key, asset, extra, strength, seen, actor)
            if _is_machine_row(asset):
                self._software_facts(key, asset, strength, seen, actor)
        self._recording = self.recorded_at
        self._plan_facts()

    def _plan_facts(self) -> None:
        if self._plan_actor is None:
            return
        for machine in self._plan:
            key = self._plan_key(machine)
            valid_at = str(machine["valid_at"] or self.recorded_at)
            strength = str(machine["strength"])
            self._say(key, "hostname", str(machine["name"]), strength, valid_at,
                      self._plan_actor)
            self._say(key, "address", ", ".join(machine["addresses"]), strength, valid_at,
                      self._plan_actor)

    def _machine_facts(self, key: str, asset: Mapping[str, Any], extra: Mapping[str, Any],
                       strength: str, seen: str, actor: Actor) -> None:
        service = _service(asset)
        if service and asset.get("host"):
            listener = self._listener_key(asset, service)
            port, _, transport = service.partition("/")
            self._say(listener, "name", f"{asset.get('host')} {service}", strength, seen, actor)
            self._say(listener, "port", port, strength, seen, actor)
            self._say(listener, "transport", transport, strength, seen, actor)
            self._say(listener, "protocol", str(asset.get("protocol") or ""), strength, seen, actor)
            self._say(listener, "bind_scope", str(extra.get("bind_scope") or ""),
                      strength, seen, actor)
            if asset.get("internet_facing") is not None:
                self._say(listener, "internet_facing", asset["internet_facing"],
                          INFERRED, seen, actor)
            self._say(listener, "encryption_verdict", str(asset.get("verdict") or ""),
                      INFERRED, seen, actor)
            self._say(listener, "evidence_depth",
                      str(asset.get("evidence_depth") or depth.classify(asset)),
                      INFERRED, seen, actor)
            # One edge per machine and listener, however many rows name it:
            # the strongest evidence, then the most recent, is the one kept.
            held = self._contains.get((key, listener))
            if held is None or ((_STRENGTH_RANK[strength], _invert_date(seen))
                                < (_STRENGTH_RANK[held[0]], _invert_date(held[1]))):
                self._contains[(key, listener)] = (strength, seen, actor, self._recording)

    def _software_facts(self, key: str | None, asset: Mapping[str, Any], strength: str,
                        seen: str, actor: Actor) -> None:
        """A machine row's software: its product and release, and every machine carrying it."""
        listed = self._listed_machines(asset)
        for name, machine in listed:
            self._say(machine, "hostname", name, strength, seen, actor)
        for name in _named_products(asset.get("extra") or {}):
            self._say(self._named_key("estate-name", f"product:{name}", asset), "name", name,
                      strength, seen, actor)
        software = self._software_keys(asset)
        if software is None:
            return
        product, release, name, label = software
        version = str(asset.get("version") or "").strip()
        self._say(product, "name", name, strength, seen, actor)
        self._say(release, "name", label, strength, seen, actor)
        self._say(release, "version", version or Absence("not-measured"),
                  strength, seen, actor)
        for src, attribute in (("support_status", "support_status"),
                               ("support_end", "end_of_support"),
                               ("migration_strategy", "migration_strategy")):
            if asset.get(src):
                self._say(release, attribute, str(asset[src]), DECLARED, seen, actor)
        self._release_of[release] = product
        self._note_read(release, asset)
        machines = [key] if key is not None and self._is_hardware(key) else []
        machines += [m for _, m in listed if m not in machines]
        for machine in machines:
            self._installs[(release, machine)] = self._installs.get((release, machine), 0) + 1
            self._note_read((release, machine), asset)

    def _note_read(self, what: Any, asset: Mapping[str, Any]) -> None:
        """Keep the latest (read, recorded) dates of the rows behind an edge the
        fold draws, so the edge is dated by them and not by the build."""
        dates = (self._read_on(asset), self._recording)
        self._edge_dates[what] = max(self._edge_dates.get(what, dates), dates)

    def _release_facts(self, asset: Mapping[str, Any], entry: Mapping[str, Any],
                       strength: str, seen: str, actor: Actor) -> None:
        """One entry of ``extra.releases``: a product, its release, and their facts."""
        product, release = self._entry_keys(asset, entry)
        versions = list(entry["versions"])
        self._say(product, "name", entry["product"], strength, seen, actor)
        self._say(release, "name", entry["label"], strength, seen, actor)
        if entry["line"]:
            version: Any = Absence("not-applicable", note=(
                f"this release is the version line {entry['line']}; the versions it covers "
                "are in covered_versions"))
        else:
            version = versions[0] if versions else Absence(
                "not-measured", note=f"{actor.name} names this release without a version")
        self._say(release, "version", version, strength, seen, actor)
        self._say(release, "covered_versions", "; ".join(versions) or Absence(
            "not-measured", note=f"{actor.name} lists no version for this release"),
            strength, seen, actor)
        support = entry["support"]
        if support:
            as_of = str(support.get("as_of") or "")
            as_of = as_of if _ISO_DATE.match(as_of) else seen
            for src, attribute in (("status", "support_status"),
                                   ("end_of_support", "end_of_support"),
                                   ("end_of_life", "end_of_life")):
                value = str(support.get(src) or "")
                self._say(release, attribute, value or Absence(
                    "not-measured", note=f"the support entry gives no {src.replace('_', ' ')}"),
                    DECLARED, as_of, actor)
        exploited = entry["exploited"]
        if exploited is not None:
            as_of = str(exploited.get("as_of") or "")
            as_of = as_of if _ISO_DATE.match(as_of) else seen
            identifiers = _names_in(exploited.get("identifiers"))
            self._say(release, "exploited_defect_ids", "; ".join(identifiers) or Absence(
                "not-applicable", note=f"{actor.name} lists no exploited defect open against "
                                       f"this release on {as_of}"),
                strength, as_of, actor)
            past_due = exploited.get("past_due")
            if isinstance(past_due, int) and not isinstance(past_due, bool):
                self._say(release, "exploited_defects_past_due", past_due, strength, as_of,
                          actor)
        self._release_of[release] = product
        self._note_read(release, asset)

    def _is_hardware(self, key: str) -> bool:
        return self.schema.classes.get(self._class.get(key, ""), {}).get("family") == "Hardware"

    def _say_environment(self, key: str, extra: Mapping[str, Any], read_on: str) -> None:
        env = extra.get("environment")
        if not isinstance(env, Mapping):
            return
        value: Any = str(env.get("value") or "")
        if not value:
            reason = str(env.get("absent") or "")
            if not reason:
                return
            value = Absence(reason, note=str(env.get("note") or ""))
        said = (key, json.dumps(_encode(value), sort_keys=True, default=str))
        if said in self._environment_said:
            return
        self._environment_said.add(said)
        valid_at = str(env.get("valid_at") or "")
        self._say(key, "environment", value, INFERRED,
                  valid_at if _ISO_DATE.match(valid_at) else read_on,
                  Actor(kind=COLLECTOR, name=str(env.get("source_name") or "environment derivation"),
                        artefact=self.artefact, artefact_digest=self.digest,
                        source=str(env.get("source") or "")))

    def _first_discovered(self, extra: Mapping[str, Any], own: str) -> str:
        sha = str(extra.get("cert_sha256") or "")
        if not sha or not obsarchive.is_stamp(self.dir.name):
            return own
        if self._cert_history is None:
            here = self.dir.resolve()
            self._cert_history = _cert_first_seen(here.parent, here.name)
        return min(self._cert_history.get(sha, own), own)

    def _attributes(self, asset: Mapping[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
        """Attribute values a row states about its own item."""
        out: dict[str, Any] = {}
        state = asset.get("data_state")
        host = str(asset.get("host") or "")
        if host:
            out["hostname"] = host
        for src, dest in (("agent_id", "agent_id"), ("host_type", "host_type"), ("os", "os"),
                          ("os_version", "os_version"), ("ip_stack", "ip_stack"),
                          ("issuer", "issuer"), ("not_after", "not_after"),
                          ("serial_number", "serial_number"),
                          ("sensor_version", "sensor_version"),
                          ("technology_zone", "technology_zone"),
                          ("technology_location", "technology_location")):
            if extra.get(src):
                out[dest] = str(extra[src])
        addresses = [str(extra[k]) for k in ("ipv4_addresses", "ipv6_addresses") if extra.get(k)]
        if not addresses and asset.get("ip"):
            addresses = [str(asset["ip"])]
        if addresses:
            out["address"] = _address_or_absence(", ".join(addresses))
        elif extra.get("ip_stack") == "unresolved":
            out["address"] = Absence("not-applicable", note="the name resolves to no address")

        if _is_estate(asset):
            out["name"] = str(extra.get("estate_class") or asset.get("name") or "")
            out["instrument_state"] = str(extra.get("estate_state") or "")
            declared = extra.get("declared_crypto")
            out["declared_crypto"] = (", ".join(str(d) for d in declared)
                                      if isinstance(declared, list) else str(declared or ""))
            out["description"] = str(asset.get("notes") or "")
        elif state == "third-party":
            identity = _third_party_identity(extra)
            if identity:
                out["name"] = identity[2]
        elif state == "certificate":
            out["name"] = host
            pubkey = extra.get("pubkey")
            if isinstance(pubkey, Mapping):
                out["key_algorithm"] = str(pubkey.get("type") or "")
                out["key_length"] = _key_length(pubkey)
            if extra.get("not_before"):
                out["not_before"] = str(extra["not_before"])
            if extra.get("cert_sha256"):
                out["certificate_sha256"] = str(extra["cert_sha256"])
            if extra.get("issuer_dn"):
                out["issuing_ca"] = _issuing_ca(str(extra["issuer_dn"]))
            if asset.get("verdict"):
                out["encryption_verdict"] = str(asset["verdict"])
            if asset.get("pq_sig"):
                out["post_quantum_signature"] = str(asset["pq_sig"])
            if _ISO_DATE.match(str(asset.get("collected_at") or "")):
                own = str(asset["collected_at"])
                out["last_seen"] = own
                out["first_discovered"] = self._first_discovered(extra, own)
        elif state == "key-material":
            out["name"] = str(asset.get("name") or "")
            out["credential_kind"] = str(extra.get("credential_type") or "")
        elif _is_name_row(asset):
            out["name"] = host
            out["internet_facing"] = asset.get("internet_facing")
            out.update(_name_record_facts(asset, extra))
        if state == "at-rest":
            out["disk_encryption_state"] = str(asset.get("verdict") or "")
            out["key_custody"] = (str(extra["key_custody"]) if extra.get("key_custody")
                                  else Absence("not-measured",
                                               note="the row does not say who holds the key"))
        return {k: v for k, v in out.items() if v is not None}

    # Pass 3: what follows from the whole observation

    def fold(self) -> None:
        actor = Actor(kind=COLLECTOR, name="configuration register build",
                      artefact=self.artefact, artefact_digest=self.digest, source="cmdb")
        for (machine, listener), (strength, seen, seen_by, recorded) in sorted(
                self._contains.items()):
            self._edge("contains", machine, listener, strength, seen, seen_by,
                       recorded_at=recorded)
        build = (self.recorded_at, self.recorded_at)
        for (release, machine), copies in sorted(self._installs.items()):
            read_on, recorded = self._edge_dates.get((release, machine), build)
            self._edge("installed-on", release, machine, MEASURED, read_on, actor,
                       count=copies, unit=_INSTALLED_ON_UNIT,
                       qualifier="An edge with a count; no item is created per copy.",
                       recorded_at=recorded)
        for release, product in sorted(self._release_of.items()):
            read_on, recorded = self._edge_dates.get(release, build)
            self._edge("release-of", release, product, INFERRED, read_on, actor,
                       recorded_at=recorded)
        self._member_of(actor)

    def _member_of(self, actor: Actor) -> None:
        # A machine joins a declared class when the instrument that saw it is
        # live for exactly that one class; anything less is not attributable.
        # A declared row may name an instrument by its collector id or by its
        # display name, so both count as the same instrument.
        owners: dict[str, set[str]] = {}
        for asset in self.assets:
            if not _is_estate(asset) or not asset.get("name"):
                continue
            key = self._named_key("estate-name", f"estate:{asset['name']}", asset)
            for instrument in (asset.get("extra") or {}).get("collectors_live") or []:
                owners.setdefault(str(instrument), set()).add(key)
        for machine, instruments in sorted(self._sources_by_machine.items()):
            joined: set[str] = set()
            for collector, display in sorted(instruments):
                classes = owners.get(collector, set()) | owners.get(display, set())
                if len(classes) == 1:
                    joined |= classes
            for declared in sorted(joined):
                self._edge("member-of", machine, declared, INFERRED, self.recorded_at, actor,
                           qualifier=("Attributed by which instrument saw the machine, "
                                      "drawn only where that instrument is live for "
                                      "exactly one declared class."))

    def count_populations(self) -> None:
        machines = {k for k, c in self._class.items()
                    if self.schema.classes.get(c, {}).get("family") == "Hardware"}
        per_source: dict[str, set[str]] = {}
        dates: dict[str, str] = {}
        rows: list[Population] = []
        for asset in self.assets:
            key = self._key_of(asset)
            named = {key} if key in machines else set()
            if _is_machine_row(asset):
                named |= {m for _, m in self._listed_machines(asset) if m in machines}
            if named:
                source = str(asset.get("source_name") or asset.get("source") or "")
                per_source.setdefault(source, set()).update(named)
                dates[source] = max(dates.get(source, ""), self._seen_at(asset))
            discovered = _whole_number((asset.get("extra") or {}).get("discovered"))
            if discovered is not None:
                rows.append(Population(
                    population="machines",
                    instrument=str(asset.get("source_name") or "discovery"),
                    count=discovered, valid_at=self._seen_at(asset), evidence_strength=REPORTED,
                    note=("A count of what exists, as a discovery source reports it. The other "
                          "rows count what an instrument can see.")))
        if self._plan_actor is not None and self._plan:
            rows.append(Population(
                population="machines", instrument=self._plan_actor.name,
                count=len({self._plan_key(m) for m in self._plan}),
                valid_at=max(str(m["valid_at"]) for m in self._plan) or self.recorded_at,
                evidence_strength=REPORTED,
                note="Machines the IP address plan's sources name at an address."))
        if not machines and not rows:
            return
        rows = [Population(population="machines", instrument=name, count=len(keys),
                           valid_at=dates.get(name, self.recorded_at),
                           evidence_strength=MEASURED)
                for name, keys in sorted(per_source.items())] + rows
        rows.append(Population(
            population="machines", instrument="every instrument together",
            count=len(machines), valid_at=self.recorded_at, evidence_strength=INFERRED,
            note="Every machine any instrument named, counted once."))
        disagree = len({r.count for r in rows}) > 1
        self.populations = [Population(population=r.population, instrument=r.instrument,
                                       count=r.count, valid_at=r.valid_at,
                                       evidence_strength=r.evidence_strength, note=r.note,
                                       contested=disagree, unit="machines")
                            for r in rows]

    def finish(self) -> Cmdb:
        items: dict[str, ConfigurationItem] = {}
        for key, item_class in sorted(self._class.items()):
            spec = self.schema.classes.get(item_class, {})
            items[key] = ConfigurationItem(
                key=key, item_class=item_class, family=str(spec.get("family") or ""),
                lifecycle_state="planned" if item_class == _DECLARED_CLASS else "discovered",
                aliases=self.ledger.aliases(key), label=self._label.get(key, ""))
        return Cmdb(schema=self.schema, items=items, assertions=self.assertions,
                    edges=self.edges, populations=self.populations, ledger=self.ledger,
                    observation=self.dir.name, recorded_at=self.recorded_at,
                    installed_on_from=self.installed_on_from, read_on=self.read_on,
                    read_again=dict(self.read.reread) if self.read else {})


def build(observation: Path | str, *, ledger: KeyLedger | None = None,
          recorded_at: str = "", ip_plan: Path | str | None = None,
          schema_overlay: Path | str | None = None,
          installed_on_from: Sequence[str] | None = None) -> Cmdb:
    """Build the register for one observation directory.

    ``recorded_at`` defaults to the observation's own date when its directory
    is named by a time stamp, so rebuilding the same observation gives the
    same register. A derived observation (``takestock rerun``) holds rows read
    on different dates, so each row's facts, keys and edges are dated by the
    observation that read the row (:func:`read_dates`), and the register's
    own date is the full observation's; a ``recorded_at`` given here is the
    recording date of every fact. ``ip_plan`` names an IP address plan's JSON (as
    ``takestock ipam`` writes it); when given, every machine it names at an
    address is an item too (:func:`plan_machines`). It is never read unless
    named. ``schema_overlay`` names a schema overlay whose wording is merged
    over the schema (:func:`apply_overlay`). ``installed_on_from`` names the
    row sources or plug-ins (a row's ``source`` or ``extra.plugin``) whose
    lists of hosts (``extra.installed_on``, or a list in ``extra.hosts``) draw
    installed-on; any other row's list is left unread, as if it held none.
    None, the default, reads every row's list.
    """
    schema = load_schema(schema_overlay) if schema_overlay else None
    builder = _Builder(Path(observation), ledger, recorded_at,
                       Path(ip_plan) if ip_plan else None, schema, installed_on_from)
    builder.classify()
    builder.assert_facts()
    builder.fold()
    builder.count_populations()
    return builder.finish()


# ── The register as one document ───────────────────────────────────────────

HOW_TO_READ: tuple[tuple[str, str], ...] = (
    ("Every value says how strongly it is known.",
     "measured: an instrument read it off the thing itself. reported: a management "
     "system states it about something it manages. declared: a person or a document "
     "says so. inferred: derived from other facts by a rule. Strength and date are "
     "separate columns, because a strong old fact and a weak fresh one are different "
     "problems."),
    ("No cell is silently empty.",
     "Where there is no value, the cell names why. Not measured: the instrument ran "
     "and this attribute was missing from its result. Not collected: nobody supplied "
     "the input, which says nothing about the estate. Not applicable: there was never "
     "a value to have."),
    ("Where sources disagree, both are kept.",
     "One value is published by a stated rule and the attribute is marked contested. "
     "Every source's value is listed with it."),
    ("Match on the key, never on a name.",
     "A key such as CI-000123 carries no meaning and is never reused, so an item keeps "
     "it through a rename or a re-address. Every name it has been seen under is in its "
     "identifiers."),
    ("What is missing is counted.",
     "Every class the schema declares is listed with its count, zeros included, and "
     "the reason for each zero. Relationships declared and not drawn are listed with "
     "their reasons, and every reason a value is missing is tallied."),
)

_LIFECYCLE_NOTE = ("Set by the build: an item an instrument saw is discovered, one that "
                   "exists only on paper is planned, and nothing is live, because live "
                   "means an owner has accepted it.")
_UNASSERTED_NOTE = ("The schema declares this attribute for the class and no row stated "
                    "it. Says nothing about the estate.")


def _cell(res: Resolution) -> dict[str, Any]:
    absent = is_absent(res.value)
    return {"value": None if absent else res.value,
            "absent": res.value.reason if absent else "",
            "absence_note": res.value.note if absent else "",
            "evidence_strength": res.evidence_strength, "valid_at": res.valid_at,
            "asserted_by": res.actor,
            "source_artefact": res.winner.actor.artefact if res.winner else "",
            "basis": res.basis, "contested": res.contested, "tie": res.tie}


def _schema_payload(schema: Schema) -> dict[str, Any]:
    carried: dict[str, list[str]] = {}
    for name, spec in schema.classes.items():
        for attribute in spec.get("attributes") or []:
            carried.setdefault(str(attribute), []).append(name)
    return {
        "version": schema.version,
        "maturity": schema.maturity,
        "governance": schema.governance,
        "authorities": schema.authorities,
        "families": schema.families,
        "classes": [{"name": name, "family": str(spec.get("family") or ""),
                     "answers": str(spec.get("answers") or ""),
                     "built_from": str(spec.get("built_from") or ""),
                     "note": str(spec.get("note") or ""),
                     "attributes": list(spec.get("attributes") or [])}
                    for name, spec in sorted(schema.classes.items())],
        "attributes": [{"name": name,
                        "expected_strength": str(spec.get("expected_strength") or ""),
                        "refresh_interval_days": spec.get("refresh_interval_days"),
                        "note": str(spec.get("note") or ""),
                        "carried_by": sorted(carried.get(name, []))}
                       for name, spec in sorted(schema.attributes.items())],
        "relationships": [{"name": name, "from": str(spec.get("from") or ""),
                           "to": str(spec.get("to") or ""),
                           "cardinality": str(spec.get("cardinality") or ""),
                           "asserts": str(spec.get("asserts") or ""),
                           "test": str(spec.get("test") or ""),
                           "drawn": bool(spec.get("built")),
                           "note": str(spec.get("note") or "")}
                          for name, spec in sorted(schema.relationships.items())],
        "vocabularies": schema.vocabularies,
        "minimum_attribute_set": schema.raw.get("minimum_attribute_set") or {},
    }


def _reading_notes(how_to_read: Sequence[Any] | None) -> list[dict[str, str]]:
    """``how_to_read`` as heading and body pairs; the built-in notes when it is None."""
    if how_to_read is None:
        return [{"heading": h, "body": b} for h, b in HOW_TO_READ]
    out: list[dict[str, str]] = []
    for n, entry in enumerate(how_to_read, start=1):
        if isinstance(entry, Mapping):
            heading, body = entry.get("heading"), entry.get("body")
        elif isinstance(entry, Sequence) and not isinstance(entry, str) and len(entry) == 2:
            heading, body = entry
        else:
            heading = body = None
        if not isinstance(heading, str) or not isinstance(body, str) or not heading.strip():
            raise ValueError(f"how_to_read entry {n} must give a heading and a body, as text")
        out.append({"heading": heading, "body": body})
    return out


#: What the workbook's read-me calls the register's items when it counts them.
ITEM_NOUN = "configuration items"


def _item_noun(noun: Any) -> str:
    """``noun`` stripped, or :data:`ITEM_NOUN` when it is empty; refused unless text."""
    if not isinstance(noun, str):
        raise ValueError("item_noun must be text: what to call the items, in the plural")
    return noun.strip() or ITEM_NOUN


def register_payload(register: Cmdb, *, title: str = "", organisation: str = "",
                     how_to_read: Sequence[Any] | None = None,
                     item_noun: str = "") -> dict[str, Any]:
    """The whole register as one plain dict: the schema, then the data.

    ``title`` and ``organisation`` head the register. ``how_to_read`` replaces
    the built-in reading notes (:data:`HOW_TO_READ`) with the caller's own:
    a list of ``{"heading": ..., "body": ...}`` mappings or (heading, body)
    pairs. It reaches the JSON and the workbook's read-me alike. ``item_noun``
    is what the workbook's read-me calls the items when it counts them, in
    the plural (default :data:`ITEM_NOUN`).
    """
    noun = _item_noun(item_noun)
    notes = _reading_notes(how_to_read)
    schema = register.schema
    resolved = register.resolved()
    items: list[dict[str, Any]] = []
    unasserted = 0
    for key, item in sorted(register.items.items()):
        attrs = resolved.get(key, {})
        cells: dict[str, Any] = {}
        for attribute in schema.class_attributes(item.item_class):
            if attribute in attrs:
                cells[attribute] = _cell(attrs[attribute])
            elif attribute == "lifecycle_state":
                cells[attribute] = {"value": item.lifecycle_state, "absent": "",
                                    "evidence_strength": INFERRED,
                                    "asserted_by": "configuration register build",
                                    "basis": PROPOSED, "note": _LIFECYCLE_NOTE}
            else:
                cells[attribute] = {"value": None, "absent": "not-collected",
                                    "absence_note": _UNASSERTED_NOTE}
                unasserted += 1
        items.append({"key": key, "class": item.item_class, "family": item.family,
                      "name": item.label, "lifecycle_state": item.lifecycle_state,
                      "aliases": [vars(a) for a in item.aliases], "attributes": cells})

    conflicts = [{"item": key, "attribute": attr, **r.payload()}
                 for key, attrs in sorted(resolved.items())
                 for attr, r in sorted(attrs.items()) if r.contested]
    contested = {(c["item"], c["attribute"]) for c in conflicts}
    facts = []
    for a in register.assertions:
        held = register.items.get(a.item)
        absent = is_absent(a.value)
        facts.append({"key": a.item, "class": held.item_class if held else "",
                      "name": held.label if held else "", "attribute": a.attribute,
                      "value": None if absent else a.value,
                      "absent": a.value.reason if absent else "",
                      "absence_note": a.value.note if absent else "",
                      "evidence_strength": a.evidence_strength, "valid_at": a.valid_at,
                      "recorded_at": a.recorded_at, "asserted_by": a.actor.name,
                      "actor_kind": a.actor.kind, "source_artefact": a.actor.artefact,
                      "source_artefact_digest": a.actor.artefact_digest, "basis": a.basis,
                      "contested": (a.item, a.attribute) in contested})

    def label(key: str) -> str:
        return register.items[key].label if key in register.items else ""

    relationships = [{"from": e.from_key, "from_name": label(e.from_key), "type": e.kind,
                      "to": e.to_key, "to_name": label(e.to_key), "count": e.count,
                      "unit": e.unit, "evidence_strength": e.evidence_strength,
                      "valid_at": e.valid_at, "qualifier": e.qualifier}
                     for e in register.edges]

    absence: dict[str, int] = {}
    for attrs in resolved.values():
        for r in attrs.values():
            if is_absent(r.value):
                absence[r.value.reason] = absence.get(r.value.reason, 0) + 1
    census = register.census()
    return {
        "register": {
            "title": title or "Configuration register",
            "organisation": organisation,
            "observation": register.observation,
            "recorded_at": register.recorded_at,
            "read_on": register.read_on or register.recorded_at,
            "read_again": dict(sorted(register.read_again.items())),
            "item_noun": noun,
            "schema_version": schema.version,
            "schema_maturity": schema.maturity,
            "schema_overlay": schema.overlay,
            "counts": {
                "configuration_items": len(register.items),
                "recorded_facts": len(register.assertions),
                "relationships": len(register.edges),
                "contested_attributes": len(conflicts),
                "absences_recorded": sum(absence.values()),
                "attributes_declared_and_unasserted": unasserted,
                "classes_declared": len(census),
                "classes_populated": sum(1 for row in census if row["items"]),
            },
            "governance": {**{k: v for k, v in schema.governance.items() if k != "cites"},
                           "unassigned": schema.unassigned_roles()},
            **({"installed_on_from": list(register.installed_on_from)}
               if register.installed_on_from is not None else {}),
        },
        "how_to_read": notes,
        "schema": _schema_payload(schema),
        "census": census,
        "items": items,
        "relationships": relationships,
        "relationships_not_drawn": [{"relationship": name, "reason": reason}
                                    for name, reason in schema.declared_not_built()],
        "conflicts": conflicts,
        "populations": [p.payload() for p in register.populations],
        "absence": {"recorded_by_reason": dict(sorted(absence.items())),
                    "attributes_declared_and_unasserted": unasserted},
        "merges": register.ledger.merges,
        "facts": facts,
        "key_ledger": register.ledger.records(),
    }


def read_keys(path: Path | str) -> KeyLedger:
    """A ledger from a ``keys.jsonl`` written by an earlier build."""
    lines = Path(path).read_text().splitlines()
    return KeyLedger.from_records(json.loads(line) for line in lines if line.strip())


def build_register(observation_dir: Path | str, *, keys: Path | str | None = None,
                   recorded_at: str = "", title: str = "",
                   ip_plan: Path | str | None = None,
                   schema_overlay: Path | str | None = None, organisation: str = "",
                   how_to_read: Sequence[Any] | None = None,
                   installed_on_from: Sequence[str] | None = None,
                   item_noun: str = "") -> dict[str, Any]:
    """Build the register for ``observation_dir`` and return it as one dict.

    ``keys`` names an earlier build's ``keys.jsonl`` so items keep their keys;
    ``ip_plan`` an IP address plan's JSON whose named machines become items;
    ``schema_overlay`` a schema overlay (:func:`apply_overlay`). ``title``,
    ``organisation``, ``how_to_read`` and ``item_noun`` are as for
    :func:`register_payload`; ``installed_on_from`` as for :func:`build`.
    """
    ledger = read_keys(keys) if keys else None
    return register_payload(build(observation_dir, ledger=ledger, recorded_at=recorded_at,
                                  ip_plan=ip_plan, schema_overlay=schema_overlay,
                                  installed_on_from=installed_on_from),
                            title=title, organisation=organisation, how_to_read=how_to_read,
                            item_noun=item_noun)


def write_outputs(register: Mapping[str, Any], out_dir: Path | str, *,
                  theme: Any = None, jira_assets: bool = False) -> list[Path]:
    """Write ``register`` as JSON, CSV per class, a workbook and the key ledger.

    ``theme`` (a :class:`takestock.htmlpage.Theme`) styles the workbook;
    ``jira_assets`` also writes an import for Jira Assets (see
    :func:`takestock.cmdb_export.write_jira_assets`).
    """
    from . import cmdb_export
    return cmdb_export.write_all(register, Path(out_dir), theme=theme, jira_assets=jira_assets)


# ── Options a target profile sets ──────────────────────────────────────────

#: The keys a profile's ``cmdb:`` block may hold.
PROFILE_KEYS: tuple[str, ...] = ("title", "schema_overlay", "how_to_read", "jira_assets",
                                 "installed_on_from", "item_noun")


@dataclass(frozen=True)
class ProfileOptions:
    """What a target profile asks of the register, read by :func:`profile_options`."""

    title: str = ""
    organisation: str = ""
    schema_overlay: Path | None = None
    how_to_read: tuple[dict[str, str], ...] | None = None
    theme: Any = None
    jira_assets: bool = False
    installed_on_from: tuple[str, ...] | None = None
    item_noun: str = ""

    def build_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for :func:`build_register`."""
        return {"title": self.title, "organisation": self.organisation,
                "schema_overlay": self.schema_overlay, "how_to_read": self.how_to_read,
                "installed_on_from": self.installed_on_from, "item_noun": self.item_noun}

    def write_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for :func:`write_outputs`."""
        return {"theme": self.theme, "jira_assets": self.jira_assets}


def profile_options(target: Mapping[str, Any]) -> ProfileOptions:
    """The register options a loaded target profile sets.

    Read from the profile's ``cmdb:`` block (``title``, ``schema_overlay``,
    ``how_to_read``, ``jira_assets``, ``installed_on_from``, ``item_noun``), its
    organisation's name, and its
    ``branding:`` block, which styles the workbook only when it sets
    anything. A relative path is read from the directory holding the profile;
    ``how_to_read`` is a list of ``{heading, body}`` entries, or the path of a
    YAML file holding that list. An unknown key in ``cmdb:`` is refused.
    """
    from . import htmlpage

    block = target.get("cmdb") or {}
    if not isinstance(block, Mapping):
        raise ValueError("cmdb: must be a mapping")
    unknown = sorted(set(block) - set(PROFILE_KEYS))
    if unknown:
        raise ValueError(f"cmdb: does not take {', '.join(unknown)}; "
                         f"it takes {', '.join(PROFILE_KEYS)}")
    tpath = target.get("_path")
    base = Path(tpath).parent if tpath else Path()

    def path(value: Any, key: str) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"cmdb.{key} must name a file")
        p = Path(value).expanduser()
        return p if p.is_absolute() else base / p

    overlay = path(block["schema_overlay"], "schema_overlay") if block.get("schema_overlay") else None
    notes: tuple[dict[str, str], ...] | None = None
    raw_notes = block.get("how_to_read")
    if isinstance(raw_notes, str):
        raw_notes = load_yaml_strict(path(raw_notes, "how_to_read"))
    if raw_notes is not None:
        if not isinstance(raw_notes, list):
            raise ValueError("cmdb.how_to_read must be a list of {heading, body} entries")
        notes = tuple(_reading_notes(raw_notes))
    title = block.get("title") or ""
    if not isinstance(title, str):
        raise ValueError("cmdb.title must be text")
    jira = block.get("jira_assets", False)
    if not isinstance(jira, bool):
        raise ValueError("cmdb.jira_assets must be true or false")
    sources = block.get("installed_on_from")
    if sources is not None and not isinstance(sources, list):
        raise ValueError("cmdb.installed_on_from must be a list of non-blank row sources "
                         "or plug-in names")
    try:
        installed_on_from = _source_names(sources)
    except ValueError as exc:
        raise ValueError(f"cmdb.{exc}") from exc
    item_noun = block.get("item_noun", "")
    if "item_noun" in block and not (isinstance(item_noun, str) and item_noun.strip()):
        raise ValueError("cmdb.item_noun must be text: what to call the items, in the plural")
    has_org = any(target.get(k) for k in ("organisation", "org"))
    theme = htmlpage.theme_from_target(dict(target)) if target.get("branding") else None
    return ProfileOptions(
        title=title,
        organisation=htmlpage.organisation_name(dict(target)) if has_org else "",
        schema_overlay=overlay, how_to_read=notes, theme=theme, jira_assets=jira,
        installed_on_from=installed_on_from, item_noun=item_noun)


def build_and_write(observation: Path | str, out_dir: Path | str, *,
                    keys: Path | str | None = None, ip_plan: Path | str | None = None,
                    target: str | None = None) -> tuple[dict[str, Any], list[Path]]:
    """Build the register and write every view, with a named target profile's options.

    Returns the register and the paths written.
    """
    options = ProfileOptions()
    if target:
        from . import config
        options = profile_options(config.load_target(target))
    register = build_register(observation, keys=keys, ip_plan=ip_plan,
                              **options.build_kwargs())
    return register, write_outputs(register, out_dir, **options.write_kwargs())


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m takestock.cmdb``: build and write the register for one observation.

    Exits 0 when the register is written, and 2 for wrong arguments or an
    unreadable input (see :mod:`takestock.exits`).
    """
    return guarded("takestock.cmdb", _main, argv)


def _main(argv: Sequence[str] | None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m takestock.cmdb",
        description="Build a draft configuration register from one observation.")
    parser.add_argument("observation", type=Path, help="the observation directory")
    parser.add_argument("out", type=Path, nargs="?",
                        help="where to write it (default: <observation>/cmdb)")
    parser.add_argument("--keys", type=Path,
                        help="an earlier build's keys.jsonl, so items keep their keys")
    parser.add_argument("--ip-plan", type=Path,
                        help="an IP address plan's JSON; each machine it names becomes an item")
    parser.add_argument("--target", metavar="PROFILE",
                        help="a target profile whose cmdb:, organisation and branding: "
                             "blocks set the register's options")
    args = parser.parse_args(argv)
    out = args.out or args.observation / "cmdb"
    register, paths = build_and_write(args.observation, out, keys=args.keys,
                                      ip_plan=args.ip_plan, target=args.target)
    for path in paths:
        print(path)
    counts = register["register"]["counts"]
    print(f"{counts['configuration_items']} items, {counts['recorded_facts']} facts, "
          f"{counts['relationships']} relationships")
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
