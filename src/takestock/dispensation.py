"""Recorded exceptions to a control, assessed per asset.

Deciding that a finding can wait is a priority call. It is not, by itself, a
position on compliance: where the finding breaches a MUST-level control, the
New Zealand Information Security Manual (NZISM) lets that control go unmet only
under a **dispensation**, and says who grants one and what it must record.
This module checks each asset against the dispensations an organisation has
recorded and reports one state per asset (see :data:`STATE_LABEL`).

Dispensation records live in the organisation's dispositions overlay
(``targets/<stem>.dispositions.yaml``) under ``dispensations:``. Each has an
``id``, a ``match:`` block (the same keys as a disposition rule), the
``controls`` it covers, and the fields below, each required by the NZISM
control named beside it. A ``third_party`` match key needs the target's
outside-provider list, which arrives with the loaded rules (``rules=``,
from :func:`takestock.disposition.load_dispositions_for_target`); without
them every host counts as the organisation's own.

==========================  ===========  ======================================
Field                       Control      Requires
==========================  ===========  ======================================
``authority``               1.1.64.C.01  granted by the Accreditation Authority
``reason`` and five more    1.1.65.C.01  the six elements of the risk assessment
``parties_consulted``       1.1.67.C.01  consultation, where ``multi_agency``
==========================  ===========  ======================================

Annual review (1.1.68.C.01) is a SHOULD, not a MUST; record retention
(1.1.69.C.01) is a MUST that the record itself satisfies.

Only citations the baseline marks ``breaches: true`` count, and only for
controls cited on a graded row. A ``not-applicable`` state therefore means no
breach is *visible to this tool*, not that none exists. A control whose text
carries a condition the tool cannot resolve is reported as a question, never a
breach. Nothing here refuses a malformed record: it is assessed ``incomplete``
with the missing elements named.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace

from . import citations as citations_data
from . import config, disposition
from .model import CryptoAsset

GRANT_FIELD = "authority"
GRANT_CONTROL = "1.1.64.C.01"
GRANT_REQUIRES = "granted by the Accreditation Authority"

# The six elements of the risk assessment, in the order the control lists them.
ASSESSMENT_FIELDS: dict[str, str] = {
    "reason": "the reason(s) for not being able to comply",
    "multi_agency_effect": "the effect on their own, multi-agency or All-of-Government systems",
    "alternative_mitigations": "the alternative mitigation measure(s) to be implemented",
    "mitigation_strength": "the strength and applicability of the alternative mitigations",
    "residual_risk": "an assessment of the residual security risk(s)",
    "review_by": "a date by which to review the decision",
}
ASSESSMENT_CONTROL = "1.1.65.C.01"

# Required only where the record declares the system multi-agency or
# All-of-Government, which the tool cannot tell for itself.
CONSULT_FIELD = "parties_consulted"
CONSULT_CONTROL = "1.1.67.C.01"
CONSULT_REQUIRES = "interested parties formally consulted"
MULTI_AGENCY_FLAG = "multi_agency"

REVIEW_CONTROL = "1.1.68.C.01"      # SHOULD: reviewed at least annually
RETENTION_CONTROL = "1.1.69.C.01"   # MUST: a record is kept

#: The citation field that marks a row as failing the cited control.
BREACH_KEY = "breaches"

NOT_APPLICABLE = "not-applicable"
ACTING = "acting"
UNDECIDED = "undecided"
NO_DISPENSATION = "no-dispensation"
INCOMPLETE = "incomplete"
LAPSED = "lapsed"
COVERED = "covered"

STATE_LABEL: dict[str, str] = {
    NOT_APPLICABLE: "No breach of a MUST-level control is visible here",
    ACTING: "Breaches a MUST-level control, and is scheduled to act now",
    UNDECIDED: "Breaches a MUST-level control, and no decision has been recorded",
    NO_DISPENSATION: "Deferred, and breaches a MUST-level control with no dispensation recorded",
    INCOMPLETE: "A dispensation is recorded, but it is missing something the manual requires",
    LAPSED: "A dispensation is recorded and complete, but its review date has passed",
    COVERED: "Deferred under a recorded dispensation",
}

#: States a report should present as adverse.
ADVERSE_STATES = frozenset({NO_DISPENSATION, INCOMPLETE, LAPSED})

_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MONTH = re.compile(r"^(\d{4})-(\d{2})$")


@dataclass
class Breach:
    """A cited MUST-level control the asset fails."""

    control: str
    authority: str
    level: str
    key: str
    token: str
    note: str = ""
    control_text: str = ""
    classifications: str = ""
    commentary: str = ""

    def as_dict(self) -> dict:
        return {"control": self.control, "authority": self.authority,
                "level": self.level, "key": self.key, "token": self.token,
                "note": self.note, "control_text": self.control_text,
                "classifications": self.classifications,
                "commentary": self.commentary}


@dataclass
class Question:
    """A cited MUST-level control whose condition the tool cannot resolve."""

    control: str
    authority: str
    level: str
    key: str
    token: str
    condition: str = ""
    control_text: str = ""
    commentary: str = ""

    def as_dict(self) -> dict:
        return {"control": self.control, "authority": self.authority,
                "level": self.level, "key": self.key, "token": self.token,
                "condition": self.condition, "control_text": self.control_text,
                "commentary": self.commentary}


@dataclass
class Assessment:
    """One asset's dispensation state, with what it rests on."""

    state: str
    breaches: list[Breach] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    record_id: str = ""
    missing: list[dict] = field(default_factory=list)
    review_by: str = ""
    authority: str = ""

    @property
    def adverse(self) -> bool:
        return self.state in ADVERSE_STATES

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "breaches": [b.as_dict() for b in self.breaches],
            "questions": [q.as_dict() for q in self.questions],
            "record": self.record_id,
            "missing": list(self.missing),
            "review_by": self.review_by,
            "authority": self.authority,
        }


def breaches_and_questions(a: CryptoAsset,
                           resolved: Mapping[str, list[dict]]) -> tuple[list[Breach], list[Question]]:
    """The breaches and open questions among ``a``'s citations.

    ``resolved`` is :func:`takestock.citations.resolve` output. Only citations
    marked as breached at a binding level count; each (authority, control, key)
    is reported once.
    """
    breaches: list[Breach] = []
    questions: list[Question] = []
    seen: set[tuple[str, str, str]] = set()
    for key in a.citations:
        token = str(key).partition("/")[2]
        for cite in resolved.get(key, []):
            if not cite.get(BREACH_KEY):
                continue
            if cite.get("compliance") not in citations_data.BINDING_LEVELS:
                continue
            ident = (cite.get("authority", ""), cite.get("control", ""), key)
            if ident in seen:
                continue
            seen.add(ident)
            common = {"control": cite.get("control", ""), "authority": cite.get("authority", ""),
                      "level": cite.get("compliance", ""), "key": key, "token": token,
                      "control_text": cite.get("control_text", ""),
                      "commentary": cite.get("commentary", "")}
            if cite.get("condition"):
                questions.append(Question(condition=cite.get("condition", ""), **common))
            else:
                breaches.append(Breach(note=cite.get("note", ""),
                                       classifications=cite.get("classifications", ""),
                                       **common))
    return breaches, questions


def _covers(record: Mapping, breaches: Iterable[Breach]) -> bool:
    declared = {str(c).strip() for c in (record.get("controls") or [])}
    if not declared:
        return False
    return all(b.control in declared for b in breaches)


def _review_last_day(value: str) -> _dt.date | None:
    """The last day a review date can mean (a day, or the end of a month); None if not a date."""
    v = str(value or "").strip()
    try:
        if _DAY.match(v):
            return _dt.date.fromisoformat(v)
        m = _MONTH.match(v)
        if m:
            y, mo = int(m.group(1)), int(m.group(2))
            first_next = _dt.date(y + (mo == 12), 1 if mo == 12 else mo + 1, 1)
            return first_next - _dt.timedelta(days=1)
    except ValueError:
        return None
    return None


def _missing_elements(record: Mapping) -> list[dict]:
    out: list[dict] = []
    if not str(record.get(GRANT_FIELD, "") or "").strip():
        out.append({"field": GRANT_FIELD, "control": GRANT_CONTROL,
                    "level": citations_data.MUST, "requires": GRANT_REQUIRES})
    for name, what in ASSESSMENT_FIELDS.items():
        value = str(record.get(name, "") or "").strip()
        # A review date that is not a date can never lapse, so it counts as missing.
        if not value or (name == "review_by" and _review_last_day(value) is None):
            out.append({"field": name, "control": ASSESSMENT_CONTROL,
                        "level": citations_data.MUST, "requires": what})
    if record.get(MULTI_AGENCY_FLAG) and not str(record.get(CONSULT_FIELD, "") or "").strip():
        out.append({"field": CONSULT_FIELD, "control": CONSULT_CONTROL,
                    "level": citations_data.MUST, "requires": CONSULT_REQUIRES})
    return out


def _tool_out_of_cycle() -> frozenset[str]:
    return frozenset(r["track"] for r in disposition.load_ladder() if r["out_of_cycle"])


def assess(a: CryptoAsset,
           resolved: Mapping[str, list[dict]],
           records: Iterable[Mapping] = (),
           asof: _dt.date | None = None,
           out_of_cycle: Iterable[str] | None = None,
           rules: disposition.DispositionRules | None = None) -> Assessment:
    """The dispensation state of one asset on ``asof`` (default today).

    ``a`` should already carry its disposition. ``rules`` are the disposition
    rules loaded for the target; they carry its outside-provider list, which
    a ``third_party`` match key reads. ``out_of_cycle`` names the ladder's
    act-now rungs; by default, those of ``rules``, or else of the tool's own
    ladder. The first record whose match block fits the asset and whose
    ``controls`` cover every breach is used.
    """
    asof = asof or _dt.date.today()
    breaches, questions = breaches_and_questions(a, resolved)
    if not breaches:
        return Assessment(state=NOT_APPLICABLE, questions=questions)
    if out_of_cycle is None:
        out_of_cycle = rules.out_of_cycle if rules is not None else _tool_out_of_cycle()
    if a.disposition in set(out_of_cycle):
        return Assessment(state=ACTING, breaches=breaches, questions=questions)
    if a.disposition_basis == disposition.BASIS_NONE or not a.disposition:
        return Assessment(state=UNDECIDED, breaches=breaches, questions=questions)

    record = next((r for r in records
                   if disposition.matches(r.get("match", {}), a, rules) and _covers(r, breaches)),
                  None)
    if record is None:
        return Assessment(state=NO_DISPENSATION, breaches=breaches, questions=questions)

    found = Assessment(state=COVERED, breaches=breaches, questions=questions,
                       record_id=str(record.get("id", "") or ""),
                       review_by=str(record.get("review_by", "") or "").strip(),
                       authority=str(record.get(GRANT_FIELD, "") or "").strip())
    missing = _missing_elements(record)
    if missing:
        return replace(found, state=INCOMPLETE, missing=missing)
    last = _review_last_day(found.review_by)
    if last is not None and last < asof:
        return replace(found, state=LAPSED)
    return found


def commentary_cell(row: Mapping) -> str:
    """The commentary of every breach and question in an assessment row, once each."""
    parts = [f"{b.get('control', '')}: {b.get('commentary', '')}".strip(": ")
             for b in row.get("breaches", []) if b.get("commentary")]
    parts += [f"{q.get('control', '')}: {q.get('commentary', '')}".strip(": ")
              for q in row.get("questions", []) if q.get("commentary")]
    out: list[str] = []
    for p in parts:
        if p not in out:
            out.append(p)
    return "  ".join(out)


def records_for_target(target: Mapping | None) -> list[dict]:
    """The ``dispensations:`` records in a target's dispositions overlay; [] if none."""
    if not target:
        return []
    path = disposition.overlay_path_for_target(dict(target))
    if path is None:
        return []
    doc = config.load_yaml_strict(path) or {}
    return [r for r in (doc.get("dispensations") or []) if isinstance(r, dict)]


def required_elements() -> list[dict]:
    """Every element a dispensation record must carry, with the control requiring it."""
    return ([{"field": GRANT_FIELD, "control": GRANT_CONTROL,
              "level": citations_data.MUST, "requires": GRANT_REQUIRES}]
            + [{"field": k, "control": ASSESSMENT_CONTROL,
                "level": citations_data.MUST, "requires": v}
               for k, v in ASSESSMENT_FIELDS.items()]
            + [{"field": CONSULT_FIELD, "control": CONSULT_CONTROL,
                "level": citations_data.MUST,
                "requires": CONSULT_REQUIRES + ", where the system is multi-agency "
                                               "or All-of-Government"}])


def payload(assets: Iterable[CryptoAsset],
            baseline: Mapping,
            records: Iterable[Mapping] = (),
            asof: _dt.date | None = None,
            out_of_cycle: Iterable[str] | None = None,
            rules: disposition.DispositionRules | None = None) -> dict:
    """Every asset's assessment, with counts per state and per control, for a report.

    ``rules`` and ``out_of_cycle`` are as for :func:`assess`.
    """
    asof = asof or _dt.date.today()
    if out_of_cycle is not None:
        out_of_cycle = frozenset(out_of_cycle)
    elif rules is not None:
        out_of_cycle = rules.out_of_cycle
    else:
        out_of_cycle = _tool_out_of_cycle()
    resolved = citations_data.resolve(dict(baseline))
    records = list(records)
    rows: list[dict] = []
    counts: dict[str, int] = {s: 0 for s in STATE_LABEL}
    controls: dict[str, int] = {}
    for a in assets:
        got = assess(a, resolved, records, asof, out_of_cycle, rules)
        counts[got.state] = counts.get(got.state, 0) + 1
        for b in got.breaches:
            controls[b.control] = controls.get(b.control, 0) + 1
        rows.append(got.as_dict())
    return {
        "rows": rows,
        "counts": counts,
        "by_control": controls,
        "labels": dict(STATE_LABEL),
        "adverse": sorted(ADVERSE_STATES),
        "records": len(records),
        "asof": asof.isoformat(),
        "required": required_elements(),
        "review_control": {"control": REVIEW_CONTROL, "level": citations_data.SHOULD,
                           "requires": "reviewed at least annually"},
        "retention_control": {"control": RETENTION_CONTROL, "level": citations_data.MUST,
                              "requires": "a record of the risk assessment and the decision "
                                          "is retained"},
    }
