"""Coverage gaps: what an observation could not see, and why.

A report that lists only what it found reads as complete. Every collector
therefore also records its *gaps*: questions it was meant to answer and could
not. A :class:`Gap` is a string (the sentence a reader sees) carrying a
classification, so a report can group gaps and say what each one costs.

Three independent classifications travel with each gap:

* **kind**: why the answer is missing (input not supplied, probe could not
  run, known incomplete, measured incompletely);
* **impact kind**: whether the missing fact could change a conclusion or only
  narrows confidence in it;
* **nature**: whether nothing is held, or something is held at too coarse a
  grain.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

# ── kind: why the answer is missing ──
NOT_COLLECTED = "not-collected"
COULD_NOT_TEST = "could-not-test"
EXTENT_UNKNOWN = "extent-unknown"
NOT_MEASURED = "not-measured"
# Read back from an observation written before gaps were classified.
UNCLASSIFIED = "unclassified"

KINDS = (NOT_COLLECTED, COULD_NOT_TEST, EXTENT_UNKNOWN, NOT_MEASURED, UNCLASSIFIED)

# ── impact kind: what the gap costs a reader ──
CHANGES_CONCLUSION = "changes-conclusion"
NARROWS_CONFIDENCE = "narrows-confidence"
IMPACT_UNWRITTEN = "impact-unwritten"

IMPACT_KINDS = (CHANGES_CONCLUSION, NARROWS_CONFIDENCE, IMPACT_UNWRITTEN)

# ── nature: nothing held, or held too coarsely ──
NO_DATA = "no-data"
LOW_FIDELITY = "low-fidelity"
NATURE_UNSTATED = "nature-unstated"

NATURES = (NO_DATA, LOW_FIDELITY, NATURE_UNSTATED)

#: Heading and one-line gloss for each nature.
NATURE_LABELS: dict[str, tuple[str, str]] = {
    NO_DATA: (
        "No data held",
        "Nothing has been recorded about this. The subject may be well "
        "configured or badly configured; this report cannot say which, and "
        "must not be read as saying either.",
    ),
    LOW_FIDELITY: (
        "Held, but not in enough detail",
        "A record exists and was read. It answers a coarser question than the "
        "one asked — the fact is present, the detail that would settle it is "
        "not.",
    ),
    NATURE_UNSTATED: (
        "Nature not yet stated",
        "Nobody has recorded whether this is missing data or data at too "
        "coarse a grain. The report is not held back for it.",
    ),
}

NATURE_UNSTATED_TEXT = (
    "⏳ Nature not yet stated — whether this is missing data or data at too "
    "coarse a grain follows in a later update.")

#: Heading and one-line gloss for each impact kind.
IMPACT_LABELS: dict[str, tuple[str, str]] = {
    CHANGES_CONCLUSION: (
        "Changes a conclusion",
        "A statement in this report could be wrong, or a decision could go the "
        "other way, once this fact lands.",
    ),
    NARROWS_CONFIDENCE: (
        "Narrows confidence",
        "The findings stand as measured. This bounds how far they generalise, "
        "not whether they are right.",
    ),
    IMPACT_UNWRITTEN: (
        "Impact not yet written",
        "This gap is named as measured today; its impact follows in a later "
        "update. The report is not held back for it.",
    ),
}

IMPACT_UNWRITTEN_TEXT = (
    "⏳ Impact not yet written — this gap is named as measured today; its "
    "impact follows in a later update.")

#: Heading and one-line gloss for each kind.
LABELS: dict[str, tuple[str, str]] = {
    NOT_COLLECTED: (
        "Not collected",
        "Nobody has supplied this input yet. This says nothing about the "
        "estate — only that the question is still open.",
    ),
    COULD_NOT_TEST: (
        "Could not test",
        "The question was asked and no answer came back: a probe was not run "
        "or was refused, or the source carries no item for the question.",
    ),
    EXTENT_UNKNOWN: (
        "Known incomplete — extent unknown",
        "Something is shown to be missing but not what. Each of these is "
        "measured against an independent count, not inferred from the file "
        "that is short.",
    ),
    NOT_MEASURED: (
        "Measured incompletely",
        "The instrument ran and returned a result, but one attribute of "
        "that result was absent — not a failed attempt and not an "
        "unsupplied input.",
    ),
    UNCLASSIFIED: (
        "Not yet classified",
        "Recorded before coverage gaps were classified. Left exactly as the "
        "observation stated it.",
    ),
}


# Whole areas of an assessment, each mapped to the phrases that name it. A gap
# must be something WITHIN an area (a system, a population, an attribute); "the
# whole of an area is unmeasured" is undone work, not a gap, so gap() refuses
# text that says it. Which areas an assessment covers is the caller's to say:
# the bundled table is empty, and a caller either fills it or passes its own
# mapping to gap() and scope_area_subject().
SCOPE_AREAS: dict[str, tuple[str, ...]] = {}

# Phrases that say something is absent.
_ABSENCE = (
    "is unmeasured", "are unmeasured", "is unknown", "are unknown",
    "is not measured", "are not measured", "is not assessed", "are not assessed",
    "is not covered", "are not covered", "has not been measured",
    "have not been measured", "has not been assessed", "have not been assessed",
    "is a gap", "are a gap", "is missing", "are missing",
    "nobody has looked", "nothing has looked", "no evidence", "not collected",
)

# Anything that bounds a sentence to something specific: a number, a quoted
# or back-ticked name, or a data file. Bounded text is never an area claim.
_BOUND = re.compile(r"\d|`[^`]+`|\"[^\"]+\"|'[^']+'|\S+\.(?:csv|json|xlsx|yaml|yml)")

_LEADING = re.compile(r"^(?:the|our|all|any|every)\s+")


def scope_area_subject(text: str, areas: Mapping[str, Sequence[str]] | None = None) -> str | None:
    """The scope area ``text`` declares absent as a whole, or None.

    A clause counts only when it begins with an area's name (after a leading
    "the", "all" and the like) and says the area is missing or unmeasured.
    Text carrying a number, a quoted name or a file name is bounded and never
    matches.
    """
    if _BOUND.search(text):
        return None
    table = SCOPE_AREAS if areas is None else areas
    for clause in re.split(r"[.;:]\s+|\s+[—-]\s+", " ".join(text.split())):
        lowered = _LEADING.sub("", clause.strip().lower())
        if not any(p in lowered for p in _ABSENCE):
            continue
        for area, phrases in table.items():
            for phrase in phrases:
                if re.match(rf"{re.escape(phrase)}(?![a-z0-9])", lowered):
                    return area
    return None


class Gap(str):
    """A coverage gap: the sentence itself, plus its classification.

    Being a ``str`` means any code that handles gaps as plain text keeps
    working; code that knows about gaps reads the attributes.
    """

    kind: str
    required: bool
    impact: str
    impact_kind: str
    harvest: str
    nature: str

    def __new__(cls, kind: str, text: str, required: bool = True, *,
                impact: str = "", impact_kind: str = IMPACT_UNWRITTEN,
                harvest: str = "", nature: str = NATURE_UNSTATED) -> Gap:
        self = super().__new__(cls, text)
        self.kind = kind
        self.required = required
        self.impact = impact
        self.impact_kind = impact_kind
        self.harvest = harvest
        self.nature = nature
        return self


def gap(kind: str, text: str, required: bool = True, *,
        impact: str = "", impact_kind: str = IMPACT_UNWRITTEN,
        harvest: str = "", nature: str = NATURE_UNSTATED,
        areas: Mapping[str, Sequence[str]] | None = None) -> Gap:
    """Build a validated :class:`Gap`. This is how collectors should make one.

    ``required`` says whether the input is one the assessment needs.
    ``impact`` is a sentence saying what a reader cannot decide without the
    fact; it is required when ``impact_kind`` claims an impact, and forbidden
    when it does not. ``harvest`` says how the fact could be obtained.
    ``areas`` is the assessment's scope-area table (default
    :data:`SCOPE_AREAS`).

    Raises ValueError or TypeError for any combination that would let a
    report state something nobody decided, for example an impact sentence
    with no impact kind, or a whole scope area filed as a gap.
    """
    if kind not in (NOT_COLLECTED, COULD_NOT_TEST, EXTENT_UNKNOWN, NOT_MEASURED):
        raise ValueError(
            f"unknown coverage-gap kind {kind!r} — expected one of "
            f"{[NOT_COLLECTED, COULD_NOT_TEST, EXTENT_UNKNOWN, NOT_MEASURED]}")
    if not isinstance(required, bool):
        raise TypeError(
            f"coverage.gap() required= must be a real bool, got {required!r} "
            f"({type(required).__name__}) — a truthy or falsy non-bool would record a "
            f"required/optional claim nobody stated")
    if impact_kind not in IMPACT_KINDS:
        raise ValueError(
            f"unknown gap impact_kind {impact_kind!r} — expected one of "
            f"{list(IMPACT_KINDS)}. A gap that changes a conclusion and one "
            "that only narrows confidence are different risks, and a reader "
            "cannot tell them apart if the label is invented")
    if not isinstance(impact, str) or not isinstance(harvest, str):
        raise TypeError(
            f"coverage.gap() impact= and harvest= must be str, got "
            f"{type(impact).__name__}/{type(harvest).__name__}")
    if impact_kind in (CHANGES_CONCLUSION, NARROWS_CONFIDENCE) and not impact.strip():
        raise ValueError(
            f"coverage.gap() impact_kind={impact_kind!r} with no impact= sentence. "
            "Naming the kind is a claim about a sentence, so the sentence is owed: "
            "say what a reader cannot decide, or would decide differently, because "
            "this fact is missing")
    if impact_kind == IMPACT_UNWRITTEN and impact.strip():
        raise ValueError(
            "coverage.gap() carries an impact= sentence but leaves impact_kind at "
            f"{IMPACT_UNWRITTEN!r}. A reader told what a gap costs and not told "
            "whether it moves a conclusion has been handed the softer reading by "
            f"default — pass impact_kind={CHANGES_CONCLUSION!r} or "
            f"{NARROWS_CONFIDENCE!r}")
    area = scope_area_subject(text, areas)
    if area is not None:
        raise ValueError(
            f"coverage.gap() text is about {area!r} as a whole, which is a scope "
            "area and cannot be a gap: a gap is something within an area. An area "
            "with no instrument is undone work, and filing it as a gap disguises "
            "the difference. Bound it: name the system, the population or the "
            "attribute — a count, a `named system` or a file all clear this check. "
            f"Text was: {text[:120]!r}")
    if nature not in NATURES:
        raise ValueError(
            f"unknown gap nature {nature!r} — expected one of {list(NATURES)}. "
            "A gap filed as 'nothing held' when a coarse record was in fact "
            "read sends the reader to the wrong remedy: chase a new source, "
            "rather than ask the existing source for more detail")
    if kind == NOT_MEASURED and nature == NO_DATA:
        raise ValueError(
            f"coverage.gap() kind={NOT_MEASURED!r} with nature={NO_DATA!r}. "
            f"{NOT_MEASURED!r} means the instrument ran and returned a result "
            "with one attribute absent — which IS the low-fidelity statement, "
            "so one of the two labels is wrong and there is no reading that "
            f"makes both true. Pass nature={LOW_FIDELITY!r}, or a different kind")
    return Gap(kind, text, required, impact=impact, impact_kind=impact_kind,
               harvest=harvest, nature=nature)


# Readers. Each accepts a Gap or a plain string (from an older observation)
# and falls back to the "not stated" value rather than raising.

def kind_of(entry: object) -> str:
    """The gap's kind, or ``unclassified``."""
    k = getattr(entry, "kind", "")
    return k if k in KINDS else UNCLASSIFIED


def kinds(gaps: Iterable[object]) -> list[str]:
    """:func:`kind_of` for each gap, in order."""
    return [kind_of(g) for g in gaps]


def is_required(entry: object) -> bool:
    """Whether the gap is in a required input; only an explicit False is optional."""
    return getattr(entry, "required", True) is not False


def impact_of(entry: object) -> str:
    """The impact sentence, or ""."""
    v = getattr(entry, "impact", "")
    return v if isinstance(v, str) else ""


def impact_kind_of(entry: object) -> str:
    """The impact kind, or ``impact-unwritten``."""
    k = getattr(entry, "impact_kind", "")
    return k if k in IMPACT_KINDS else IMPACT_UNWRITTEN


def nature_of(entry: object) -> str:
    """The nature, or ``nature-unstated``."""
    n = getattr(entry, "nature", "")
    return n if n in NATURES else NATURE_UNSTATED


def natures(gaps: Iterable[object]) -> list[str]:
    """:func:`nature_of` for each gap, in order."""
    return [nature_of(g) for g in gaps]


def harvest_of(entry: object) -> str:
    """How the missing fact could be obtained, or ""."""
    v = getattr(entry, "harvest", "")
    return v if isinstance(v, str) else ""


def impacts(gaps: Iterable[object]) -> list[str]:
    """:func:`impact_of` for each gap, in order."""
    return [impact_of(g) for g in gaps]


def impact_kinds(gaps: Iterable[object]) -> list[str]:
    """:func:`impact_kind_of` for each gap, in order."""
    return [impact_kind_of(g) for g in gaps]


def harvests(gaps: Iterable[object]) -> list[str]:
    """:func:`harvest_of` for each gap, in order."""
    return [harvest_of(g) for g in gaps]


def required_gaps(gaps: Iterable[object]) -> list[object]:
    """Only the gaps in required inputs."""
    return [g for g in gaps if is_required(g)]


def group(gaps: Sequence[str],
          gap_kinds: Sequence[str] | None = None,
          gap_impacts: Sequence[str] | None = None,
          gap_impact_kinds: Sequence[str] | None = None,
          gap_harvests: Sequence[str] | None = None,
          gap_natures: Sequence[str] | None = None,
          ) -> list[tuple[str, str, str, list[Gap]]]:
    """Group gaps by kind for display, as (kind, heading, gloss, gaps).

    A stored observation keeps gap text and its classifications in parallel
    lists; pass them here. A list shorter than ``gaps`` leaves the remainder
    unclassified rather than guessing. Kinds come back in :data:`KINDS` order
    and empty kinds are omitted.
    """
    ks = list(gap_kinds or [])
    ims = list(gap_impacts or [])
    imks = list(gap_impact_kinds or [])
    hs = list(gap_harvests or [])
    ns = list(gap_natures or [])
    buckets: dict[str, list[Gap]] = {k: [] for k in KINDS}
    for i, text in enumerate(gaps):
        k = ks[i] if i < len(ks) else UNCLASSIFIED
        impact = ims[i] if i < len(ims) else impact_of(text)
        imk = imks[i] if i < len(imks) else impact_kind_of(text)
        harvest = hs[i] if i < len(hs) else harvest_of(text)
        nat = ns[i] if i < len(ns) else nature_of(text)
        buckets[k if k in KINDS else UNCLASSIFIED].append(
            Gap(k, str(text), True, impact=impact if isinstance(impact, str) else "",
                impact_kind=imk if imk in IMPACT_KINDS else IMPACT_UNWRITTEN,
                harvest=harvest if isinstance(harvest, str) else "",
                nature=nat if nat in NATURES else NATURE_UNSTATED))
    return [(k, *LABELS[k], buckets[k]) for k in KINDS if buckets[k]]
