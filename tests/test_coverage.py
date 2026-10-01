"""Coverage gaps: classification, validation and grouping."""

from __future__ import annotations

import pytest

from takestock import coverage
from takestock.coverage import gap


def test_a_gap_is_a_string_with_its_classification():
    g = gap(coverage.NOT_COLLECTED, "No export of the 40 example-site switches was supplied.")
    assert isinstance(g, str)
    assert g == "No export of the 40 example-site switches was supplied."
    assert (g.kind, g.required, g.impact_kind, g.nature) == (
        coverage.NOT_COLLECTED, True, coverage.IMPACT_UNWRITTEN, coverage.NATURE_UNSTATED)


def test_an_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="unknown coverage-gap kind"):
        gap("guessed", "text")
    with pytest.raises(ValueError):
        gap(coverage.UNCLASSIFIED, "text")   # read-back only, never produced


def test_required_must_be_a_real_bool():
    with pytest.raises(TypeError):
        gap(coverage.NOT_COLLECTED, "text", 1)  # type: ignore[arg-type]
    assert gap(coverage.NOT_COLLECTED, "text", False).required is False


def test_an_impact_kind_needs_its_sentence_and_a_sentence_needs_its_kind():
    with pytest.raises(ValueError, match="no impact= sentence"):
        gap(coverage.COULD_NOT_TEST, "text", impact_kind=coverage.CHANGES_CONCLUSION)
    with pytest.raises(ValueError, match="leaves impact_kind"):
        gap(coverage.COULD_NOT_TEST, "text", impact="A reader cannot tell X from Y.")
    g = gap(coverage.COULD_NOT_TEST, "text", impact="A reader cannot tell X from Y.",
            impact_kind=coverage.NARROWS_CONFIDENCE)
    assert coverage.impact_of(g) == "A reader cannot tell X from Y."


def test_an_unknown_impact_kind_or_nature_is_refused():
    with pytest.raises(ValueError):
        gap(coverage.NOT_COLLECTED, "text", impact_kind="dramatic")
    with pytest.raises(ValueError):
        gap(coverage.NOT_COLLECTED, "text", nature="fuzzy")


def test_not_measured_cannot_also_be_no_data():
    with pytest.raises(ValueError):
        gap(coverage.NOT_MEASURED, "text", nature=coverage.NO_DATA)
    assert gap(coverage.NOT_MEASURED, "text", nature=coverage.LOW_FIDELITY).nature == coverage.LOW_FIDELITY


# A neutral sample of an assessment's scope areas, as a caller would supply them.
SAMPLE_AREAS = {
    "Backup and recovery": ("backup and recovery",),
    "Logging and monitoring": ("logging and monitoring", "security monitoring"),
    "Physical security": ("physical security", "site security"),
}


def test_no_scope_areas_are_bundled():
    assert coverage.SCOPE_AREAS == {}
    assert coverage.scope_area_subject("Physical security is unmeasured.") is None


@pytest.mark.parametrize("text", [
    "Backup and recovery is unmeasured.",
    "The security monitoring is not assessed",
    "All physical security is missing",
])
def test_a_whole_scope_area_is_not_a_gap(text):
    assert coverage.scope_area_subject(text, SAMPLE_AREAS) is not None
    with pytest.raises(ValueError, match="scope area"):
        gap(coverage.NOT_COLLECTED, text, areas=SAMPLE_AREAS)


@pytest.mark.parametrize("text", [
    "Backup and recovery on the 12 file servers is unmeasured.",
    "Backup and recovery on `files.example.test` is unmeasured.",
    "Backup and recovery in hosts.csv is unmeasured.",
    "Backup and recovery was read from the export.",
])
def test_a_bounded_or_present_statement_is_not_an_area_claim(text):
    assert coverage.scope_area_subject(text, SAMPLE_AREAS) is None


def test_the_module_table_applies_when_a_caller_fills_it(monkeypatch):
    monkeypatch.setattr(coverage, "SCOPE_AREAS", SAMPLE_AREAS)
    with pytest.raises(ValueError, match="scope area"):
        gap(coverage.NOT_COLLECTED, "Physical security is unknown")


def test_readers_tolerate_plain_strings():
    plain = "An old gap stored as text"
    assert coverage.kind_of(plain) == coverage.UNCLASSIFIED
    assert coverage.is_required(plain) is True
    assert coverage.impact_kind_of(plain) == coverage.IMPACT_UNWRITTEN
    assert coverage.nature_of(plain) == coverage.NATURE_UNSTATED
    assert coverage.harvest_of(plain) == ""


def test_required_gaps_drops_only_explicitly_optional_ones():
    gaps = [gap(coverage.NOT_COLLECTED, "a"), gap(coverage.NOT_COLLECTED, "b", False), "c"]
    assert coverage.required_gaps(gaps) == ["a", "c"]


def test_group_orders_by_kind_and_omits_empty_kinds():
    texts = ["one", "two", "three"]
    groups = coverage.group(texts, [coverage.COULD_NOT_TEST, coverage.NOT_COLLECTED, "from-the-future"])
    assert [g[0] for g in groups] == [coverage.NOT_COLLECTED, coverage.COULD_NOT_TEST,
                                      coverage.UNCLASSIFIED]
    kind, heading, gloss, members = groups[0]
    assert heading == coverage.LABELS[coverage.NOT_COLLECTED][0] and gloss
    assert members == ["two"]


def test_a_short_kinds_list_leaves_the_rest_unclassified():
    groups = coverage.group(["a", "b"], [coverage.NOT_COLLECTED])
    assert [(g[0], list(g[3])) for g in groups] == [(coverage.NOT_COLLECTED, ["a"]),
                                                     (coverage.UNCLASSIFIED, ["b"])]


def test_group_keeps_parallel_classifications():
    groups = coverage.group(["a"], [coverage.COULD_NOT_TEST], ["Impact sentence."],
                            [coverage.CHANGES_CONCLUSION], ["Ask for the export."],
                            [coverage.LOW_FIDELITY])
    g = groups[0][3][0]
    assert (g.impact, g.impact_kind, g.harvest, g.nature) == (
        "Impact sentence.", coverage.CHANGES_CONCLUSION, "Ask for the export.", coverage.LOW_FIDELITY)


def test_every_label_table_is_complete():
    assert set(coverage.LABELS) == set(coverage.KINDS)
    assert set(coverage.IMPACT_LABELS) == set(coverage.IMPACT_KINDS)
    assert set(coverage.NATURE_LABELS) == set(coverage.NATURES)
