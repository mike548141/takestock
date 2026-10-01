"""Recorded exceptions to a control, assessed per asset."""

from __future__ import annotations

import datetime as dt

import pytest
import yaml

from takestock import config
from takestock import dispensation as ds
from takestock.model import CryptoAsset

# A small synthetic baseline: one table, one row marked as breaching a MUST,
# one row under a conditional MUST, one under a SHOULD.
BASELINE = {
    "authorities": {"EXAMPLE": {"title": "Example Manual", "publisher": "Example Body",
                                "version": "1.0", "date": "2000-01"}},
    "compliance_levels": {"EXAMPLE": {
        "1.1.C.01": {"level": "must", "text": "Systems MUST use the example cipher."},
        "1.2.C.01": {"level": "must", "text": "New systems MUST NOT use the old hash.",
                     "condition": "Applies to new systems only."},
        "1.3.C.01": {"level": "should", "text": "Systems SHOULD rotate keys."},
    }},
    "example_table": {"old-cipher": "weak", "old-hash": "weak", "soft": "weak", "good": "strong"},
    "citations": {"example_table": {"tokens": {
        "old-cipher": [{"authority": "EXAMPLE", "control": "1.1.C.01", "breaches": True,
                        "commentary": "Settled: the cipher is not the example cipher."}],
        "old-hash": [{"authority": "EXAMPLE", "control": "1.2.C.01", "breaches": True,
                      "commentary": "Depends on whether the system is new."}],
        "soft": [{"authority": "EXAMPLE", "control": "1.3.C.01", "breaches": True,
                  "commentary": "A recommendation only."}],
        "good": [{"authority": "EXAMPLE", "control": "1.1.C.01"}],
    }}},
}

COMPLETE = {
    "id": "disp-01", "match": {"host_pattern": r"^web-"}, "controls": ["1.1.C.01"],
    "authority": "Example accreditation authority",
    "reason": "Example reason", "multi_agency_effect": "None",
    "alternative_mitigations": "Example mitigation", "mitigation_strength": "Moderate",
    "residual_risk": "Low", "review_by": "2050-06",
}

ASOF = dt.date(2050, 1, 1)


@pytest.fixture(autouse=True)
def _bundled_data_only(tmp_path):
    """Read the bundled ladder, never a data/ directory in the caller's working directory."""
    config.set_workspace(tmp_path)


def asset(token: str = "old-cipher", **kw) -> CryptoAsset:
    base = {"name": "svc", "data_state": "in-transit", "protocol": "tls",
            "host": "web-01.example.test", "verdict": "weak",
            "citations": [f"example_table/{token}"],
            "disposition": "wave-2", "disposition_basis": "decided"}
    base.update(kw)
    return CryptoAsset(**base)


def state(a: CryptoAsset, records=(), asof=ASOF) -> ds.Assessment:
    from takestock import citations
    return ds.assess(a, citations.resolve(BASELINE), list(records), asof)


def test_only_marked_must_level_citations_are_breaches():
    assert state(asset("good")).state == ds.NOT_APPLICABLE
    assert state(asset("soft")).state == ds.NOT_APPLICABLE
    got = state(asset("old-hash"))
    assert got.state == ds.NOT_APPLICABLE
    assert [q.control for q in got.questions] == ["1.2.C.01"]


@pytest.mark.parametrize("kw, expected", [
    ({"disposition": "critical"}, ds.ACTING),
    ({"disposition": "", "disposition_basis": "none"}, ds.UNDECIDED),
    ({}, ds.NO_DISPENSATION),
])
def test_states_before_any_record(kw, expected):
    assert state(asset(**kw)).state == expected


def test_the_act_now_rungs_come_from_the_ladder():
    from takestock import citations
    a = asset(disposition="now")
    assert ds.assess(a, citations.resolve(BASELINE), (), ASOF, out_of_cycle={"now"}).state == ds.ACTING
    assert state(a).state == ds.NO_DISPENSATION


def test_a_complete_current_record_covers_the_breach():
    got = state(asset(), [COMPLETE])
    assert (got.state, got.record_id, got.authority, got.adverse) == (
        ds.COVERED, "disp-01", "Example accreditation authority", False)


def test_a_record_must_cover_every_breached_control():
    assert state(asset(), [dict(COMPLETE, controls=["9.9.C.01"])]).state == ds.NO_DISPENSATION
    assert state(asset(host="db-01.example.test"), [COMPLETE]).state == ds.NO_DISPENSATION


def test_missing_elements_are_named_with_their_control():
    record = dict(COMPLETE, authority="", residual_risk="", multi_agency=True)
    got = state(asset(), [record])
    assert got.state == ds.INCOMPLETE and got.adverse
    assert {(m["field"], m["control"]) for m in got.missing} == {
        ("authority", ds.GRANT_CONTROL), ("residual_risk", ds.ASSESSMENT_CONTROL),
        ("parties_consulted", ds.CONSULT_CONTROL)}


def test_a_review_date_that_is_not_a_date_counts_as_missing():
    got = state(asset(), [dict(COMPLETE, review_by="next year")])
    assert [m["field"] for m in got.missing] == ["review_by"]


def test_a_review_month_lapses_only_once_it_is_over():
    assert state(asset(), [COMPLETE], dt.date(2050, 6, 30)).state == ds.COVERED
    assert state(asset(), [COMPLETE], dt.date(2050, 7, 1)).state == ds.LAPSED


def test_payload_counts_states_and_controls():
    rows = [asset(), asset(host="db-01.example.test"), asset("good")]
    out = ds.payload(rows, BASELINE, [COMPLETE], ASOF)
    assert out["counts"][ds.COVERED] == 1
    assert out["counts"][ds.NO_DISPENSATION] == 1
    assert out["counts"][ds.NOT_APPLICABLE] == 1
    assert out["by_control"] == {"1.1.C.01": 2}
    assert out["asof"] == "2050-01-01"
    assert out["review_control"]["level"] == "should"
    assert {r["field"] for r in out["required"]} >= {"authority", "review_by", "parties_consulted"}
    assert ds.commentary_cell(out["rows"][0]) == "1.1.C.01: Settled: the cipher is not the example cipher."


def test_records_are_read_from_the_dispositions_overlay(tmp_path):
    profile = tmp_path / "widgets.yaml"
    profile.write_text("{}\n")
    (tmp_path / "widgets.dispositions.yaml").write_text(
        yaml.safe_dump({"dispensations": [COMPLETE, "not a record"]}))
    assert [r["id"] for r in ds.records_for_target({"_path": str(profile)})] == ["disp-01"]
    assert ds.records_for_target({"_path": str(tmp_path / "other.yaml")}) == []
    assert ds.records_for_target(None) == []


# A record that applies only to endpoints an outside provider runs.
OUTSIDE = {**COMPLETE, "id": "disp-outside", "match": {"third_party": True}}


def outside_rules():
    from takestock import disposition
    profile = {"third_party": [{"name": "Example Hosting", "domains": ["hosting.example.com"]}],
               "scan_targets": {"saas_443": [{"host": "app.example.net"}]}}
    rules = disposition.DispositionRules()
    rules.third_party_hosts, rules.third_party_domains = disposition.operated_elsewhere(profile)
    return rules


def test_a_third_party_record_matches_with_the_outside_provider_list():
    from takestock import citations
    resolved, rules = citations.resolve(BASELINE), outside_rules()
    for host in ("web-01.hosting.example.com", "app.example.net"):
        got = ds.assess(asset(host=host), resolved, [OUTSIDE], ASOF, rules=rules)
        assert (got.state, got.record_id) == (ds.COVERED, "disp-outside"), host
    own = ds.assess(asset(host="web-01.example.test"), resolved, [OUTSIDE], ASOF, rules=rules)
    assert own.state == ds.NO_DISPENSATION


def test_payload_passes_the_outside_provider_list_through():
    rows = [asset(host="web-01.hosting.example.com"), asset(host="web-01.example.test")]
    out = ds.payload(rows, BASELINE, [OUTSIDE], ASOF, rules=outside_rules())
    assert out["counts"][ds.COVERED] == 1
    assert out["counts"][ds.NO_DISPENSATION] == 1


def test_the_act_now_rungs_can_come_from_the_rules():
    from takestock import citations, disposition
    rules = disposition.DispositionRules(ladder=[{"track": "urgent", "out_of_cycle": True}])
    got = ds.assess(asset(disposition="urgent"), citations.resolve(BASELINE), [], ASOF,
                    rules=rules)
    assert got.state == ds.ACTING
