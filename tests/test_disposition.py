"""Disposition rules, an organisation's overlay, decisions and adoptions."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from takestock import config
from takestock import disposition as d
from takestock.model import CryptoAsset


@pytest.fixture(autouse=True)
def _bundled_data_only(tmp_path):
    """Read the bundled data files, never a data/ directory in the caller's working directory."""
    config.set_workspace(tmp_path)


def asset(**kw) -> CryptoAsset:
    base = {"name": "svc", "data_state": "in-transit", "protocol": "tls",
            "host": "web-01.example.test", "port": "443"}
    base.update(kw)
    return CryptoAsset(**base)


@pytest.fixture(scope="module")
def bundled() -> d.DispositionRules:
    return d.load_dispositions(path=config.BUNDLED_DATA_DIR / "dispositions.yaml")


def write_yaml(path: Path, doc: dict) -> Path:
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    return path


RULE = {"id": "example-weak", "match": {"verdict": "weak"}, "disposition": "wave-2",
        "effort": "M", "effort_scope": "per-asset", "reason": "An example reason."}


# ── the bundled rules ──

def test_every_bundled_rule_is_valid_and_nothing_is_decided(bundled):
    assert bundled.rules
    assert all(d.validate_rule(r) == [] for r in bundled.rules)
    assert bundled.decisions == [] and bundled.adoptions == [] and bundled.programme == {}


@pytest.mark.parametrize("kw, track, rule_id", [
    ({"verdict": "weak", "flags": ["null-cipher"]}, "critical", "null-cipher"),
    ({"verdict": "weak", "flags": ["deprecated-protocol:SSLv3"]}, "critical", "sslv2-or-sslv3-offered"),
    ({"verdict": "weak", "flags": ["deprecated-protocol:TLSv1.0"], "internet_facing": True},
     "wave-1", "internet-facing-weak"),
    ({"verdict": "weak", "flags": ["deprecated-protocol:TLSv1.0"]}, "wave-1", "weak-not-internet-facing"),
    ({"verdict": "unknown", "flags": ["plaintext:telnet"]}, "wave-1", "cleartext-service"),
    ({"verdict": "unknown", "flags": ["plaintext:dns", "no-encrypted-alternative:dns"]},
     "accept-no-alternative", "accept-no-alternative-cleartext"),
    ({"verdict": "unknown", "flags": ["plaintext:ssdp", "cleartext-exposure:metadata"]},
     "wave-1", "cleartext-device-metadata"),
    ({"verdict": "strong", "extra": {"replaced_by": True}},
     "accept-replacement-planned", "accept-replacement-tolerable-control"),
    ({"verdict": "acceptable", "extra": {"retiring_by": True}},
     "defer-migration", "defer-migration-retiring-infrastructure"),
    ({"verdict": "acceptable", "hashes": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]},
     "retire-planned", "retire-planned-sha1-still-accepted"),
    ({"verdict": "strong", "flags": ["quantum-vulnerable-signature"]},
     "pqc-migrate", "pqc-migrate-signature-only"),
    ({"verdict": "pqc"}, "no-action", "no-action-strong-or-pqc"),
])
def test_bundled_rules_place_each_case(bundled, kw, track, rule_id):
    a = d.apply_disposition(asset(**kw), bundled)
    assert a.disposition == track
    assert a.disposition_basis == d.BASIS_PROPOSED
    assert d.deciding_entry(a, bundled)[1]["id"] == rule_id


def test_a_weak_internet_facing_asset_is_never_absorbed_by_a_softer_track(bundled):
    a = d.apply_disposition(asset(verdict="weak", internet_facing=True,
                                  extra={"replaced_by": True}), bundled)
    assert a.disposition == "wave-1"


def test_a_per_rule_effort_groups_by_rule_id(bundled):
    a = d.apply_disposition(asset(verdict="strong", flags=["quantum-vulnerable-kex"]), bundled)
    assert (a.disposition, a.effort, a.effort_group) == ("pqc-migrate", "L", "pqc-migrate-key-establishment")
    b = d.apply_disposition(asset(verdict="weak", flags=["null-cipher"]), bundled)
    assert b.effort_group == ""


def test_nothing_matching_leaves_the_asset_undecided(bundled):
    a = d.apply_disposition(asset(verdict="unknown"), bundled)
    assert (a.disposition, a.disposition_basis, a.effort) == ("", d.BASIS_NONE, "")


def test_the_tool_supplies_no_post_quantum_date(bundled):
    a = d.apply_disposition(asset(verdict="strong", flags=["quantum-vulnerable-kex"]), bundled)
    assert a.pqc_deadline == ""


# ── the overlay ──

def test_overlay_rules_and_decisions_come_first(tmp_path):
    overlay = write_yaml(tmp_path / "widgets.dispositions.yaml", {
        "programme": {"pqc_target_year": 2040},
        "rules": [RULE],
        "decisions": [{"when": "2000-01-01", "match": {"host_pattern": r"^legacy-"},
                       "disposition": "accept-no-alternative", "effort": "S",
                       "effort_scope": "per-asset", "reason": "Example acceptance.",
                       "until": "the example system is replaced", "review": "2099-12"}],
    })
    dr = d.load_dispositions(overlay=overlay)
    a = d.apply_disposition(asset(verdict="weak"), dr)
    assert (a.disposition, a.disposition_basis) == ("wave-2", d.BASIS_PROPOSED)

    b = d.apply_disposition(asset(verdict="weak", host="legacy-01.example.test",
                                  flags=["quantum-vulnerable-kex"]), dr)
    assert (b.disposition, b.disposition_basis) == ("accept-no-alternative", d.BASIS_DECIDED)
    assert b.disposition_until == "the example system is replaced"
    assert b.disposition_review == "2099-12"
    assert b.pqc_deadline == "2040"


def test_an_unknown_section_is_refused(tmp_path):
    overlay = write_yaml(tmp_path / "widgets.dispositions.yaml", {"decision": []})
    with pytest.raises(ValueError, match="unknown section"):
        d.load_dispositions(overlay=overlay)


def test_an_effort_without_a_scope_is_refused(tmp_path):
    bad = dict(RULE)
    del bad["effort_scope"]
    overlay = write_yaml(tmp_path / "widgets.dispositions.yaml", {"rules": [bad]})
    with pytest.raises(d.UndeclaredEffortScopeError, match="example-weak"):
        d.load_dispositions(overlay=overlay)


def test_the_overlay_and_providers_are_found_from_the_target(tmp_path):
    profile = tmp_path / "widgets.yaml"
    profile.write_text("{}\n")
    write_yaml(tmp_path / "widgets.dispositions.yaml", {"rules": [RULE]})
    target = {"_path": str(profile),
              "scan_targets": {"saas_443": [{"host": "app.saas.example"}], "smtp_25": ["mx.mail.example"]},
              "third_party": [{"name": "Example Hosting", "domains": ["hosting.example.net."]}]}
    dr = d.load_dispositions_for_target(target)
    assert dr.rules[0]["id"] == "example-weak"
    assert dr.is_third_party("APP.saas.example.")
    assert dr.is_third_party("mx.mail.example")
    assert dr.is_third_party("www.hosting.example.net")
    assert not dr.is_third_party("www.example.test")
    assert d.overlay_path_for_target({"_path": str(tmp_path / "other.yaml")}) is None


def test_a_provider_endpoint_without_hsts_is_accepted_not_scheduled(bundled):
    dr = d.DispositionRules(rules=bundled.rules, third_party_hosts=frozenset({"app.saas.example"}))
    provider = d.apply_disposition(asset(source="hsts", host="app.saas.example", flags=["hsts-absent"]), dr)
    own = d.apply_disposition(asset(source="hsts", host="www.example.test", flags=["hsts-absent"]), dr)
    assert provider.disposition == "accept-no-alternative"
    assert provider.disposition_until
    assert own.disposition == "wave-1"


# ── adoptions ──

def test_an_adopted_rule_is_decided_until_it_is_reworded():
    adoption = {"rules": ["example-weak"], "rule_hashes": {"example-weak": d.rule_hash(RULE)}}
    dr = d.DispositionRules(rules=[RULE], adoptions=[adoption])
    assert d.apply_disposition(asset(verdict="weak"), dr).disposition_basis == d.BASIS_DECIDED
    assert dr.adoption_drift() == []

    reworded = dict(RULE, reason="A different reason.")
    dr = d.DispositionRules(rules=[reworded], adoptions=[adoption])
    assert d.apply_disposition(asset(verdict="weak"), dr).disposition_basis == d.BASIS_PROPOSED
    assert [x["state"] for x in dr.adoption_drift()] == ["reworded"]


def test_the_rule_hash_ignores_id_and_whitespace_and_an_explicit_default():
    implicit = {k: v for k, v in RULE.items() if k != "effort_scope"}
    assert d.rule_hash(implicit) == d.rule_hash(RULE)
    assert d.rule_hash(dict(RULE, id="renamed", reason="An  example\nreason.")) == d.rule_hash(RULE)


# ── match keys ──

def test_match_keys_each_constrain():
    a = asset(verdict="weak", flags=["plaintext:ftp", "x"], extra={"tier": "Gold"},
              key_exchange=["ecdhe"], hashes=["hmac-sha1"])
    assert d.matches({"flags_prefix_none": ["deprecated-protocol:"]}, a)
    assert not d.matches({"flags_prefix_none": ["plaintext:"]}, a)
    assert d.matches({"flags_all": ["x", "plaintext:ftp"]}, a)
    assert d.matches({"primitive_any": ["sha1"]}, a)
    assert d.matches({"extra_any": {"tier": ["gold", "silver"]}}, a)
    assert not d.matches({"extra_any": {"zone": "a"}}, a)
    assert not d.matches({"third_party": True}, a)
    with pytest.raises(ValueError, match="unknown match key"):
        d.matches({"colour": "red"}, a)
    with pytest.raises(ValueError, match="true or false"):
        d.matches({"third_party": "yes"}, a)


# ── end conditions and review dates ──

def test_review_states():
    assert d.review_state("wave-1", "2000-01-01", "2050-01-01") == d.REVIEW_NOT_APPLICABLE
    assert d.review_state("accept-replacement-planned", "", "2050-01-01") == d.REVIEW_NONE
    assert d.review_state("accept-replacement-planned", "2050-01", "2050-01-31") == d.REVIEW_SET
    assert d.review_state("accept-replacement-planned", "2050-01", "2050-02-01") == d.REVIEW_LAPSED


def test_end_condition_texts():
    open_ended = d.end_condition("retire-planned", "")
    assert open_ended["state"] == d.END_OPEN_ENDED
    bounded = d.end_condition("accept-replacement-planned", "the new service is in use",
                              "2000-01-01", "2050-01-01")
    assert bounded["state"] == d.END_UNTIL and bounded["stale"]
    assert "the new service is in use" in bounded["text"]
    assert d.end_condition("wave-1", "")["state"] == d.END_NOT_APPLICABLE


def test_accepted_breakout_counts_lapsed_apart():
    rows = [asset(verdict="weak", disposition="accept-replacement-planned", disposition_review="2000-01-01"),
            asset(verdict="weak", disposition="accept-replacement-planned", disposition_review="2099-01-01"),
            asset(verdict="strong", disposition="accept-no-alternative"),
            asset(verdict="weak", disposition="wave-1")]
    out = d.accepted_breakout(rows, today="2050-06-01")
    assert out == {"assets": 2, "findings": 1, "with_review": 1, "no_review_date": 1,
                   "lapsed": 1, "lapsed_findings": 1}
    assert d.is_stale_acceptance(rows[0], today="2050-06-01")


# ── validation and integrity ──

@pytest.mark.parametrize("change, problem", [
    ({"disposition": "later"}, "not in"),
    ({"effort": "XXL"}, "effort"),
    ({"effort_scope": None}, "missing 'effort_scope'"),
    ({"effort_scope": "per-rule", "id": ""}, "needs an 'id'"),
    ({"until": " "}, "'until' is present but empty"),
    ({"disposition": "no-action", "until": "never"}, "nothing ends"),
    ({"disposition": "accept-replacement-planned", "review": "soon"}, "is not a date"),
    ({"review": "2050-01-01"}, "belongs to an acceptance"),
    ({"match": {"colour": "red"}}, "unknown match key"),
])
def test_validate_rule_names_each_problem(change, problem):
    rule = dict(RULE, **change)
    if rule.get("effort_scope") is None:
        rule.pop("effort_scope")
    assert any(problem in p for p in d.validate_rule(rule))


def test_integrity_problems_count_the_inflation():
    no_id = {"match": {"verdict": "weak"}, "disposition": "wave-1", "effort": "M",
             "effort_scope": "per-rule", "reason": "x", "when": "2000-01-01"}
    dr = d.DispositionRules(decisions=[no_id])
    rows = [asset(verdict="weak"), asset(verdict="weak"), asset(verdict="weak")]
    (p,) = d.integrity_problems(dr, rows)
    assert (p["kind"], p["affected"], p["inflated_units_by"]) == ("decision", 3, 2)
    assert d.integrity_problems(d.DispositionRules(rules=[RULE])) == []


# ── recording which set an observation ran under ──

def test_set_digest_and_render_basis():
    one = d.set_digest(d.DispositionRules(rules=[RULE]))
    two = d.set_digest(d.DispositionRules(rules=[RULE], decisions=[RULE]))
    assert one != two
    assert d.render_basis(one, one, "2050-01-01")["state"] == d.BASIS_AS_OBSERVED
    assert d.render_basis(one, two, "2050-01-01")["state"] == d.BASIS_CHANGED
    assert d.render_basis("", two, "2050-01-01")["state"] == d.BASIS_NOT_RECORDED
    assert d.render_basis(one, "", "2050-01-01")["state"] == d.BASIS_NOT_REAPPLIED


def test_the_bundled_ladder_and_its_labels(bundled):
    assert bundled.rungs == ("critical", "wave-1", "wave-2", "wave-3")
    assert bundled.out_of_cycle == frozenset({"critical"})
    assert set(bundled.track_order) == bundled.valid_tracks
    assert bundled.track_label("wave-1") == "Wave 1"
    assert bundled.track_label("no-action") == "No action"
    assert d.ACCEPTANCE_TRACKS <= bundled.valid_tracks


def test_an_overlay_may_declare_its_own_ladder(tmp_path):
    ladder = [{"track": "now", "label": "Now", "out_of_cycle": True},
              {"track": "critical", "label": "Urgent"}, {"track": "wave-1", "label": "Next"},
              {"track": "later", "label": "Later"}]
    rule = dict(RULE, disposition="later")
    dr = d.load_dispositions(overlay=write_yaml(tmp_path / "widgets.dispositions.yaml",
                                                {"ladder": ladder, "rules": [rule]}))
    assert dr.rungs == ("now", "critical", "wave-1", "later")
    assert dr.out_of_cycle == frozenset({"now"})
    assert d.apply_disposition(asset(verdict="weak"), dr).disposition == "later"
    assert d.validate_rule(rule, dr.valid_tracks) == []
    assert any("not in" in p for p in d.validate_rule(rule))


def test_a_ladder_missing_a_proposed_rung_is_refused(tmp_path):
    overlay = write_yaml(tmp_path / "widgets.dispositions.yaml",
                         {"ladder": [{"track": "critical", "label": "Critical"}]})
    with pytest.raises(d.LadderError, match="internet-facing-weak"):
        d.load_dispositions(overlay=overlay)
    with pytest.raises(d.LadderError):
        d.parse_ladder([{"track": "no-action"}])
    with pytest.raises(d.LadderError):
        d.parse_ladder([])
