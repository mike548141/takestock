"""Units of work (``takestock.remediation``): one row per piece of work, not per finding.

Every asset here is composed for an invented organisation: ``.example.test``
hosts, round numbers and 2030 dates. The assertions that matter most are the
negative ones. The planner exists to stop a plan looking more achievable than
the evidence allows, so the tests that earn their keep show it refusing to
claim leverage it cannot prove.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from takestock import plugin_kinds, plugins, remediation
from takestock.disposition import DispositionRules
from takestock.model import CryptoAsset

ROOT = Path(__file__).resolve().parents[1]


def _a(name, **kw) -> CryptoAsset:
    kw.setdefault("data_state", "in-transit")
    kw.setdefault("disposition", "critical")
    kw.setdefault("disposition_basis", "proposed")
    kw.setdefault("disposition_reason", "This service carries traffic in clear.")
    kw.setdefault("effort", "M")
    return CryptoAsset(name=name, **kw)


def _fleet(n, prefix="svc", **kw) -> list[CryptoAsset]:
    return [_a(f"{prefix}{i}", host=f"h{i}.example.test", **kw) for i in range(n)]


# ── the grouping itself ──

def test_a_shared_effort_group_is_one_unit_of_work():
    plan = remediation.plan(_fleet(5, effort_group="rule-x"))
    assert plan["totals"]["findings"] == 5
    assert plan["totals"]["units"] == 1
    assert plan["rows"][0]["assets_cleared"] == 5
    assert plan["rows"][0]["shared"] is True


def test_an_ungrouped_asset_is_its_own_unit():
    plan = remediation.plan(_fleet(3))
    assert plan["totals"]["units"] == 3
    assert all(r["assets_cleared"] == 1 and not r["shared"] for r in plan["rows"])


def test_an_asset_with_no_disposition_is_skipped_not_bucketed():
    assets = [_a("decided", host="a.example.test"),
              CryptoAsset(name="undecided", data_state="in-transit")]
    plan = remediation.plan(assets)
    assert plan["totals"]["units"] == 1
    assert plan["totals"]["findings"] == 1
    assert plan["coverage"]["assets_with_no_track"] == 1


def test_two_different_groups_never_merge():
    assets = [_a("a", host="a.example.test", effort_group="rule-x"),
              _a("b", host="b.example.test", effort_group="rule-y")]
    assert remediation.plan(assets)["totals"]["units"] == 2


def test_one_host_with_two_findings_is_one_visit_not_two():
    assets = [_a("a", host="a.example.test", port="80", effort_group="rule-x"),
              _a("b", host="a.example.test", port="81", effort_group="rule-x")]
    row = remediation.plan(assets)["rows"][0]
    assert (row["assets_cleared"], row["hosts"]) == (2, 1)


def test_an_asset_with_no_host_falls_back_to_its_address_then_its_name():
    assets = [_a("by-ip", ip="192.0.2.7", effort_group="g"),
              _a("by-name", effort_group="g")]
    assert remediation.unit_assets(assets) == {"g": ["192.0.2.7", "by-name"]}


# ── one decision, or N actions ──

def test_a_multi_asset_unit_can_never_read_as_verified():
    for n in (2, 5, 40):
        actions = remediation.plan(_fleet(n, effort_group="rule-x"))["rows"][0]["actions"]
        assert actions["basis"] == "unverified"
        assert actions["actions"] is None
        assert actions["upper_bound"] == n


def test_the_upper_bound_is_distinct_hosts_not_assets():
    assets = [_a(f"s{i}", host=f"h{i % 4}.example.test", port=str(i), effort_group="rule-x")
              for i in range(12)]
    actions = remediation.plan(assets)["rows"][0]["actions"]
    assert actions["upper_bound"] == 4
    assert "4" in actions["note"]


def test_a_single_asset_unit_is_the_one_case_that_is_proven():
    actions = remediation.plan([_a("solo", host="solo.example.test")])["rows"][0]["actions"]
    assert (actions["basis"], actions["actions"], actions["upper_bound"]) == ("single-asset", 1, 1)


def test_unverified_units_are_counted_in_the_totals():
    assets = _fleet(4, effort_group="rule-x") + [_a("solo", host="solo.example.test")]
    totals = remediation.plan(assets)["totals"]
    assert (totals["units"], totals["unverified_units"], totals["shared_units"]) == (2, 1, 1)


# ── work and non-work ──

def test_tracks_that_decline_to_act_are_not_work():
    for track in ("no-action", "accept-replacement-planned", "accept-no-alternative"):
        plan = remediation.plan([_a("a", host="a.example.test", disposition=track)])
        assert plan["rows"][0]["is_work"] is False, track
        assert plan["totals"]["work_units"] == 0


def test_deferred_and_retiring_work_is_still_work():
    for track in ("defer-migration", "retire-planned", "pqc-migrate", "wave-2"):
        plan = remediation.plan([_a("a", host="a.example.test", disposition=track)])
        assert plan["rows"][0]["is_work"] is True, track


def test_an_acceptance_past_its_review_date_is_work_again():
    lapsed = _a("a", host="a.example.test", disposition="accept-no-alternative",
                disposition_review="2000-01-01")
    current = _a("b", host="b.example.test", disposition="accept-no-alternative",
                 disposition_review="2090-01-01")
    plan = remediation.plan([lapsed, current])
    by_host = {r["key"]: r["is_work"] for r in plan["rows"]}
    assert by_host[f"asset:{lapsed.bom_ref()}"] is True
    assert by_host[f"asset:{current.bom_ref()}"] is False


# ── sizes, lifecycle, flags, usage ──

def test_a_unit_with_one_size_reports_it_and_a_mixed_unit_reports_none():
    same = remediation.plan(_fleet(2, effort_group="g", effort="L"))["rows"][0]
    mixed = remediation.plan([_a("a", host="a.example.test", effort_group="g", effort="S"),
                              _a("b", host="b.example.test", effort_group="g", effort="XL")]
                             )["rows"][0]
    assert (same["size"], same["size_label"]) == ("L", "large")
    assert (mixed["size"], mixed["size_label"]) == ("", "")


def test_a_unit_holding_an_unsupported_asset_is_not_a_patch():
    assets = [_a("old", host="old.example.test", effort_group="g", support_status="end-of-support"),
              _a("new", host="new.example.test", effort_group="g")]
    plan = remediation.plan(assets)
    row = plan["rows"][0]
    assert (row["patch_possible"], row["unpatchable"]) == (False, 1)
    assert plan["totals"]["unpatchable_units"] == 1
    assert remediation.plan([_a("a", host="a.example.test")])["rows"][0]["patch_possible"] is True


def test_finding_classes_count_flag_families_and_skip_informational_flags():
    assets = [_a("a", host="a.example.test", effort_group="g",
                 flags=["plaintext:http", "plaintext:ftp", "weak-floor:tls", "cleartext-exposure:http"]),
              _a("b", host="b.example.test", effort_group="g", flags=["plaintext:smtp"])]
    classes = remediation.plan(assets)["rows"][0]["finding_classes"]
    assert classes == {"plaintext": 3, "weak-floor": 1}
    assert list(classes) == ["plaintext", "weak-floor"]  # most common first


def test_leverage_sums_distinct_service_classes_never_assets():
    extra = {"service": "svc-a", "estate_connections": "800"}
    other = {"service": "svc-b", "estate_connections": "200"}
    assets = [_a(f"s{i}", host=f"h{i}.example.test", effort_group="g", extra=dict(extra))
              for i in range(10)]
    assets.append(_a("t", host="t.example.test", effort_group="g", extra=dict(other)))
    lev = remediation.plan(assets)["rows"][0]["leverage"]
    assert lev == {"connections": 1000, "service_classes": 2, "assets_with_a_figure": 11, "assets": 11}


def test_a_missing_or_unreadable_connection_figure_is_not_a_zero_claim():
    assets = [_a("a", host="a.example.test", effort_group="g"),
              _a("b", host="b.example.test", effort_group="g",
                 extra={"service": "svc-a", "estate_connections": "many"}),
              _a("c", host="c.example.test", effort_group="g",
                 extra={"service": "svc-a", "estate_connections": ""})]
    lev = remediation.plan(assets)["rows"][0]["leverage"]
    assert (lev["connections"], lev["assets_with_a_figure"], lev["assets"]) == (0, 0, 3)


def test_usage_bands_are_counted_per_unit():
    assets = [_a("a", host="a.example.test", effort_group="g", usage_band="high"),
              _a("b", host="b.example.test", effort_group="g", usage_band="high"),
              _a("c", host="c.example.test", effort_group="g", usage_band="low"),
              _a("d", host="d.example.test", effort_group="g")]
    assert remediation.plan(assets)["rows"][0]["usage"] == {"high": 2, "low": 1}


def test_a_row_names_its_sources_verdict_deadline_and_basis():
    assets = [_a("a", host="a.example.test", effort_group="g", source="tls_scan", verdict="acceptable",
                 pqc_deadline="2030-06-30", disposition_basis="decided"),
              _a("b", host="b.example.test", effort_group="g", source="ssh_audit", verdict="weak",
                 pqc_deadline="2030-03-31", disposition_basis="proposed")]
    row = remediation.plan(assets)["rows"][0]
    assert row["sources"] == ["ssh_audit", "tls_scan"]
    assert row["worst_verdict"] == "weak"
    assert row["deadline"] == "2030-03-31"
    assert row["basis"] == "mixed"


# ── kinds, and the decision owed ──

def test_many_ungrouped_units_of_one_kind_say_nobody_has_decided_they_are_one():
    kind = remediation.plan(_fleet(6))["kinds"][0]
    assert (kind["units"], kind["shared_units"]) == (6, 0)
    assert kind["grouping"]["basis"] == "unverified"
    assert "6 separate jobs" in kind["grouping"]["note"]


def test_a_shared_kind_is_ruled_shared_and_a_lone_unit_is_single():
    shared = remediation.plan(_fleet(3, effort_group="g"))["kinds"][0]
    lone = remediation.plan([_a("a", host="a.example.test")])["kinds"][0]
    assert shared["grouping"]["basis"] == "ruled-shared"
    assert lone["grouping"] == {"basis": "single-unit", "note": ""}


def test_a_kind_adds_a_service_class_up_once_not_once_per_unit():
    assets = _fleet(40, extra={"service": "svc-a", "estate_connections": "1000"})
    plan = remediation.plan(assets)
    assert plan["totals"]["units"] == 40
    assert plan["kinds"][0]["connections"] == 1000


def test_a_kind_names_what_it_closes_by_flag_family_not_by_its_reason():
    reason = "Decided at review: handle these together."
    assets = [_a("a", host="a.example.test", effort_group="g", disposition_reason=reason,
                 flags=["plaintext:http"]),
              _a("b", host="b.example.test", effort_group="g", disposition_reason=reason,
                 flags=["plaintext:ftp", "weak-floor:tls"])]
    kind = remediation.plan(assets)["kinds"][0]
    assert kind["finding_classes"] == {"plaintext": 2, "weak-floor": 1}


def test_kinds_are_keyed_by_the_deciding_entrys_reason():
    assets = [_a("a", host="a.example.test", disposition_reason="Reason one."),
              _a("b", host="b.example.test", disposition_reason="Reason one."),
              _a("c", host="c.example.test", disposition_reason="Reason two.")]
    kinds = remediation.plan(assets)["kinds"]
    assert sorted((k["kind"], k["units"]) for k in kinds) == [("Reason one.", 2), ("Reason two.", 1)]


def test_the_decision_owed_prints_both_figures_and_never_touches_the_totals():
    assets = _fleet(10, prefix="a", disposition_reason="Kind A.") \
        + _fleet(5, prefix="b", disposition_reason="Kind B.") \
        + _fleet(4, prefix="c", effort_group="g", disposition_reason="Kind C.") \
        + _fleet(3, prefix="d", disposition="no-action", disposition_reason="Kind D.")
    plan = remediation.plan(assets)
    owed = plan["decision_owed"]
    assert owed["kinds"] == 2                      # A and B; C is ruled shared, D is not work
    assert owed["units_at_stake"] == (10 - 1) + (5 - 1)
    assert owed["work_units_now"] == plan["totals"]["work_units"] == 16
    assert owed["work_units_if_each_is_one_change"] == 16 - 13
    assert owed["largest_kind"] == 10
    assert owed["work_units_now"] > owed["work_units_if_each_is_one_change"]
    assert "not the same as no work" in owed["cost"]
    assert owed["note"] == remediation.DECISION_OWED_NOTE


def test_nothing_owed_when_every_kind_is_decided():
    owed = remediation.plan(_fleet(4, effort_group="g"))["decision_owed"]
    assert (owed["kinds"], owed["units_at_stake"], owed["largest_kind"]) == (0, 0, 0)
    assert owed["work_units_now"] == owed["work_units_if_each_is_one_change"]


# ── the prioritisation axes ──

NAMED_AXES = [
    "Size of the work", "Complexity", "Specialist skill", "Assets cleared per fix",
    "Likelihood", "Usage volume", "Blast radius", "Reversibility",
    "Already proven elsewhere in the observation", "Owner", "Change window", "Lifecycle",
    "Does one fix close several finding classes?", "Greatest risk first",
]
UNMODELLED = ("Complexity", "Specialist skill", "Blast radius", "Reversibility",
              "Already proven", "Owner", "Change window", "Greatest risk first")


def test_every_axis_a_planner_weighs_has_a_register_row():
    registered = " · ".join(x["axis"] for x in remediation.AXES)
    for axis in NAMED_AXES:
        assert axis in registered, f"no register row for {axis!r}"


def test_the_axes_with_no_source_stay_unmodelled():
    """A guard against quietly promoting a guess. If an axis earns a real source,
    this test is where the change is argued rather than slipped through."""
    for prefix in UNMODELLED:
        rows = [x for x in remediation.AXES if x["axis"].startswith(prefix)]
        assert rows, prefix
        assert all(x["state"] == "not-modelled" for x in rows), prefix


def test_no_axis_claims_a_source_it_does_not_have():
    assert {x["state"] for x in remediation.AXES} <= {"modelled", "partly-modelled", "not-modelled"}
    for x in remediation.AXES:
        if x["state"] == "not-modelled":
            assert x["source"] == ""
        else:
            assert x["source"], f"{x['axis']} claims to be modelled with no source"
        assert x["note"]


def test_the_plan_carries_the_register():
    assert remediation.plan([])["axes"] is remediation.AXES


# ── order and denominator ──

def test_the_view_never_claims_to_be_a_recommended_sequence():
    order = remediation.plan([_a("a", host="a.example.test")])["order"]
    assert order["is_a_recommended_sequence"] is False
    assert order["sorted_by"]
    assert "not risk" in order["note"] or "not that order" in order["note"].lower()


def test_the_denominator_is_the_observation_and_says_so():
    assets = [_a("tracked", host="a.example.test", source="tls_scan"),
              _a("tracked2", host="b.example.test", source="tls_scan", data_state="at-rest"),
              CryptoAsset(name="untracked", data_state="in-transit", source="tls_scan")]
    cov = remediation.plan(assets)["coverage"]
    assert (cov["assets_in_observation"], cov["assets_with_a_track"],
            cov["assets_with_no_track"]) == (3, 2, 1)
    assert cov["by_source"] == {"tls_scan": 2}
    assert cov["by_data_state"] == {"in-transit": 1, "at-rest": 1}
    assert "bounded by coverage" in cov["note"]


def test_declared_classes_are_none_not_zero_when_nobody_declared_any():
    assets = [_a("a", host="a.example.test")]
    assert remediation.plan(assets)["coverage"]["dark_classes"] is None
    cov = remediation.plan(assets, {"estate": {"declared_classes": 12, "dark_count": 3}})["coverage"]
    assert (cov["declared_classes"], cov["dark_classes"]) == (12, 3)


def test_a_counting_defect_recorded_on_the_observation_reaches_the_view():
    problem = {"problem": "per-rule-without-id", "entry": "a decision recorded in 2030",
               "kind": "decision", "detail": "declares shared effort with no id",
               "affected": 20, "inflated_units_by": 19}
    plan = remediation.plan([_a("a", host="a.example.test")], {"disposition_integrity": [problem]})
    assert plan["integrity"] == [problem]


def test_an_observation_that_never_checked_claims_nothing():
    assert remediation.plan([_a("a", host="a.example.test")])["integrity"] == []


def test_an_empty_observation_is_an_empty_plan():
    plan = remediation.plan([])
    assert plan["rows"] == [] and plan["kinds"] == []
    assert plan["totals"]["units"] == 0 and plan["totals"]["largest_unit"] == 0


# ── tracks: labels, order, out of cycle ──

def test_rows_sort_by_track_then_by_assets_cleared():
    assets = [_a("w2", host="a.example.test", disposition="wave-2", effort_group="w2"),
              *_fleet(2, prefix="w1s", disposition="wave-1", effort_group="w1-small"),
              *_fleet(5, prefix="w1b", disposition="wave-1", effort_group="w1-big"),
              _a("crit", host="c.example.test", disposition="critical"),
              _a("none", host="d.example.test", disposition="no-action")]
    keys = [r["key"] for r in remediation.plan(assets)["rows"]]
    assert keys[:3] == ["asset:" + assets[-2].bom_ref(), "w1-big", "w1-small"]
    assert keys[3:] == ["w2", "asset:" + assets[-1].bom_ref()]


def test_the_default_tables_come_from_the_bundled_ladder():
    rows = remediation.plan([_a("a", host="a.example.test"),
                             _a("b", host="b.example.test", disposition="wave-1")])["rows"]
    by_track = {r["track"]: r for r in rows}
    assert by_track["critical"]["track_label"] == "Critical"
    assert by_track["critical"]["act_out_of_cycle"] is True
    assert by_track["wave-1"]["act_out_of_cycle"] is False


def test_an_organisations_own_ladder_labels_orders_and_marks_urgency():
    rules = DispositionRules(ladder=[
        {"track": "now", "label": "Right now", "out_of_cycle": True},
        {"track": "later", "label": "Later", "out_of_cycle": False}])
    tracks = remediation.TrackTables.from_rules(rules)
    assets = [_a("a", host="a.example.test", disposition="later"),
              _a("b", host="b.example.test", disposition="now"),
              _a("c", host="c.example.test", disposition="no-action")]
    rows = remediation.plan(assets, tracks=tracks)["rows"]
    assert [r["track"] for r in rows] == ["now", "later", "no-action"]
    assert [r["track_label"] for r in rows] == ["Right now", "Later", "No action"]
    assert [r["act_out_of_cycle"] for r in rows] == [True, False, False]


def test_hand_built_tables_cover_tracks_a_ladder_no_longer_holds():
    tracks = remediation.TrackTables(label={"old-rung": "Old rung"}, order={"old-rung": 0},
                                     out_of_cycle={"old-rung"})
    rows = remediation.plan([_a("a", host="a.example.test", disposition="old-rung")], tracks=tracks)["rows"]
    assert (rows[0]["track_label"], rows[0]["act_out_of_cycle"]) == ("Old rung", True)


def test_a_track_no_table_knows_keeps_its_slug_and_sorts_last():
    assets = [_a("a", host="a.example.test", disposition="made-up"),
              _a("b", host="b.example.test", disposition="no-action")]
    rows = remediation.plan(assets)["rows"]
    assert [r["track"] for r in rows] == ["no-action", "made-up"]
    assert rows[1]["track_label"] == "made-up"


# ── naming the assets ──

def test_unit_assets_is_keyed_exactly_as_the_rows_are():
    assets = _fleet(3, prefix="g", effort_group="grp") + [_a("solo", host="solo.example.test")] \
        + [CryptoAsset(name="undecided", data_state="in-transit", host="x.example.test")]
    plan = remediation.plan(assets)
    named = remediation.unit_assets(assets)
    assert set(named) == {r["key"] for r in plan["rows"]}
    assert named["grp"] == ["h0.example.test", "h1.example.test", "h2.example.test"]
    assert "x.example.test" not in {h for hs in named.values() for h in hs}


def test_the_rows_name_no_host():
    plan = remediation.plan(_fleet(3, effort_group="grp"))
    assert "example.test" not in repr(plan)


# ── source labels ──

_DECL = re.compile(r'(?:source(?:\s*:\s*str)?\s*=\s*|SOURCE(?:_KEY)?\s*=\s*)"([a-z0-9_]+)"')
_SHIM = re.compile(r"^from (takestock\.[\w.]+) import \*", re.M)


def _declared_sources() -> set[str]:
    """Every source id a collector or library reader can stamp on a row."""
    found: set[str] = set()
    for mod in (ROOT / "src" / "takestock" / "collectors").glob("*.py"):
        text = mod.read_text()
        shim = _SHIM.search(text)
        if shim:  # a re-export: the rows come from the module it re-exports
            spec = importlib.util.find_spec(shim.group(1))
            assert spec is not None and spec.origin
            text = Path(spec.origin).read_text()
        found |= set(_DECL.findall(text))
    for reader in plugins.library():
        if reader.kind in (plugin_kinds.COVERAGE_CHECK, plugin_kinds.ANNOTATION):
            continue  # writes gaps or keys, never a row
        found.add(plugin_kinds.fixed_source(reader.kind) or reader.name)
    return found


def test_every_declared_source_has_a_reader_facing_name():
    missing = sorted(_declared_sources() - set(remediation.SOURCE_LABEL))
    assert not missing, "add to remediation.SOURCE_LABEL: " + ", ".join(missing)


def test_no_label_is_just_the_identifier_again():
    lazy = sorted(k for k, v in remediation.SOURCE_LABEL.items()
                  if v.strip().lower().replace(" ", "_") == k)
    assert not lazy, lazy


def test_the_map_has_no_dead_entries():
    dead = sorted(set(remediation.SOURCE_LABEL) - _declared_sources())
    assert not dead, "SOURCE_LABEL names sources nothing declares: " + ", ".join(dead)


def test_an_unmapped_source_falls_back_to_its_id_rather_than_disappearing():
    assert remediation.source_label("a_source_nobody_named") == "a_source_nobody_named"
    assert remediation.source_label("tls_scan") == remediation.SOURCE_LABEL["tls_scan"]


def test_a_caller_can_extend_the_map_with_sources_of_its_own():
    mine = {**remediation.SOURCE_LABEL, "local_export": "the local export"}
    assert remediation.source_label("local_export", mine) == "the local export"
    assert remediation.source_label("local_export") == "local_export"
    assert remediation.source_label("tls_scan", mine) == remediation.SOURCE_LABEL["tls_scan"]
