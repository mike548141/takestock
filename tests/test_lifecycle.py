"""Migration strategy, declared and derived support status."""

from __future__ import annotations

from datetime import date

import pytest

from takestock import config
from takestock import lifecycle as lc
from takestock.model import CryptoAsset


@pytest.fixture(autouse=True)
def _bundled_data_only(tmp_path):
    """Read the bundled data files, never a data/ directory in the caller's working directory."""
    config.set_workspace(tmp_path)


def host(name: str, **kw) -> CryptoAsset:
    return CryptoAsset(name=name, data_state="in-transit", host=f"{name}.example.test", **kw)


# ── declared in the target profile ──

def test_migration_strategy_is_tagged_by_pattern():
    rows = [host("app-01"), host("app-02"), host("db-01")]
    lc.apply_migration_strategy(rows, {"retire": [r"^app-"], "replatform": [r"^db-"]})
    assert [a.migration_strategy for a in rows] == ["retire", "retire", "replatform"]


def test_a_strategy_outside_the_six_is_refused():
    with pytest.raises(lc.LifecycleError, match="migrate"):
        lc.apply_migration_strategy([host("app-01")], {"migrate": [".*"]})


def test_support_status_can_carry_an_end_date():
    rows = [host("app-01"), host("db-01")]
    lc.apply_support_status(rows, {"end-of-support": [{"match": "^db-", "ends": "2000-01-01"}],
                                   "supported": ["^app-"]})
    assert [(a.support_status, a.support_end) for a in rows] == [
        ("supported", ""), ("end-of-support", "2000-01-01")]
    assert lc.is_unpatchable(rows[1]) and not lc.is_unpatchable(rows[0])


def test_unknown_cannot_be_declared():
    with pytest.raises(lc.LifecycleError, match="absence of a value"):
        lc.apply_support_status([host("app-01")], {"unknown": [".*"]})


def test_unmatched_patterns_are_reported():
    rows = [host("app-01")]
    block = {"retire": ["^app-", "^gone-"]}
    assert lc.unmatched_patterns(rows, block, "migration_strategy") == [
        "migration_strategy.retire: /^gone-/ matched no asset"]


# ── Windows, against the bundled Microsoft tables ──

@pytest.fixture(scope="module")
def windows() -> dict:
    return config.load_yaml_strict(config.BUNDLED_DATA_DIR / "windows-lifecycle.yaml")


def device(version: str, edition: str = "", name: str = "", collected: str = "2026-01-15") -> CryptoAsset:
    extra = {lc.OS_VERSION_KEY: version}
    if edition:
        extra[lc.OS_EDITION_KEY] = edition
    if name:
        extra[lc.OS_NAME_KEY] = name
    return CryptoAsset(name="device", data_state="at-rest", collected_at=collected, extra=extra)


@pytest.mark.parametrize("kw, status, end", [
    ({"version": "10.0.26100.1000", "edition": "Enterprise"}, "supported", "2027-10-12"),
    ({"version": "10.0.26100.1000", "edition": "Professional"}, "supported", "2026-10-13"),
    ({"version": "10.0.19045.1000", "edition": "Education"}, "end-of-support", "2025-10-14"),
    ({"version": "10.0.19045", "edition": "Pro", "collected": "2025-10-14"}, "supported", "2025-10-14"),
    ({"version": "10.0.20348.100", "name": "Windows Server 2022 Datacenter",
      "collected": "2027-01-01"}, "security-only", "2031-10-14"),
    ({"version": "6.3.9600", "name": "Windows Server 2012 R2 Standard"}, "security-only", "2023-10-10"),
    ({"version": "10.0.19044.100", "name": "Windows 10 Enterprise LTSC 2021",
      "collected": "2027-06-01"}, "end-of-support", "2027-01-12"),
])
def test_windows_support_is_derived(windows, kw, status, end):
    a = device(**kw)
    counts = lc.derive_windows_support([a], windows)
    assert counts["matched"] == 1
    assert (a.support_status, a.support_end) == (status, end)
    assert a.extra[lc.SUPPORT_STATUS_BASIS_KEY] == lc.DERIVED


def test_paid_extended_updates_are_recorded_as_a_condition(windows):
    a = device("6.3.9600", name="Windows Server 2012 R2 Standard")
    lc.derive_windows_support([a], windows)
    assert "Extended Security Updates" in a.extra[lc.SUPPORT_CONDITION_KEY]


@pytest.mark.parametrize("kw, reason", [
    ({"version": "10.0.26100.1000"}, "wrong_or_missing_edition"),
    ({"version": "10.0.26100.1000", "edition": "ServerStandard"}, "wrong_or_missing_edition"),
    ({"version": "10.0.12345.1", "edition": "Enterprise"}, "unrecognised_build"),
    ({"version": "10.0.17763.1", "name": "Windows Server 2022 Standard"}, "unrecognised_product"),
    ({"version": "10.0.17763.1", "name": "Windows Server 1999"}, "unrecognised_product"),
    ({"version": "10.0.26100.1000", "edition": "Enterprise", "collected": ""}, "uncollected_date"),
])
def test_a_near_match_is_left_unknown(windows, kw, reason):
    a = device(**kw)
    counts = lc.derive_windows_support([a], windows)
    assert counts[reason] == 1 and counts["matched"] == 0
    assert a.support_status == ""


def test_a_declared_status_is_never_overwritten(windows):
    a = device("10.0.19045.1", "Enterprise")
    a.support_status = "supported"
    lc.derive_windows_support([a], windows)
    assert a.support_status == "supported" and lc.SUPPORT_STATUS_BASIS_KEY not in a.extra


def test_a_non_windows_row_is_ignored(windows):
    a = host("app-01", extra={lc.OS_VERSION_KEY: "5.15.0"})
    assert lc.derive_windows_support([a], windows)["matched"] == 0


def test_summary_separates_declared_from_derived(windows):
    derived = device("10.0.26100.1", "Enterprise")
    lc.derive_windows_support([derived], windows)
    declared = host("db-01", support_status="end-of-life", migration_strategy="retire")
    out = lc.lifecycle_summary([derived, declared, host("app-01")])
    assert out["by_support_status"] == {"supported": 1, "end-of-life": 1, "unknown": 1}
    assert (out["support_declared"], out["support_derived"], out["unpatchable"]) == (1, 1, 1)
    assert out["declared_share"] == round(2 / 3, 3)


# ── software inventory rows ──

DATASET = {
    "schema": 1,
    "sources": {"vendor": {"url": "https://vendor.example/lifecycle", "read": "2000-01-01", "says": "x"},
                "other": {"url": "https://other.example/lifecycle", "read": "2000-01-01", "says": "x"}},
    "lines": [
        {"id": "widget-2", "match": [{"kind": "application", "product_pattern": r"Widget Server 2(\.\d+)*"}],
         "variants": [{"name": "vendor", "source": "vendor", "phases": [
             {"until": "2030-06", "band": "supported"},
             {"until": "2032-12-31", "band": "security-only", "condition": "paid support"}],
             "after": "end-of-support"}]},
        {"id": "widget-3", "match": [{"kind": "application", "product": "Widget Server",
                                      "version_pattern": r"3(\.\d+)*"}],
         "variants": [{"name": "vendor", "source": "vendor",
                       "phases": [{"until": "2035-01-31", "band": "supported"}], "after": "unknown"},
                      {"name": "other", "source": "other",
                       "phases": [{"until": "2034-01-31", "band": "supported"}], "after": "end-of-life"}]},
        {"id": "gadget-os-1", "match": [{"kind": "os", "product_pattern": r"Gadget OS 1.*"}],
         "variants": [{"name": "vendor", "source": "vendor", "known_from": "2020-01-01",
                       "phases": [{"until": "2040-01-01", "band": "supported"}], "after": "end-of-life"}]},
    ],
}


@pytest.mark.parametrize("on, band, condition", [
    ("2030-05-31", "supported", ""),
    ("2030-06-15", None, ""),            # inside a month-only boundary: undetermined
    ("2030-07-01", "security-only", "paid support"),
    ("2032-12-31", "security-only", "paid support"),
    ("2033-01-01", "end-of-support", ""),
])
def test_variant_band_reads_each_phase_inclusively(on, band, condition):
    variant = DATASET["lines"][0]["variants"][0]
    got, cond, _until = lc.variant_band(variant, date.fromisoformat(on))
    assert (got, cond) == (band, condition)


def test_known_from_and_unknown_after_leave_the_band_undetermined():
    v = DATASET["lines"][2]["variants"][0]
    assert lc.variant_band(v, date(2019, 12, 31))[0] is None
    assert lc.variant_band(DATASET["lines"][1]["variants"][0], date(2036, 1, 1))[0] is None


def test_variants_that_disagree_give_unknown_with_the_reason():
    line = DATASET["lines"][1]
    assert lc.line_support(line, date(2033, 1, 1))["band"] == "supported"
    out = lc.line_support(line, date(2034, 6, 1))
    assert out["band"] == lc.UNKNOWN_SUPPORT and "disagree" in out["reason"]


def test_matching_is_whole_string_only():
    assert [x["id"] for x in lc.match_lines(DATASET, "application", "Widget Server 2.1", "")] == ["widget-2"]
    assert [x["id"] for x in lc.match_lines(DATASET, "application", "widget  server", "3.0")] == ["widget-3"]
    assert lc.match_lines(DATASET, "application", "Widget Server 2.1 Beta", "") == []
    assert lc.match_lines(DATASET, "os", "Widget Server 2.1", "") == []


def test_census_rows_are_graded_at_both_dates():
    rows = [
        {"source": "inv", "source_date": "2031-01-01", "kind": "application",
         "product": "Widget Server 2.4", "population": 10},
        {"source": "inv", "kind": "os", "product": "Mystery OS 9"},
        {"source": "inv", "kind": "application", "product": "Unlisted App"},
        {"source": "inv", "kind": "application", "product": "WS2", "version": "x"},
    ]
    aliases = [{"source": "inv", "product": "ws2", "version": "X", "line": "widget-2"}]
    out, counts = lc.derive_census_support(rows, DATASET, "2033-06-01", aliases)
    assert counts == {"matched": 2, "ambiguous": 0, "unmatched": 2}
    graded = out[0]
    assert (graded["line"], graded["band_at_source_date"], graded["band_at_as_of"]) == (
        "widget-2", "security-only", "end-of-support")
    assert graded["condition_at_source_date"] == "paid support"
    assert graded["vendor_sources"] == "https://vendor.example/lifecycle"
    assert out[1]["reason"].startswith("no lifecycle line")      # an unmatched OS is reported
    assert out[2]["matched_by"] == "alias"                       # an unmatched app is not


def test_a_row_matching_two_lines_is_ambiguous():
    dataset = {"lines": [dict(DATASET["lines"][0], id="a"), dict(DATASET["lines"][0], id="b")]}
    out, counts = lc.derive_census_support(
        [{"source": "inv", "kind": "application", "product": "Widget Server 2"}], dataset, "2030-01-01")
    assert counts["ambiguous"] == 1 and out[0]["reason"] == "ambiguous: matches a, b"


def test_an_alias_to_an_unknown_line_is_refused():
    with pytest.raises(lc.LifecycleError):
        lc.derive_census_support([], DATASET, "2030-01-01",
                                 [{"source": "inv", "product": "x", "line": "nope"}])


def test_the_bundled_software_table_grades_a_known_line():
    dataset = config.load_software_lifecycle()
    out, counts = lc.derive_census_support(
        [{"source": "inv", "kind": "os", "product": "Rocky Linux 9.3", "source_date": "2026-01-01"}],
        dataset, "2026-01-01")
    assert counts["matched"] == 1
    assert (out[0]["line"], out[0]["band_at_as_of"]) == ("rocky-9", "supported")
