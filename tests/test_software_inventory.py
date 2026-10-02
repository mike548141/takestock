"""Software inventory: matching, release lines, ceilings, spread, lifecycle and coverage."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from takestock import agility, coverage, lifecycle
from takestock.collectors import software_inventory as si
from takestock.model import NA_VERDICT, is_informational_flag

HEADER = "host,product,version,vendor,path"


def export(tmp_path, *lines: str, header: str = HEADER, dated: str = "", target: dict | None = None):
    path = tmp_path / "software.csv"
    path.write_text("\n".join([header, *lines]) + "\n")
    if dated:
        stamp = datetime.fromisoformat(dated).replace(hour=12, tzinfo=UTC).timestamp()
        os.utime(path, (stamp, stamp))
    profile = dict(target or {})
    profile["software_inbox"] = {"export": str(path)}
    return si.collect(profile)


def by_name(assets) -> dict:
    return {a.name: a for a in assets}


def provider_rows(assets):
    return [a for a in assets if a.name != si.SCOPE_NAME and not a.name.endswith("version spread")]


# ── matching ──

def test_products_match_the_register_and_others_are_ignored(tmp_path):
    assets, gaps = export(tmp_path,
                          "app-01.example.test,OpenSSL,3.0.0,,",
                          "app-01.example.test,Example Office Suite,1.0.0,,",
                          "app-02.example.test,gnutls,3.0.0,,")
    assert gaps == []
    rows = by_name(assets)
    assert set(rows) == {"OpenSSL 3.0.0", "GnuTLS 3.0.0", si.SCOPE_NAME}
    scope = rows[si.SCOPE_NAME]
    assert scope.verdict == NA_VERDICT
    assert scope.extra["rows"] == 3 and scope.extra["machines"] == 2
    assert scope.extra["matched_rows"] == 2
    assert scope.extra["unmatched_rows"] == 1 and scope.extra["unmatched_products"] == 1
    assert "Example Office Suite" not in scope.notes


def test_header_spellings_are_matched_ignoring_case_and_separators(tmp_path):
    assets, gaps = export(tmp_path, "APP-01.example.test,OpenSSL,3.0.0,Example Vendor,/opt/lib",
                          header="Computer Name,Display_Name,DISPLAY-VERSION,Publisher,Install Location")
    assert gaps == []
    row = by_name(assets)["OpenSSL 3.0.0"]
    assert row.software == "OpenSSL" and row.version == "3.0.0"
    assert row.extra["vendors"] == "Example Vendor" and row.extra["paths"] == "/opt/lib"


@pytest.mark.parametrize("branch, version, expected", [
    ("1.0", "1.0.2", True),
    ("1.0", "1.0", True),
    ("1.0", "1.01", False),
    ("1.1.1", "1.1.10", False),
    ("3", "3.0.0", True),
    ("3", "30.0", False),
    ("1.0", "1:1.0.2-fips", True),
])
def test_a_branch_is_a_version_prefix_ending_at_a_non_digit(branch, version, expected):
    assert si.branch_matches(branch, version) is expected


def test_the_longest_matching_branch_wins():
    register = [
        {"product": "Lib", "branch": "1.0", "max_tls": "TLSv1.2"},
        {"product": "Lib", "branch": "1.0.0", "max_tls": "TLSv1.0"},
        {"product": "Other", "branch": "1.0.0", "max_tls": "TLSv1.3"},
    ]
    assert si.release_line(register, "Lib", "1.0.0")["max_tls"] == "TLSv1.0"
    assert si.release_line(register, "Lib", "1.0.2")["max_tls"] == "TLSv1.2"
    assert si.release_line(register, "Lib", "2.0.0") is None


# ── ceilings ──

def test_a_line_capped_below_tls_1_3_carries_a_ceiling_and_stays_unknown(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,1.0.2,,",
                       "app-02.example.test,OpenSSL,1.0.2,,")
    row = by_name(assets)["OpenSSL 1.0.2"]
    assert f"{agility.CEILING_FLAG}TLSv1.2" in row.flags
    assert row.verdict == "unknown"
    assert row.hosts_count == 2
    assert row.extra["release_line"] == "1.0" and row.extra["capability_citation"]


def test_a_ceiling_below_the_floor_is_weak(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,1.0.0,,")
    row = by_name(assets)["OpenSSL 1.0.0"]
    assert row.flags == [f"{agility.CEILING_FLAG}TLSv1.0"]
    assert row.verdict == "weak"


def test_a_line_that_reaches_tls_1_3_has_no_ceiling(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,1.1.1,,")
    row = by_name(assets)["OpenSSL 1.1.1"]
    assert row.flags == [] and row.verdict == "unknown"
    assert row.extra["max_tls"] == "TLSv1.3"


def test_a_version_with_no_line_on_record_is_flagged_ungraded(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,GnuTLS,3.0.0,,")
    row = by_name(assets)["GnuTLS 3.0.0"]
    assert row.flags == ["ungraded:crypto-software:GnuTLS 3.0.0"]
    assert row.verdict == "unknown"


def test_the_floor_comes_from_the_baseline():
    assert si.tls_floor({"tls_versions": {"TLSv1.0": "weak", "TLSv1.2": "acceptable"}}) == "TLSv1.2"
    assert si.tls_floor({"tls_versions": {"TLSv1.2": "weak", "TLSv1.3": "strong"}}) == "TLSv1.3"
    assert si.has_ceiling("TLSv1.2", "TLSv1.2")
    assert not si.has_ceiling("TLSv1.3", "TLSv1.2")
    assert not si.has_ceiling("not a version", "TLSv1.2")


# ── spread ──

def test_one_provider_at_several_versions_gets_a_spread_row(tmp_path):
    assets, _ = export(tmp_path,
                       "app-01.example.test,OpenSSL,1.0.2,,",
                       "app-02.example.test,OpenSSL,1.1.1,,",
                       "app-03.example.test,OpenSSL,3.0.0,,",
                       "app-03.example.test,OpenSSL,3.0.0,,/opt/bundled",
                       "app-04.example.test,GnuTLS,3.0.0,,")
    rows = by_name(assets)
    spread = rows["OpenSSL version spread"]
    assert spread.flags == [f"{agility.SPREAD_FLAG}3"]
    assert spread.hosts_count == 3 and spread.verdict == NA_VERDICT
    assert is_informational_flag(spread.flags[0])
    assert "GnuTLS version spread" not in rows
    assert rows["OpenSSL 3.0.0"].hosts_count == 1 and rows["OpenSSL 3.0.0"].extra["inventory_rows"] == 2


def test_the_packaging_epoch_does_not_count_as_a_second_version(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,3.0.0,,",
                       "app-02.example.test,OpenSSL,1:3.0.0,,")
    assert "OpenSSL version spread" not in by_name(assets)


def test_both_agility_positions_are_reached(tmp_path):
    assets, _ = export(tmp_path,
                       "app-01.example.test,OpenSSL,1.0.2,,",
                       "app-02.example.test,OpenSSL,3.0.0,,")
    result = agility.agility(assets)
    positions = {p["position"]: p for p in result["positions"]}
    assert set(positions) == {agility.REPLACEMENT, agility.LIBRARY}
    [replacement] = positions[agility.REPLACEMENT]["groups"]
    assert replacement["label"] == "OpenSSL 1.0.2" and replacement["count"] == 1
    [library] = positions[agility.LIBRARY]["groups"]
    assert library["label"] == "OpenSSL" and library["count"] == 2


# ── naming machines ──

def test_an_address_the_profile_names_is_reported_by_that_name(tmp_path):
    target = {"scan_targets": {"vpn_gateways": [{"host": "gw.example.test", "ip": "203.0.113.10"}]}}
    assets, _ = export(tmp_path, "203.0.113.10,OpenSSL,3.0.0,,", "gw.example.test,OpenSSL,3.0.0,,",
                       "198.51.100.7,OpenSSL,3.0.0,,", target=target)
    row = by_name(assets)["OpenSSL 3.0.0"]
    assert row.hosts_count == 2
    assert row.extra["hosts"] == "198.51.100.7, gw.example.test"
    assert row.host == ""


# ── lifecycle ──

def test_lifecycle_is_read_on_the_export_date(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,1.0.2,,", "app-01.example.test,OpenSSL,3.0.0,,",
                       dated="2025-01-15")
    rows = by_name(assets)
    old = rows["OpenSSL 1.0.2"]
    assert old.collected_at == "2025-01-15"
    assert old.support_status == lifecycle.END_OF_SUPPORT
    assert old.extra["lifecycle_line"] == "openssl-1.0.2"
    assert old.extra[lifecycle.SUPPORT_STATUS_BASIS_KEY] == lifecycle.DERIVED
    current = rows["OpenSSL 3.0.0"]
    assert current.support_status == lifecycle.SUPPORTED
    assert current.extra["lifecycle_line"] == "openssl-3.0"


def test_a_product_with_no_lifecycle_line_is_left_blank(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,GnuTLS,3.0.0,,", dated="2025-01-15")
    row = by_name(assets)["GnuTLS 3.0.0"]
    assert row.support_status == "" and "lifecycle_line" not in row.extra


def test_a_declared_status_still_wins(tmp_path):
    assets, _ = export(tmp_path, "app-01.example.test,OpenSSL,3.0.0,,", dated="2025-01-15")
    lifecycle.apply_support_status(assets, {"end-of-life": ["^OpenSSL 3"]})
    assert by_name(assets)["OpenSSL 3.0.0"].support_status == lifecycle.END_OF_LIFE


# ── coverage ──

def test_a_missing_export_is_a_gap_and_no_rows(tmp_path):
    assets, gaps = si.collect({"software_inbox": {"export": str(tmp_path / "absent.csv")}})
    assert assets == []
    [gap] = gaps
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert gap.impact_kind == coverage.CHANGES_CONCLUSION


@pytest.mark.parametrize("header, lines, reason", [
    ("machine,version", ["app-01.example.test,3.0.0"], "no host or no product column"),
    (HEADER, [], "no data rows"),
])
def test_an_unreadable_export_is_a_gap_saying_why(tmp_path, header, lines, reason):
    assets, gaps = export(tmp_path, *lines, header=header)
    assert assets == []
    [gap] = gaps
    assert reason in gap


def test_rows_without_a_machine_or_a_version_are_gaps(tmp_path):
    assets, gaps = export(tmp_path, ",OpenSSL,3.0.0,,", "app-01.example.test,OpenSSL,,,",
                          "app-02.example.test,OpenSSL,3.0.0,,")
    unversioned = by_name(assets)["OpenSSL (version not recorded)"]
    assert unversioned.flags == [si.VERSION_UNRECORDED]
    assert "OpenSSL version spread" not in by_name(assets)
    assert len(gaps) == 2
    assert gaps[0].startswith("1 of 3 row(s)")
    assert "no version" in gaps[1]
    assert all(coverage.kind_of(g) == coverage.EXTENT_UNKNOWN for g in gaps)
    assert len(provider_rows(assets)) == 2
