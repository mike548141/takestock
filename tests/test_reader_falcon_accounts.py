"""The CrowdStrike Falcon account reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (or
others named in the settings), with dates in 2029 and 2030 measured against a
file dated 2030-03-17. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_accounts as reader
from takestock.readers import library

COLUMNS = ("account_type", "last_logon_type", "password_last_set", "admin")


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _acct(kind: str, last: str, pwd: str, admin: str = "No") -> dict:
    return {"account_type": kind, "last_logon_type": last, "password_last_set": pwd,
            "admin": admin}


FRESH = "2030-02-01T09:00:00Z"   # within 90 days of the file date
YEAR = "2029-09-01T09:00:00Z"    # within a year
OLD = "2028-01-01T09:00:00Z"     # more than a year


def test_the_reader_is_in_the_library():
    assert library()["falcon_accounts"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_gives_one_gap():
    out = reader.step(ctx(reader.PLUGIN, None))
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_populations_buckets_and_scope(tmp_path):
    path = _export(tmp_path / "a.csv", [
        _acct("Domain", "Remote interactive", OLD, "Yes"),
        _acct("Domain", "Interactive", "", "yes"),
        _acct("Local", "Interactive", FRESH, "true"),
        _acct("Domain", "Service", ""),
        _acct("Local", "Service", YEAR),
        _acct("Domain", "Network", "--"),
    ])
    out = reader.step(ctx(reader.PLUGIN, path))
    rows = by_name(out.records)
    assert out.gaps == []
    priv = rows["Privileged accounts"]
    assert priv.verdict == "acceptable"
    assert priv.flags == ["privileged-accounts:3", "admin-remote-interactive:1"]
    assert priv.extra == {"accounts": "3", "population": "6", "local": "1", "domain": "2",
                          "remote_interactive": "1", "local_share": "0.33"}
    admin_age = rows["Privileged account credential age"]
    assert admin_age.verdict == "weak"
    assert admin_age.flags == ["password-stale:1", "credential-age-unknown:1"]
    assert admin_age.extra["age_fresh"] == "1" and admin_age.extra["age_unknown"] == "1"
    every = rows["Account credential age (all observed accounts)"]
    assert {k: every.extra[k] for k in ("age_fresh", "age_within_year", "age_stale",
                                        "age_unknown")} == {
        "age_fresh": "1", "age_within_year": "1", "age_stale": "1", "age_unknown": "3"}
    svc = rows["Service accounts"]   # exactly half undated: unknown
    assert svc.verdict == "unknown" and svc.hosts_count == 2
    assert svc.flags == ["service-accounts:2", "credential-age-unknown:1"]
    scope = rows["Account inventory scope"]
    assert scope.verdict == "n/a" and scope.flags == ["scope-observed-not-enumerated"]
    assert scope.extra == {"observed_accounts": "6", "domain_rows": "4"}
    for r in out.records:
        assert r.data_state == "identity" and r.protocol == "account"
        assert r.collected_at == "2030-03-17" and r.verdict != "strong"


def test_a_local_majority_of_administrators_is_weak(tmp_path):
    path = _export(tmp_path / "a.csv", [_acct("Local", "Interactive", FRESH, "Yes"),
                                        _acct("Local", "Interactive", FRESH, "Yes"),
                                        _acct("Domain", "Interactive", FRESH, "Yes")])
    rows = by_name(reader.step(ctx(reader.PLUGIN, path)).records)
    assert rows["Privileged accounts"].verdict == "weak"
    assert rows["Privileged accounts"].flags == ["privileged-accounts:3",
                                                 "privilege-outside-directory:2"]
    assert rows["Privileged account credential age"].verdict == "acceptable"
    assert "Service accounts" not in rows


def test_age_limits_date_format_and_headings_are_settings(tmp_path):
    path = _export(tmp_path / "a.csv", [
        {"Kind": "Domain", "Last": "Interactive", "Set": "01/09/2029", "Priv": "Yes"}],
        ("Kind", "Last", "Set", "Priv"))
    settings = {"fresh_days": 30, "stale_days": 120, "date_format": "%d/%m/%Y",
                "columns": {"accounts": {"account_type": "Kind", "last_logon": "Last",
                                         "password_set": "Set", "admin": ["Missing", "Priv"]}}}
    rows = by_name(reader.step(ctx(reader.PLUGIN, path, settings)).records)
    age = rows["Privileged account credential age"]
    assert age.extra["age_stale"] == "1"
    assert "set within 30 days" in age.notes


def test_an_unreadable_date_is_unknown_never_old(tmp_path):
    path = _export(tmp_path / "a.csv", [_acct("Domain", "Interactive", "not a date", "Yes")])
    age = by_name(reader.step(ctx(reader.PLUGIN, path)).records)["Privileged account credential age"]
    assert age.verdict == "acceptable" and age.extra["age_unknown"] == "1"
