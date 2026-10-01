"""WinRM configuration export: what decides the verdict, and what never does."""

from __future__ import annotations

import pytest

from takestock import coverage
from takestock.collectors import winrm_config as wc
from takestock.model import CryptoAsset, is_informational_flag

HEADER = ("hostname,host_id,allow_unencrypted_service,basic_service,allow_unencrypted_client,"
          "basic_client,credssp_service,https_listener")


def run_export(tmp_path, *lines: str, other=()):
    path = tmp_path / "winrm.csv"
    path.write_text("\n".join([HEADER, *lines]) + "\n")
    return wc.collect({"winrm_inbox": {"export": str(path)}}, other_assets=other)


def one(tmp_path, line: str) -> CryptoAsset:
    [a], _ = run_export(tmp_path, line)
    return a


# ── single cells ──

@pytest.mark.parametrize(("raw", "value"), [
    ("true", True), ("True", True), ("1", True), ("Enabled", True),
    ("false", False), ("0", False), ("off", False),
    ("", wc.BLANK), ("  ", wc.BLANK), ("maybe", wc.UNREADABLE)])
def test_a_cell_is_true_false_blank_or_unreadable(raw, value):
    assert wc.setting(raw) == value


# ── the verdict ──

def test_defaults_are_acceptable_never_strong(tmp_path):
    a = one(tmp_path, "app-01.example.test,,false,false,false,true,false,false")
    assert a.verdict == "acceptable"
    assert a.flags == []
    assert "Windows default" in a.notes


def test_client_basic_is_never_flagged(tmp_path):
    a = one(tmp_path, "app-01.example.test,,false,false,false,true,false,false")
    assert not any("basic" in f for f in a.flags)


@pytest.mark.parametrize(("line", "flag"), [
    ("app-01.example.test,,true,false,false,false,false,false", wc.ALLOWS_UNENCRYPTED),
    ("app-01.example.test,,false,true,false,false,false,false", wc.BASIC_ON_SERVICE),
    ("app-01.example.test,,false,false,true,false,false,false", wc.CLIENT_ALLOWS_UNENCRYPTED),
])
def test_each_disabled_protection_is_weak(tmp_path, line, flag):
    a = one(tmp_path, line)
    assert a.verdict == "weak"
    assert flag in a.flags
    assert a.notes.startswith("PROTECTION DISABLED")
    assert not is_informational_flag(flag)


def test_a_blank_deciding_setting_is_unknown_not_passed(tmp_path):
    assets, gaps = run_export(tmp_path, "app-01.example.test,,,false,false,true,false,false")
    assert assets[0].verdict == "unknown"
    assert f"{wc.NOT_ASSESSED}{wc.ALLOW_UNENCRYPTED_SERVICE}" in assets[0].flags
    assert "NOT READ" in assets[0].notes
    assert [g.kind for g in gaps] == [coverage.EXTENT_UNKNOWN]


def test_a_blank_never_makes_a_host_weak(tmp_path):
    a = one(tmp_path, "app-01.example.test,,,,,,,")
    assert a.verdict == "unknown"
    assert all(is_informational_flag(f) for f in a.flags)


def test_credssp_and_https_are_recorded_without_moving_the_verdict(tmp_path):
    a = one(tmp_path, "app-01.example.test,,false,false,false,false,true,true")
    assert a.verdict == "acceptable"
    assert {wc.CREDSSP_ON_SERVICE, wc.HTTPS_LISTENER_FLAG} <= set(a.flags)
    assert is_informational_flag(wc.HTTPS_LISTENER_FLAG)
    assert not is_informational_flag(wc.CREDSSP_ON_SERVICE)


def test_an_unreadable_value_is_surfaced(tmp_path):
    a = one(tmp_path, "app-01.example.test,,sometimes,false,false,false,false,false")
    assert a.verdict == "unknown"
    assert f"{wc.UNREADABLE_VALUE}{wc.ALLOW_UNENCRYPTED_SERVICE}" in a.flags


# ── identity, the file and coverage ──

def test_rows_carry_provenance_and_identity(tmp_path):
    a = one(tmp_path, "app-01.example.test,00000000-0000-4000-8000-000000000001,"
                      "false,false,false,false,false,false")
    assert (a.source, a.source_class, a.port, a.protocol) == (wc.SOURCE, "private", "5985",
                                                              "winrm")
    assert a.extra["join_basis"] == "host_id"
    assert a.role == wc.ROLE
    assert a.collected_at


def test_unnamed_and_repeated_rows_are_counted_not_dropped(tmp_path):
    assets, gaps = run_export(tmp_path,
                              "app-01.example.test,,false,false,false,false,false,false",
                              "APP-01.example.test,,true,true,true,true,true,true",
                              ",,true,true,true,true,true,true")
    assert len(assets) == 1 and assets[0].verdict == "acceptable"
    assert "2 of 3 row(s)" in gaps[0]
    assert gaps[0].impact_kind == coverage.NARROWS_CONFIDENCE


def test_a_missing_export_is_one_gap(tmp_path):
    assets, [gap] = wc.collect({"winrm_inbox": {"export": str(tmp_path / "absent.csv")}})
    assert assets == []
    assert gap.kind == coverage.NOT_COLLECTED
    assert gap.impact_kind == coverage.CHANGES_CONCLUSION


def test_listeners_the_export_does_not_cover_are_a_gap(tmp_path):
    seen = [CryptoAsset(name="l", data_state="in-transit", host="app-02.example.test",
                        port="5985", source="listeners"),
            CryptoAsset(name="l", data_state="in-transit", host="app-01.example.test",
                        port="5985", source="listeners"),
            CryptoAsset(name="l", data_state="in-transit", host="web-01.example.test",
                        port="443", source="listeners")]
    _, gaps = run_export(tmp_path, "app-01.example.test,,false,false,false,false,false,false",
                         other=seen)
    assert len(gaps) == 1
    assert "app-02.example.test" in gaps[0]
    assert "web-01" not in gaps[0]
