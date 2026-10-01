"""Network device export: placement, the verdicts no table can express, and coverage."""

from __future__ import annotations

import copy

import pytest

from takestock import coverage
from takestock.collectors import netdev
from takestock.model import NA_VERDICT, is_informational_flag
from takestock.policy import Policy

HEADER = "device,device_class,control,state,algorithms,key_custody,vendor,peer,site"


def export(tmp_path, *lines: str, expect: list[str] | None = None):
    path = tmp_path / "netdev.csv"
    path.write_text("\n".join([HEADER, *lines]) + "\n")
    inbox: dict = {"devices": str(path)}
    if expect is not None:
        inbox["expect"] = expect
    return netdev.collect({"netdev_inbox": inbox})


def control_rows(assets):
    return [a for a in assets if a.name != "Network device export scope"]


def one(tmp_path, line: str):
    assets, _ = export(tmp_path, line, expect=[])
    [a] = control_rows(assets)
    return a


# ── placement ──

def test_ssh_tokens_land_where_the_ssh_tables_are_read(tmp_path, policy):
    a = one(tmp_path, "sw-01.example.test,switch,ssh-mgmt,enabled,"
                      "curve25519-sha256;aes256-ctr;hmac-sha2-256-etm@openssh.com;ssh-ed25519,"
                      "device,Example Networks,,")
    assert a.protocol == "ssh"
    assert a.extra["ssh_kex"] == ["curve25519-sha256"]
    assert a.symmetric == ["aes256-ctr"]
    assert a.extra["ssh_mac"] == ["hmac-sha2-256-etm@openssh.com"]
    assert a.extra["ssh_hostkey"] == ["ssh-ed25519"]
    assert not any(f.startswith(netdev.PARTIAL) for f in a.flags)
    policy.apply(a)
    assert a.verdict == "strong"


def test_an_explicit_table_is_taken_at_its_word(tmp_path):
    a = one(tmp_path, "fw-01.example.test,firewall,ipsec,enabled,"
                      "ike_encryption=aes256;ike_dh=14;ike_prf=sha256,device,,peer-01,")
    assert a.protocol == "ike"
    assert a.extra["ike_dh_groups"] and a.extra["ike_prf"] == ["sha256"]


def test_vendor_spellings_map_to_baseline_tokens(tmp_path, policy):
    mac = one(tmp_path, "sw-01.example.test,switch,macsec,enabled,GCM-AES-XPN-256,device,,,")
    assert mac.symmetric == ["aes256_gcm"]
    wifi = one(tmp_path, "ap-01.example.test,wireless,wifi,enabled,TKIP,device,,,")
    assert wifi.symmetric == ["rc4"]
    policy.apply(wifi)
    assert wifi.verdict == "weak"


def test_an_unknown_token_is_surfaced_not_dropped(tmp_path):
    a = one(tmp_path, "sw-01.example.test,switch,snmp,enabled,frobnicate-9,device,,,")
    assert "ungraded:netdev:frobnicate-9" in a.flags
    assert is_informational_flag("ungraded:netdev:frobnicate-9")


def test_a_half_answered_control_is_named_but_not_regraded(tmp_path, policy):
    a = one(tmp_path, "sw-01.example.test,switch,snmp,enabled,sha256,device,,,")
    assert f"{netdev.PARTIAL}symmetric" in a.flags
    policy.apply(a)
    assert a.verdict == "strong"


def test_a_token_two_tables_grade_differently_is_not_placed(baseline):
    tables = ("symmetric", "hashes")
    assert netdev.place(Policy(baseline), "sha1", tables) == ("hashes", "sha1")
    disagreeing = copy.deepcopy(baseline)
    disagreeing["symmetric"]["sha1"] = "strong"
    assert netdev.place(Policy(disagreeing), "sha1", tables) is None


# ── the two verdicts set here ──

def test_a_control_recorded_off_is_weak(tmp_path):
    a = one(tmp_path, "wan-01,wan-link,wan-link,disabled,,,,,")
    assert a.verdict == "weak"
    assert netdev.ENCRYPTION_OFF in a.flags
    assert a.notes.startswith("NOT ENCRYPTED")
    assert not is_informational_flag(netdev.ENCRYPTION_OFF)


def test_on_without_an_algorithm_is_unknown(tmp_path):
    a = one(tmp_path, "sw-01.example.test,switch,tls-mgmt,enabled,,device,,,")
    assert a.verdict == "unknown"
    assert netdev.NOT_RECORDED in a.flags
    assert "ALGORITHM NOT STATED" in a.notes


def test_a_blank_state_is_unknown(tmp_path):
    a = one(tmp_path, "sw-01.example.test,switch,tls-mgmt,,,,,,")
    assert netdev.STATE_UNKNOWN in a.flags
    assert netdev.CUSTODY_UNKNOWN in a.flags


@pytest.mark.parametrize(("state", "flag", "informational"), [
    ("present", netdev.KEY_STORE_PRESENT, True),
    ("absent", netdev.KEY_STORE_ABSENT, False),
    ("", netdev.KEY_STORE_UNKNOWN, True)])
def test_a_key_store_is_a_custody_fact_not_a_grade(tmp_path, state, flag, informational):
    a = one(tmp_path, f"oob-01.example.test,out-of-band,key-storage,{state},,,,,")
    assert a.verdict == NA_VERDICT
    assert flag in a.flags
    assert is_informational_flag(flag) is informational


def test_a_weak_management_plane_gets_advice_and_a_link_does_not(tmp_path):
    ssh = one(tmp_path, "sw-01.example.test,switch,ssh-mgmt,disabled,,,,,")
    assert netdev.FRONTING_REMEDY in ssh.notes
    link = one(tmp_path, "sw-01.example.test,switch,macsec,disabled,,,,,")
    assert netdev.FRONTING_REMEDY not in link.notes


def test_researched_port_table_advice_wins(port_table):
    notes = netdev.fronting_notes_by_control(port_table)
    assert "ssh-mgmt" not in notes and "tls-mgmt" not in notes
    assert notes["snmp"].startswith("Fronting does not apply here")
    assert netdev.management_remedy("snmp", notes) == notes["snmp"]
    assert netdev.management_remedy("wifi", notes) == ""


def test_unrecognised_names_keep_their_row(tmp_path):
    a = one(tmp_path, "x-01,mainframe,telepathy,enabled,,device,,,")
    assert f"{netdev.UNRECOGNISED_CLASS}mainframe" in a.flags
    assert f"{netdev.UNRECOGNISED_CONTROL}telepathy" in a.flags
    assert a.extra["netdev_device_class"] == "other"


# ── coverage ──

def test_no_export_is_one_gap_plus_one_per_expected_class(tmp_path):
    assets, gaps = netdev.collect({"netdev_inbox": {"devices": str(tmp_path / "none.csv")}})
    assert assets == []
    assert len(gaps) == 1 + len(netdev.EXPECTED_CLASSES_DEFAULT)
    assert all(g.kind == coverage.NOT_COLLECTED for g in gaps)


def test_a_partial_export_names_each_missing_class(tmp_path):
    assets, gaps = export(tmp_path, "sw-01.example.test,switch,ssh-mgmt,enabled,aes256-ctr,"
                                    "device,,,", expect=["switch", "firewall"])
    scope = assets[-1]
    assert scope.name == "Network device export scope"
    assert scope.flags == [f"{netdev.CLASSES_MISSING}firewall"]
    assert "not a share of the estate" in scope.notes
    assert len(gaps) == 1 and "`firewall`" in gaps[0]


def test_unreadable_rows_are_counted(tmp_path):
    assets, gaps = export(tmp_path, ",switch,ssh-mgmt,enabled,,,,,",
                          "sw-01.example.test,switch,,enabled,,,,,", expect=[])
    assert assets == []
    assert [g.kind for g in gaps] == [coverage.COULD_NOT_TEST, coverage.COULD_NOT_TEST]
    assert "2 row(s)" in gaps[0]


def test_rows_carry_provenance(tmp_path):
    a = one(tmp_path, "sw-01.example.test,switch,ssh-mgmt,enabled,aes256-ctr,hsm,"
                      "Example Networks,,")
    assert (a.source, a.source_class) == (netdev.SOURCE, "private")
    assert a.software == "Example Networks"
    assert a.role == netdev.CONTROL_ROLES["ssh-mgmt"]
    assert f"{netdev.CUSTODY}hsm" in a.flags
    assert a.collected_at
