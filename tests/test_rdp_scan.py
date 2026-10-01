"""Remote desktop: is network-level authentication enforced?"""

from __future__ import annotations

import pytest
from probe_helpers import AUTH, FakeRun, has, never_run, target

from takestock.collectors import rdp_scan
from takestock.collectors.rdp_scan import RdpTarget
from takestock.model import is_informational_flag

T = RdpTarget(probe="192.0.2.33", ident="desk-01.example.test", port=3389)

# Composed from rdp-enum-encryption's documented @output block, with the
# script heading nmap prints in front of it.
EVERYTHING = """\
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     Native RDP: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Encryption level: High
|     40-bit RC4: SUCCESS
|     56-bit RC4: SUCCESS
|     128-bit RC4: SUCCESS
|     FIPS 140-1: SUCCESS
|_  RDP Protocol Version:  RDP 5.x, 6.x, 7.x, or 8.x server
"""

NLA_ONLY = """\
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|_    CredSSP with Early User Auth: SUCCESS
"""

TLS_AND_NLA = NLA_ONLY.replace("|_    CredSSP with Early User Auth: SUCCESS",
                               "|     CredSSP with Early User Auth: SUCCESS\n|_    SSL: SUCCESS")

NO_DATA = """\
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): Unknown
|_    SSL: Unknown
"""

NOT_RDP = """\
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
|_rdp-enum-encryption: Received unhandled packet
"""


def reading(out: str):
    return rdp_scan.asset_from_reading(T, rdp_scan.parse_rdp_enum(out))


def rdp_target(entries: list, authorised: bool = True, record: dict | None = None) -> dict:
    extra = {"rdp_3389": record if record is not None else dict(AUTH)} if authorised else {}
    return target(extra_auth=extra, rdp_3389=entries)


def test_the_documented_example_reads_every_layer_and_method():
    r = rdp_scan.parse_rdp_enum(EVERYTHING)
    assert set(r.layers) == set(rdp_scan.LAYERS.values())
    assert r.encryption_level == "High"
    assert r.native_methods == ["40-bit RC4", "56-bit RC4", "128-bit RC4", "FIPS 140-1"]
    assert r.protocol_version.startswith("RDP 5.x")


def test_accepting_native_rdp_is_weak_on_both_axes(policy):
    a = reading(EVERYTHING)
    assert a.verdict == "weak"
    assert {rdp_scan.NLA_NOT_ENFORCED, rdp_scan.STANDARD_SECURITY_ACCEPTED} <= set(a.flags)
    assert a.symmetric == ["3des", "rc4"]
    policy.apply(a)
    assert a.verdict == "weak"
    assert "weak-symmetric:rc4" in a.flags


def test_nla_enforced_is_acceptable_never_strong():
    a = reading(NLA_ONLY)
    assert a.verdict == "acceptable"
    assert a.extra["rdp_nla"] == "enforced"
    assert a.flags == []


def test_plain_tls_accepted_means_nla_is_not_enforced():
    a = reading(TLS_AND_NLA)
    assert a.verdict == "weak"
    assert "plain TLS" in a.notes
    assert rdp_scan.STANDARD_SECURITY_ACCEPTED not in a.flags


def test_no_negotiation_data_is_unknown():
    a = reading(NO_DATA)
    assert a.verdict == "unknown"
    assert f"{rdp_scan.INCONCLUSIVE}no-negotiation-data" in a.flags


@pytest.mark.parametrize(("out", "verdict", "reason"), [
    (NOT_RDP, "unknown", "no-rdp-negotiation"),
    ("PORT STATE SERVICE\n3389/tcp filtered ms-wbt-server\n", "unknown", "no-answer"),
    ("Failed to resolve \"desk-09.example.test\".\n", "unknown", "unresolved"),
    ("", "unknown", "no-answer"),
])
def test_anything_short_of_a_negotiation_is_unknown_with_the_reason(out, verdict, reason):
    a = reading(out)
    assert a.verdict == verdict
    assert a.flags == [f"{rdp_scan.INCONCLUSIVE}{reason}"]
    assert is_informational_flag(a.flags[0])


def test_a_closed_port_is_not_a_finding():
    a = reading("PORT STATE SERVICE\n3389/tcp closed ms-wbt-server\n")
    assert a.verdict == "n/a" and a.flags == []


def test_the_role_describes_the_question():
    assert "before showing a login screen" in reading(NLA_ONLY).role


def test_an_authorised_run_prints_the_list_then_sends_the_named_command(monkeypatch, tmp_path):
    fake = FakeRun([(has("192.0.2.33"), EVERYTHING)])
    monkeypatch.setattr(rdp_scan, "run", fake)
    monkeypatch.setattr(rdp_scan.shutil, "which", lambda name: "/usr/bin/nmap")
    said: list[str] = []
    [a], failures = rdp_scan.collect(
        rdp_target([{"host": "desk-01.example.test", "ip": "192.0.2.33", "port": 3390}]),
        raw_dir=tmp_path, announce=said.append)
    assert failures == []
    assert fake.calls == [["nmap", "-Pn", "-p", "3390", "--script", rdp_scan.SCRIPT,
                           "192.0.2.33"]]
    assert (a.host, a.ip, a.port) == ("desk-01.example.test", "192.0.2.33", "3390")
    assert said[-1] == "  host     : 192.0.2.33:3390 (desk-01.example.test)"
    assert (tmp_path / "nmap-rdp-192.0.2.33-3390.txt").read_text() == EVERYTHING


def test_inert_when_no_rdp_hosts_are_declared(monkeypatch):
    monkeypatch.setattr(rdp_scan, "run", never_run)
    assert rdp_scan.collect(target()) == ([], [])


@pytest.mark.parametrize(("entries", "authorised", "record", "reason"), [
    (["192.0.2.33"], False, None, "authorisation.rdp_3389"),
    (["192.0.2.33"], True, {**AUTH, "authorised_by": ""}, "authorised_by"),
    (["192.0.2.33"], True, "yes", "authorisation.rdp_3389"),
    (["192.0.2.33", "192.0.2.33"], True, None, "twice"),
    ([{"host": "192.0.2.33", "port": "3389,3390"}], True, None, "not one port number"),
    (["192.0.2.0/24"], True, None, "refused by construction"),
    ([f"192.0.2.{n}" for n in range(1, 62)], True, None, "ceiling"),
])
def test_refusals_contact_nothing_and_print_no_list(monkeypatch, entries, authorised, record,
                                                    reason):
    monkeypatch.setattr(rdp_scan, "run", never_run)
    said: list[str] = []
    assets, failures = rdp_scan.collect(rdp_target(entries, authorised, record),
                                        announce=said.append)
    assert assets == [] and said == []
    assert failures[0].startswith("rdp_scan: REFUSED, nothing contacted")
    assert reason in failures[0]


def test_missing_nmap_is_an_unknown_row_and_a_failure(monkeypatch):
    monkeypatch.setattr(rdp_scan, "run", never_run)
    monkeypatch.setattr(rdp_scan.shutil, "which", lambda name: None)
    said: list[str] = []
    [a], failures = rdp_scan.collect(rdp_target(["192.0.2.33"]), announce=said.append)
    assert a.flags == [f"{rdp_scan.INCONCLUSIVE}nmap-unavailable"]
    assert failures and said                       # the list is still printed first
