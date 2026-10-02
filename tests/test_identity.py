"""One naming rule for rows about a host: the host name when there is one, the address beside it."""

from __future__ import annotations

import pytest
from probe_helpers import FakeRun, fixture, has, target

from takestock.collectors import implicit_tls, tls_scan
from takestock.identity import names_by_address, report_as, row_identity
from takestock.model import CryptoAsset


@pytest.mark.parametrize(("name", "probe", "expected"), [
    ("web-01.example.test", "192.0.2.10", ("web-01.example.test", "192.0.2.10")),
    ("", "192.0.2.10", ("192.0.2.10", "")),
    ("web-01.example.test", "web-01.example.test", ("web-01.example.test", "")),
    ("web-01.example.test", "", ("web-01.example.test", "")),
    ("192.0.2.10", "192.0.2.10", ("192.0.2.10", "")),
    ("vpn.example.test", "2001:db8::10", ("vpn.example.test", "2001:db8::10")),
])
def test_the_host_is_the_name_and_the_address_sits_beside_it(name, probe, expected):
    assert row_identity(name, probe) == expected


def test_names_come_from_every_group_that_pairs_a_name_with_an_address():
    t = target(vpn_gateways=[{"host": "vpn.example.test", "ip": "192.0.2.1"}],
               smb_445=[{"host": "files-01.example.test", "ip": "[2001:db8::45]"}, "192.0.2.46"],
               ssh_22=["192.0.2.22:2222", {"ip": "192.0.2.23"}])
    assert names_by_address(t) == {"192.0.2.1": "vpn.example.test",
                                   "2001:db8::45": "files-01.example.test"}


def test_an_address_given_two_names_keeps_its_address():
    t = target(smb_445=[{"host": "files-01.example.test", "ip": "192.0.2.45"}],
               rdp_3389=[{"host": "desk-01.example.test", "ip": "192.0.2.45"}],
               ssh_22=[{"host": "bastion.example.test", "ip": "192.0.2.22"}])
    assert names_by_address(t) == {"192.0.2.22": "bastion.example.test"}


def _row(host: str, port: str = "445") -> CryptoAsset:
    return CryptoAsset(name=f"SMB signing {host}:{port}", data_state="in-transit",
                       protocol="smb", host=host, port=port)


@pytest.mark.parametrize(("probed", "names", "host", "ip", "name"), [
    ("192.0.2.45", {"192.0.2.45": "files-01.example.test"},
     "files-01.example.test", "192.0.2.45", "SMB signing files-01.example.test:445"),
    ("2001:db8::45", {"2001:db8::45": "files-01.example.test"},
     "files-01.example.test", "2001:db8::45", "SMB signing files-01.example.test:445"),
    ("[2001:DB8::45]", {"2001:db8::45": "files-01.example.test"},
     "files-01.example.test", "[2001:DB8::45]", "SMB signing files-01.example.test:445"),
    ("192.0.2.46", {"192.0.2.45": "files-01.example.test"},
     "192.0.2.46", "", "SMB signing 192.0.2.46:445"),
    ("files-02.example.test", {"192.0.2.45": "files-01.example.test"},
     "files-02.example.test", "", "SMB signing files-02.example.test:445"),
])
def test_a_row_built_at_an_address_is_renamed_after_its_host(probed, names, host, ip, name):
    a = report_as(_row(probed), names)
    assert (a.host, a.ip, a.name) == (host, ip, name)


def test_renaming_twice_changes_nothing():
    names = {"192.0.2.45": "files-01.example.test"}
    once = report_as(_row("192.0.2.45"), names)
    twice = report_as(_row("192.0.2.45"), names)
    report_as(twice, names)
    assert (once.host, once.ip, once.name) == (twice.host, twice.ip, twice.name)


def test_an_implicit_tls_row_is_named_by_the_host_its_address_belongs_to(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")),
        *[(has("s_client", flag), fixture(f"openssl-{name}.txt"))
          for flag, name in (("-tls1", "tls1"), ("-tls1_1", "tls1_1"),
                             ("-tls1_2", "tls1_2"), ("-tls1_3", "tls1_3"))]]))
    t = target(vpn_gateways=[{"host": "vpn-01.example.test", "ip": "192.0.2.60"}])
    t["plaintext_ports"] = ["993/tcp"]
    [a], _ = implicit_tls.collect(t)
    assert (a.name, a.host, a.ip) == ("IMAPS vpn-01.example.test:993", "vpn-01.example.test",
                                      "192.0.2.60")
