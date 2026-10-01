"""CAA issuance policy against held certificates, and DANE for mail, from synthetic answers."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from dnsfake import RESOLVERS, dig_text, table_reader

from takestock import ctcache
from takestock.collectors import caa, dane
from takestock.digresponse import parse
from takestock.model import CryptoAsset, is_informational_flag

NOW = datetime(2030, 6, 15, tzinfo=UTC)
ISSUERS = {"example ca": ["ca.example.net"], "other ca": ["other.example.org"]}


def _caa(owner: str, *props: str) -> str:
    return dig_text(answer=[f"{owner}. 300 IN CAA {p}" for p in props])


def _cert(host: str, issuer: str) -> CryptoAsset:
    return CryptoAsset(name=f"certificate {host}", data_state="certificate", protocol="tls",
                       host=host, extra={"issuer": issuer, "not_before": "2030-01-01T00:00:00Z"})


def _caa_collect(table: dict, certs: list[CryptoAsset], raw_dir=None):
    return caa.collect({"discovery": {"domains": ["example.com"]},
                        "dns": {"caa_issuers": ISSUERS}}, certs, NOW,
                       reader=table_reader(table, dig_text("NOERROR")),
                       resolvers=RESOLVERS, raw_dir=raw_dir)


def test_properties_and_parameters_are_read():
    props = caa.properties(parse(_caa("example.com", '0 issue "ca.example.net; accounturi=x"',
                                      '128 future "x"')))
    assert [(p.flags, p.tag) for p in props] == [(0, "issue"), (128, "future")]
    assert props[0].issuer_domain == "ca.example.net"
    assert props[0].parameters == {"accounturi": "x"}


def test_issuance_locked_and_every_certificate_consistent():
    apex = _caa("example.com", '0 issue "ca.example.net"', '0 iodef "mailto:sec@example.com"')
    table = {("example.com", r): apex for r in RESOLVERS}
    assets, failures = _caa_collect(table, [_cert("www.example.com", "Example CA")])
    a = assets[0]
    assert failures == []
    assert "issuance-locked" in a.flags and "caa-no-iodef" not in a.flags
    assert {"caa-wildcard-follows-issue", "caa-no-account-binding"} <= set(a.flags)
    assert a.extra["certificates_consistent"] == 1
    assert a.extra["authorised_issue"] == ["ca.example.net"]


def test_an_unauthorised_and_an_unmapped_issuer_are_told_apart():
    apex = _caa("example.com", '0 issue "ca.example.net"')
    table = {("example.com", r): apex for r in RESOLVERS}
    certs = [_cert("a.example.com", "Other CA"), _cert("b.example.com", "Unknown CA")]
    a = _caa_collect(table, certs)[0][0]
    assert "caa-issuer-not-authorised:1" in a.flags and "caa-issuer-unmapped:1" in a.flags
    assert not is_informational_flag("caa-issuer-not-authorised:1")
    assert is_informational_flag("caa-issuer-unmapped:1")
    assert a.extra["certificates_not_authorised"][0]["host"] == "a.example.com"


def test_a_name_with_its_own_set_is_judged_by_it():
    apex = _caa("example.com", '0 issue "ca.example.net"')
    table = {("example.com", r): apex for r in RESOLVERS}
    table[("shop.example.com", RESOLVERS[0])] = _caa("shop.example.com", '0 issue "other.example.org"')
    a = _caa_collect(table, [_cert("shop.example.com", "Other CA")])[0][0]
    assert "caa-names-own-set:1" in a.flags
    assert "caa-issuer-not-authorised:1" not in " ".join(a.flags)


def test_no_record_and_disagreeing_resolvers():
    table = {("example.com", r): dig_text("NOERROR") for r in RESOLVERS}
    table[("example.com", RESOLVERS[2])] = _caa("example.com", '0 issue "ca.example.net"')
    a = _caa_collect(table, [])[0][0]
    assert "caa-resolvers-disagree" in a.flags
    absent = _caa_collect({("example.com", r): dig_text("NOERROR") for r in RESOLVERS}, [])[0][0]
    assert "caa-absent" in absent.flags and "any publicly trusted" in absent.notes


def test_unreadable_everywhere_is_a_failure():
    table = {("example.com", r): "__ERROR__ timed out" for r in RESOLVERS}
    assets, failures = _caa_collect(table, [])
    assert "caa-unreadable" in assets[0].flags and failures


def test_wildcards_follow_issuewild(tmp_path):
    (tmp_path / ctcache.raw_name("example.com")).write_text(json.dumps([
        {"dns_names": ["*.example.com", "example.com"], "not_before": "2030-01-01T00:00:00Z",
         "issuer": {"friendly_name": "Other CA"}}]))
    apex = _caa("example.com", '0 issue "ca.example.net"', '0 issuewild "other.example.org"')
    table = {("example.com", r): apex for r in RESOLVERS}
    a = _caa_collect(table, [], raw_dir=tmp_path)[0][0]
    assert a.extra["wildcard_certificates_checked"] == 1
    assert a.extra["certificates_consistent"] == 1
    assert a.extra["authorised_issuewild"] == ["other.example.org"]


def test_climb_stops_at_the_first_set():
    reader = table_reader({("example.com", "r"): _caa("example.com", '0 issue ";"')},
                          dig_text("NOERROR"))
    rel = caa.climb("a.b.example.com", reader, "r")
    assert rel.found_at == "example.com"
    assert [p["name"] for p in rel.path] == ["a.b.example.com", "b.example.com", "example.com"]
    assert caa.authorised(rel.props, False) == (True, set())


# ── DANE ─────────────────────────────────────────────────────────────

def _dane_table(tlsa: dict[str, list[str]], ad: bool = True) -> dict:
    flags = "qr rd ra ad" if ad else "qr rd ra"
    table: dict = {}
    for r in RESOLVERS:
        table[("example.com", "MX", r)] = dig_text(answer=[
            "example.com. 300 IN MX 20 mx2.example.com.",
            "example.com. 300 IN MX 10 mx1.example.com."], flags=flags)
        for server, rows in tlsa.items():
            table[(dane.tlsa_name(server), "TLSA", r)] = dig_text(
                answer=[f"{dane.tlsa_name(server)}. 300 IN TLSA {row}" for row in rows], flags=flags)
    return table


def _dane_collect(table: dict):
    return dane.collect({"discovery": {"email_domains": ["example.com"]}}, NOW,
                        reader=table_reader(table, dig_text("NXDOMAIN")), resolvers=RESOLVERS)


def test_no_tlsa_is_a_fact_not_a_failing():
    a = _dane_collect(_dane_table({}))[0][0]
    assert a.extra["mail_servers"] == ["mx1.example.com", "mx2.example.com"]
    assert "dane-absent" in a.flags and is_informational_flag("dane-absent")
    assert "is not recommended at this stage" in a.notes


def test_published_records_and_unusable_usages():
    a = _dane_collect(_dane_table({"mx1.example.com": ["3 1 1 ABCD", "1 1 1 EF01"]}))[0][0]
    assert {"dane-published", "dane-usage-not-applicable:1"} <= set(a.flags)
    assert a.extra["servers_publishing"] == 1
    server = next(s for s in a.extra["servers"] if s["server"] == "mx1.example.com")
    assert [r["usage_name"] for r in server["records"]] == ["DANE-EE", "PKIX-EE"]


def test_unauthenticated_answers_are_flagged():
    a = _dane_collect(_dane_table({"mx1.example.com": ["3 1 1 ABCD"]}, ad=False))[0][0]
    assert {"dane-unauthenticated", "dane-mx-unauthenticated"} <= set(a.flags)
    assert not is_informational_flag("dane-unauthenticated")


def test_a_domain_without_mx_and_an_unreadable_one():
    no_mx = {("example.com", "MX", r): dig_text() for r in RESOLVERS}
    assert "dane-no-mx" in _dane_collect(no_mx)[0][0].flags
    unread = {("example.com", "MX", r): "__ERROR__ no servers" for r in RESOLVERS}
    assets, failures = _dane_collect(unread)
    assert "dane-unreadable" in assets[0].flags and failures
