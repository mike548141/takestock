"""DNSSEC: signing state, algorithm strength and validation control, from synthetic answers."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from dnsfake import RESOLVERS, dig_text, table_reader

from takestock.collectors import dnssec

NOW = datetime(2030, 6, 15, tzinfo=UTC)
CONTROL = "broken.example"
DOMAIN = "example.com"
EC_KEY = base64.b64encode(bytes(range(64))).decode()


def rsa_key(bits: int) -> str:
    """An RFC 3110 RSA public key with a modulus of exactly ``bits`` bits."""
    modulus = (1 << (bits - 1)) | 1
    return base64.b64encode(bytes([3]) + b"\x01\x00\x01"
                            + modulus.to_bytes(bits // 8, "big")).decode()


def _signed_zone(alg: int = 13, key: str = EC_KEY, digest: int = 2,
                 denial: str = "", expires: str = "20300701000000") -> dict:
    table: dict[tuple, str] = {}
    for r in RESOLVERS:
        table[(CONTROL, "SOA", r, False)] = dig_text("SERVFAIL")
        table[(DOMAIN, "SOA", r, False)] = dig_text(
            answer=[f"{DOMAIN}. 300 IN SOA ns1.{DOMAIN}. host.{DOMAIN}. 1 2 3 4 5"],
            flags="qr rd ra ad")
    p = RESOLVERS[0]
    rrsig = f"{DOMAIN}. 300 IN RRSIG SOA {alg} 2 300 {expires} 20300601000000 1 {DOMAIN}. AAAA"
    table[(DOMAIN, "SOA", p, True)] = dig_text(answer=[rrsig])
    table[(DOMAIN, "DS", p, True)] = dig_text(answer=[f"{DOMAIN}. 300 IN DS 1 {alg} {digest} AB"])
    table[(DOMAIN, "DNSKEY", p, True)] = dig_text(answer=[
        f"{DOMAIN}. 300 IN DNSKEY 257 3 {alg} {key}",
        f"{DOMAIN}. 300 IN DNSKEY 256 3 {alg} {key}"])
    if denial:
        table[(f"{dnssec.DENIAL_LABEL}.{DOMAIN}", "A", p, True)] = dig_text(
            "NXDOMAIN", authority=[denial])
    return table


def _collect(table: dict, control: str = CONTROL):
    return dnssec.collect({"discovery": {"domains": [DOMAIN]}}, NOW,
                          reader=table_reader(table), resolvers=RESOLVERS,
                          control_zone=control)


def test_a_signed_zone_with_a_recommended_algorithm():
    assets, failures = _collect(_signed_zone())
    a = assets[0]
    assert failures == [] and a.extra["state"] == "signed"
    assert a.signatures == ["ecdsa_p256"] and a.hashes == ["sha256"]
    assert a.verdict == "unknown"  # left for the baseline to grade
    assert "dnssec-validation-uncorroborated" not in a.flags
    assert a.extra["shortest_signature_headroom_hours"] == pytest.approx(16 * 24)
    assert "NZISM v3.9 18.5.9.C.03" in a.notes


def test_rsa_key_size_and_weak_choices_are_flagged():
    nsec3 = f"abc.{DOMAIN}. 300 IN NSEC3 1 1 10 AABB def A RRSIG"
    assets, _ = _collect(_signed_zone(alg=5, key=rsa_key(1024), digest=1, denial=nsec3,
                                      expires="20300601000000"))
    a = assets[0]
    assert a.signatures == ["rsa_1024"]
    assert {"dnssec-algorithm-not-recommended:RSASHA1", "dnssec-ds-digest-sha1",
            "nsec3-iterations:10", "nsec3-salt", "nsec3-opt-out",
            "dnssec-signature-expired"} <= set(a.flags)
    assert "sha1" in a.hashes


def test_a_must_not_algorithm_grades_the_row_weak():
    assets, _ = _collect(_signed_zone(alg=1, key=rsa_key(2048)))
    assert assets[0].verdict == "weak"
    assert "dnssec-algorithm-must-not:RSAMD5" in assets[0].flags


@pytest.mark.parametrize("has_ds, has_keys, ad, servfail, cd, answer, state", [
    (True, True, 2, 0, True, True, "signed"),
    (False, False, 0, 0, True, True, "unsigned"),
    (False, True, 0, 0, True, True, "island"),
    (True, True, 0, 2, True, True, "bogus"),
    (True, True, 1, 0, True, True, "inconclusive"),
    (False, False, 0, 0, False, False, "unreadable"),
])
def test_classify(has_ds, has_keys, ad, servfail, cd, answer, state):
    assert dnssec.classify(has_ds, has_keys, ad, servfail, cd, answer) == state


def test_an_unsigned_zone_is_weak():
    table = {(CONTROL, "SOA", r, False): dig_text("SERVFAIL") for r in RESOLVERS}
    for r in RESOLVERS:
        table[(DOMAIN, "SOA", r, False)] = dig_text(answer=[f"{DOMAIN}. 300 IN SOA a. b. 1 2 3 4 5"])
    assets, _ = _collect(table)
    assert assets[0].extra["state"] == "unsigned"
    assert assets[0].verdict == "weak" and "dnssec-unsigned" in assets[0].flags


def test_no_control_zone_means_no_reading():
    assets, failures = _collect(_signed_zone(), control="")
    assert assets == [] and "no validation control zone is configured" in failures[0]


def test_resolvers_that_do_not_validate_are_refused():
    table = _signed_zone()
    for r in RESOLVERS:
        table[(CONTROL, "SOA", r, False)] = dig_text("NOERROR")
    assets, failures = _collect(table)
    assert assets == [] and "no resolver rejected" in failures[0]


def test_one_validator_is_uncorroborated():
    table = _signed_zone()
    for r in RESOLVERS[1:]:
        table[(CONTROL, "SOA", r, False)] = dig_text("NOERROR")
    a = _collect(table)[0][0]
    assert a.extra["state"] == "inconclusive"
    assert "dnssec-validation-uncorroborated" in a.flags


def test_rsa_modulus_and_tokens():
    assert dnssec.rsa_modulus_bits(rsa_key(2048)) == 2048
    assert dnssec.rsa_modulus_bits("!") == 0
    assert dnssec.rsa_token(3000) == "rsa_2048"
    assert dnssec.rsa_token(512) == "rsa_1024"
    assert dnssec.algorithm_tokens(15, "") == (["ed25519"], [], 0)


def test_compact_denial_is_recognised():
    resp = dnssec.parse(dig_text("NOERROR", authority=[
        f"x.{DOMAIN}. 300 IN NSEC \\000.x.{DOMAIN}. RRSIG NSEC NXNAME"]))
    assert dnssec.denial(DOMAIN, resp)["mechanism"] == "nsec-compact"
    assert dnssec.domains({"discovery": {"domains": ["Example.com."],
                                         "email_domains": ["example.com"]}}) == ["example.com"]
