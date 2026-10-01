"""STARTTLS on the mail gateways: what was offered, chosen, and what cannot be claimed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import FakeRun, fixture, has, never_run, target

from takestock.collectors import smtp_starttls, tls_scan

GATEWAY = "mail-01.example.test"
WHEN = datetime(2026, 10, 15, tzinfo=UTC)

# The stub certificate names web-01.example.test and www.example.test only.
CERT = fixture("nmap-ssl-cert.txt")


def mail_answers(**by_flag: str) -> FakeRun:
    versions = {"-tls1": fixture("smtp-tls1.txt"), "-tls1_1": fixture("smtp-tls1_1.txt"),
                "-tls1_2": fixture("smtp-tls1_2.txt"), "-tls1_3": fixture("smtp-tls1_3.txt"),
                **by_flag}
    return FakeRun([(has("ssl-cert"), CERT),
                    *[(has("s_client", flag), out) for flag, out in versions.items()]])


def gateway_target(**kw) -> dict:
    return target(smtp_25=[{"host": GATEWAY, "vendor": "Example Hosting",
                            "service": "Mail relay"}], **kw)


def test_the_session_at_each_version_is_read(monkeypatch, policy):
    fake = mail_answers()
    monkeypatch.setattr(tls_scan, "run", fake)
    [a], failures = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert failures == []
    assert a.protocol_versions == ["TLSv1.2", "TLSv1.3"]
    assert a.symmetric == ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
    assert a.key_exchange == ["x25519"]
    assert a.extra["starttls"] == "offered"
    assert smtp_starttls.PREFERENCE_ONLY in a.notes
    policy.apply(a)
    assert a.verdict == "acceptable"


def test_the_probe_upgrades_with_starttls_on_port_25(monkeypatch):
    fake = mail_answers()
    monkeypatch.setattr(tls_scan, "run", fake)
    smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    handshakes = [c for c in fake.calls if "s_client" in c]
    assert len(handshakes) == 4
    assert all(c[c.index("-starttls") + 1] == "smtp" for c in handshakes)
    assert all(f"{GATEWAY}:25" in c for c in handshakes)


def test_a_certificate_that_misses_the_gateway_name_is_flagged(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", mail_answers())
    [a], _ = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert smtp_starttls.NAME_MISMATCH_FLAG in a.flags
    assert "does not cover mail-01.example.test" in a.notes


def test_a_gateway_that_never_advertises_starttls_is_a_measured_cleartext_finding(monkeypatch):
    no = fixture("smtp-no-starttls.txt")
    monkeypatch.setattr(tls_scan, "run", mail_answers(
        **{"-tls1": no, "-tls1_1": no, "-tls1_2": no, "-tls1_3": no}))
    [a], failures = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert failures == []
    assert a.verdict == "weak"
    assert "plaintext:smtp" in a.flags
    assert a.notes.startswith("NO ENCRYPTION AVAILABLE")
    assert not any(f.startswith("cleartext-exposure:") for f in a.flags)


def test_a_gateway_that_answers_but_completes_nothing_claims_nothing(monkeypatch):
    refused = fixture("smtp-tls1.txt")
    monkeypatch.setattr(tls_scan, "run", mail_answers(
        **{"-tls1_2": refused, "-tls1_3": refused}))
    [a], failures = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert failures == []
    assert a.verdict == "unknown"
    assert "unverified-encryption:smtp" in a.flags
    assert "neither is claimed" in a.notes


def test_an_unreachable_gateway_is_a_failure_not_a_clean_row(monkeypatch):
    gone = fixture("openssl-refused.txt")
    monkeypatch.setattr(tls_scan, "run", mail_answers(
        **{"-tls1": gone, "-tls1_1": gone, "-tls1_2": gone, "-tls1_3": gone}))
    [a], failures = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert len(failures) == 1 and "holds NO evidence" in failures[0]
    assert a.verdict == "unknown"
    assert tls_scan.VERSION_PROBE_UNAVAILABLE in a.flags


@pytest.mark.parametrize(("name", "iana"), [
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    ("DHE-RSA-AES128-SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    ("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"),
    ("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("AEAD-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256"),
    ("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
    ("AES128-GCM", ""),
    ("WEIRD-THING-SHA", ""),
])
def test_openssl_suite_names_map_to_iana_names(name, iana):
    assert smtp_starttls.iana_suite_name(name) == iana


def test_every_mapped_suite_grades(policy):
    for name in ("ECDHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-SHA", "AES128-SHA",
                 "DES-CBC3-SHA", "ECDHE-ECDSA-CHACHA20-POLY1305"):
        verdict, flags = policy.grade_cipher_suite(smtp_starttls.iana_suite_name(name))
        assert verdict != "unknown", name
        assert not any(f.startswith("ungraded:") for f in flags), name


@pytest.mark.parametrize(("line", "token"), [
    ("Server Temp Key: ECDH, X25519, 253 bits", "x25519"),
    ("Server Temp Key: ECDH, P-256, 256 bits", "ecdh_p256"),
    ("Server Temp Key: ECDH, prime256v1, 256 bits", "ecdh_p256"),
    ("Server Temp Key: DH, 2048 bits", "dh_2048"),
    ("Server Temp Key: RSA, 512 bits", ""),
    ("no such line", ""),
])
def test_the_temporary_key_names_the_group(line, token):
    assert smtp_starttls.parse_server_temp_key(line) == token


@pytest.mark.parametrize(("host", "names", "covered"), [
    ("mail-01.example.test", ["mail-01.example.test"], True),
    ("mail-01.example.test", ["*.example.test"], True),
    ("a.mail-01.example.test", ["*.example.test"], False),
    ("mail-01.example.test", ["web-01.example.test"], False),
    ("MAIL-01.example.test.", ["mail-01.EXAMPLE.test"], True),
])
def test_name_matching_follows_the_one_label_wildcard_rule(host, names, covered):
    assert smtp_starttls.san_covers(host, names) is covered


def test_a_gateway_listed_twice_is_probed_once():
    t = target(smtp_25=[GATEWAY, {"host": GATEWAY}, "mail-02.example.test"])
    assert smtp_starttls.gateways(t) == [GATEWAY, "mail-02.example.test"]


def test_no_gateways_means_no_probe(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assert smtp_starttls.collect(target()) == ([], [])


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assets, failures = smtp_starttls.collect(gateway_target(authorised=False))
    assert assets == [] and failures[0].startswith("smtp_starttls: REFUSED")


def test_the_row_is_an_active_public_measurement(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", mail_answers())
    [a], _ = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert (a.source, a.source_class, a.collected_at) == ("smtp_starttls", "public", "2026-10-15")
    assert "Example Hosting" in a.role


def test_old_versions_the_client_would_not_offer_are_unmeasured_not_refused(monkeypatch):
    legacy = fixture("openssl3-tls1-not-offered.txt")
    monkeypatch.setattr(tls_scan, "run", mail_answers(**{"-tls1": legacy, "-tls1_1": legacy}))
    [a], failures = smtp_starttls.collect(gateway_target(), ref_time=WHEN)
    assert failures == []
    assert a.extra["version_probe"] == (
        "TLSv1.0=unknown-client-cannot-offer; TLSv1.1=unknown-client-cannot-offer; "
        "TLSv1.2=offered; TLSv1.3=offered")
    assert tls_scan.VERSION_PROBE_UNAVAILABLE in a.flags
    assert "would not offer TLSv1.0, TLSv1.1" in a.notes
    assert "DEFAULT@SECLEVEL=0" in a.notes
