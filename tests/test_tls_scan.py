"""The outside-in TLS scan: enumeration, version probes, negotiation and certificate."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import FakeRun, fixture, has, never_run, target

from takestock.collectors import tls_scan
from takestock.model import is_informational_flag
from takestock.tls_negotiate import Negotiation
from takestock.tls_session import COULD_NOT_ASK, OFFERED, REFUSED, TlsSession

HOST = "web-01.example.test"


def openssl_answers(**overrides: str) -> list:
    """FakeRun answers for the four pinned handshakes against the captured stub."""
    by_flag = {"-tls1": fixture("openssl-tls1.txt"), "-tls1_1": fixture("openssl-tls1_1.txt"),
               "-tls1_2": fixture("openssl-tls1_2.txt"), "-tls1_3": fixture("openssl-tls1_3.txt"),
               **overrides}
    return [(has("s_client", flag), out) for flag, out in by_flag.items()]


def scan_answers(**overrides: str) -> FakeRun:
    return FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-ssl-enum-ciphers.txt")),
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")),
        *openssl_answers(**overrides),
    ])


@pytest.fixture()
def no_negotiation(monkeypatch):
    monkeypatch.setattr(tls_scan, "negotiate", lambda *_a: None)


# ── parsing ──

def test_ssl_enum_ciphers_is_read():
    parsed = tls_scan.parse_enum_ciphers(fixture("nmap-ssl-enum-ciphers.txt"))
    assert parsed["versions"] == ["TLSv1.2"]
    assert parsed["grade"] == "C"
    assert "TLS_RSA_WITH_RC4_128_MD5" in parsed["suites"]
    assert parsed["key_exchange"] == ["dh_2048", "ecdh_p256", "rsa"]


@pytest.mark.parametrize(("raw", "token"), [
    ("secp256r1", "ecdh_p256"), ("x25519", "x25519"), ("ecdh_x25519", "x25519"),
    ("dh 2048", "dh_2048"), ("rsa 2048", "rsa"), ("ecdh 256", "ecdh_256"),
    ("X25519MLKEM768", "x25519mlkem768"), ("odd name!", "odd_name_"), ("", ""),
])
def test_groups_are_named_the_way_the_baseline_names_them(raw, token):
    assert tls_scan.normalise_tls_group(raw) == token


def test_the_certificate_is_read():
    cert = tls_scan.parse_ssl_cert(fixture("nmap-ssl-cert.txt"))
    assert cert is not None
    assert (cert["pubkey_type"], cert["pubkey_bits"]) == ("rsa", 2048)
    assert cert["signature_algorithm"] == "sha256WithRSAEncryption"
    assert cert["subject_alt_names"] == ["web-01.example.test", "www.example.test"]
    assert cert["issuer"] == "commonName=web-01.example.test"


def test_output_without_the_script_has_no_certificate():
    assert tls_scan.parse_ssl_cert("PORT STATE SERVICE\n443/tcp open https\n") is None


@pytest.mark.parametrize(("out", "expect"), [
    ("443/tcp open  https\n", "something is listening that did not speak TLS"),
    ("443/tcp closed https\n", "closed: the host answered and refused"),
    ("443/tcp filtered https\n", tls_scan.NO_TLS_RESPONSE),
])
def test_no_tls_is_explained_by_the_port_state(out, expect):
    assert expect in tls_scan.no_tls_notes(out, 443)


# ── version probes ──

def test_each_version_is_pinned_and_read(monkeypatch, tmp_path):
    fake = FakeRun(openssl_answers())
    monkeypatch.setattr(tls_scan, "run", fake)
    probed = tls_scan.probe_versions(HOST, 443, HOST, tmp_path)
    assert {v: s.state for v, s in probed.items()} == {
        "TLSv1.0": REFUSED, "TLSv1.1": REFUSED, "TLSv1.2": OFFERED, "TLSv1.3": OFFERED}
    assert all(["-servername", HOST] == c[c.index("-servername"):c.index("-servername") + 2]
               for c in fake.calls)
    kept = (tmp_path / f"openssl-versions-{HOST}-443.txt").read_text()
    assert "TLS session ticket:" in kept
    assert "0000 - 2c 59" not in kept                      # the ticket's hex dump is gone
    assert "Master-Key: <redacted by takestock" in kept


def test_an_address_gets_no_server_name(monkeypatch):
    fake = FakeRun(openssl_answers())
    monkeypatch.setattr(tls_scan, "run", fake)
    tls_scan.probe_versions("192.0.2.10", 443, "192.0.2.10")
    assert not any("-servername" in c for c in fake.calls)


def test_an_ipv6_address_is_bracketed_for_openssl(monkeypatch):
    fake = FakeRun(openssl_answers())
    monkeypatch.setattr(tls_scan, "run", fake)
    tls_scan.probe_versions("2001:db8::10", 443)
    assert all("[2001:db8::10]:443" in c for c in fake.calls)


def test_a_version_confirmed_by_handshake_is_added():
    probed = {"TLSv1.2": TlsSession(OFFERED), "TLSv1.3": TlsSession(OFFERED)}
    versions, note, flags = tls_scan.merge_versions(["TLSv1.2"], probed)
    assert versions == ["TLSv1.2", "TLSv1.3"]
    assert "TLSv1.3 confirmed by handshake" in note
    assert not flags


def test_a_conflict_is_kept_and_noted():
    versions, note, _ = tls_scan.merge_versions(["TLSv1.0"], {"TLSv1.0": TlsSession(REFUSED)})
    assert versions == ["TLSv1.0"]
    assert "worth a second look" in note


def test_a_version_that_could_not_be_asked_is_unknown_not_absent():
    _, note, flags = tls_scan.merge_versions([], {"TLSv1.3": TlsSession(COULD_NOT_ASK)})
    assert flags == {tls_scan.VERSION_PROBE_UNAVAILABLE}
    assert "unknown, not absent" in note
    assert is_informational_flag(tls_scan.VERSION_PROBE_UNAVAILABLE)


# ── redaction ──

def test_single_line_secrets_are_blanked():
    out = tls_scan.redact_transcript("    Session-ID: ABCDEF\n    Cipher    : X\n")
    assert "ABCDEF" not in out
    assert "Cipher    : X" in out


def test_an_unrecognised_block_is_kept_and_marked():
    text = "New block:\n    0000 - 01 02 03 04   ....\n"
    out = tls_scan.redact_transcript(text)
    assert tls_scan.UNRECOGNISED_BLOCK_MARKER in out
    assert "0000 - 01 02" in out


def test_a_known_safe_block_is_not_marked():
    out = tls_scan.redact_transcript(fixture("openssl-tls1_3.txt"))
    assert tls_scan.UNRECOGNISED_BLOCK_MARKER not in out


# ── the certificate and its expiry ──

@pytest.mark.parametrize(("when", "flag"), [
    (datetime(2026, 10, 15, tzinfo=UTC), None),
    (datetime(2026, 12, 18, tzinfo=UTC), "expiry-soon"),
    (datetime(2026, 12, 25, tzinfo=UTC), "renewal-overdue"),
    (datetime(2027, 1, 5, tzinfo=UTC), "expired"),
])
def test_expiry_flags_follow_the_certificate_lifetime(monkeypatch, when, flag):
    from takestock.model import CryptoAsset
    monkeypatch.setattr(tls_scan, "run", FakeRun([(has("ssl-cert"), fixture("nmap-ssl-cert.txt"))]))
    a = CryptoAsset(name="TLS", data_state="in-transit", protocol="tls")
    tls_scan.attach_cert_detail(a, HOST, 443, None, when)
    assert a.signatures == ["rsa_2048"]
    expiry = {"expired", "renewal-overdue", "expiry-soon"} & set(a.flags)
    assert expiry == ({flag} if flag else set())
    assert a.extra["cert_san"] == "web-01.example.test, www.example.test"


# ── negotiation ──

def _negotiation(group: str, pq_offered: bool, error: str = "") -> Negotiation:
    return Negotiation(client="test", version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256",
                       group=group, pq_offered=pq_offered, error=error)


def test_a_hybrid_choice_from_a_pq_offer_is_added_to_key_exchange(monkeypatch):
    from takestock.model import CryptoAsset
    monkeypatch.setattr(tls_scan, "negotiate", lambda *_a: _negotiation("X25519MLKEM768", True))
    a = CryptoAsset(name="TLS", data_state="in-transit", protocol="tls", key_exchange=["x25519"])
    tls_scan.attach_negotiation(a, HOST, 443, HOST, None)
    assert a.key_exchange == ["x25519", "x25519mlkem768"]
    assert a.extra["negotiated_group"] == "X25519MLKEM768"


def test_a_choice_from_a_classical_offer_never_reaches_the_grade(monkeypatch):
    from takestock.model import CryptoAsset
    monkeypatch.setattr(tls_scan, "negotiate", lambda *_a: _negotiation("secp384r1", False))
    a = CryptoAsset(name="TLS", data_state="in-transit", protocol="tls", key_exchange=["x25519"])
    tls_scan.attach_negotiation(a, HOST, 443, HOST, None)
    assert a.key_exchange == ["x25519"]
    assert "negotiated_pq_limit" in a.extra


def test_sni_is_withheld_for_an_address(monkeypatch):
    from takestock.model import CryptoAsset
    seen = []
    monkeypatch.setattr(tls_scan, "negotiate", lambda addr, port, sni: seen.append(sni))
    tls_scan.attach_negotiation(CryptoAsset(name="x", data_state="in-transit"),
                                "192.0.2.10", 443, "192.0.2.10", None)
    assert seen == [""]


# ── collect ──

def test_collect_grades_the_endpoint_through_the_policy(monkeypatch, policy, no_negotiation):
    monkeypatch.setattr(tls_scan, "run", scan_answers())
    assets, failures = tls_scan.collect(target(tls_443=[HOST]),
                                        ref_time=datetime(2026, 10, 15, tzinfo=UTC))
    assert failures == []
    [a] = assets
    assert (a.host, a.port, a.source, a.internet_facing) == (HOST, "443", "tls_scan", True)
    assert a.protocol_versions == ["TLSv1.2", "TLSv1.3"]
    assert a.extra["version_probe"] == (
        "TLSv1.0=refused; TLSv1.1=refused; TLSv1.2=offered; TLSv1.3=offered")
    assert a.role.startswith("Public internet-facing service")
    policy.apply(a)
    assert a.verdict == "weak"
    assert "no-forward-secrecy" in a.flags


def test_a_port_with_no_tls_is_unknown(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-enum-ciphers"), "443/tcp closed https\n")]))
    [a], _ = tls_scan.collect(target(tls_443=[HOST]))
    assert a.verdict == "unknown"
    assert "closed" in a.notes


def test_gateways_are_probed_by_address_and_reported_by_name(monkeypatch, no_negotiation):
    fake = scan_answers()
    monkeypatch.setattr(tls_scan, "run", fake)
    gw = {"host": "vpn.example.test", "ip": "192.0.2.20"}
    [a], _ = tls_scan.collect(target(vpn_gateways=[gw]))
    assert (a.host, a.ip) == ("vpn.example.test", "192.0.2.20")
    assert all("192.0.2.20" in " ".join(c) for c in fake.calls)
    assert a.role.startswith("Remote-access VPN gateway")


def test_a_third_party_endpoint_uses_its_own_port(monkeypatch, no_negotiation):
    monkeypatch.setattr(tls_scan, "run", scan_answers())
    entry = {"host": "app.example.com", "port": 8443, "vendor": "Example Hosting"}
    [a], _ = tls_scan.collect(target(saas_443=[entry]))
    assert a.port == "8443"
    assert "Example Hosting" in a.role


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assets, failures = tls_scan.collect(target(authorised=False, tls_443=[HOST]))
    assert assets == []
    assert failures == ["tls_scan: REFUSED, nothing contacted — no `authorisation:` "
                        "stanza in the target profile"]


def test_a_target_with_no_endpoints_does_nothing(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assert tls_scan.collect(target(authorised=False)) == ([], [])
