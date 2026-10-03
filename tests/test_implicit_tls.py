"""TLS on the implicit-TLS mail ports, taken from the cleartext check's own probe plan."""

from __future__ import annotations

from datetime import UTC, datetime

from probe_helpers import FakeRun, fixture, has, never_run, target

from takestock.collectors import implicit_tls, plaintext_scan, tls_scan
from takestock.model import is_informational_flag

MAIL = "mail-01.example.test"
WHEN = datetime(2030, 3, 15, tzinfo=UTC)


def mail_target(*ports: str, **kw) -> dict:
    t = target(mail_self=[MAIL], **kw)
    t["plaintext_ports"] = list(ports or ("80/tcp", "465/tcp", "993/tcp", "995/tcp"))
    return t


def all_versions(out: str) -> list:
    return [(has("s_client", flag), out) for flag in ("-tls1", "-tls1_1", "-tls1_2", "-tls1_3")]


def answering() -> FakeRun:
    return FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")),
        (has("s_client", "-tls1"), fixture("openssl-tls1.txt")),
        (has("s_client", "-tls1_1"), fixture("openssl-tls1_1.txt")),
        (has("s_client", "-tls1_2"), fixture("openssl-tls1_2.txt")),
        (has("s_client", "-tls1_3"), fixture("openssl-tls1_3.txt")),
    ])


def test_only_the_implicit_tls_ports_are_taken_from_the_plan():
    assert implicit_tls.planned(mail_target()) == [
        (MAIL, 465, "plaintext_ports"), (MAIL, 993, "plaintext_ports"),
        (MAIL, 995, "plaintext_ports")]


def test_the_pairs_never_widen_the_plan():
    assert implicit_tls.planned(mail_target("80/tcp")) == []


def test_a_refused_plan_is_a_failure_and_contacts_nothing(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assets, failures = implicit_tls.collect(mail_target("443-465/tcp"))
    assert assets == []
    assert failures[0].startswith("implicit_tls: REFUSED to probe")


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", never_run)
    assets, failures = implicit_tls.collect(mail_target(authorised=False))
    assert assets == [] and failures[0].startswith("implicit_tls: REFUSED, nothing contacted")


def test_a_listener_that_answers_is_graded_like_any_tls_endpoint(monkeypatch, policy):
    fake = answering()
    monkeypatch.setattr(tls_scan, "run", fake)
    assets, failures = implicit_tls.collect(mail_target("993/tcp"), ref_time=WHEN)
    assert failures == []
    [a] = assets
    assert (a.name, a.port, a.extra["service"]) == (f"IMAPS {MAIL}:993", "993", "993/tcp")
    assert a.protocol_versions == ["TLSv1.2", "TLSv1.3"]
    assert implicit_tls.PREFERENCE_ONLY in a.notes
    assert implicit_tls.NAME_MISMATCH_FLAG in a.flags      # stub cert names web-01 only
    assert not any("-starttls" in c for c in fake.calls)   # TLS from the first byte
    policy.apply(a)
    assert a.verdict == "acceptable"


def test_a_refused_connection_is_a_measured_negative(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun(all_versions(fixture("openssl-refused.txt"))))
    [a] = implicit_tls.collect(mail_target("995/tcp"))[0]
    assert a.verdict == "n/a"
    assert "nothing is listening" in a.notes


def test_no_answer_is_unmeasured_never_nothing_listening(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun(all_versions("__ERROR__ timed out")))
    [a] = implicit_tls.collect(mail_target("465/tcp"))[0]
    assert a.verdict == "unknown"
    assert f"{implicit_tls.UNREACHED_FLAG}smtps" in a.flags
    assert is_informational_flag(f"{implicit_tls.UNREACHED_FLAG}smtps")


def test_a_listener_that_does_not_speak_tls_is_flagged(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun(all_versions(fixture("openssl-tls1.txt"))))
    [a] = implicit_tls.collect(mail_target("465/tcp"))[0]
    assert a.verdict == "unknown"
    assert f"{implicit_tls.NO_HANDSHAKE_FLAG}smtps" in a.flags
    assert not is_informational_flag(f"{implicit_tls.NO_HANDSHAKE_FLAG}smtps")


def test_every_listed_port_has_a_service_name():
    assert all(implicit_tls.service(p) for p in implicit_tls.IMPLICIT_TLS_PORTS)
    assert implicit_tls.service(443) == ""


def test_the_plan_is_shared_with_the_cleartext_check():
    plan = plaintext_scan.build_plan(mail_target(), derived={})
    assert implicit_tls.planned(mail_target(), plan) == implicit_tls.planned(mail_target())


def test_old_versions_the_client_would_not_offer_are_unmeasured_not_refused(monkeypatch):
    legacy = fixture("openssl3-tls1-not-offered.txt")
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")),
        (has("s_client", "-tls1"), legacy),
        (has("s_client", "-tls1_1"), legacy),
        (has("s_client", "-tls1_2"), fixture("openssl-tls1_2.txt")),
        (has("s_client", "-tls1_3"), fixture("openssl-tls1_3.txt")),
    ]))
    a = implicit_tls.measure(MAIL, 993, ref_time=WHEN)
    assert a.extra["version_probe"].startswith(
        "TLSv1.0=unknown-client-cannot-offer; TLSv1.1=unknown-client-cannot-offer")
    assert tls_scan.VERSION_PROBE_UNAVAILABLE in a.flags
    assert "would not offer TLSv1.0, TLSv1.1" in a.notes


def test_without_nmap_the_certificate_is_not_read_and_says_so(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), "__ERROR__ [Errno 2] No such file or directory: 'nmap'"),
        (has("s_client", "-tls1"), fixture("openssl-tls1.txt")),
        (has("s_client", "-tls1_1"), fixture("openssl-tls1_1.txt")),
        (has("s_client", "-tls1_2"), fixture("openssl-tls1_2.txt")),
        (has("s_client", "-tls1_3"), fixture("openssl-tls1_3.txt")),
    ]))
    assets, failures = implicit_tls.collect(mail_target("465/tcp", "993/tcp"), ref_time=WHEN)
    assert len(assets) == 2
    for a in assets:
        assert a.extra["cert_detail"] == tls_scan.CERT_NOT_READ_NO_NMAP
        assert "certificate detail not read: nmap is not on PATH" in a.notes
        assert implicit_tls.NAME_MISMATCH_FLAG not in a.flags
    (line,) = failures
    assert line.startswith("implicit_tls: nmap is not on PATH")
    assert f"{MAIL}:465" in line and f"{MAIL}:993" in line
