"""Inside-the-network service checks: the plan's refusals and each kind of port.

The probes in the measurement tests are built directly on the high ports the
loopback stubs listened on, so the captured nmap port lines match.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import AUTH, FakeRun, fixture, has, never_run, target

from takestock.collectors import internal_scan as isc
from takestock.collectors import smtp_starttls, tls_scan
from takestock.inside_scope import InsideRefused
from takestock.model import NA_VERDICT

WHEN = datetime(2030, 1, 15, tzinfo=UTC)
KEY = isc.TARGET_KEY


def inside(entries: list, record: dict | None = None, authorised: bool = True) -> dict:
    extra = {KEY: record if record is not None else dict(AUTH)} if authorised else {}
    return target(extra_auth=extra, **{KEY: entries})


def probe(port: int, as_port: int, host: str = "svc-01.example.test") -> isc.Probe:
    return isc.Probe(host, port, isc.INTERNAL_PORTS[as_port])


def openssl_answers(prefix: str = "openssl") -> list:
    return [(has("s_client", flag), fixture(f"{prefix}-{name}.txt"))
            for flag, name in (("-tls1", "tls1"), ("-tls1_1", "tls1_1"),
                               ("-tls1_2", "tls1_2"), ("-tls1_3", "tls1_3"))]


@pytest.fixture()
def quiet_tls(monkeypatch):
    """tls_scan's own commands answer from the stub captures; no negotiation."""
    monkeypatch.setattr(tls_scan, "negotiate", lambda *_a: None)
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")), *openssl_answers()]))


# ── the plan ──

def test_an_undeclared_group_is_inert(monkeypatch):
    monkeypatch.setattr(isc, "run", never_run)
    assert isc.collect(target()) == ([], [])


def test_a_declared_group_without_its_own_record_is_refused(monkeypatch):
    monkeypatch.setattr(isc, "run", never_run)
    assets, failures = isc.collect(inside([{"host": "dir-01.example.test", "port": 636}],
                                          authorised=False))
    assert assets == []
    assert "REFUSED, nothing contacted" in failures[0]
    assert f"authorisation.{KEY}" in failures[0]


def test_an_incomplete_record_is_refused(monkeypatch):
    monkeypatch.setattr(isc, "run", never_run)
    _, failures = isc.collect(inside([{"host": "dir-01.example.test", "port": 636}],
                                     record={"scope": "Directory servers"}))
    assert "authorised_by" in failures[0]


@pytest.mark.parametrize(("entry", "why"), [
    ({"host": "dir-01.example.test", "port": 22}, "allow-list"),
    ({"host": "dir-01.example.test", "port": "636"}, "single port number"),
    ({"host": "dir-01.example.test", "port": True}, "single port number"),
    ({"host": "192.0.2.0/24", "port": 636}, "not one named host"),
    ({"host": "dir-01.example.test", "ip": "192.0.2.10", "port": 636}, "`host:` only"),
    ("dir-01.example.test", "mapping"),
])
def test_entries_outside_the_rules_are_refused(entry, why):
    with pytest.raises(InsideRefused, match=why):
        isc.plan(inside([entry]))


def test_a_pair_named_twice_is_refused():
    entries = [{"host": "dir-01.example.test", "port": 636},
               {"host": "DIR-01.example.test", "port": 636}]
    with pytest.raises(InsideRefused, match="twice"):
        isc.plan(inside(entries))


def test_too_many_ports_on_one_host_is_refused_not_truncated():
    ports = sorted(isc.INTERNAL_PORTS)
    assert len(ports) > isc.plaintext_scan.MAX_PORTS_PER_HOST
    entries = [{"host": "svc-01.example.test", "port": p} for p in ports]
    with pytest.raises(InsideRefused, match="REFUSED rather than truncated"):
        isc.plan(inside(entries))


def test_a_valid_plan_keeps_order_and_roles():
    probes = isc.plan(inside([{"host": "dir-01.example.test", "port": 636},
                              {"host": "mail-01.example.test", "port": 143,
                               "role": "Mailbox retrieval"}]))
    assert [(p.host, p.port, p.spec.kind) for p in probes] == [
        ("dir-01.example.test", 636, isc.TLS), ("mail-01.example.test", 143, isc.STARTTLS)]
    assert probes[1].role == "Mailbox retrieval"


def test_the_budget_names_every_pair_before_anything_runs():
    lines = isc.budget_lines(isc.plan(inside([{"host": "dir-01.example.test", "port": 389}])))
    assert any("dir-01.example.test:389" in ln and "ldap-starttls" in ln for ln in lines)
    assert any("never" in ln for ln in lines)


def test_missing_tools_are_one_failure_and_nothing_runs(monkeypatch):
    monkeypatch.setattr(isc, "run", never_run)
    monkeypatch.setattr(isc.shutil, "which", lambda name: None)
    assets, failures = isc.collect(inside([{"host": "web-01.example.test", "port": 80}]),
                                   announce=lambda _l: None)
    assert assets == []
    assert "nmap" in failures[0] and "curl" in failures[0]
    assert "openssl" not in failures[0]


# ── capability parsing ──

def test_imap_without_logindisabled_invites_a_password():
    caps = isc.parse_imap_capabilities(fixture("nmap-imap-capabilities.txt"))
    assert caps.read and caps.starttls
    assert caps.plaintext_auth == ["LOGIN command (no LOGINDISABLED)", "AUTH=PLAIN"]


def test_the_glued_command_tag_is_stripped():
    caps = isc.parse_imap_capabilities(fixture("nmap-imap-capabilities-logindisabled.txt"))
    assert caps.login_disabled
    assert caps.plaintext_auth == []


def test_pop3_user_and_plain_sasl_are_password_paths():
    caps = isc.parse_pop3_capabilities(fixture("nmap-pop3-capabilities.txt"))
    assert caps.starttls
    assert caps.plaintext_auth == ["USER", "SASL PLAIN", "SASL LOGIN"]


def test_smtp_auth_mechanisms_are_read_from_the_ehlo_line():
    caps = isc.parse_smtp_commands(fixture("nmap-smtp-commands.txt"))
    assert caps.starttls
    assert caps.plaintext_auth == ["AUTH LOGIN", "AUTH PLAIN"]
    assert "RFC 5321" not in caps.raw


def test_no_script_output_is_an_unread_list():
    caps = isc.parse_imap_capabilities(fixture("nmap-open-no-script.txt"))
    assert not caps.read


# ── WinRM's unauthenticated answer ──

def test_the_401_schemes_are_read():
    assert isc.parse_winrm_auth(fixture("curl-winrm-401.txt")) == (401, ["Negotiate", "Basic"])


def test_a_non_401_offers_nothing_to_read():
    code, schemes = isc.parse_winrm_auth(fixture("curl-winrm-501.txt"))
    assert (code, schemes) == (501, [])
    assert "not 401" in isc.winrm_sentence(5985, code, schemes, "")


def test_basic_over_plain_http_is_said_plainly():
    sentence = isc.winrm_sentence(5985, 401, ["Negotiate", "Basic"], "")
    assert "OFFERED over plain HTTP" in sentence


# ── measurement: each kind of port ──

def test_tls_port_is_measured_like_the_outside_scan(monkeypatch, quiet_tls, policy):
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-ssl-enum-ciphers.txt"))]))
    a = isc.measure_tls(probe(44330, 636), None, WHEN)
    assert a.source == isc.SOURCE and a.internet_facing is False
    assert a.source_class == "private"
    assert a.role == "Internal service — LDAPS"
    assert "TLSv1.2" in a.protocol_versions
    assert "TLS_RSA_WITH_RC4_128_MD5" in a.symmetric
    assert a.collected_at == "2030-01-15"
    policy.apply(a)
    assert a.verdict == "weak"


def test_a_tls_port_that_serves_plain_http_is_cleartext(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun([(has("s_client"), fixture("openssl-refused.txt"))]))
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt")),
        (has("curl"), fixture("curl-plain-http.txt"))]))
    a = isc.measure_tls(probe(18080, 8443), None, WHEN)
    assert a.extra["plaintext_outcome"] == isc.plaintext_scan.CLEARTEXT_SERVED
    assert a.extra["expected"] == "tls"
    assert "expected to carry TLS" in a.notes


def test_a_tls_port_that_speaks_neither_is_flagged(monkeypatch):
    monkeypatch.setattr(tls_scan, "run", FakeRun([(has("s_client"), fixture("openssl-refused.txt"))]))
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt")),
        (has("curl"), fixture("curl-tls-port.txt"))]))
    a = isc.measure_tls(probe(18080, 636), None, WHEN)
    assert a.verdict == "unknown"
    assert a.flags == [f"{isc.NO_HANDSHAKE_FLAG}ldaps"]


def test_a_closed_port_is_not_a_finding(monkeypatch):
    monkeypatch.setattr(isc, "run", FakeRun([(has("ssl-enum-ciphers"), fixture("nmap-closed.txt"))]))
    a = isc.measure_tls(probe(18999, 636), None, WHEN)
    assert a.verdict == NA_VERDICT
    assert a.internet_facing is False


def test_ldap_starttls_is_measured_by_nmap_alone(monkeypatch, quiet_tls):
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-ssl-enum-ciphers.txt"))]))
    a = isc.measure_ldap_starttls(probe(44330, 389), None, WHEN)
    assert a.extra["starttls"] == "offered"
    assert tls_scan.VERSION_PROBE_UNAVAILABLE in a.flags
    assert not any("s_client" in c for c in tls_scan.run.calls)


def test_ldap_without_an_enumeration_claims_nothing(monkeypatch):
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt"))]))
    a = isc.measure_ldap_starttls(probe(18080, 389), None, WHEN)
    assert a.verdict == "unknown" and a.protocol == "ldap"
    assert "neither" in a.notes


def test_imap_gives_a_session_row_and_a_sign_in_row(monkeypatch, quiet_tls):
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")), *openssl_answers("smtp")]))
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("+imap-capabilities"), fixture("nmap-imap-capabilities.txt")),
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt"))]))
    session, auth = isc.measure_starttls(probe(14300, 143, "mail-01.example.test"), None, WHEN)
    assert session.extra["starttls"] == "offered"
    assert session.extra["starttls_advertised"] is True
    assert smtp_starttls.PREFERENCE_ONLY in session.notes
    assert auth.verdict == "weak"
    assert auth.flags == [f"{isc.CLEARTEXT_AUTH_FLAG}imap"]
    assert "RFC 3501" in auth.notes and "16.1.33.C.01" in auth.notes
    handshakes = [c for c in tls_scan.run.calls if "s_client" in c]
    assert all(c[c.index("-starttls") + 1] == "imap" for c in handshakes)


def test_logindisabled_leaves_no_password_path(monkeypatch, quiet_tls):
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")), *openssl_answers("smtp")]))
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("+imap-capabilities"), fixture("nmap-imap-capabilities-logindisabled.txt")),
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt"))]))
    _session, auth = isc.measure_starttls(probe(14301, 143), None, WHEN)
    assert auth.verdict == NA_VERDICT
    assert "LOGINDISABLED is advertised" in auth.notes


def test_a_service_that_advertises_no_starttls_runs_in_clear(monkeypatch):
    caps = fixture("nmap-pop3-capabilities.txt").replace(" STLS", "")
    monkeypatch.setattr(tls_scan, "run", FakeRun([(has("s_client"), fixture("smtp-no-starttls.txt"))]))
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("+pop3-capabilities"), caps),
        (has("ssl-enum-ciphers"), fixture("nmap-open-no-script.txt"))]))
    session, auth = isc.measure_starttls(probe(11000, 110), None, WHEN)
    assert session.verdict == "weak"
    assert "plaintext:pop3" in session.flags
    assert "NO ENCRYPTION AVAILABLE" in session.notes
    assert "no STARTTLS at all" in auth.notes


def test_http_port_answered_in_clear_is_cleartext(monkeypatch):
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("http-title"), fixture("nmap-open-no-script.txt")),
        (has("curl"), fixture("curl-plain-http.txt"))]))
    a = isc.measure_http(probe(18080, 8080), None, WHEN)
    assert a.extra["plaintext_outcome"] == isc.plaintext_scan.CLEARTEXT_SERVED
    assert a.extra["http_status"].startswith("HTTP/1.0 200")


def test_http_400_is_inconclusive(monkeypatch):
    answer = fixture("curl-plain-http.txt").replace("200 OK", "400 Bad Request")
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("http-title"), fixture("nmap-open-no-script.txt")), (has("curl"), answer)]))
    a = isc.measure_http(probe(18080, 80), None, WHEN)
    assert a.extra["plaintext_outcome"] == isc.plaintext_scan.INCONCLUSIVE


def test_winrm_over_http_keeps_its_table_reading_and_records_the_schemes(monkeypatch):
    # The WinRM steps are keyed on the real port, so the stub's port line is renamed.
    open_5985 = fixture("nmap-open-no-script.txt").replace("18080/tcp", "5985/tcp")
    monkeypatch.setattr(isc, "run", FakeRun([
        (has("http-title"), open_5985),
        (has("-X", "POST"), fixture("curl-winrm-401.txt")),
        (has("curl"), fixture("curl-plain-http.txt"))]))
    a = isc.measure_http(probe(5985, 5985), None, WHEN)
    assert a.extra["plaintext_outcome"] == isc.plaintext_scan.UPGRADABLE_LISTENING
    assert a.extra["winrm_auth_offered"] == "Negotiate, Basic"
    assert a.extra["winrm_basic_offered"] is True
    assert "Basic is OFFERED over plain HTTP" in a.notes


def test_collect_writes_the_budget_and_reports_an_unread_port(monkeypatch, tmp_path):
    monkeypatch.setattr(isc.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(isc, "run", FakeRun([(has("http-title"), "Note: Host seems down.\n")]))
    lines: list[str] = []
    assets, failures = isc.collect(inside([{"host": "web-01.example.test", "port": 80}]),
                                   raw_dir=tmp_path, ref_time=WHEN, announce=lines.append)
    assert (tmp_path / "internal-budget.txt").exists()
    assert lines[0].startswith(f"[{isc.SOURCE}]")
    assert assets[0].verdict == "unknown"
    assert "web-01.example.test:80" in failures[0]
