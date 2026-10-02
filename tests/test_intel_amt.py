"""Intel AMT: is the firmware interface answering, and how is it graded?"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import AUTH, FakeRun, fixture, has, never_run, target

from takestock.collectors import intel_amt as amt
from takestock.collectors import tls_scan
from takestock.tls_session import OFFERED, REFUSED, TlsSession

WHEN = datetime(2030, 1, 15, tzinfo=UTC)
HOST = "desk-01.example.test"


def amt_target(entries: list, authorised: bool = True) -> dict:
    extra = {amt.TARGET_KEY: dict(AUTH)} if authorised else {}
    return target(extra_auth=extra, **{amt.TARGET_KEY: entries})


def row(name: str, port: str = "16992", table: dict | None = None):
    return amt.asset_for(HOST, port, fixture(name), table or {}, WHEN)


# ── parsing and classification ──

def test_the_amt_server_header_is_recognised():
    ans = amt.parse_curl(fixture("curl-amt-answered.txt"))
    assert (ans.status, ans.exit_code, ans.connected) == (303, 0, "127.0.0.1")
    assert ans.headers["location"] == "/logon.htm"
    assert amt.classify(ans, "16992")[0] == amt.AMT_ANSWERED


@pytest.mark.parametrize("server", [
    "Intel(R) Active Management Technology 12.0.0", "Intel(R) Standard Manageability 9.1.0",
    "AMT"])
def test_every_server_string_nmap_lists_matches(server):
    assert amt.AMT_SERVER.match(server)


@pytest.mark.parametrize("server", ["ExampleHTTP/1.0", "AMT-lookalike", ""])
def test_other_server_strings_do_not(server):
    assert not amt.AMT_SERVER.match(server)


@pytest.mark.parametrize(("name", "outcome", "finding"), [
    ("curl-amt-answered.txt", amt.AMT_ANSWERED, amt.CONFIRMED),
    ("curl-amt-other-server.txt", amt.OTHER_HTTP, amt.NOT_CONFIRMED),
    ("curl-amt-refused.txt", amt.NO_CONNECTION, amt.NOT_CONFIRMED),
    ("curl-amt-no-http.txt", amt.NO_HTTP_ANSWER, amt.NOT_CONFIRMED),
])
def test_each_captured_answer_has_its_outcome(name, outcome, finding):
    a = row(name)
    assert a.extra["amt_outcome"] == outcome
    assert a.extra["amt_listener_finding"] == finding


def test_a_timeout_is_unmeasured():
    ans = amt.parse_curl(f"curl: (28) Connection timed out\n\n{amt.PROBE_MARKER} exit=28 connected=\n")
    outcome, evidence = amt.classify(ans, "16992")
    assert outcome == amt.NO_ANSWER
    assert amt.listener_finding(outcome) == amt.UNMEASURED
    assert "NOT measured" in evidence


# ── grading ──

def test_amt_in_clear_is_graded_by_the_port_table(port_table):
    a = row("curl-amt-answered.txt", table=port_table)
    assert a.protocol == "intel-amt-http"
    assert a.verdict == "weak"
    assert any(f.startswith("plaintext:") for f in a.flags)
    assert a.internet_facing is False and a.source_class == "private"


def test_amt_over_tls_leaves_the_strength_to_the_tls_row(port_table):
    a = row("curl-amt-answered.txt", port="16993", table=port_table)
    assert a.verdict == "unknown"
    assert a.extra["amt_outcome"] == amt.AMT_ANSWERED


def test_something_else_answering_is_not_graded(port_table):
    a = row("curl-amt-other-server.txt", table=port_table)
    assert a.verdict == "unknown"
    assert a.protocol == "http"


def test_the_tls_row_reads_the_enumeration(policy):
    probed = {"TLSv1.2": TlsSession(OFFERED, "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", True),
              "TLSv1.3": TlsSession(REFUSED)}
    a = amt.tls_asset(HOST, fixture("nmap-ssl-enum-ciphers.txt"), probed, WHEN)
    assert a.protocol_versions == ["TLSv1.2"]
    assert a.extra["nmap_grade"] == "C"
    policy.apply(a)
    assert a.verdict == "weak"


def test_a_tls_row_with_no_handshake_is_unmeasured():
    probed = {v: TlsSession(REFUSED) for v in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")}
    a = amt.tls_asset(HOST, fixture("nmap-open-no-script.txt"), probed, WHEN)
    assert a.verdict == "unknown"
    assert "not measured" in a.notes


# ── the plan and the run ──

def test_an_undeclared_group_is_inert(monkeypatch):
    monkeypatch.setattr(amt, "run", never_run)
    assert amt.collect(target()) == ([], [])


def test_a_declared_group_without_its_record_is_refused(monkeypatch):
    monkeypatch.setattr(amt, "run", never_run)
    assets, failures = amt.collect(amt_target([HOST], authorised=False))
    assert assets == []
    assert "REFUSED, nothing contacted" in failures[0]


def test_a_subnet_is_refused(monkeypatch):
    monkeypatch.setattr(amt, "run", never_run)
    _, failures = amt.collect(amt_target(["198.51.100.0/24"]))
    assert "not one named host" in failures[0]


def test_a_port_outside_the_fixed_pair_cannot_be_built():
    with pytest.raises(amt.inside_scope.InsideRefused):
        amt.curl_command(HOST, "443")


def test_collect_probes_both_ports_and_measures_tls_where_reached(monkeypatch, tmp_path):
    monkeypatch.setattr(amt.shutil, "which", lambda name: f"/usr/bin/{name}")
    fake = FakeRun([
        (has("http://192.0.2.40:16992/"), fixture("curl-amt-answered.txt")),
        (has("https://192.0.2.40:16993/"), fixture("curl-amt-answered.txt")),
        (has("ssl-enum-ciphers"), fixture("nmap-ssl-enum-ciphers.txt"))])
    monkeypatch.setattr(amt, "run", fake)
    monkeypatch.setattr(tls_scan, "negotiate", lambda *_a: None)
    monkeypatch.setattr(tls_scan, "run", FakeRun([
        (has("ssl-cert"), fixture("nmap-ssl-cert.txt")),
        *[(has("s_client", flag), fixture(f"openssl-{name}.txt"))
          for flag, name in (("-tls1", "tls1"), ("-tls1_1", "tls1_1"),
                             ("-tls1_2", "tls1_2"), ("-tls1_3", "tls1_3"))]]))
    lines: list[str] = []
    assets, failures = amt.collect(amt_target([{"host": HOST, "ip": "192.0.2.40"}]),
                                   raw_dir=tmp_path, ref_time=WHEN, announce=lines.append)
    assert failures == []
    # Probed at the address, named by the host name, the address kept beside it.
    assert [a.name for a in assets] == [f"Intel AMT probe {HOST}:16992",
                                        f"Intel AMT probe {HOST}:16993",
                                        f"Intel AMT TLS {HOST}:16993"]
    assert {(a.host, a.ip) for a in assets} == {(HOST, "192.0.2.40")}
    assert "-k" in fake.calls[1]
    assert (tmp_path / "intel-amt-budget.txt").exists()
    assert any("never" in ln for ln in lines)


def test_no_tls_measurement_where_nothing_was_reached(monkeypatch):
    monkeypatch.setattr(amt.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(amt, "run", FakeRun([(has("curl"), fixture("curl-amt-refused.txt"))]))
    monkeypatch.setattr(tls_scan, "run", never_run)
    assets, _ = amt.collect(amt_target([HOST]), announce=lambda _l: None)
    assert len(assets) == 2


def test_without_curl_nothing_runs(monkeypatch):
    monkeypatch.setattr(amt.shutil, "which", lambda name: None)
    monkeypatch.setattr(amt, "run", never_run)
    assets, failures = amt.collect(amt_target([HOST]), announce=lambda _l: None)
    assert assets == []
    assert "curl is not on PATH" in failures[0]
