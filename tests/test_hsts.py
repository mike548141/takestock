"""HSTS on the authorised HTTPS endpoints, and the HTTP/3 advertisements beside it."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import FakeRun, fixture, has, never_run, target

from takestock import coverage
from takestock.collectors import hsts
from takestock.model import is_informational_flag

HOST = "www.example.test"
WHEN = datetime(2030, 1, 31, tzinfo=UTC)

# dig answers composed in dig's documented format with reserved names.
DIG_NONE = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra;\n"
DIG_H3 = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\n;; flags: qr rd ra;\n"
          ";; ANSWER SECTION:\n"
          f'{HOST}.\t300\tIN\tHTTPS\t1 . alpn="h3,h2"\n')
DIG_TIMEOUT = ";; connection timed out; no servers could be reached\n"


def header_dump(*headers: str, status: str = "HTTP/2 200") -> str:
    return "\r\n".join([status, *headers, "", ""]) + f"\n{hsts.CONNECTED_MARKER} 192.0.2.80\n"


@pytest.fixture()
def dns(monkeypatch):
    """Every DNS HTTPS lookup answers 'none published' unless a test says otherwise."""
    answers = {"text": DIG_NONE}
    monkeypatch.setattr(hsts.digresponse, "query", lambda *a, **k: answers["text"])
    return answers


@pytest.fixture()
def curl_present(monkeypatch):
    monkeypatch.setattr(hsts.shutil, "which", lambda name: f"/usr/bin/{name}")


# ── the header ──

@pytest.mark.parametrize(("header", "expect"), [
    ("max-age=31536000; includeSubDomains; preload", (31536000, True, True, False)),
    ("max-age=\"600\"", (600, False, False, False)),
    ("MAX-AGE=0", (0, False, False, False)),
    ("includeSubDomains", (None, True, False, True)),
    ("max-age=600; max-age=700", (700, False, False, True)),
    ("max-age=abc", (None, False, False, True)),
])
def test_the_policy_is_parsed_per_rfc_6797(header, expect):
    assert hsts.parse_policy(header) == expect


def test_the_captured_response_is_read():
    dump, address = hsts.split_connected_address(fixture("curl-hsts.txt"))
    assert address == "127.0.0.1"
    p = hsts.parse_response(dump)
    assert p is not None
    assert (p.outcome, p.max_age, p.include_subdomains, p.preload) == (
        hsts.ENFORCED, 31536000, True, False)
    assert hsts.alt_svc_protocols(p.alt_svc) == ["h3"]
    assert p.http_version == "HTTP/1.0"


def test_no_http_response_is_unreadable():
    dump, _ = hsts.split_connected_address(fixture("curl-refused.txt"))
    assert hsts.parse_response(dump) is None


def test_only_the_last_response_counts():
    dump = header_dump("Strict-Transport-Security: max-age=600", status="HTTP/1.1 100 Continue")
    dump += header_dump(status="HTTP/1.1 200 OK")
    assert hsts.parse_response(dump).outcome == hsts.ABSENT


@pytest.mark.parametrize(("header", "verdict", "flag"), [
    (None, "weak", hsts.ABSENT_FLAG),
    ("max-age=abc", "weak", hsts.MALFORMED_FLAG),
    ("max-age=0", "weak", hsts.ZERO_FLAG),
    ("max-age=600", "acceptable", f"{hsts.SHORT_FLAG}600"),
    ("max-age=63072000; preload", "acceptable", hsts.PRELOAD_FLAG),
])
def test_each_outcome_grades(monkeypatch, dns, curl_present, header, verdict, flag):
    headers = [f"Strict-Transport-Security: {header}"] if header else []
    monkeypatch.setattr(hsts, "run", FakeRun([(has("curl"), header_dump(*headers))]))
    [a], failures = hsts.collect(target(tls_443=[HOST]), ref_time=WHEN)
    assert failures == []
    assert a.verdict == verdict
    assert flag in a.flags
    assert a.protocol == "hsts" and a.port == "443"


def test_an_endpoint_with_no_answer_is_unknown_and_a_gap(monkeypatch, dns, curl_present):
    monkeypatch.setattr(hsts, "run", FakeRun([(has("curl"), fixture("curl-refused.txt"))]))
    t = target(tls_443=[HOST, "app.example.test"])
    assets, failures = hsts.collect(t, ref_time=WHEN)
    assert {a.verdict for a in assets} == {"unknown"}
    assert is_informational_flag(hsts.UNREADABLE_FLAG)
    assert "says NOTHING about HSTS coverage" in failures[-1]   # none answered at all
    [gap] = [g for g in hsts.coverage_gaps(t, assets) if g.startswith("HSTS")]
    assert gap.kind == coverage.COULD_NOT_TEST
    assert HOST in gap


def test_credentials_and_trace_ids_never_reach_the_raw_capture(monkeypatch, dns, curl_present,
                                                               tmp_path):
    monkeypatch.setattr(hsts, "run", FakeRun([(has("curl"), fixture("curl-hsts.txt"))]))
    hsts.collect(target(tls_443=[HOST]), raw_dir=tmp_path)
    kept = (tmp_path / f"hsts-{HOST}.txt").read_text()
    assert "abc123" not in kept
    assert "00000000-0000-4000-8000-000000000001" not in kept
    assert "Strict-Transport-Security: max-age=31536000" in kept


# ── third-party endpoints read several times ──

def test_a_third_party_name_is_read_several_times_and_the_weakest_stated(monkeypatch, dns,
                                                                         curl_present):
    reads = iter([header_dump("Strict-Transport-Security: max-age=31536000; preload"),
                  header_dump("Strict-Transport-Security: max-age=600"),
                  header_dump("Strict-Transport-Security: max-age=31536000; preload")])
    monkeypatch.setattr(hsts, "run", lambda cmd, timeout=60: next(reads))
    monkeypatch.setattr(hsts, "_pause", lambda _s: None)
    t = target(saas_443=[{"host": "app.example.com", "vendor": "Example Hosting"}])
    [a], _ = hsts.collect(t, ref_time=WHEN)
    assert a.extra["header_reads"] == 3
    assert a.extra["header_reads_agree"] is False
    assert f"{hsts.SHORT_FLAG}600" in a.flags
    assert hsts.PRELOAD_FLAG not in a.flags          # not every read carried it
    assert hsts.DIFFERS_FLAG in a.flags
    assert "read 3 times" in a.notes


def test_the_read_count_can_be_set_and_a_bad_value_is_reported(monkeypatch):
    monkeypatch.setenv(hsts.THIRD_PARTY_READS_ENV, "5")
    assert hsts.third_party_reads() == (5, "")
    monkeypatch.setenv(hsts.THIRD_PARTY_READS_ENV, "lots")
    n, problem = hsts.third_party_reads()
    assert n == hsts.THIRD_PARTY_READS and "lots" in problem


def test_own_hosts_are_not_third_party():
    t = target(tls_443=[HOST], saas_443=[{"host": HOST}, {"host": "app.example.com"}])
    assert hsts.third_party_hosts(t) == {"app.example.com"}
    assert hsts.scan_hosts(t) == [HOST, "app.example.com"]


# ── HTTP/3 advertisements ──

def test_an_alt_svc_header_advertising_h3_is_read():
    assert hsts.alt_svc_protocols(['h3=":443"; ma=86400, h3-29=":443"', 'h2="alt.example.test:443"']) \
        == ["h2", "h3", "h3-29"]
    assert hsts.is_h3("h3-29") and not hsts.is_h3("h2")


def test_a_dns_https_record_advertising_h3_is_read(monkeypatch):
    monkeypatch.setattr(hsts.digresponse, "query", lambda *a, **k: DIG_H3)
    got = hsts.read_https_record(HOST, ("192.0.2.53", "198.51.100.53"))
    assert got["dns_https_outcome"] == hsts.DNS_PUBLISHED
    assert got["dns_https_alpn"] == ["h2", "h3"]
    assert got["dns_https_advertises_h3"] is True


def test_resolvers_that_disagree_settle_nothing(monkeypatch):
    replies = iter([DIG_H3, DIG_NONE])
    monkeypatch.setattr(hsts.digresponse, "query", lambda *a, **k: next(replies))
    got = hsts.read_https_record(HOST, ("192.0.2.53", "198.51.100.53"))
    assert got["dns_https_outcome"] == hsts.DNS_DISAGREE
    assert got["dns_https_advertises_h3"] is None


def test_one_answering_resolver_out_of_two_cannot_say_none_is_published(monkeypatch):
    replies = iter([DIG_NONE, DIG_TIMEOUT])
    monkeypatch.setattr(hsts.digresponse, "query", lambda *a, **k: next(replies))
    got = hsts.read_https_record(HOST, ("192.0.2.53", "198.51.100.53"))
    assert got["dns_https_outcome"] == hsts.DNS_FAILED
    assert "198.51.100.53" in got["dns_https_detail"]


def test_the_system_resolver_alone_can_say_none_is_published(monkeypatch):
    monkeypatch.setattr(hsts.digresponse, "query", lambda *a, **k: DIG_NONE)
    got = hsts.read_https_record(HOST)
    assert got["dns_https_outcome"] == hsts.DNS_NONE
    assert got["dns_https_resolvers"] == ["system resolver"]


def test_the_profile_may_name_its_resolvers():
    assert hsts.resolvers_for({"dns_resolvers": ["192.0.2.53"]}) == ("192.0.2.53",)
    assert hsts.resolvers_for({}) == ("",)


def test_a_generic_form_record_is_decoded():
    # priority 1, target ".", alpn "h3": RFC 9460 wire form written as RFC 3597 hex.
    rdata = "\\# 10 0001 00 0001 0003 026833"
    assert hsts.parse_https_rdata(rdata) == {"priority": 1, "target": ".", "alpn": ["h3"],
                                             "no_default_alpn": False}
    assert hsts.parse_https_rdata("\\# 99 0001") is None


@pytest.mark.parametrize(("alt", "dns", "either"), [
    (True, None, True), (None, True, True), (False, False, False), (False, None, None)])
def test_http3_is_advertised_if_either_channel_says_so(alt, dns, either):
    assert hsts.http3_advertised(alt, dns) is either


# ── gating ──

def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(hsts, "run", never_run)
    assets, failures = hsts.collect(target(authorised=False, tls_443=[HOST]))
    assert assets == [] and failures[0].startswith("hsts: REFUSED, nothing contacted")


def test_missing_curl_is_a_failure(monkeypatch):
    monkeypatch.setattr(hsts, "run", never_run)
    monkeypatch.setattr(hsts.shutil, "which", lambda name: None)
    assets, failures = hsts.collect(target(tls_443=[HOST]))
    assert assets == [] and "curl is not on PATH" in failures[0]
