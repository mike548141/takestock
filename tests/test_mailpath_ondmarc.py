"""Red Sift OnDMARC connector.

Every response here is invented, written from the field names and shapes in
the vendor's published OpenAPI specification (https://docs.redsift.com/ondmarc.yaml),
with reserved names and documentation addresses. Nothing is called live: the
HTTP call (``ondmarc._get``) is replaced.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest

from takestock.mailpath import dmarc, ondmarc, systems


def _source_row(source_id="exampleesp", name="Example ESP", cls="valid", total=100, passed=90,
                spf=80, dkim=85):
    return {"source_id": source_id, "display_name": name, "known_source": source_id,
            "known_source_display_name": name, "source_type": "knownSource",
            "business_type": "transactional", "distinct_ip_count": 2, "ip_info": None,
            "classification": {"value": cls, "recommendation": {
                "value": "forwarder", "reasons": [],
                "details": {"classification": "forwarder", "subCategory": "classic", "confidence": "low"}}},
            "classification_value": cls, "email_count": total, "delivery_rate": 0.9,
            "spf_pass_rate": 0.8, "dkim_pass_rate": 0.85, "dmarc_fail_count": total - passed,
            "reputation_trusted": True, "blocklist_count": 0,
            "reputation": {"is_trusted": True, "suspicious_ip_count": 0, "ip_blocklist": []},
            "email_metrics": {"total_count": total, "subdomain_emails_total_count": 0,
                              "dmarc_pass_count": passed,
                              "dmarc_fail_override_to_passing_disposition_count": 3,
                              "dkim_and_spf_pass_count": 75, "dkim_pass_count": dkim,
                              "dkim_only_pass_count": dkim - 75, "spf_pass_count": spf,
                              "spf_only_pass_count": spf - 75}}


def _analyst_row(ip="192.0.2.10", volume=40, spf="pass", dkim="pass", source="exampleesp",
                 name="Example ESP", cls="valid", blocklisted=False):
    passed = volume if "pass" in (spf, dkim) else 0
    return {"report_id": "00000000-0000-4000-8000-000000000001", "receiver": "receiver.example.org",
            "receiver_email": "reports@receiver.example.org", "report_generator": None,
            "source": source, "source_display_name": name, "source_ip": ip,
            "source_asn": "Example Networks", "source_country": "ZZ", "has_blocklist": blocklisted,
            "email_volume": volume, "disposition": "none", "dkim_result": dkim, "spf_result": spf,
            "dmarc_result": "pass" if passed else "fail", "pass_volume": passed,
            "fail_volume": volume - passed,
            "spf_pass_volume": volume if spf == "pass" else 0,
            "dkim_pass_volume": volume if dkim == "pass" else 0,
            "source_hostname": "out1.mail.example.net.", "ondmarc_domain": "example.test",
            "date": "2026-01-05", "envelope_from": "Bounce.Example.Test", "header_from": "News.Example.Test",
            "policy_domain": "example.test", "policy_p": "reject",
            "classification": cls, "recommendation": None}


def _ip_row(ip="198.51.100.7", total=50, both=20, dkim_only=10, spf_only=5):
    return {"ip": ip, "country": "ZZ", "autonomous_system_org": "Example Networks",
            "autonomous_system_number": "64500",
            "reputation": {"is_trusted": False, "ip_blocklist": []},
            "email_metrics": {"total_count": total, "subdomain_emails_total_count": 0,
                              "dmarc_pass_count": both + dkim_only + spf_only,
                              "dmarc_fail_override_to_passing_disposition_count": 0,
                              "dkim_and_spf_pass_count": both, "dkim_pass_count": both + dkim_only,
                              "dkim_only_pass_count": dkim_only, "spf_pass_count": both + spf_only,
                              "spf_only_pass_count": spf_only}}


class FakeApi:
    """Answers by path; each value is a list of (status, body) answered in turn."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, api_key, timeout=120):
        parsed = urlparse(url)
        path = parsed.path.split("/api/ondmarc/v2", 1)[1]
        self.calls.append((path, {k: v[0] for k, v in parse_qs(parsed.query).items()}))
        assert api_key == "k"
        status, body = self.answers[path].pop(0)
        return status, body, {}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(ondmarc, "_sleep", lambda s: None)


def test_fetch_pages_sources_and_analyst_rows_and_maps_them(monkeypatch):
    api = FakeApi({
        "/reports/aggregate/sources": [
            (200, {"data": [_source_row()], "totals": {"total_count": 130},
                   "pagination": {"page_size": 1, "page": 0, "page_count": 2, "count": 2}}),
            (200, {"data": [_source_row("203.0.113.9", "203.0.113.9", "invalid", 30, 0, 0, 75)],
                   "totals": {"total_count": 130},
                   "pagination": {"page_size": 1, "page": 1, "page_count": 2, "count": 2}})],
        "/reports/aggregate/analyst": [
            (200, {"mode": "flat", "rowCount": 3, "data": [_analyst_row(), _analyst_row("192.0.2.11", 60)],
                   "aggregateRow": {"email_volume": 130}}),
            (200, {"mode": "flat", "rowCount": 3,
                   "data": [_analyst_row("203.0.113.9", 30, "fail", "fail", "203.0.113.9", "203.0.113.9",
                                         "invalid", True)]})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, notes = ondmarc.fetch("k", ["Example.Test"], "eu", "2026-01-01", "2026-01-31", page_size=2)

    paths = [c[0] for c in api.calls]
    assert paths == ["/reports/aggregate/sources"] * 2 + ["/reports/aggregate/analyst"] * 2
    first = api.calls[2][1]
    assert first["domain"] == "example.test" and first["from_date"] == "2026-01-01"
    assert json.loads(first["pagination_model"]) == {"page": 0, "pageSize": 2}
    assert json.loads(api.calls[3][1]["pagination_model"])["page"] == 1
    assert not ondmarc.refusals(raw)
    assert any("3 analyst rows" in n for n in notes)

    recs = ondmarc.to_records(raw)
    assert sum(r.count for r in recs) == 130
    r0 = recs[0]
    assert (r0.header_from, r0.source_ip, r0.spf, r0.dkim, r0.reporter) == (
        "news.example.test", "192.0.2.10", "pass", "pass", "receiver.example.org")
    assert (r0.source_ptr, r0.source_org, r0.envelope_from, r0.begin, r0.policy) == (
        "out1.mail.example.net", "Example Networks", "bounce.example.test", "2026-01-05", "reject")
    assert not recs[2].passed

    summary = ondmarc.sources_summary(raw)
    assert [s["source"] for s in summary] == ["Example ESP", "203.0.113.9"]
    esp = summary[0]
    assert esp["basis"] == "sources" and esp["classification"] == "valid"
    assert esp["recommendation"] == "forwarder" and esp["recommendation_detail"] == "classic/low"
    assert (esp["messages"], esp["dmarc_pass"], esp["dmarc_fail"]) == (100, 90, 10)
    assert summary[1]["classification"] == "invalid"


def test_records_feed_the_common_grouping(monkeypatch):
    api = FakeApi({
        "/reports/aggregate/sources": [(200, {"data": [], "pagination": {"page_size": 0, "page": 0,
                                                                          "page_count": 1, "count": 0}})],
        "/reports/aggregate/analyst": [(200, {"mode": "flat", "rowCount": 1, "data": [_analyst_row()]})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, _ = ondmarc.fetch("k", ["example.test"], "uk", "2026-01-01", "2026-01-31")
    srcs = dmarc.sources(ondmarc.to_records(raw), systems.Catalogue([]))
    assert srcs[0].messages == 40 and srcs[0].dmarc_pass == 40


def test_analyst_refused_falls_back_to_per_address_totals(monkeypatch):
    api = FakeApi({
        "/reports/aggregate/sources": [(403, {"message": "Forbidden"})],
        "/reports/aggregate/analyst": [(402, {"message": "DMARC Analyst is not enabled", "errorId": "e1"})],
        "/reports/aggregate/ips": [
            (200, {"data": [_ip_row()],
                   "pagination": {"page_size": 1, "page": 0, "page_count": 2, "count": 2}}),
            (200, {"data": [_ip_row("198.51.100.8", 5, 0, 0, 0)],
                   "pagination": {"page_size": 1, "page": 1, "page_count": 2, "count": 2}})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, notes = ondmarc.fetch("k", ["example.test"], "us", "2026-01-01", "2026-01-31")

    refused = ondmarc.refusals(raw)
    assert {(r["endpoint"], r["status"]) for r in refused} == {
        ("/reports/aggregate/sources", 403), ("/reports/aggregate/analyst", 402)}
    assert any(n.startswith("REFUSED example.test /reports/aggregate/analyst: 402") for n in notes)
    assert any("falling back" in n for n in notes)

    recs = ondmarc.to_records(raw)
    assert sum(r.count for r in recs) == 55
    split = {(r.spf, r.dkim): r.count for r in recs if r.source_ip == "198.51.100.7"}
    assert split == {("pass", "pass"): 20, ("fail", "pass"): 10, ("pass", "fail"): 5, ("fail", "fail"): 15}
    assert all(r.disposition == "unknown" and r.header_from == "example.test" and r.reporter == ""
               and r.begin == "2026-01-01" and r.end == "2026-01-31" for r in recs)
    # No sources rows and no analyst rows: OnDMARC's own naming is unavailable, and says so by absence.
    assert ondmarc.sources_summary(raw) == []


def test_summary_falls_back_to_analyst_rows_when_sources_refused(monkeypatch):
    api = FakeApi({
        "/reports/aggregate/sources": [(422, {"errors": [{"source": {"parameter": ["domain"]},
                                                          "title": "Invalid", "detail": "unknown domain",
                                                          "status": "422"}]})],
        "/reports/aggregate/analyst": [(200, {"mode": "flat", "rowCount": 2, "data": [
            _analyst_row(), _analyst_row("192.0.2.11", 10, "fail", "fail", blocklisted=True)]})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, notes = ondmarc.fetch("k", ["example.test"], "uk", "2026-01-01", "2026-01-31")
    assert any("422 unknown domain" in n for n in notes)
    (s,) = ondmarc.sources_summary(raw)
    assert s["basis"] == "records" and s["messages"] == 50 and s["dmarc_pass"] == 40
    assert s["addresses"] == 2 and s["blocklisted_addresses"] == 1 and s["blocklist_count"] is None


def test_rate_limit_is_retried_then_reported(monkeypatch):
    waits = []
    monkeypatch.setattr(ondmarc, "_sleep", waits.append)
    api = FakeApi({
        "/reports/aggregate/sources": [(429, {"message": "slow down"})] * 4,
        "/reports/aggregate/analyst": [(500, {"message": "oops"}),
                                       (200, {"mode": "flat", "rowCount": 0, "data": []})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, notes = ondmarc.fetch("k", ["example.test"], "uk", "2026-01-01", "2026-01-31")
    assert len(waits) == 4
    assert [r["status"] for r in ondmarc.refusals(raw)] == [429]
    assert any("0 analyst rows" in n for n in notes)


def test_rejected_key_stops_the_fetch(monkeypatch):
    monkeypatch.setattr(ondmarc, "_get", FakeApi({"/reports/aggregate/sources": [(401, {"message": "bad"})]}))
    with pytest.raises(ondmarc.FetchError, match="401"):
        ondmarc.fetch("k", ["example.test"], "uk", "2026-01-01", "2026-01-31")


def test_domains_default_to_the_account_list(monkeypatch):
    api = FakeApi({
        "/domains/flat": [(200, {"data": ["Example.Test"], "pagination": {"page_size": 1000, "page": 0,
                                                                          "page_count": 1, "count": 1}})],
        "/reports/aggregate/sources": [(200, {"data": [], "pagination": {"page_count": 1}})],
        "/reports/aggregate/ips": [(200, {"data": [], "pagination": {"page_count": 1}})],
    })
    monkeypatch.setattr(ondmarc, "_get", api)
    raw, notes = ondmarc.fetch("k", [], "uk", "2026-01-01", "2026-01-31", analyst=False)
    assert api.calls[1][1]["domain"] == "example.test" and raw == []
    assert "1 domain(s)" in notes[0]


def test_bad_region_and_date_are_refused_before_any_call():
    with pytest.raises(ondmarc.FetchError, match="region"):
        ondmarc.fetch("k", ["example.test"], "mars", "2026-01-01", "2026-01-31")
    with pytest.raises(ondmarc.FetchError, match="YYYY-MM-DD"):
        ondmarc.fetch("k", ["example.test"], "uk", "January", "2026-01-31")


def test_token_is_required(monkeypatch):
    monkeypatch.delenv("ONDMARC_API_KEY", raising=False)
    with pytest.raises(ondmarc.FetchError):
        ondmarc.token()
    monkeypatch.setenv("ONDMARC_API_KEY", "k")
    assert ondmarc.token() == "k"


def test_key_goes_on_stdin_never_argv(monkeypatch):
    seen = {}

    class Done:
        stdout = 'HTTP/2 200\r\ncontent-type: application/json\r\n\r\n{"data": []}'
        stderr = ""

    def fake_run(cmd, input, **kw):
        seen["cmd"], seen["input"] = cmd, input
        return Done()
    monkeypatch.setattr(ondmarc.subprocess, "run", fake_run)
    status, doc, _ = ondmarc._get("https://rpc.redsift.cloud/api/ondmarc/v2/domains/flat", "secret")
    assert status == 200 and doc == {"data": []}
    assert "secret" not in " ".join(seen["cmd"]) and "Authorization: Api-Key secret" in seen["input"]


def test_main_writes_an_archive_that_loads_back(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ONDMARC_API_KEY", "k")
    monkeypatch.setattr(ondmarc, "_get", FakeApi({
        "/reports/aggregate/sources": [(200, {"data": [_source_row()], "pagination": {"page_count": 1}})],
        "/reports/aggregate/analyst": [(402, {"message": "not enabled"})],
        "/reports/aggregate/ips": [(200, {"data": [_ip_row()], "pagination": {"page_count": 1}})],
    }))
    out = tmp_path / "ondmarc.json"
    code = ondmarc.main(["--domain", "example.test", "--since", "2026-01-01", "--until", "2026-01-31",
                         "--out", str(out)])
    assert code == 3                      # something was refused: never a silent success
    raw, notes = ondmarc.load_archive(out)
    assert ondmarc.is_archive(json.loads(out.read_text()))
    assert sum(r.count for r in ondmarc.to_records(raw)) == 50
    assert any("REFUSED" in n for n in notes)
    assert "50 messages" in capsys.readouterr().out
