"""takestock mailpath: the Google Workspace source (Gmail log events, usage, Postmaster Tools).

No response here was captured from Google. Each is written by hand from Google's
published references, with invented values: the Reports API ``Activity`` and
``UsageReports`` resources from its discovery document, the Gmail log fields
from the *Schema for Gmail logs in BigQuery* page, and Postmaster Tools v2's
``QueryDomainStatsResponse`` and ``DomainComplianceStatus`` from its discovery
document. Every name is under example.test, example.com or example.org, and
every address is from a documentation range. The HTTP layer is replaced, so
nothing leaves the machine.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from takestock.mailpath import google_workspace as gw


def _p(name: str, **value: Any) -> dict:
    return {"name": name, **value}


def _msg(name: str, *params: dict) -> dict:
    return {"name": name, "messageValue": {"parameter": list(params)}}


def _activity(time: str, *params: dict) -> dict:
    return {"kind": "admin#reports#activity", "id": {"time": time, "applicationName": "gmail"},
            "actor": {"email": "admin@example.test"},
            "events": [{"type": "delivery_type", "name": "delivery", "parameters": list(params)}]}


def _inbound_stage(time: str, action: int, mail_event: int = 2, conn: tuple[dict, ...] = ()) -> dict:
    """One stage of an inbound message, nested one message per level."""
    return _activity(
        time,
        _msg("event_info", _p("mail_event_type", intValue=str(mail_event)), _p("success", boolValue=True)),
        _msg("message_info",
             _p("action_type", intValue=str(action)),
             _p("rfc2822_message_id", value="<synthetic-1@example.org>"),
             _p("subject", value="Quarterly figures"),
             _p("payload_size", intValue="48213"),
             _p("num_message_attachments", intValue="1"),
             {"name": "message_set", "multiMessageValue": [
                 {"parameter": [_p("type", intValue="1")]}, {"parameter": [_p("type", intValue="9")]}]},
             _msg("source", _p("address", value="bounces+x1@mailer.example.org"),
                  _p("from_header_address", value="Someone.Else@Example.ORG")),
             {"name": "destination", "multiMessageValue": [
                 {"parameter": [_p("address", value="alice@example.test"), _p("service", value="gmail-ui")]},
                 {"parameter": [_p("address", value="bob@sub.example.test")]}]},
             _msg("connection_info", *conn)))


def _inbound_message() -> list[dict]:
    smtp = (_p("smtp_tls_state", intValue="1"), _p("smtp_tls_version", value="TLSv1.3"),
            _p("smtp_tls_cipher", value="TLS_AES_256_GCM_SHA384"),
            _p("spf_pass", boolValue=True), _p("dkim_pass", boolValue=True), _p("dmarc_pass", boolValue=True),
            _p("smtp_in_connect_ip", value="203.0.113.25"), _p("client_ip", value="198.51.100.77"),
            _p("is_internal", boolValue=False))
    return [
        _inbound_stage("2026-03-02T01:00:00.000Z", 1, conn=smtp),
        _inbound_stage("2026-03-02T01:00:01.000Z", 2),
        _inbound_stage("2026-03-02T01:00:02.000Z", 3),
        _inbound_stage("2026-03-02T02:00:00.000Z", 3, mail_event=7),   # opened: not mail flow
    ]


def _outbound_dotted() -> dict:
    """An outbound stage written with dotted names at the top level, the other plausible layout."""
    return _activity(
        "2026-03-03T05:00:00.000Z",
        _p("event_info.mail_event_type", intValue="1"),
        _p("message_info.action_type", intValue="10"),
        _p("message_info.rfc2822_message_id", value="<synthetic-2@example.test>"),
        _p("message_info.payload_size", intValue="1200"),
        _p("message_info.message_set.type", multiIntValue=["2", "8", "29"]),
        _p("message_info.source.address", value="carol@example.test"),
        _p("message_info.flattened_destinations",
           value="smtp-outbound:gmail:dave@example.com,smtp-outbound:gmail:erin@example.net"),
        _p("message_info.connection_info.smtp_tls_state", intValue="0"),
        _p("message_info.connection_info.smtp_out_connect_ip", value="198.51.100.10"),
        _p("message_info.connection_info.smtp_out_remote_host", value="mx.example.com"),
        _p("message_info.connection_info.dmarc_pass", value="example.test"),
        _p("message_info.connection_info.spf_pass", boolValue=False),
    )


def test_inbound_message_becomes_one_row_of_domains_only():
    rows, skipped = gw.normalise(_inbound_message())
    assert skipped == 1
    assert rows == [{
        "time": "2026-03-02T01:00:00.000Z", "direction": "inbound", "sender_domain": "example.org",
        "recipient_domains": ["example.test", "sub.example.test"], "size": 48213, "tls": "TLS 1.3",
        "spf": "pass", "dkim": "pass", "dmarc": "pass", "remote_host": "", "remote_ip": "203.0.113.25",
        "connector": "", "delivery": "delivered", "source": "google-gmail-log",
    }]
    text = json.dumps(rows)
    for kept_nowhere in ("@", "synthetic-1", "Quarterly", "alice", "bounces", "198.51.100.77", "admin"):
        assert kept_nowhere not in text


def test_dotted_names_outbound_cleartext_through_relay():
    rows, _ = gw.normalise([_outbound_dotted()])
    (row,) = rows
    assert row["direction"] == "outbound"
    assert row["sender_domain"] == "example.test"
    assert row["recipient_domains"] == ["example.com", "example.net"]
    assert row["tls"] == "none"
    assert (row["remote_host"], row["remote_ip"]) == ("mx.example.com", "198.51.100.10")
    assert row["spf"] == "fail" and row["dmarc"] == "" and row["dkim"] == ""   # a domain is not a verdict
    assert row["connector"] == "SMTP relay" and row["delivery"] == "sent"
    assert "@" not in json.dumps(rows)


def test_internal_and_unknown_and_bounce():
    internal = _activity("2026-03-04T00:00:00Z", _p("message_info.message_set.type", multiIntValue=["10"]),
                         _p("message_info.action_type", intValue="18"),
                         _p("message_info.connection_info.smtp_tls_state", intValue="1"))
    bare = _activity("2026-03-04T00:00:01Z", _p("event_info.mail_event_type", intValue="0"))
    rows, _ = gw.normalise([internal, bare])
    assert [(r["direction"], r["delivery"], r["tls"]) for r in rows] == [
        ("internal", "bounced", "TLS (version not recorded)"), ("unknown", "", "")]


class FakeHTTP:
    """Stands in for the HTTP layer: each answer is used once, by URL or body substring."""

    def __init__(self, answers: list[tuple[str, int, dict]]):
        self.answers = answers
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, method: str, url: str, bearer: str, body: dict | None = None,
                 timeout: int = 120) -> tuple[int, dict]:
        self.calls.append((method, url, body))
        for i, (match, status, doc) in enumerate(self.answers):
            if match in url or (body and match in json.dumps(body)):
                self.answers.pop(i)
                return status, doc
        raise AssertionError(f"unexpected request {method} {url}")


def test_gmail_log_pages_and_windows(monkeypatch):
    msgs = _inbound_message()
    fake = FakeHTTP([
        ("pageToken=p2", 200, {"items": msgs[2:]}),
        ("startTime=2026-03-01", 200, {"items": msgs[:2], "nextPageToken": "p2"}),
        ("startTime=2026-03-31", 200, {}),
    ])
    monkeypatch.setattr(gw, "_http", fake)
    rows, notes = gw.gmail_log("tok", "2026-03-01", "2026-04-15")
    starts = [u.split("startTime=")[1][:10] for _, u, _ in fake.calls]
    ends = [u.split("endTime=")[1][:10] for _, u, _ in fake.calls]
    assert starts == ["2026-03-01", "2026-03-01", "2026-03-31"]
    assert ends == ["2026-03-31", "2026-03-31", "2026-04-15"]
    assert all("applications/gmail" in u and "eventName=delivery" in u for _, u, _ in fake.calls)
    assert len(rows) == 1 and rows[0]["delivery"] == "delivered"
    assert "1 messages" in notes[-1]


def test_gmail_log_refusal_is_not_no_mail(monkeypatch):
    refusal = {"error": {"code": 403, "message": "Caller does not have access to the reporting data.",
                         "status": "PERMISSION_DENIED", "errors": [{"reason": "forbidden"}]}}
    monkeypatch.setattr(gw, "_http", FakeHTTP([("gmail", 403, refusal)]))
    rows, notes = gw.gmail_log("tok", "2026-03-01", "2026-03-02")
    assert rows == []
    assert "refusal, not an absence of mail" in notes[0] and "403" in notes[0]


def test_rate_limit_is_retried_and_daily_quota_is_not(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(gw, "_sleep", slept.append)
    busy = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED",
                      "errors": [{"reason": "rateLimitExceeded"}]}}
    fake = FakeHTTP([("x", 429, busy), ("x", 200, {"ok": 1})])
    monkeypatch.setattr(gw, "_http", fake)
    assert gw._call("GET", "https://example.test/x", "t") == {"ok": 1}
    assert slept == [2.0]
    quota = {"error": {"code": 403, "message": "Quota exceeded", "errors": [{"reason": "quotaExceeded"}]}}
    monkeypatch.setattr(gw, "_http", FakeHTTP([("x", 403, quota)]))
    with pytest.raises(gw.Refused) as exc:
        gw._call("GET", "https://example.test/x", "t")
    assert exc.value.reason == "quotaExceeded" and len(slept) == 1


def test_usage_totals_and_users_reduced_to_counts(monkeypatch):
    customer = {"kind": "admin#reports#usageReports", "usageReports": [{
        "date": "2026-03-01", "entity": {"customerId": "C00000000", "type": "CUSTOMER"},
        "parameters": [{"name": "gmail:num_emails_sent", "intValue": "120"},
                       {"name": "gmail:num_inbound_encrypted_emails", "intValue": "300"},
                       {"name": "gmail:num_inbound_unencrypted_emails", "intValue": "4"}]}]}

    def user(email: str, sent: int, received: int) -> dict:
        return {"entity": {"userEmail": email, "profileId": "000000000000000000001", "type": "USER"},
                "date": "2026-03-01",
                "parameters": [{"name": "gmail:is_gmail_enabled", "boolValue": True},
                               {"name": "gmail:num_emails_sent", "intValue": str(sent)},
                               {"name": "gmail:num_emails_received", "intValue": str(received)}]}

    fake = FakeHTTP([
        ("pageToken=u2", 200, {"usageReports": [user("bob@example.test", 0, 9)]}),
        ("usage/users/all", 200, {"usageReports": [user("alice@example.test", 5, 2)], "nextPageToken": "u2"}),
        ("usage/dates/2026-03-01", 200, customer),
    ])
    monkeypatch.setattr(gw, "_http", fake)
    out = gw.usage("tok", "2026-03-01", "2026-03-01")
    assert out["customer"]["2026-03-01"] == {"num_emails_sent": 120, "num_inbound_encrypted_emails": 300,
                                             "num_inbound_unencrypted_emails": 4}
    assert out["users"]["2026-03-01"] == {"users": 2, "gmail_enabled": 2, "senders": 1, "receivers": 2,
                                          "sent": 5, "received": 11, "spam_received": 0}
    text = json.dumps(out)
    assert "@" not in text and "profileId" not in text and "0000001" not in text


def test_usage_warning_and_refusal_are_noted(monkeypatch):
    warn = {"warnings": [{"code": "200", "message": (
        'Data for date 2026-03-02 for application "gmail" is not available right now, '
        "please try again after a few hours.")}]}
    refusal = {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Not authorized"}}
    monkeypatch.setattr(gw, "_http", FakeHTTP([
        ("usage/users/all/dates/2026-03-02", 200, {}), ("usage/dates/2026-03-02", 200, warn),
        ("dates/2026-03-03", 403, refusal)]))
    out = gw.usage("tok", "2026-03-02", "2026-03-04")
    assert any("not available right now" in n for n in out["notes"])
    assert "refused on 2026-03-03" in out["notes"][-1] and "2026-03-04" not in json.dumps(out["notes"])


def test_postmaster_stats_pages_compliance_and_refusal(monkeypatch):
    page1 = {"domainStats": [
        {"name": "domains/example.test/domainStats/a1", "metric": "spam_rate",
         "date": {"year": 2026, "month": 3, "day": 1}, "value": {"doubleValue": 0.001}},
        {"name": "domains/example.test/domainStats/a2", "metric": "tls_inbound_rate",
         "date": {"year": 2026, "month": 3, "day": 1}, "value": {"doubleValue": 1.0}}],
        "nextPageToken": "2026-03-01/tls_inbound_rate"}
    page2 = {"domainStats": [{"metric": "delivery_error_count", "date": {"year": 2026, "month": 3, "day": 2},
                              "value": {"intValue": "3"}}]}
    compliance = {"name": "domains/example.test/complianceStatus", "complianceData": {
        "domainId": "example.test",
        "rowData": [{"requirement": "SPF", "status": {"status": "COMPLIANT"}},
                    {"requirement": "ENCRYPTION", "status": {"status": "NEEDS_WORK"}}],
        "deliverabilityStatusVerdict": {"state": {"status": "COMPLIANT"}}}}
    denied = {"error": {"code": 403, "status": "PERMISSION_DENIED",
                        "message": "The caller does not have permission"}}
    fake = FakeHTTP([
        ("2026-03-01/tls_inbound_rate", 200, page2),
        ("example.test/domainStats:query", 200, page1),
        ("example.test/complianceStatus", 200, compliance),
        ("example.com/domainStats:query", 403, denied),
    ])
    monkeypatch.setattr(gw, "_http", fake)
    out = gw.postmaster("tok", ["example.test", "example.com"], "2026-03-01", "2026-03-02")
    ok = out["domains"]["example.test"]
    assert ok["days"] == {"2026-03-01": {"spam_rate": 0.001, "tls_inbound_rate": 1.0},
                          "2026-03-02": {"delivery_error_count": 3}}
    assert ok["compliance"] == {"SPF": "COMPLIANT", "ENCRYPTION": "NEEDS_WORK",
                                "deliverabilityStatusVerdict": {"status": "COMPLIANT", "reason": ""}}
    assert "PERMISSION_DENIED" in out["domains"]["example.com"]["error"]
    assert "verified in Postmaster Tools" in out["domains"]["example.com"]["error"]
    first_body = fake.calls[0][2] or {}
    assert first_body["aggregationGranularity"] == "DAILY"
    (rng,) = first_body["timeQuery"]["dateRanges"]["dateRanges"]
    assert rng["end"] == {"year": 2026, "month": 3, "day": 2}
    assert {"name": "dmarc_success_rate", "baseMetric": {"standardMetric": "AUTH_SUCCESS_RATE"},
            "filter": 'auth_type = "dmarc"'} in first_body["metricDefinitions"]
    assert "reputation" in out["notes"][0]


# The code verifier and challenge RFC 7636 Appendix B publishes as its example.
_RFC_V = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # secretscan:allow:high-entropy: RFC 7636 example
_RFC_C = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # secretscan:allow:high-entropy: RFC 7636 example


def test_pkce_matches_rfc7636_appendix_b():
    verifier, challenge = gw.pkce_pair(_RFC_V)
    assert challenge == _RFC_C
    v2, c2 = gw.pkce_pair()
    assert 43 <= len(v2) <= 128 and gw.pkce_pair(v2)[1] == c2


def test_consent_url_asks_read_only_scopes_on_loopback():
    url = gw.consent_url("client-id.example.test", "http://127.0.0.1:8765", "CHAL", "STATE")
    q = gw.urllib.parse.parse_qs(gw.urllib.parse.urlsplit(url).query)
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert q["redirect_uri"] == ["http://127.0.0.1:8765"] and q["code_challenge_method"] == ["S256"]
    scopes = q["scope"][0].split()
    assert scopes and all(s.endswith(".readonly") for s in scopes)


def test_parse_redirect_checks_state():
    assert gw.parse_redirect("/?state=S1&code=C1&scope=x", "S1") == "C1"
    with pytest.raises(gw.FetchError):
        gw.parse_redirect("/?state=other&code=C1", "S1")
    with pytest.raises(gw.FetchError, match="access_denied"):
        gw.parse_redirect("/?error=access_denied&state=S1", "S1")


def test_client_forms(monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    installed = json.dumps({"installed": {"client_id": "client-id.example.test",
                                          "client_secret": "s1"}})
    assert gw._parse_client(installed) == gw.Client("client-id.example.test", "s1")
    assert gw._parse_client("client-id.example.test:s2").client_secret == "s2"
    monkeypatch.setattr(gw, "keychain_secret", lambda item: "")
    with pytest.raises(gw.FetchError):
        gw.client("absent-item")


class FakeRun:
    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout, self.returncode = stdout, returncode
        self.seen: list[tuple[list[str], str]] = []

    def __call__(self, args: list[str], input: str = "", **kw: Any) -> subprocess.CompletedProcess:
        self.seen.append((args, input))
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


def test_secrets_travel_on_stdin_never_argv(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "client-id.example.test")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "client-secret-value")
    monkeypatch.setenv("GOOGLE_OAUTH_REFRESH_TOKEN", "refresh-token-value")
    run = FakeRun(stdout='{"access_token": "access-token-value", "expires_in": 3599}\n200')
    monkeypatch.setattr(gw.subprocess, "run", run)
    assert gw.access_token() == "access-token-value"
    args, stdin = run.seen[0]
    assert "refresh-token-value" in stdin and "client-secret-value" in stdin
    assert not any("refresh-token-value" in a or "client-secret-value" in a for a in args)

    run2 = FakeRun(stdout='{"items": []}\n200')
    monkeypatch.setattr(gw.subprocess, "run", run2)
    assert gw._http("GET", "https://admin.googleapis.com/x", "access-token-value") == (200, {"items": []})
    args, stdin = run2.seen[0]
    assert "Bearer access-token-value" in stdin and not any("access-token-value" in a for a in args)

    run3 = FakeRun()
    monkeypatch.setattr(gw.subprocess, "run", run3)
    gw.store_secret("example-item", "refresh-token-value")
    args, stdin = run3.seen[0]
    assert args[:2] == ["security", "add-generic-password"] and args[-1] == "-w"
    assert stdin == "refresh-token-value\nrefresh-token-value\n"
    assert not any("refresh-token-value" in a for a in args)


def test_token_endpoint_refusal_names_no_secret(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "client-id.example.test")
    monkeypatch.setenv("GOOGLE_OAUTH_REFRESH_TOKEN", "refresh-token-value")
    monkeypatch.setattr(gw.subprocess, "run", FakeRun(
        stdout='{"error": "invalid_grant", "error_description": "Token has been expired or revoked."}\n400'))
    with pytest.raises(gw.FetchError) as exc:
        gw.access_token()
    assert "invalid_grant" in str(exc.value) and "refresh-token-value" not in str(exc.value)
