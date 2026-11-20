"""Platform-log rows: the shared schema, grouping into flows, Cloudflare's email datasets.

Cloudflare rows are written from the fields its GraphQL schema documents
(``emailRoutingAdaptive``, ``emailSendingAdaptive``), with invented values.
Every name is under a reserved domain and every address is from a
documentation range.
"""

from __future__ import annotations

from takestock.mailpath import cloudflare, platformlog, systems

CAT = systems.load()


def _row(**kw):
    base = {k: "" for k in platformlog.FIELDS}
    base.update(recipient_domains=[], size=None)
    base.update(kw)
    return base


def test_rows_group_into_flows_by_direction_far_system_and_connector():
    rows = [
        _row(direction="outbound", sender_domain="example.test", recipient_domains=["example.org"],
             size=1000, tls="TLS 1.3", dmarc="pass", remote_host="mx.example.org",
             delivery="delivered", source="s", time="2026-01-02T00:00:00Z"),
        _row(direction="outbound", sender_domain="example.test",
             recipient_domains=["example.org", "example.net"],
             size=500, tls="none", dmarc="pass", remote_host="mx.example.org",
             delivery="delivered", source="s", time="2026-01-03T00:00:00Z"),
        _row(direction="inbound", sender_domain="example.net", recipient_domains=["sub.example.test"],
             tls="TLS 1.2", remote_ip="198.51.100.4", source="s"),
        _row(direction="inbound", sender_domain="example.net", recipient_domains=["elsewhere.example"],
             source="s"),
    ]
    flows = {(f.direction, f.far_system): f for f in platformlog.flows(rows, {"example.test"}, CAT)}
    out = flows[("outbound", "example.org")].as_dict()
    assert (out["messages"], out["bytes"], out["counterparty_domains"]) == (2, 1500, 2)
    assert out["tls"] == {"TLS 1.3": 1, "none": 1} and out["first"].startswith("2026-01-02")
    inbound = next(f for (d, _), f in flows.items() if d == "inbound")
    assert inbound.domain == "example.test" and inbound.counterparties == {"example.net"}
    assert len(flows) == 2          # the message for nobody we own is left out


def test_the_schema_check_finds_addresses_and_stray_keys():
    assert platformlog.check([_row(sender_domain="a@example.test")])
    assert platformlog.check([{**_row(), "subject": "x"}])
    assert not platformlog.check([_row(sender_domain="example.test")])


def test_cloudflare_email_rows_keep_the_last_event_and_domains_only():
    raw = [
        {"datetime": "2026-01-02T00:00:00Z", "action": "forward", "status": "delivered",
         "from": "Person <a@example.org>", "to": "b@example.test", "spf": "pass", "dkim": "pass",
         "dmarc": "pass", "isLastEvent": 1},
        {"datetime": "2026-01-02T00:00:00Z", "action": "forward", "status": "queued",
         "from": "a@example.org", "to": "b@example.test", "isLastEvent": 0},
    ]
    rows = cloudflare.email_rows(raw, "routing")
    assert len(rows) == 1 and not platformlog.check(rows)
    assert rows[0]["sender_domain"] == "example.org" and rows[0]["recipient_domains"] == ["example.test"]
    assert rows[0]["direction"] == "inbound" and rows[0]["delivery"] == "forward"
    sent = cloudflare.email_rows([{"sendingDomain": "example.test", "status": "delivered",
                                   "to": "x@example.org,y@example.net", "isLastEvent": 1}], "sending")
    assert sent[0]["recipient_domains"] == ["example.net", "example.org"]
    assert sent[0]["direction"] == "outbound"


def test_run_reads_platform_logs_and_a_google_pull(tmp_path):
    import json
    from datetime import UTC, datetime

    from takestock.mailpath import run
    log = tmp_path / "rows.json"
    log.write_text(json.dumps([_row(direction="outbound", sender_domain="example.test",
                                    recipient_domains=["example.org"], size=10, tls="TLS 1.3",
                                    source="test-log", time="2026-01-02T00:00:00Z")]))
    g = tmp_path / "google"
    g.mkdir()
    inbound = _row(direction="inbound", source="google-gmail-log", sender_domain="example.org",
                   recipient_domains=["example.test"])
    (g / "gmail-log.json").write_text(json.dumps({"rows": [inbound], "notes": ["one note"]}))
    (g / "postmaster.json").write_text(json.dumps({"domains": {"example.test": {"days": {
        "2026-01-02": {"SPAM_RATE": 0.001, "TLS_ENCRYPTION_RATE": 1.0}}}}}))
    (g / "usage.json").write_text(json.dumps({"users": {"2026-01-02": {"sent": 5, "received": 9}}}))
    inp = run.Inputs(organisation="Example", domains=["example.test"], platform_logs=[log],
                     google_dirs=[g], out=tmp_path / "out")
    result = run.run(inp, now=datetime(2026, 1, 5, tzinfo=UTC), resolve=lambda n, t: [])
    assert result["evidence"]["platform"]["messages"] == 2
    assert {f["source"] for f in result["platform_flows"]} == {"test-log", "google-gmail-log"}
    _, page = run.write(result, tmp_path / "out")
    html = page.read_text()
    assert "What the mail platforms recorded" in html and "as Gmail sees it" in html
    assert "Daily volumes" in html
