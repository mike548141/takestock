"""Certificate transparency paging, certificates, mail-authentication rows and the sub-domain rows.

The transparency answers are synthetic issuance records with invented ids and
times; no network is used.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import dnsfake
import pytest
from dnsfake import dig_text

from takestock import coverage, ctcache, dnsevidence
from takestock.collectors import ct_dns

NOW = datetime(2030, 6, 15, tzinfo=UTC)
API = "https://ct.example.com/v1/issuances"


def issuance(ident: str, names: list[str], not_before: str, not_after: str,
             issuer: str = "Example CA") -> dict:
    return {"id": ident, "dns_names": names, "not_before": not_before, "not_after": not_after,
            "issuer": {"friendly_name": issuer, "name": f"C=ZZ, O={issuer}"},
            "pubkey": {"type": "ecdsa", "bit_length": 256, "curve": "P-256"},
            "cert_sha256": "0" * 64, "pubkey_sha256": "1" * 64}


PAGES = {
    "": [issuance("100", ["www.example.com", "*.example.com"],
                  "2030-01-01T00:00:00Z", "2030-04-01T00:00:00Z"),
         issuance("101", ["www.example.com"], "2030-04-01T00:00:00Z", "2030-06-20T00:00:00Z",
                  "Other CA")],
    "101": [issuance("102", ["api.example.com", "api.example.net"],
                     "2030-02-01T00:00:00Z", "2031-02-01T00:00:00Z")],
    "102": [],
}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(ct_dns, "token", lambda: "")
    monkeypatch.setattr(ct_dns, "CT_PAGE_PAUSE_SECONDS", 0.0)
    monkeypatch.setattr(ct_dns, "dig", lambda name, rtype="A", short=True:
                        ["192.0.2.80"] if rtype == "A" and name.startswith("www") else [])


def serve(pages: dict, statuses: dict | None = None):
    asked: list[str] = []

    def http_json(url, timeout=25, bearer="", meta=None):
        q = parse_qs(urlparse(url).query)
        after = (q.get("after") or [""])[0]
        asked.append(after)
        if statuses and after in statuses:
            meta.update(statuses[after])
            return {"code": "rate_limited"}
        if meta is not None:
            meta["status"] = 200
        return pages.get(after)
    return http_json, asked


def test_pages_are_read_to_the_end_and_kept(monkeypatch, tmp_path):
    fake, asked = serve(PAGES)
    monkeypatch.setattr(ct_dns, "http_json", fake)
    read = ct_dns._ct_names("example.com", tmp_path, API)
    assert read.ok and read.pages == 3 and read.records == 3 and asked == ["", "101", "102"]
    assert sorted(read.names) == ["api.example.com", "example.com", "www.example.com"]
    www = read.names["www.example.com"]
    assert www["issuers"] == {"Example CA", "Other CA"} and www["current"]["id"] == "101"
    raw = json.loads((tmp_path / ctcache.raw_name("example.com")).read_text())
    pages = json.loads((tmp_path / ctcache.pages_name("example.com")).read_text())
    assert len(raw) == 3 and pages["exhausted"] is True and pages["last_id"] == "102"


def test_endpoint_and_certificate_rows(monkeypatch):
    fake, _ = serve(PAGES)
    monkeypatch.setattr(ct_dns, "http_json", fake)
    read = ct_dns._ct_names("example.com", None, API)
    rows = ct_dns._endpoint_assets("example.com", read.names, "2030-06-15", NOW, lambda m: None)
    www = next(a for a in rows if a.name == "endpoint www.example.com")
    assert www.extra["ip_stack"] == "ipv4-only" and www.data_state == "discovery"
    cert = next(a for a in rows if a.name == "certificate www.example.com")
    assert cert.signatures == ["ecdsa_p256"] and cert.extra["issuer"] == "Other CA"
    assert cert.flags == ["renewal-overdue"]  # 80-day certificate, 5 days left
    api = next(a for a in rows if a.name == "endpoint api.example.com")
    assert api.extra["ip_stack"] == "unresolved"


@pytest.mark.parametrize("not_after, flag", [
    ("2030-06-01T00:00:00Z", "expired"),
    ("2030-06-25T00:00:00Z", "expiry-soon"),
    ("2031-06-25T00:00:00Z", None),
])
def test_long_lived_certificate_expiry(not_after, flag):
    a = ct_dns._cert_asset("www.example.com",
                           issuance("1", ["www.example.com"], "2029-06-01T00:00:00Z", not_after),
                           NOW)
    assert a is not None and (a.flags == [flag] if flag else a.flags == [])
    assert ct_dns._cert_asset("x.example.com", {"not_after": ""}, NOW) is None


def test_a_rate_limit_parks_the_domain_and_resume_finishes_it(monkeypatch, tmp_path):
    fake, asked = serve(PAGES, statuses={"101": {"status": 429,
                                                 "headers": {"retry-after": "30"}}})
    monkeypatch.setattr(ct_dns, "http_json", fake)
    clock = [1000.0]
    monkeypatch.setattr(ct_dns, "_now", lambda: clock[0])
    waited: list[float] = []
    monkeypatch.setattr(ct_dns, "_wait", lambda s: (waited.append(s), clock.__setitem__(0, clock[0] + s)))
    swept: list[tuple[str, bool, tuple[str, ...]]] = []
    monkeypatch.setattr(ct_dns, "_ned_sweep", lambda d, found, *a, parked=False, **k: (
        swept.append((d, parked, tuple(sorted(found)))) or []))
    monkeypatch.setattr(ct_dns, "parked_assets", lambda *a, **k: ([], []))
    deferral = ct_dns.CTDeferral()
    target = {"discovery": {"domains": ["example.com", "example.net"]},
              "dns": {"ct_search_api": API}}
    assets, failures, reused = ct_dns.collect(target, tmp_path, NOW, deferral=deferral)
    assert assets == [] and failures == [] and reused == []
    assert swept == []                  # the sweep waits for the names it reads
    assert [c.domain for c in deferral.pending] == ["example.com", "example.net"]
    assert deferral.retry_after_seconds == [30.0]

    fake2, _ = serve({**PAGES, "": PAGES[""]})
    monkeypatch.setattr(ct_dns, "http_json", fake2)
    more, more_failures = ct_dns.resume(deferral)
    assert waited == [30.0] and more_failures == []
    assert {a.host for a in more if a.data_state == "discovery"} >= {"api.example.com"}
    assert deferral.record()["outcome"] == "every deferred lookup was resumed"
    # Both domains are parked, so the names found beneath them are swept on resume.
    assert [(d, parked) for d, parked, _ in swept] == [("example.com", True),
                                                       ("example.net", True)]
    assert "api.example.com" in swept[0][2]


def test_the_page_ceiling_is_reported(monkeypatch):
    endless = {str(i): [issuance(str(i + 1), ["a.example.com"], "2030-01-01T00:00:00Z",
                                 "2031-01-01T00:00:00Z")] for i in range(1, 10)}
    endless[""] = [issuance("1", ["a.example.com"], "2030-01-01T00:00:00Z",
                            "2031-01-01T00:00:00Z")]
    fake, _ = serve(endless)
    monkeypatch.setattr(ct_dns, "http_json", fake)
    monkeypatch.setattr(ct_dns, "CT_MAX_PAGES", 3)
    read = ct_dns._ct_names("example.com", None, API)
    assert not read.ok and "3-page ceiling" in read.partial and read.names


def test_an_error_page_with_nothing_read_is_a_failure(monkeypatch):
    fake, _ = serve({"": {"code": "not_allowed"}})
    monkeypatch.setattr(ct_dns, "http_json", fake)
    read = ct_dns._ct_names("example.com", None, API)
    assert "returned error 'not_allowed'" in read.failure


def test_a_configured_endpoint_that_errors_is_a_failure_not_a_gap(monkeypatch):
    fake, _ = serve({"": {"code": "not_allowed"}})
    monkeypatch.setattr(ct_dns, "http_json", fake)
    monkeypatch.setattr(ct_dns, "parked_assets", lambda *a, **k: ([], []))
    monkeypatch.setattr(ct_dns, "_ned_sweep", lambda *a, **k: [])
    target = {"discovery": {"domains": ["example.com"]}, "dns": {"ct_search_api": API}}
    assets, failures, _ = ct_dns.collect(target, None, NOW)
    (failure,) = failures
    assert assets == [] and "returned error 'not_allowed'" in failure
    assert not isinstance(failure, coverage.Gap)


def test_no_endpoint_is_a_gap_not_a_failure(monkeypatch, tmp_path):
    from takestock import config
    config.set_workspace(tmp_path)
    monkeypatch.setattr(ct_dns, "http_json", lambda *a, **k: pytest.fail("asked"))
    monkeypatch.setattr(ct_dns, "parked_assets", lambda *a, **k: ([], []))
    monkeypatch.setattr(ct_dns, "_ned_sweep", lambda *a, **k: [])
    assets, failures, _ = ct_dns.collect({"discovery": {"domains": ["example.com"]}})
    (gap,) = failures
    assert assets == [] and isinstance(gap, coverage.Gap)
    assert gap.startswith("not measured: no certificate-transparency search endpoint")
    assert coverage.kind_of(gap) == coverage.COULD_NOT_TEST


DNS = {
    ("example.com", "MX"): ["10 mx1.example.com."],
    ("example.com", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 ~all"', '"v=spf1 -all"',
                             '"spf2.0/pra -all"', '"site-verification=abc"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"'],
    ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"'],
    ("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:t@example.com"'],
    ("s1._domainkey.example.com", "CNAME"): ["s1.dkim.example.net."],
    ("s1.dkim.example.net", "TXT"): ['"v=DKIM1; k=rsa; p=' + "A" * 216 + '"'],
    ("s2._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=' + "B" * 392 + '"'],
}


def resolving(table: dict, status: dict | None = None):
    """A stand-in for ``dnsevidence.run``: full ``dig`` transcripts answered from ``table``.

    ``status`` maps a name to the response code every resolver gives for it,
    or to ``"timeout"`` for a resolver that never replies.
    """
    def run(cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
        rtype, name = [c for c in cmd[1:] if not c.startswith(("+", "@"))][:2]
        given = (status or {}).get(name)
        if given == "timeout":
            return "__ERROR__ Command 'dig' timed out after 44 seconds"
        records = table.get((name, rtype), [])
        known = any(n == name for n, _t in table)
        answer = [f"{name}. 300 IN {rtype} {r}" for r in records]
        return dig_text(given or ("NOERROR" if known else "NXDOMAIN"), answer)
    return run


def email_rows(monkeypatch, table: dict, status: dict | None = None,
               selectors: list[str] | None = None,
               policy: tuple[str, dict] = ("__ERROR__ refused", {}),
               resolvers: tuple[str, ...] = ("",)):
    monkeypatch.setattr(ct_dns, "dig", lambda n, t="A", short=True: table.get((n, t), []))
    monkeypatch.setattr(dnsevidence, "run", resolving(table, status))
    monkeypatch.setattr(ct_dns, "http_get_full", lambda url, *a, **k: policy)
    rows, failures = ct_dns._email_assets("example.com", NOW, selectors or [], resolvers)
    return {a.protocol: a for a in rows}, rows, failures


POLICY = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n"


def test_mail_authentication_rows(monkeypatch):
    rows, every, failures = email_rows(
        monkeypatch, DNS, selectors=["s1", "s2", "s3"],
        policy=(POLICY, {"status": 200}))
    assert failures == []
    assert rows["mx"].extra["records"] == ["10 mx1.example.com."]
    assert set(rows["spf"].flags) == {"softfail-all", "duplicate-spf", "legacy-spf2"}
    assert rows["spf"].extra["present"] is True
    assert set(rows["dmarc"].flags) == {"dmarc-reject", "subdomains-unprotected"}
    assert rows["dmarc"].extra["present"] is True
    assert rows["mta-sts"].flags == ["enforce"] and rows["mta-sts"].extra["mx"] == ["mx1.example.com"]
    assert rows["tls-rpt"].notes == "reports to mailto:t@example.com"
    dkim = [a for a in every if a.protocol == "dkim"]
    assert [(a.extra["selector"], a.flags) for a in dkim] == [("s1", ["weak-key-1024"]), ("s2", [])]
    assert dkim[0].notes.endswith("via s1.dkim.example.net")


def test_an_answered_lookup_with_no_record_is_a_measured_absence(monkeypatch):
    # The domain exists and publishes other TXT records, but no SPF; _dmarc is NXDOMAIN.
    table = {("example.com", "TXT"): ['"site-verification=abc"']}
    rows, _, failures = email_rows(monkeypatch, table, resolvers=dnsfake.RESOLVERS)
    assert failures == []
    spf, dmarc = rows["spf"], rows["dmarc"]
    assert spf.extra["present"] is False and spf.flags == ["no-spf-record"]
    assert spf.extra["record"] == "" and spf.notes == "no v=spf1 record published"
    assert dmarc.extra["present"] is False and dmarc.flags == ["no-dmarc-record"]
    # The resolver evidence travels with the absence.
    lookup = dmarc.extra["lookup"]
    assert lookup["name"] == "_dmarc.example.com" and lookup["measured"] is True
    assert [r["rcode"] for r in lookup["lookups"]] == ["NXDOMAIN"] * 3
    assert [r["resolver"] for r in lookup["lookups"]] == list(dnsfake.RESOLVERS)
    assert spf.extra["lookup"]["lookups"][0]["rcode"] == "NOERROR"
    assert rows["mta-sts"].flags == ["no-mta-sts-record"]
    assert rows["mta-sts"].extra["policy_reachable"] is False
    assert rows["tls-rpt"].flags == ["no-tls-reporting"]


@pytest.mark.parametrize(("answer", "status", "valid", "flag"), [
    ((POLICY, {"status": 200}), 200, True, "enforce"),
    (("<html>not found</html>", {"status": 404}), 404, True, ct_dns.MTA_STS_INVALID),
    (("", {"status": 301}), 301, True, ct_dns.MTA_STS_INVALID),
    (("curl: (60) SSL certificate problem: certificate has expired\n", {}), None, False,
     ct_dns.MTA_STS_INVALID),
    (("curl: (6) Could not resolve host: mta-sts.example.com\n", {}), None, None, None),
    (("__ERROR__ curl not found", {}), None, None, None),
])
def test_the_policy_fetch_keeps_its_status_and_certificate_result(monkeypatch, answer,
                                                                  status, valid, flag):
    rows, _, _ = email_rows(monkeypatch, DNS, policy=answer)
    sts = rows["mta-sts"]
    assert sts.extra["policy_http_status"] == status
    assert sts.extra["policy_certificate_valid"] is valid
    assert sts.extra["policy_reachable"] is (status is not None)
    assert sts.flags == ([flag] if flag else [])
    if valid is False:
        assert sts.extra["policy_fetch_error"].startswith("curl: (60)")
    if status == 200:
        assert (sts.extra["policy_version"], sts.extra["policy_max_age"]) == ("STSv1", "604800")
    else:                       # only a 200 answer is read as a policy (RFC 8461 §3.3)
        assert sts.extra["mode"] == "" and sts.extra["mx"] == []


def test_a_lookup_that_failed_is_not_an_absence(monkeypatch):
    status = {"example.com": "SERVFAIL", "_dmarc.example.com": "timeout",
              "_mta-sts.example.com": "REFUSED", "_smtp._tls.example.com": "timeout"}
    rows, _, failures = email_rows(monkeypatch, {}, status)
    assert {"spf", "dmarc", "mta-sts", "tls-rpt"}.isdisjoint(rows)
    assert len(failures) == 1
    (line,) = failures
    assert line.startswith("ct_dns example.com:")
    for words in ("SPF (example.com: SERVFAIL)", "DMARC (_dmarc.example.com: no reply",
                  "MTA-STS (_mta-sts.example.com: REFUSED)", "TLS-RPT"):
        assert words in line, words


def test_one_resolver_failing_while_another_answers_is_not_an_absence(monkeypatch):
    table = {("example.com", "TXT"): ['"site-verification=abc"']}
    answers = resolving(table)

    def split(cmd, timeout=60, stdin_text=None):
        if "@198.51.100.53" in cmd:
            return dig_text("SERVFAIL")
        return answers(cmd, timeout, stdin_text)
    monkeypatch.setattr(ct_dns, "dig", lambda n, t="A", short=True: [])
    monkeypatch.setattr(dnsevidence, "run", split)
    monkeypatch.setattr(ct_dns, "http_get_full", lambda url, *a, **k: ("__ERROR__ refused", {}))
    rows, failures = ct_dns._email_assets("example.com", NOW, [], dnsfake.RESOLVERS)
    assert "spf" not in {a.protocol for a in rows}
    assert failures and "SERVFAIL" in failures[0]


def _sub(name: str, *, enabled: bool = False, spf: bool = True, dkim: bool = True,
         dmarc: str = "", read: bool = True, agreed: bool = True, **more) -> dict:
    return {"name": name, "email_enabled": enabled, "read": read, "exists": True,
            "agreed": agreed, "spf_conformant": spf, "dkim_conformant": dkim,
            "dmarc_record": dmarc, **more}


def test_sub_domain_rows_from_a_sweep():
    cap = {
        "resolvers": ["192.0.2.53"], "tries": 3, "captured_at": "2030-06-15T00:00:00Z",
        "control": {"name": "x", "rcode": "NXDOMAIN", "usable": True},
        "names_offered": 5, "names_dropped_by_cap": 0,
        "wildcard_spf": {"name": "*.example.com", "record": "v=spf1 -all", "rcode": "NOERROR",
                         "agreed": True},
        "wildcard_dkim": {"name": "*._domainkey.example.com", "record": "", "rcode": "NXDOMAIN",
                          "agreed": True},
        "subdomains": [
            _sub("a.example.com"),
            _sub("b.example.com", spf=False, dmarc="v=DMARC1; p=reject; sp=reject"),
            _sub("c.example.com", enabled=True, spf=False, dkim=False),
            _sub("d.example.com", read=False),
        ],
    }
    rows = {a.protocol: a for a in ct_dns.ned_rows("example.com", cap, NOW)}
    spf, dkim, dmarc = rows["ned-spf"], rows["ned-dkim"], rows["ned-dmarc"]
    assert spf.extra["names_in_scope"] == 2 and spf.extra["names_without_record"] == ["b.example.com"]
    assert spf.extra["wildcard_conformant"] and not dkim.extra["wildcard_conformant"]
    assert spf.extra["names_email_enabled"] == ["c.example.com"]
    assert spf.extra["names_unread"] == ["d.example.com"]
    assert dmarc.extra["names_with_sp_tag"] == ["b.example.com"]
    assert dmarc.extra["names_without_own_dmarc"] == ["a.example.com"]
    assert dmarc.extra["intermediate_dmarc"] == {} and dmarc.extra["intermediate_unsettled"] == []


def test_the_sweep_row_keeps_the_intermediate_dmarc_reads():
    cap = {
        "resolvers": ["192.0.2.53"], "tries": 3, "captured_at": "2030-06-15T00:00:00Z",
        "control": {"name": "x", "rcode": "NXDOMAIN", "usable": True},
        "names_offered": 1, "names_dropped_by_cap": 0,
        "wildcard_spf": {"name": "*.example.com", "record": "", "rcode": "NXDOMAIN",
                         "agreed": True},
        "wildcard_dkim": {"name": "*._domainkey.example.com", "record": "", "rcode": "NXDOMAIN",
                          "agreed": True},
        "subdomains": [_sub("a.b.example.com")],
        "intermediate_dmarc": [
            {"name": "b.example.com", "dmarc_record": "v=DMARC1; p=reject; psd=n",
             "settled": True},
            {"name": "c.example.com", "dmarc_record": "", "settled": False}],
    }
    dmarc = {a.protocol: a for a in ct_dns.ned_rows("example.com", cap, NOW)}["ned-dmarc"]
    assert dmarc.extra["intermediate_dmarc"] == {"b.example.com": "v=DMARC1; p=reject; psd=n"}
    assert dmarc.extra["intermediate_unsettled"] == ["c.example.com"]


def test_the_name_servers_are_read_for_an_email_domain(monkeypatch):
    table = {**DNS, ("example.com", "NS"): ["ns1.example.net.", "NS2.example.net."]}
    rows, _, failures = email_rows(monkeypatch, table)
    assert failures == []
    ns = rows[ct_dns.NAME_SERVERS]
    assert ns.extra["name_servers"] == ["ns1.example.net", "ns2.example.net"]
    assert ns.notes == "ns1.example.net, ns2.example.net" and ns.role
    # A name that is not the top of its own zone answers with no NS record.
    rows, _, _ = email_rows(monkeypatch, DNS)
    assert rows[ct_dns.NAME_SERVERS].extra["name_servers"] == []
    rows, _, failures = email_rows(monkeypatch, DNS, {"example.com": "SERVFAIL"})
    assert ct_dns.NAME_SERVERS not in rows and "NS (example.com: SERVFAIL)" in failures[0]


def test_mail_handling_names_get_a_row_and_unsettled_names_are_counted_neither_way():
    cap = {
        "resolvers": ["192.0.2.53", "198.51.100.53"], "tries": 3,
        "captured_at": "2030-06-15T00:00:00Z",
        "control": {"name": "x", "rcode": "NOERROR", "usable": True, "basis": "wildcard"},
        "names_offered": 3, "names_dropped_by_cap": 0,
        "wildcard_spf": {"name": "*.example.com", "record": "v=spf1 -all", "rcode": "NOERROR",
                         "agreed": True},
        "wildcard_dkim": {"name": "*._domainkey.example.com", "record": "",
                          "rcode": "NXDOMAIN", "agreed": True},
        "subdomains": [
            _sub("a.example.com"),
            _sub("mail.example.com", enabled=True, spf=False,
                 spf_record="v=spf1 mx ~all", mx_records=["10 mx.example.net."],
                 email_enabled_because="publishes an MX record"),
            _sub("split.example.com", agreed=False, spf=False),
        ],
    }
    rows = {a.protocol: a for a in ct_dns.ned_rows("example.com", cap, NOW)}
    spf, mail = rows["ned-spf"], rows[ct_dns.SUBDOMAIN_MAIL]
    assert spf.extra["names_in_scope"] == 1 and spf.extra["names_without_record"] == []
    assert spf.extra["names_unsettled"] == ["split.example.com"]
    assert spf.extra["control_basis"] == "wildcard"
    assert mail.name == "Mail-handling sub-domains of example.com" and mail.role
    assert mail.extra["names"] == {"mail.example.com": {
        "spf_record": "v=spf1 mx ~all", "dmarc_record": "", "exists": True,
        "mx_records": ["10 mx.example.net."], "because": "publishes an MX record"}}


def test_only_the_domain_and_names_beneath_it_are_kept(monkeypatch):
    fake, _ = serve({"": [issuance("1", ["widgets.test", "www.widgets.test", "notwidgets.test"],
                                   "2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z")], "1": []})
    monkeypatch.setattr(ct_dns, "http_json", fake)
    read = ct_dns._ct_names("widgets.test", None, API)
    assert sorted(read.names) == ["widgets.test", "www.widgets.test"]


# ── The sweep's names, and a population attested complete ────────────

ZONE = """$ORIGIN example.com.
@            IN SOA  ns1.example.com. hostmaster.example.com. 2030010101 3600 600 604800 300
@            IN NS   ns1.example.com.
@            IN TXT  "v=spf1 include:spf.example.com -all"
_dmarc       IN TXT  "v=DMARC1; p=reject"
*            IN TXT  "v=spf1 -all"
www          IN A    192.0.2.80
x.deep       IN A    192.0.2.81
s1._domainkey.mail IN TXT "v=DKIM1; p="
lab          IN NS   ns1.example.net.
"""

LAB = """$ORIGIN lab.example.com.
@            IN SOA  ns1.example.net. hostmaster.example.com. 2030010101 3600 600 604800 300
@            IN NS   ns1.example.net.
bench        IN A    192.0.2.90
"""


def zones(*texts: tuple[str, str]):
    from takestock import zonefile
    return [zonefile.parse(text, origin) for origin, text in texts]


def test_the_sweep_reads_every_name_the_observation_knows():
    target = {"discovery": {"domains": ["example.com", "shop.example.com"]},
              "scan_targets": {"tls_443": ["portal.example.com", "203.0.113.5"],
                               "smtp_25": [{"host": "mx1.example.com"}],
                               "ssh_22": ["jump.example.com:2222"]}}
    got = ct_dns.sweep_names("example.com", {"api.example.com", "www.example.com",
                                             "api.example.net"}, target,
                             zones(("example.com", ZONE)))
    zone, ct = dnsevidence.NAME_FROM_ZONE, dnsevidence.NAME_FROM_CT
    assert got == {
        "api.example.com": [ct],
        # deep.example.com owns nothing, and exists as an empty non-terminal.
        "deep.example.com": [zone], "x.deep.example.com": [zone],
        "jump.example.com": [dnsevidence.NAME_FROM_SCAN],
        "lab.example.com": [zone],
        # The DKIM key's owner is not a mail domain; the name above it is.
        "mail.example.com": [zone],
        "mx1.example.com": [dnsevidence.NAME_FROM_SCAN],
        "portal.example.com": [dnsevidence.NAME_FROM_SCAN],
        "shop.example.com": [dnsevidence.NAME_FROM_PROFILE],
        "spf.example.com": [dnsevidence.NAME_FROM_SPF],
        "www.example.com": [ct, zone],
    }


ATTESTED = {"zone": "example.com", "attested_by": "Example Widgets Ltd, DNS administrator",
            "attested_on": "2030-01-31"}


def test_a_zone_is_complete_only_on_a_full_attestation_of_it_and_what_it_delegates():
    held = zones(("example.com", ZONE), ("lab.example.com", LAB))
    lab = {**ATTESTED, "zone": "lab.example.com"}

    def pop(entries: list[dict], files=held) -> dict:
        return ct_dns.zone_population("example.com",
                                      {"dns_zones": {"complete_zones": entries}}, files)

    assert pop([]) == {}
    whole = pop([ATTESTED, lab])
    assert whole["complete"] and whole["zones"] == ["example.com", "lab.example.com"]
    assert whole["wildcard"] and whole["attested_by"] == ATTESTED["attested_by"]
    assert "lab.example.com is delegated" in pop([ATTESTED])["why_not"]
    assert "no zone file for lab.example.com" in pop([ATTESTED, lab], held[:1])["why_not"]
    assert "who made it and when" in pop([{**ATTESTED, "attested_on": ""}, lab])["why_not"]
    broken = zones(("example.com", ZONE + "odd line nobody can place\n"),
                   ("lab.example.com", LAB))
    assert "not understood" in pop([ATTESTED, lab], broken)["why_not"]


def _swept(name: str, found_in: list[str], exists: bool = True) -> dict:
    return _sub(name, found_in=found_in, exists=exists)


def test_the_rows_carry_the_sources_and_where_the_live_reading_disagrees_with_the_files():
    cap = {
        "resolvers": ["192.0.2.53"], "tries": 3, "captured_at": "2030-06-15T00:00:00Z",
        "control": {"name": "x", "rcode": "NXDOMAIN", "usable": True},
        "names_offered": 3, "names_dropped_by_cap": 0,
        "wildcard_spf": {"name": "*.example.com", "record": "", "rcode": "NXDOMAIN",
                         "agreed": True},
        "wildcard_dkim": {"name": "*._domainkey.example.com", "record": "",
                          "rcode": "NXDOMAIN", "agreed": True},
        "subdomains": [
            _swept("www.example.com", [dnsevidence.NAME_FROM_CT, dnsevidence.NAME_FROM_ZONE]),
            _swept("gone.example.com", [dnsevidence.NAME_FROM_ZONE], exists=False),
            _swept("new.example.com", [dnsevidence.NAME_FROM_CT]),
            _swept("old.example.com", [dnsevidence.NAME_FROM_CT], exists=False),
        ],
    }
    population = {"zone": "example.com", "complete": True, "wildcard": False}
    rows = {a.protocol: a for a in ct_dns.ned_rows("example.com", cap, NOW,
                                                   population=population)}
    spf = rows["ned-spf"].extra
    assert spf["name_sources"]["www.example.com"] == [dnsevidence.NAME_FROM_CT,
                                                      dnsevidence.NAME_FROM_ZONE]
    assert spf["names_by_source"] == {dnsevidence.NAME_FROM_CT: 3,
                                      dnsevidence.NAME_FROM_ZONE: 2}
    assert spf["population"] == population
    assert spf["names_disagreeing_with_zone"] == ["gone.example.com", "new.example.com"]
    # A wildcard in the files answers names they do not list.
    rows = {a.protocol: a for a in ct_dns.ned_rows(
        "example.com", cap, NOW, population={**population, "wildcard": True})}
    assert rows["ned-spf"].extra["names_disagreeing_with_zone"] == ["gone.example.com"]
    # No attestation, no population and nothing compared.
    plain = {a.protocol: a for a in ct_dns.ned_rows("example.com", cap, NOW)}["ned-spf"].extra
    assert "population" not in plain and "names_disagreeing_with_zone" not in plain
