"""Parsing full ``dig`` output: status, flags and records by section."""

from __future__ import annotations

from takestock import digresponse

# Composed by hand in dig's documented output format, with reserved names and
# a documentation address.
NOERROR = """\
; <<>> DiG 9.18 <<>> +dnssec +time=8 +tries=3 TYPE65 www.example.test
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;www.example.test.\t\tIN\tTYPE65

;; ANSWER SECTION:
www.example.test.\t300\tIN\tHTTPS\t1 . alpn="h3,h2"
www.example.test.\t300\tIN\tRRSIG\tHTTPS 13 3 300 20300101000000 20291201000000 4242 example.test. AAAA

;; Query time: 20 msec
;; SERVER: 192.0.2.53#53(192.0.2.53) (UDP)
"""

NXDOMAIN = """\
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4243
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; AUTHORITY SECTION:
example.test.\t900\tIN\tSOA\tns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 900
"""

TIMED_OUT = ";; connection timed out; no servers could be reached\n"


def test_status_flags_and_answers_are_read():
    r = digresponse.parse(NOERROR)
    assert r.answered and r.authenticated
    assert r.status == "NOERROR"
    https = r.records("HTTPS")
    assert len(https) == 1
    assert https[0].ttl == 300
    assert https[0].rdata == ["1", ".", 'alpn="h3,h2"']
    assert len(r.records("rrsig")) == 1


def test_an_nxdomain_answer_is_still_an_answer():
    r = digresponse.parse(NXDOMAIN)
    assert r.answered and not r.authenticated
    assert r.answer == []
    assert [rr.rtype for rr in r.records("SOA", "authority")] == ["SOA"]


def test_no_server_is_an_error_not_an_empty_answer():
    r = digresponse.parse(TIMED_OUT)
    assert not r.answered
    assert "timed out" in r.error


def test_a_command_that_could_not_run_is_an_error():
    assert not digresponse.parse("__ERROR__ dig missing").answered


def test_norm_compares_names_without_case_or_trailing_dot():
    assert digresponse.norm(" WWW.Example.Test. ") == "www.example.test"


def test_query_names_the_resolver_only_when_one_is_given(monkeypatch):
    seen: list[list[str]] = []
    monkeypatch.setattr(digresponse, "run", lambda cmd, timeout=60: seen.append(cmd) or "")
    digresponse.query("www.example.test", "TYPE65")
    digresponse.query("www.example.test", "TYPE65", "192.0.2.53", dnssec=True, cd=True)
    assert not any(a.startswith("@") for a in seen[0])
    assert seen[1][-1] == "@192.0.2.53"
    assert "+dnssec" in seen[1] and "+cd" in seen[1]
