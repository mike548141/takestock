"""Parked domains: listed among the domains, not the email domains, and read as sending no mail."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import dnsfake
import pytest
from dnsfake import dig_text

from takestock import cli, config, dnsevidence, sge, sge_note
from takestock.collectors import ct_dns

NOW = datetime(2030, 1, 15, tzinfo=UTC)
P = "example.org"
STD = sge.load_standard()


def test_a_parked_domain_is_listed_and_not_an_email_domain():
    t = {"discovery": {"domains": ["example.com", "Example.ORG.", "example.net", "example.org"],
                       "email_domains": ["EXAMPLE.com", "example.net."]}}
    assert dnsevidence.parked_domains(t) == ["example.org"]
    assert dnsevidence.parked_domains({"discovery": {"domains": ["example.com"]}}) == [
        "example.com"]
    assert dnsevidence.parked_domains({}) == []


# ── Collection ────────────────────────────────────────────────────────

def resolving(table: dict, status: dict | None = None):
    """``dnsevidence.run`` answering full ``dig`` transcripts from ``table``."""
    def run(cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
        rtype, name = [c for c in cmd[1:] if not c.startswith(("+", "@"))][:2]
        given = (status or {}).get(name)
        if given == "timeout":
            return "__ERROR__ Command 'dig' timed out"
        records = table.get((name, rtype), [])
        known = any(n == name for n, _t in table)
        return dig_text(given or ("NOERROR" if known else "NXDOMAIN"),
                        [f"{name}. 300 IN {rtype} {r}" for r in records])
    return run


DKIM_AT = f"*._domainkey.{P}"
CLEAN = {
    (P, "TXT"): ['"v=spf1 -all"'],
    (f"_dmarc.{P}", "TXT"): ['"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@example.com"'],
    (DKIM_AT, "TXT"): ['"v=DKIM1; p="'],
    (P, "MX"): ["0 ."],
    (P, "NS"): ["ns2.example.net.", "ns1.example.net."],
}


def parked(monkeypatch, table: dict, status: dict | None = None):
    monkeypatch.setattr(dnsevidence, "run", resolving(table, status))
    rows, failures = ct_dns.parked_assets(P, NOW, dnsfake.RESOLVERS)
    return {r.protocol: r for r in rows}, failures


def test_a_parked_domain_yields_spf_dmarc_dkim_and_null_mx_rows(monkeypatch):
    rows, failures = parked(monkeypatch, CLEAN)
    assert failures == []
    assert set(rows) == {"spf", "dmarc", ct_dns.NAME_SERVERS, ct_dns.DKIM_WILDCARD,
                         ct_dns.NULL_MX}
    assert rows[ct_dns.NAME_SERVERS].extra["name_servers"] == ["ns1.example.net",
                                                              "ns2.example.net"]
    assert all(r.extra["parked"] is True and r.host == P for r in rows.values())
    assert rows["spf"].extra["record"].strip('"') == "v=spf1 -all"
    assert "dmarc-reject" in rows["dmarc"].flags
    mx = rows[ct_dns.NULL_MX]
    assert (mx.name, mx.extra["null_mx"], mx.flags) == (
        f"Null MX {P}", ct_dns.NULL_MX_PUBLISHED, ["null-mx:published"])
    assert mx.extra["lookup"]["measured"] is True


@pytest.mark.parametrize(("mx", "state"), [
    ([], ct_dns.NULL_MX_NONE),
    (["10 mail.example.org."], ct_dns.NULL_MX_MAIL_EXCHANGERS),
    (["0 .", "10 mail.example.org."], ct_dns.NULL_MX_WITH_OTHERS),
])
def test_each_mx_answer_has_its_null_mx_state(monkeypatch, mx, state):
    table = {**CLEAN, (P, "MX"): mx}
    rows, _ = parked(monkeypatch, table)
    assert rows[ct_dns.NULL_MX].extra["null_mx"] == state


def test_the_wildcard_dkim_record_is_read_with_its_lookup(monkeypatch):
    rows, _ = parked(monkeypatch, CLEAN)
    dkim = rows[ct_dns.DKIM_WILDCARD]
    assert (dkim.name, dkim.flags) == (f"DKIM wildcard {P}", [])
    assert dkim.extra["present"] is True and dkim.extra["blank"] is True
    assert dkim.extra["record"] == "v=DKIM1; p="
    assert dkim.extra["lookup"]["name"] == DKIM_AT and dkim.extra["lookup"]["measured"]


@pytest.mark.parametrize(("answer", "present", "blank", "flag"), [
    ([], False, False, "no-dkim-wildcard"),
    (['"v=DKIM1; k=rsa; " "p=EXAMPLEKEY"'],
     True, False, "dkim-wildcard-not-blank"),
])
def test_an_absent_or_keyed_wildcard_is_read_as_such(monkeypatch, answer, present, blank, flag):
    rows, failures = parked(monkeypatch, {**CLEAN, (DKIM_AT, "TXT"): answer})
    dkim = rows[ct_dns.DKIM_WILDCARD]
    assert failures == []
    assert (dkim.extra["present"], dkim.extra["blank"], dkim.flags) == (present, blank, [flag])
    if present:                                  # quoted strings joined, as a receiver does
        assert dkim.extra["record"] == "v=DKIM1; k=rsa; p=EXAMPLEKEY"


def test_a_dkim_lookup_that_does_not_settle_is_a_failure_not_an_absence(monkeypatch):
    rows, failures = parked(monkeypatch, CLEAN, status={DKIM_AT: "SERVFAIL"})
    assert ct_dns.DKIM_WILDCARD not in rows
    assert len(failures) == 1 and f"DKIM ({DKIM_AT}: SERVFAIL)" in failures[0]


def test_an_mx_lookup_that_does_not_settle_is_a_failure_not_an_absence(monkeypatch):
    def run(cmd, timeout=60, stdin_text=None):
        if "MX" in cmd:
            return dig_text("SERVFAIL")
        return resolving(CLEAN)(cmd, timeout, stdin_text)
    monkeypatch.setattr(dnsevidence, "run", run)
    rows, failures = ct_dns.parked_assets(P, NOW, dnsfake.RESOLVERS)
    assert ct_dns.NULL_MX not in {r.protocol for r in rows}
    assert len(failures) == 1 and failures[0].startswith(f"ct_dns {P} (parked):")
    assert "MX (example.org: SERVFAIL)" in failures[0]


def test_the_collector_reads_each_parked_domain(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(ct_dns, "_email_assets", lambda *a, **k: ([], []))
    monkeypatch.setattr(ct_dns, "_ned_sweep", lambda *a, **k: [])
    monkeypatch.setattr(ct_dns, "parked_assets",
                        lambda d, *a, **k: (seen.append(d) or [], []))
    target = {"discovery": {"domains": ["example.com", P], "email_domains": ["example.com"]},
              "dns": {"ct_search_api": ""}}
    monkeypatch.setattr(ct_dns, "search_endpoint", lambda t: "")
    ct_dns.collect(target, ref_time=NOW)
    assert seen == [P]


def test_the_collector_sweeps_the_names_beneath_each_parked_domain(monkeypatch):
    swept: list[tuple[str, bool, tuple[str, ...]]] = []
    monkeypatch.setattr(ct_dns, "_email_assets", lambda *a, **k: ([], []))
    monkeypatch.setattr(ct_dns, "parked_assets", lambda *a, **k: ([], []))
    monkeypatch.setattr(ct_dns, "_ned_sweep", lambda d, found, *a, parked=False, **k: (
        swept.append((d, parked, tuple(sorted(found)))) or []))
    monkeypatch.setattr(ct_dns, "search_endpoint", lambda t: "")
    target = {"discovery": {"domains": ["example.com", P], "email_domains": ["example.com"]}}
    ct_dns.collect(target, ref_time=NOW)
    assert [(d, parked) for d, parked, _ in swept] == [("example.com", False), (P, True)]


def test_a_sweep_beneath_a_parked_domain_marks_its_rows_and_lists_names_that_do_not_exist():
    def sub(name: str, exists: bool = True) -> dict:
        return {"name": name, "email_enabled": False, "read": True, "exists": exists,
                "spf_conformant": False, "dkim_conformant": False, "dmarc_record": ""}
    cap = {"resolvers": ["192.0.2.53"], "tries": 3, "captured_at": "2030-01-15T00:00:00Z",
           "control": {"name": "x", "rcode": "NXDOMAIN", "usable": True},
           "names_offered": 2, "names_dropped_by_cap": 0,
           "wildcard_spf": {"name": f"*.{P}", "record": "", "rcode": "NXDOMAIN",
                            "agreed": True},
           "wildcard_dkim": {"name": DKIM_AT, "record": "", "rcode": "NXDOMAIN", "agreed": True},
           "subdomains": [sub(f"www.{P}"), sub(f"old.{P}", exists=False)]}
    rows = ct_dns.ned_rows(P, cap, NOW, parked=True)
    assert [r.protocol for r in rows] == ["ned-spf", "ned-dkim", "ned-dmarc",
                                          ct_dns.SUBDOMAIN_MAIL]
    assert all(r.extra["parked"] is True and r.host == P for r in rows)
    assert rows[2].extra["names_nonexistent"] == [f"old.{P}"]
    assert "parked" not in ct_dns.ned_rows(P, cap, NOW)[0].extra


# ── Grading ───────────────────────────────────────────────────────────

def _rows(spf: str | None = "v=spf1 -all", dmarc: str | None = "v=DMARC1; p=reject; adkim=s; "
          "aspf=s; rua=mailto:d@example.com", null_mx: str | None = "published",
          spf_flags: tuple[str, ...] = ("hardfail-all",),
          dkim: str | None = "v=DKIM1; p=") -> list[dict]:
    out: list[dict] = []
    if dkim is not None:
        out.append({"name": f"DKIM wildcard {P}", "protocol": "dkim-wildcard", "host": P,
                    "flags": [], "notes": "",
                    "extra": {"present": bool(dkim), "record": dkim, "parked": True,
                              "lookup": {"name": f"*._domainkey.{P}", "measured": True,
                                         "lookups": [{"resolver": "192.0.2.53",
                                                      "rcode": "NOERROR", "at": ""}]}}})
    if spf is not None:
        out.append({"name": f"SPF {P}", "protocol": "spf", "host": P, "flags": list(spf_flags),
                    "notes": spf or "no v=spf1 record published",
                    "extra": {"present": bool(spf), "record": spf, "parked": True,
                              "legacy_spf2_records": []}})
    if dmarc is not None:
        out.append({"name": f"DMARC {P}", "protocol": "dmarc", "host": P, "flags": [],
                    "notes": dmarc or "no DMARC record published",
                    "extra": {"present": bool(dmarc), "record": dmarc, "parked": True}})
    if null_mx is not None:
        out.append({"name": f"Null MX {P}", "protocol": "null-mx", "host": P,
                    "extra": {"null_mx": null_mx, "records": ["0 ."], "parked": True}})
    return out


def graded(assets: list[dict], req: str) -> sge.Conformance:
    report = sge.evaluate(assets, [], STD, parked=[P])
    [row] = [r for r in report.rows if r.requirement == req and r.subject == P]
    assert row.parked
    return row


def test_a_clean_parked_domain_meets_the_rules_for_domains_that_send_no_mail():
    report = sge.evaluate(_rows(), [], STD, parked=[P])
    by = {r.requirement: r for r in report.rows if r.parked and r.subject == P}
    assert {k: v.status for k, v in by.items()} == {
        "SGE-NED-SPF-01": sge.PASS, "SGE-NED-DMARC-01": sge.PASS,
        "SGE-NED-DMARC-R01": sge.PASS, "SGE-NED-DKIM-01": sge.PASS,
        "SGE-SPF-R02": sge.PASS, "SGE-DMARC-R03": sge.PASS}
    assert report.breaches() == []
    assert [(p.domain, p.null_mx, p.published) for p in report.parked] == [
        (P, "published", True)]


@pytest.mark.parametrize(("record", "flags", "observed"), [
    ("", ("no-spf-record",), "no SPF record"),
    ("v=spf1 ~all", ("softfail-all",), "not blank; ends ~all"),
    ("v=spf1 include:_spf.example.net -all", ("hardfail-all",), "not blank; ends -all"),
])
def test_a_parked_domain_without_the_blank_spf_record_breaches_a_must(record, flags, observed):
    rows = _rows(spf=record, spf_flags=flags)
    row = graded(rows, "SGE-NED-SPF-01")
    assert (row.status, row.level, row.observed) == (sge.FAIL, "must", observed)
    assert row.breaches_must and sge.PARKED_NOTE in row.subject_note


@pytest.mark.parametrize(("record", "observed"), [
    ("", "no DMARC record"),
    ("v=DMARC1; p=none; rua=mailto:d@example.com", "p=none; pct=100"),
    ("v=DMARC1; p=quarantine", "p=quarantine; pct=100"),
])
def test_a_parked_domain_without_a_reject_policy_breaches_a_must(record, observed):
    row = graded(_rows(dmarc=record), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.FAIL, observed) and row.breaches_must


@pytest.mark.parametrize("sp", ["none", "quarantine"])
def test_a_parked_domain_whose_sub_domain_policy_is_weaker_than_reject_breaches_a_must(sp):
    row = graded(_rows(dmarc=f"v=DMARC1; p=reject; sp={sp}"), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.FAIL, f"p=reject; pct=100; sp={sp}")
    assert row.breaches_must and f"sets sp={sp}" in row.reason


@pytest.mark.parametrize(("record", "observed"), [
    ("v=DMARC1; p=reject", "p=reject; pct=100"),            # no sp=: inherits p=reject
    ("v=DMARC1; p=reject; sp=reject", "p=reject; pct=100; sp=reject"),
])
def test_a_parked_domain_whose_sub_domains_inherit_or_set_reject_passes(record, observed):
    row = graded(_rows(dmarc=record), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.PASS, observed)


def test_a_weak_sub_domain_policy_adds_to_a_failing_parked_policy():
    row = graded(_rows(dmarc="v=DMARC1; p=none; sp=none"), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.FAIL, "p=none; pct=100; sp=none")
    assert "p=none" in row.reason and "sets sp=none" in row.reason


@pytest.mark.parametrize("np_", ["none", "quarantine"])
def test_a_parked_domain_whose_np_is_weaker_than_reject_breaches_a_must(np_):
    row = graded(_rows(dmarc=f"v=DMARC1; p=reject; np={np_}"), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.FAIL, f"p=reject; pct=100; np={np_}")
    assert row.breaches_must and f"sets np={np_}" in row.reason and "RFC 9989" in row.reason


def test_a_parked_domain_with_np_reject_passes():
    row = graded(_rows(dmarc="v=DMARC1; p=reject; sp=reject; np=reject"), "SGE-NED-DMARC-01")
    assert (row.status, row.observed) == (sge.PASS, "p=reject; pct=100; sp=reject; np=reject")


def test_the_empty_dkim_key_on_a_parked_domain_passes():
    row = graded(_rows(), "SGE-NED-DKIM-01")
    assert (row.status, row.observed, row.record) == (sge.PASS, "v=DKIM1; p=", "v=DKIM1; p=")
    assert sge.PARKED_NOTE in row.subject_note


@pytest.mark.parametrize(("record", "observed"), [
    ("", "no DKIM record"),
    ("v=DKIM1; k=rsa; p=EXAMPLEKEY", "not blank; carries a key"),
    ("v=DKIM1; k=rsa", "not blank; no p= tag"),
])
def test_a_parked_domain_without_the_empty_dkim_key_breaches_a_must(record, observed):
    row = graded(_rows(dkim=record), "SGE-NED-DKIM-01")
    assert (row.status, row.level, row.observed) == (sge.FAIL, "must", observed)
    assert row.breaches_must
    if not record:
        assert "settled and returned no such record" in row.reason


def test_an_unsettled_dkim_lookup_on_a_parked_domain_is_inconclusive():
    row = graded(_rows(dkim=None), "SGE-NED-DKIM-01")
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    assert "did not settle" in row.evidence


def test_relaxed_alignment_on_a_parked_domain_is_a_recommendation_not_a_breach():
    row = graded(_rows(dmarc="v=DMARC1; p=reject"), "SGE-NED-DMARC-R01")
    assert row.status == sge.FAIL and not row.breaches_must
    assert row.observed == "adkim=r (by default), aspf=r (by default), no rua="


def test_a_legacy_spf2_record_on_a_parked_domain_is_a_recommendation_unmet():
    rows = _rows()
    next(r for r in rows if r["protocol"] == "spf")["extra"]["legacy_spf2_records"] = [
        "spf2.0/pra -all"]
    row = graded(rows, "SGE-SPF-R02")
    assert row.status == sge.FAIL and not row.breaches_must and "SPF2.0" in row.reason


def test_unwanted_dmarc_tags_on_a_parked_domain_are_a_recommendation_unmet():
    row = graded(_rows(dmarc="v=DMARC1; p=reject; ruf=mailto:f@example.com"), "SGE-DMARC-R03")
    assert row.status == sge.FAIL and not row.breaches_must and "ruf" in row.observed
    # No DMARC record at all is graded under SGE-NED-DMARC-01, not here.
    row = graded(_rows(dmarc=""), "SGE-DMARC-R03")
    assert row.status == sge.NOT_MEASURED and "SGE-NED-DMARC-01" in row.evidence


def test_an_unread_parked_domain_is_not_measured_never_met():
    report = sge.evaluate([], [], STD, parked=[P])
    statuses = {r.requirement: r.status for r in report.rows if r.parked}
    assert set(statuses.values()) == {sge.NOT_MEASURED}
    assert report.parked[0].null_mx == "" and "not read" in report.parked[0].observed


def test_a_missing_null_mx_is_reported_and_never_a_breach():
    report = sge.evaluate(_rows(null_mx="no-mx"), [], STD, parked=[P])
    assert report.breaches() == []
    assert report.parked[0].observed == "no MX record and no null MX"


def test_parked_readings_never_stand_in_for_an_email_domains_records():
    # An email domain's grading reads only its own rows, never a parked domain's.
    rows = [{**r, "host": "example.com", "name": r["name"].replace(P, "example.com")}
            for r in _rows()]
    report = sge.evaluate(rows, [], STD, parked=[P])
    assert {r.status for r in report.rows if r.parked} == {sge.NOT_MEASURED}
    assert not [r for r in sge.evaluate(_rows(), ["example.com"], STD).rows if r.subject == P]


def test_the_text_report_lists_parked_domains_on_their_own():
    report = sge.evaluate(_rows(null_mx="no-mx"), [], STD, parked=[P])
    text = sge._format(report, [])
    assert f"{P} (parked)" in text
    assert "Parked domains (1)" in text and "no MX record and no null MX" in text


# ── The names beneath a parked domain ─────────────────────────────────

SUBS = sge.parked_subdomains_subject(P)


def _ned(protocol: str, missing: tuple[str, ...] = (), in_scope: int = 2, **extra) -> dict:
    """A sweep row for the names beneath the parked domain, as ``ct_dns.ned_rows`` writes it."""
    base: dict = {"control_usable": True, "names_in_scope": in_scope, "parked": True,
                  "read_at": "2030-01-15T00:00:00Z", "resolvers": ["192.0.2.53"]}
    if protocol != "ned-dmarc":
        base |= {"expected_record": ("v=spf1 -all" if protocol == "ned-spf" else "v=DKIM1; p="),
                 "wildcard_name": f"*.{P}" if protocol == "ned-spf" else DKIM_AT,
                 "wildcard_conformant": False, "names_without_record": list(missing)}
    return {"name": f"{protocol} beneath {P}", "protocol": protocol, "host": P,
            "extra": {**base, **extra}}


def beneath(assets: list[dict]) -> dict[str, sge.Conformance]:
    report = sge.evaluate(assets, [], STD, parked=[P])
    return {r.requirement: r for r in report.rows if r.subject == SUBS}


def test_the_names_beneath_a_parked_domain_are_read_on_rows_of_their_own():
    assets = _rows() + [
        _ned("ned-spf", missing=(f"a.{P}",)), _ned("ned-dkim"),
        _ned("ned-dmarc", dmarc_records={f"b.{P}": "v=DMARC1; p=reject; sp=reject"})]
    report = sge.evaluate(assets, [], STD, parked=[P])
    subs = {r.requirement: r for r in report.rows if r.subject == SUBS}
    assert set(subs) == set(sge.PARKED_SUBDOMAIN_REQUIREMENTS)
    assert all(r.parked and sge.PARKED_NOTE in r.subject_note for r in subs.values())
    spf = subs["SGE-NED-SPF-01"]
    assert (spf.status, spf.observed) == (sge.FAIL, "1 of 2 sub-domains without v=spf1 -all")
    assert spf.breaches_must
    # A floor of names: conformant names show nothing, so nothing beneath ever passes.
    assert sge.PASS not in {r.status for r in subs.values()}
    assert subs["SGE-NED-DKIM-01"].status == sge.NOT_MEASURED
    assert subs["SGE-NED-DMARC-01"].status == sge.NOT_MEASURED     # falls back to p=reject
    sp = subs["SGE-DMARC-R05"]
    assert sp.status == sge.FAIL and not sp.breaches_must and f"b.{P}" in sp.subject_note
    # The parked domain's own records still pass on their own rows.
    own = {r.requirement: r.status for r in report.rows if r.subject == P}
    assert set(own.values()) == {sge.PASS}
    assert [(b.requirement, b.subject) for b in report.breaches()] == [("SGE-NED-SPF-01", SUBS)]
    assert f"{SUBS} (parked)" in sge._format(report, [])


def test_without_a_sweep_the_names_beneath_a_parked_domain_are_not_collected():
    subs = beneath(_rows())
    assert {(r.status, r.reason) for r in subs.values()} == {(sge.NOT_MEASURED,
                                                              sge.NOT_COLLECTED)}


def test_unwanted_dmarc_tags_on_the_names_beneath_a_parked_domain():
    sweep = _ned("ned-dmarc", dmarc_records={f"b.{P}": "v=DMARC1; p=reject; ri=86400"})
    row = beneath(_rows() + [sweep])["SGE-DMARC-R03"]
    assert row.status == sge.FAIL and row.parked and f"b.{P} (ri)" in row.reason


def test_names_beneath_fall_back_to_the_parked_domains_own_dmarc_record():
    weak = _rows(dmarc="v=DMARC1; p=reject; sp=none")
    row = beneath(weak + [_ned("ned-dmarc", dmarc_records={})])["SGE-NED-DMARC-01"]
    assert (row.status, row.observed) == (sge.FAIL, "2 of 2 sub-domains without a reject policy")
    # The row holds no walk, so it says what was read rather than naming discovery.
    assert "are read against the organisational domain's record" in row.subject_note
    assert "policy discovery" not in row.subject_note
    # A name that does not exist takes np= instead of sp= (RFC 9989 §4.7).
    split = _rows(dmarc="v=DMARC1; p=reject; sp=reject; np=none")
    row = beneath(split + [_ned("ned-dmarc", dmarc_records={},
                                names_nonexistent=[f"old.{P}"])])["SGE-NED-DMARC-01"]
    assert row.observed == "1 of 2 sub-domains without a reject policy"
    # Unswept, the row does not repeat the sp= the parked domain's own row grades.
    alone = beneath(weak)["SGE-NED-DMARC-01"]
    assert alone.status == sge.NOT_MEASURED and "graded on its own row" in alone.evidence


# ── An observation whose rows are not marked parked ───────────────────

def _unmarked(**kw) -> list[dict]:
    rows = _rows(**kw)
    for r in rows:
        r["extra"].pop("parked", None)
    return rows


def test_unmarked_spf_and_dmarc_rows_of_a_parked_domain_are_graded_and_say_so():
    assets = _unmarked(spf="v=spf1 ~all", spf_flags=("softfail-all",),
                       dmarc="v=DMARC1; p=none", dkim=None, null_mx=None)
    report = sge.evaluate(assets, [], STD, parked=[P])
    breaches = [(b.requirement, b.subject) for b in report.breaches()]
    assert breaches == [("SGE-NED-SPF-01", P), ("SGE-NED-DMARC-01", P)]
    assert all(sge.PARKED_UNMARKED_NOTE in b.subject_note for b in report.breaches())
    # No reading at all, in an observation with no parked readings: said plainly.
    dkim = graded(assets, "SGE-NED-DKIM-01")
    assert (dkim.status, dkim.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)
    assert "no parked reading of any domain" in dkim.evidence
    assert "no parked reading of any domain" in report.parked[0].observed


def test_marked_rows_still_win_and_carry_no_unmarked_note():
    row = graded(_rows(), "SGE-NED-SPF-01")
    assert row.status == sge.PASS and sge.PARKED_UNMARKED_NOTE not in row.subject_note


# ── The note and the command ──────────────────────────────────────────

TARGET = {"organisation": {"name": "Example Widgets Ltd"},
          "discovery": {"domains": ["example.com", P], "email_domains": ["example.com"]}}


def test_the_note_reports_parked_domains_in_their_own_section():
    report = sge.evaluate(_rows(spf="v=spf1 ~all", spf_flags=("softfail-all",),
                                null_mx="no-mx"), ["example.com"], STD, parked=[P])
    out = sge_note.build_note(report, TARGET, standard=STD)
    section = out[out.index('<section id="parked"'):]
    section = section[:section.index("</section>")]
    assert f"<code>{P}</code>" in section
    assert "no MX record and no null MX" in section
    assert "M3AAWG" in section and "RFC 7505" in section
    assert "Not met" in section
    dns = out[out.index('<section id="dns-records"'):]
    assert f"<h3>{P}</h3>" not in dns                     # mail domains only there
    assert f"{P} (parked)" in out[:out.index('<section id="parked"')]   # listed as unmet must


def test_the_note_gives_the_names_beneath_a_parked_domain_a_line_of_their_own():
    report = sge.evaluate(_rows() + [_ned("ned-spf", missing=(f"a.{P}",))], ["example.com"],
                          STD, parked=[P])
    out = sge_note.build_note(report, TARGET, standard=STD)
    section = out[out.index('<section id="parked"'):]
    section = section[:section.index("</section>")]
    assert f"<code>{P}</code>" in section and f"<code>{SUBS}</code>" in section
    assert "SGE-DMARC-R05" in section
    assert f"{SUBS} (parked)" in out[:out.index('<section id="parked"')]


def test_the_command_counts_a_breach_on_unmarked_rows(tmp_path: Path,
                                                      capsys: pytest.CaptureFixture):
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "example.yaml").write_text(
        f"name: example\ndiscovery:\n  domains: [{P}]\n")
    obs = tmp_path / "observations" / "2030-01-31T0930Z"
    obs.mkdir(parents=True)
    (obs / "assets.json").write_text(json.dumps(_unmarked(
        spf="v=spf1 ~all", spf_flags=("softfail-all",), dmarc="v=DMARC1; p=none",
        dkim=None, null_mx=None)))
    config.set_workspace(tmp_path)
    assert cli.main(["comply", "sge", str(obs), "example", "--format", "text",
                     "--workspace", str(tmp_path)]) == 1
    assert "2 unmet MUST" in capsys.readouterr().out


def test_no_parked_section_without_parked_domains():
    report = sge.evaluate([], ["example.com"], STD)
    assert 'id="parked"' not in sge_note.build_note(report, TARGET, standard=STD)


def test_the_command_reads_a_profile_with_only_parked_domains(tmp_path: Path,
                                                              capsys: pytest.CaptureFixture):
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "example.yaml").write_text(
        f"name: example\ndiscovery:\n  domains: [{P}]\n")
    obs = tmp_path / "observations" / "2030-01-31T0930Z"
    obs.mkdir(parents=True)
    (obs / "assets.json").write_text(json.dumps(_rows(spf="v=spf1 ~all",
                                                      spf_flags=("softfail-all",))))
    config.set_workspace(tmp_path)
    assert cli.main(["comply", "sge", str(obs), "example", "--format", "text",
                     "--workspace", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "SGE-NED-SPF-01" in out and f"{P} (parked)" in out
