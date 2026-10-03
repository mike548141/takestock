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
}


def parked(monkeypatch, table: dict, status: dict | None = None):
    monkeypatch.setattr(dnsevidence, "run", resolving(table, status))
    rows, failures = ct_dns.parked_assets(P, NOW, dnsfake.RESOLVERS)
    return {r.protocol: r for r in rows}, failures


def test_a_parked_domain_yields_spf_dmarc_dkim_and_null_mx_rows(monkeypatch):
    rows, failures = parked(monkeypatch, CLEAN)
    assert failures == []
    assert set(rows) == {"spf", "dmarc", ct_dns.DKIM_WILDCARD, ct_dns.NULL_MX}
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
                    "extra": {"present": bool(spf), "record": spf, "parked": True}})
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
    [row] = [r for r in report.rows if r.requirement == req]
    assert row.parked and row.subject == P
    return row


def test_a_clean_parked_domain_meets_the_rules_for_domains_that_send_no_mail():
    report = sge.evaluate(_rows(), [], STD, parked=[P])
    by = {r.requirement: r for r in report.rows if r.parked}
    assert {k: v.status for k, v in by.items()} == {
        "SGE-NED-SPF-01": sge.PASS, "SGE-NED-DMARC-01": sge.PASS,
        "SGE-NED-DMARC-R01": sge.PASS, "SGE-NED-DKIM-01": sge.PASS}
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
    assert cli.main(["sge", str(obs), "example", "--workspace", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "SGE-NED-SPF-01" in out and f"{P} (parked)" in out
