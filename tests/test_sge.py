"""Secure Government Email: the requirement set's own rules, and each evaluator's verdicts."""

from __future__ import annotations

import json
import re

import pytest

from takestock import sge
from takestock.model import CryptoAsset

D = "example.com"
STD = sge.load_standard()
REQS = {r["id"]: r for r in STD["requirements"]}


def rows_for(req_id: str, assets: list, domains: list[str] | None = None, **kw) -> list:
    report = sge.evaluate(assets, [D] if domains is None else domains, STD, **kw)
    return [r for r in report.rows if r.requirement == req_id]


def one(req_id: str, assets: list, **kw):
    got = rows_for(req_id, assets, **kw)
    assert len(got) == 1, got
    return got[0]


def spf(record: str, flags: list[str], **extra) -> dict:
    return {"name": f"SPF {D}", "protocol": "spf", "host": D, "flags": flags,
            "notes": record, "extra": {"record": record, **extra}}


def dmarc(record: str) -> dict:
    return {"name": f"DMARC {D}", "protocol": "dmarc", "host": D, "notes": record,
            "extra": {"record": record}}


# ── The data file's own rules ─────────────────────────────────────────

MUST_WORDS = re.compile(r"\b(must|mandatory)\b", re.IGNORECASE)
SHOULD_WORDS = re.compile(r"\b(should|recommend\w*|advised?)\b", re.IGNORECASE)


def test_every_level_rests_on_its_own_sentence_or_says_why_not():
    for r in STD["requirements"]:
        basis = r["level_basis"]
        assert basis["quote"].strip() and basis["where"].strip(), r["id"]
        words = MUST_WORDS if r["level"] == "must" else SHOULD_WORDS
        assert r["level"] in ("must", "recommended"), r["id"]
        if not words.search(basis["quote"]):
            assert basis.get("judgement", "").strip(), r["id"]


def test_every_requirement_cites_a_listed_document():
    for r in STD["requirements"]:
        assert r["document"] in STD["documents"], r["id"]
        assert sge.citation(STD, r).startswith(STD["documents"][r["document"]]["title"])
    assert sge.citation(STD, {"document": "absent"}) == ""
    cite = sge.citation(STD, REQS["SGE-SPF-01"])
    assert "v1.0 (2025-11-03), index AoGSD.SGE.Guidance.2025_249, SHA-256 ca53bf325c14574a…" in cite


def test_every_observed_requirement_has_an_evaluator():
    ids = {r["id"] for r in STD["requirements"]}
    assert len(ids) == len(STD["requirements"])
    for r in STD["requirements"]:
        assert r["measurable"] in ("observed", "not-collected", "no-instrument"), r["id"]
        if r["measurable"] == "observed":
            assert r["id"] in sge._EVALUATORS, r["id"]
    assert set(sge._EVALUATORS) <= ids


def test_the_floor_and_the_forbidden_list_agree():
    tls = REQS["SGE-TLS-01"]
    floor = sge._version_rank(tls["minimum_version"])
    assert floor is not None
    for v in tls["forbidden_versions"]:
        rank = sge._version_rank(v)
        assert rank is not None and rank < floor, v


def test_the_standard_loads_as_json():
    json.dumps(STD)


# ── Report shape ──────────────────────────────────────────────────────

def test_unobservable_requirements_are_unmeasured_never_passed():
    report = sge.evaluate([], [D], STD)
    assert {r.requirement for r in report.rows} == set(REQS)
    for r in report.rows:
        if REQS[r.requirement]["measurable"] == "no-instrument":
            assert r.status == sge.NOT_MEASURED and r.reason == sge.NO_INSTRUMENT
    counts = report.counts()
    assert counts[sge.PASS] == 0 and sum(counts.values()) == len(report.rows)
    assert set(report.unmeasured_reasons()) <= {sge.NO_INSTRUMENT, sge.NOT_COLLECTED,
                                                sge.INCONCLUSIVE}
    assert all(r.citation for r in report.rows)


def test_assets_may_be_dataclasses():
    a = CryptoAsset(name=f"SPF {D}", data_state="email-auth", protocol="spf", host=D,
                    flags=["hardfail-all"], extra={"record": "v=spf1 -all"})
    assert one("SGE-SPF-01", [a]).status == sge.PASS


# ── SPF ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("flags, status", [
    (["hardfail-all"], sge.PASS), (["softfail-all"], sge.FAIL), (["neutral-all"], sge.FAIL)])
def test_spf_is_graded_on_its_all_qualifier(flags, status):
    row = one("SGE-SPF-01", [spf("v=spf1 ~all", flags)])
    assert row.status == status
    assert row.breaches_must is (status == sge.FAIL)


def test_no_spf_reading_is_unmeasured():
    assert one("SGE-SPF-01", []).reason == sge.INCONCLUSIVE


LOOKUP = {"name": D, "measured": True,
          "lookups": [{"resolver": "192.0.2.53", "at": "2030-06-15T00:00:00Z",
                       "rcode": "NOERROR", "error": ""}]}


def no_spf() -> dict:
    return {"name": f"SPF {D}", "protocol": "spf", "host": D, "flags": ["no-spf-record"],
            "notes": "no v=spf1 record published",
            "extra": {"present": False, "record": "", "spf_records": [],
                      "legacy_spf2_records": [], "lookup": LOOKUP}}


def no_dmarc() -> dict:
    return {"name": f"DMARC {D}", "protocol": "dmarc", "host": D, "flags": ["no-dmarc-record"],
            "notes": "no DMARC record published",
            "extra": {"present": False, "record": "",
                      "lookup": {**LOOKUP, "name": f"_dmarc.{D}"}}}


def test_a_measured_absence_of_spf_is_not_met():
    row = one("SGE-SPF-01", [no_spf()])
    assert row.status == sge.FAIL and row.breaches_must
    assert row.observed == "no SPF record"
    assert "NOERROR from 192.0.2.53" in row.reason
    assert row.evidence == f"SPF {D}" and row.record == ""
    # The other SPF rows do not invent a record to read.
    ptr = one("SGE-SPF-R01", [no_spf()])
    assert ptr.status == sge.NOT_MEASURED and "SGE-SPF-01" in ptr.evidence
    assert one("SGE-SPF-R02", [no_spf()]).status == sge.PASS


def test_a_measured_absence_of_dmarc_is_not_met():
    row = one("SGE-DMARC-01", [no_dmarc()])
    assert row.status == sge.FAIL and row.observed == "no DMARC record"
    assert "_dmarc.example.com" in row.reason
    assert one("SGE-DMARC-04", [no_dmarc()]).status == sge.FAIL
    assert one("SGE-DMARC-R02", [no_dmarc()]).status == sge.FAIL
    for rid in ("SGE-DMARC-R01", "SGE-DMARC-R03"):
        got = one(rid, [no_dmarc()])
        assert got.status == sge.NOT_MEASURED and "SGE-DMARC-01" in got.evidence, rid
    # With no record at the root, a sub-domain has nothing to fall back to.
    sweep = {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
             "extra": {"control_usable": True, "names_in_scope": 2, "dmarc_records": {},
                       "read_at": "t", "resolvers": ["192.0.2.53"]}}
    ned_row = one("SGE-NED-DMARC-01", [no_dmarc(), sweep])
    assert ned_row.status == sge.FAIL and "no DMARC record published" not in ned_row.record
    align = one("SGE-NED-DMARC-R01", [no_dmarc(), sweep])
    assert align.status == sge.FAIL
    assert "publishes no DMARC record for them to fall back to" in align.subject_note


def test_an_spf_record_past_its_lookup_limit_says_the_qualifier_is_never_reached():
    surface = {"name": "s", "protocol": "spf-senders", "host": D,
               "flags": ["spf-lookup-limit-exceeded"],
               "extra": {"dns_lookups": 12, "dns_lookup_limit": 10}}
    row = one("SGE-SPF-01", [spf("v=spf1 -all", ["hardfail-all"]), surface])
    assert row.status == sge.PASS and "permerror" in row.reason


def test_ptr_fails_and_ranges_are_left_to_the_reader():
    assert one("SGE-SPF-R01", [spf("v=spf1 ptr -all", [])]).status == sge.FAIL
    row = one("SGE-SPF-R01", [spf("v=spf1 ip4:192.0.2.0/24 -all", [])])
    assert row.status == sge.NOT_MEASURED and "ip4:192.0.2.0/24" in row.observed


def test_legacy_spf2_records():
    row = one("SGE-SPF-R02", [spf("v=spf1 -all", [], legacy_spf2_records=['"spf2.0/pra -all"'],
                                  spf_records=["a", "b"])])
    assert row.status == sge.FAIL and "2 v=spf1 records" in row.subject_note
    assert one("SGE-SPF-R02", [spf("v=spf1 -all", [], legacy_spf2_records=[])]).status == sge.PASS
    assert one("SGE-SPF-R02", [spf("v=spf1 -all", [])]).reason == sge.NOT_COLLECTED


# ── DMARC ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("record, status", [
    ("v=DMARC1; p=reject", sge.PASS),
    ("v=DMARC1; p=reject; pct=100", sge.PASS),
    ("v=DMARC1; p=reject; pct=50", sge.FAIL),
    ("v=DMARC1; p=quarantine", sge.FAIL),
    ("v=DMARC1", sge.FAIL),
])
def test_dmarc_must_reject_all_failing_mail(record, status):
    assert one("SGE-DMARC-01", [dmarc(record)]).status == status


def test_reporting_address_fails_only_when_absent():
    assert one("SGE-DMARC-04", [dmarc("v=DMARC1; p=reject")]).status == sge.FAIL
    row = one("SGE-DMARC-04", [dmarc("v=DMARC1; p=reject; rua=mailto:d@reports.example.net")])
    assert row.status == sge.NOT_MEASURED and row.observed.endswith("reports.example.net")


def test_strict_dkim_alignment_passes_and_relaxed_stays_unsettled():
    assert one("SGE-DMARC-R01", [dmarc("v=DMARC1; p=reject; adkim=s")]).status == sge.PASS
    row = one("SGE-DMARC-R01", [dmarc("v=DMARC1; p=reject")])
    assert row.status == sge.NOT_MEASURED and row.observed == "adkim=r"
    assert "RFC 9989 §4.7 reads as relaxed" in row.evidence and row.subject_note == ""
    assert "7489" not in row.evidence


def test_a_bulk_mail_provider_in_the_sender_policy_is_an_indicator():
    surface = {"name": "s", "protocol": "spf-senders", "host": D,
               "extra": {"policies_traversed": "_spf.bulk.example.net, other.example.org"}}
    row = one("SGE-DMARC-R01", [dmarc("v=DMARC1; p=reject"), surface],
              bulk_mail_domains=("bulk.example.net",))
    assert "bulk.example.net, a bulk-mail provider" in row.subject_note
    assert sge.bulk_mail_domains({"sge": {"bulk_mail_domains": [" Bulk.Example.net "]}}) == (
        "bulk.example.net",)


def test_spf_alignment_and_unwanted_tags():
    assert one("SGE-DMARC-R02", [dmarc("v=DMARC1; p=reject; aspf=s")]).status == sge.PASS
    relaxed = one("SGE-DMARC-R02", [dmarc("v=DMARC1; p=reject")])
    assert relaxed.status == sge.FAIL and "RFC 9989 §4.7 reads as relaxed" in relaxed.reason
    row = one("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject; ruf=mailto:f@example.com; pct=100")])
    assert row.status == sge.FAIL and "ruf=" in row.observed
    assert "removed from DMARC by RFC 9989 (Appendix C.5.2)" in row.reason
    assert "DMARCbis" not in row.reason
    assert one("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject")]).status == sge.PASS


# ── MTA-STS and TLS-RPT ───────────────────────────────────────────────

def sts(mode: str = "enforce", published: bool = True, reachable: bool = True,
        mx: list[str] | None = None) -> dict:
    extra: dict = {"published": published, "policy_reachable": reachable}
    if mx is not None:
        extra["mx"] = mx
    return {"name": f"MTA-STS {D}", "protocol": "mta-sts", "host": D,
            "notes": f"mode={mode}" if reachable else "mode=unknown", "extra": extra}


def mx_row(*hosts: str) -> dict:
    return {"name": f"MX {D}", "protocol": "mx", "host": D,
            "extra": {"records": [f"10 {h}." for h in hosts]}}


def test_mta_sts_mode_and_publication():
    assert one("SGE-MTASTS-01", [sts()]).status == sge.PASS
    assert one("SGE-MTASTS-01", [sts("testing")]).status == sge.FAIL
    assert one("SGE-MTASTS-01", [sts(published=False)]).status == sge.FAIL
    unreachable = one("SGE-MTASTS-01", [sts(reachable=False)])
    assert unreachable.status == sge.NOT_MEASURED and "limit of this instrument" in unreachable.evidence


def test_the_policy_must_list_every_mx_host_without_wildcards():
    hosts = ["mx1.example.com", "mx2.example.com"]
    assert one("SGE-MTASTS-02", [sts(mx=hosts), mx_row(*hosts)]).status == sge.PASS
    missing = one("SGE-MTASTS-02", [sts(mx=["mx1.example.com", "spare.example.com"]),
                                    mx_row(*hosts)])
    assert missing.status == sge.FAIL and "mx2.example.com" in missing.reason
    assert "spare.example.com" in missing.subject_note
    wild = one("SGE-MTASTS-02", [sts(mx=["*.example.com"]), mx_row(*hosts)])
    assert wild.status == sge.FAIL and "wildcard" in wild.reason
    assert one("SGE-MTASTS-02", [sts(), mx_row(*hosts)]).reason == sge.NOT_COLLECTED


def test_tls_reporting():
    def rpt(published: bool, record: str) -> dict:
        return {"name": f"TLS-RPT {D}", "protocol": "tls-rpt", "host": D,
                "extra": {"published": published, "record": record}}
    assert one("SGE-TLSRPT-01", [rpt(True, "v=TLSRPTv1; rua=mailto:t@example.com")]).status == sge.PASS
    assert one("SGE-TLSRPT-01", [rpt(True, "v=TLSRPTv1;")]).status == sge.FAIL
    assert one("SGE-TLSRPT-01", [rpt(False, "")]).status == sge.FAIL
    # No row means the lookup did not settle; ct_dns writes a row whenever it does.
    assert one("SGE-TLSRPT-01", []).reason == sge.INCONCLUSIVE


# ── DKIM ──────────────────────────────────────────────────────────────

def dkim(selector: str, bits: int, key: str = "") -> dict:
    return {"name": f"DKIM {selector}.{D}", "protocol": "dkim", "host": D,
            "extra": {"selector": selector, "key_bits": bits, "public_key": key}}


def test_dkim_key_size_is_a_recommendation():
    short = one("SGE-DKIM-R01", [dkim("s1", 1024)])
    assert short.status == sge.FAIL and not short.breaches_must
    assert one("SGE-DKIM-R01", [dkim("s1", 2048)]).status == sge.PASS
    assert one("SGE-DKIM-R01", []).reason == sge.INCONCLUSIVE


def test_a_key_shared_between_selectors_fails_and_distinct_keys_settle_nothing():
    shared = one("SGE-DKIM-R02", [dkim("s1", 2048, "KEYA"), dkim("s2", 2048, "KEYA")])
    assert shared.status == sge.FAIL and "s1, s2" in shared.observed
    distinct = one("SGE-DKIM-R02", [dkim("s1", 2048, "KEYA"), dkim("s2", 2048, "KEYB")])
    assert distinct.status == sge.NOT_MEASURED


# ── Names that send no mail ───────────────────────────────────────────

def ned(protocol: str, missing: list[str], usable: bool = True, **extra) -> dict:
    expected = "v=spf1 -all" if protocol == "ned-spf" else "v=DKIM1; p="
    wildcard = f"*.{D}" if protocol == "ned-spf" else f"*._domainkey.{D}"
    return {"name": f"{protocol} {D}", "protocol": protocol, "host": D,
            "extra": {"expected_record": expected, "wildcard_name": wildcard,
                      "wildcard_conformant": False, "names_in_scope": 3,
                      "names_without_record": missing, "control_usable": usable,
                      "read_at": "2030-06-15T00:00:00Z", "resolvers": ["192.0.2.53"],
                      **extra}}


def test_a_missing_denying_record_fails_and_a_full_set_never_passes():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["a.example.com"])])
    assert row.status == sge.FAIL and row.breaches_must
    assert "1 of the 3 enumerated" in row.subject_note
    assert "true number is higher" in row.reason
    assert one("SGE-NED-SPF-01", [ned("ned-spf", [])]).status == sge.NOT_MEASURED
    assert one("SGE-NED-SPF-01", [ned("ned-spf", ["a"], usable=False)]).reason == sge.INCONCLUSIVE


def test_the_dkim_wildcard_read_must_be_the_one_the_standard_names():
    row = one("SGE-NED-DKIM-01", [ned("ned-dkim", ["a.example.com"],
                                      wildcard_name=f"*.{D}")])
    assert row.status == sge.NOT_MEASURED and "what was measured is not" in row.evidence


def test_sub_domain_dmarc():
    root = dmarc("v=DMARC1; p=reject; sp=none")
    assert one("SGE-NED-DMARC-01", [root]).status == sge.FAIL
    sweep = {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
             "extra": {"control_usable": True, "names_in_scope": 2,
                       "dmarc_records": {"a.example.com": "v=DMARC1; p=none; sp=reject"},
                       "read_at": "t", "resolvers": ["192.0.2.53"]}}
    rejecting_root = dmarc("v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@example.com")
    row = one("SGE-NED-DMARC-01", [rejecting_root, sweep])
    assert row.status == sge.FAIL and "a.example.com" in row.subject_note
    sp_row = one("SGE-DMARC-R05", [rejecting_root, sweep])
    assert sp_row.status == sge.FAIL and "a.example.com" in sp_row.subject_note
    align = one("SGE-NED-DMARC-R01", [rejecting_root, sweep])
    assert align.status == sge.FAIL and "no rua=" in align.subject_note
    assert one("SGE-NED-DMARC-01", [rejecting_root]).reason == sge.NOT_COLLECTED


# ── TLS on the mail path ──────────────────────────────────────────────

def gateway(host: str, versions: list[str], flags: list[str] | None = None) -> dict:
    return {"name": f"smtp {host}", "protocol": "tls", "host": host,
            "protocol_versions": versions, "flags": flags or []}


def test_the_receiving_floor():
    base = [mx_row("mx1.example.com")]
    rows = rows_for("SGE-TLS-01", base + [gateway("mx1.example.com", ["TLSv1.2", "TLSv1.3"])])
    assert rows[0].status == sge.PASS and "receiving path only" in rows[0].reason
    assert rows[1].subject == "outbound mail (all paths)" and rows[1].reason == sge.NOT_COLLECTED
    bad = rows_for("SGE-TLS-01", base + [gateway("mx1.example.com", ["TLSv1.0", "TLSv1.2"])])
    assert bad[0].status == sge.FAIL
    odd = rows_for("SGE-TLS-01", base + [gateway("mx1.example.com", ["QUICv9"])])
    assert odd[0].status == sge.NOT_MEASURED and "QUICv9" in odd[0].evidence
    clear = rows_for("SGE-TLS-01", base + [gateway("mx1.example.com", [], ["plaintext:smtp"])])
    assert clear[0].status == sge.FAIL and clear[0].observed == "no TLS offered"
    assert rows_for("SGE-TLS-01", [])[0].reason == sge.NOT_COLLECTED


def transport(direction: str, messages: int, clear: int, dist: str, **extra) -> dict:
    return {"name": f"transport {direction}", "source": sge.TRANSPORT_SOURCE,
            "extra": {"direction": direction, "messages": messages, "no_tls_messages": clear,
                      "tls_distribution": dist, "window": "2030-06-01 to 2030-06-14",
                      **extra}}


def test_the_sending_clause_reads_the_transport_export():
    clean = rows_for("SGE-TLS-01", [transport("outbound", 1000, 0, "TLS1.2=400; TLS1.3=600")])
    assert clean[-1].status == sge.PASS and "2030-06-01 to 2030-06-14" in clean[-1].reason
    dirty = rows_for("SGE-TLS-01", [transport("outbound", 1000, 10,
                                              "TLS1.2=900; TLS1.0=90; No TLS=10")])
    assert dirty[-1].status == sge.FAIL
    assert "10 of the 1,000" in dirty[-1].reason and "TLS1.0" in dirty[-1].reason
    inbound_only = rows_for("SGE-TLS-01", [transport("inbound", 5, 5, "No TLS=5")])
    assert inbound_only[-1].reason == sge.NOT_COLLECTED


def test_implicit_tls_is_never_passed():
    assert one("SGE-ITLS-01", []).reason == sge.NOT_COLLECTED
    row = one("SGE-ITLS-01", [transport("outbound", 100, 0, "TLS1.2=100",
                                        govt_messages=40, govt_no_tls_messages=0,
                                        govt_tls_distribution="TLS1.2=40",
                                        govt_counterparty_domains=4, connector_present="no",
                                        govt_days=3)])
    assert row.status == sge.NOT_MEASURED and row.reason == sge.INCONCLUSIVE
    assert row.observed.startswith("40 messages with government organisations")
    assert "travelled on a path with no configured route" in row.evidence


# ── Writing the verdict back onto assets ──────────────────────────────

def test_a_must_breach_marks_the_asset_behind_it():
    a = CryptoAsset(name=f"SPF {D}", data_state="email-auth", protocol="spf", host=D,
                    flags=["softfail-all"], extra={"record": "v=spf1 ~all"})
    b = CryptoAsset(name=f"DKIM s1.{D}", data_state="email-auth", protocol="dkim", host=D,
                    extra={"selector": "s1", "key_bits": 1024})
    assert sge.apply_conformance([a, b], [D], STD) == 1
    assert a.standards_verdict == sge.NON_CONFORMANT
    assert a.standards_requirement.startswith("SGE-SPF-01 (must)")
    assert "SPF Deployment Guide" in a.standards_citation
    assert b.standards_verdict == ""  # a recommendation unmet is not a must breached
    assert sge.apply_conformance([a], [], STD) == 0


def test_the_text_report_lists_unmet_musts():
    report = sge.evaluate([spf("v=spf1 ~all", ["softfail-all"])], [D], STD)
    text = sge._format(report, [D])
    assert "1 unmet MUST requirement(s)." in text
    assert "SGE-SPF-01 — SPF record ending in hardfail: example.com" in text
