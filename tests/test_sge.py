"""Secure Government Email: the requirement set's own rules, and each evaluator's verdicts."""

from __future__ import annotations

import json
import re

import pytest

from takestock import dnsevidence, sge
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


def fetched(status: int | None = 200, valid: bool | None = True, version: str = "STSv1",
            max_age: str = "604800", **more) -> dict:
    row = sts(mx=["mx1.example.com"], **more)
    row["extra"] |= {"policy_reachable": status is not None, "policy_http_status": status,
                     "policy_certificate_valid": valid, "policy_version": version,
                     "policy_max_age": max_age, "policy_fetch_error": ""}
    return row


def test_a_policy_a_sender_cannot_validly_fetch_is_not_met():
    assert one("SGE-MTASTS-01", [fetched()]).status == sge.PASS
    # RFC 8461 §3.3: the certificate must validate, and only a 200 answer is a policy.
    bad_cert = fetched(status=None, valid=False)
    bad_cert["extra"]["policy_fetch_error"] = "curl: (60) SSL certificate problem"
    row = one("SGE-MTASTS-01", [bad_cert])
    assert row.status == sge.FAIL and "§3.3" in row.reason and "curl: (60)" in row.reason
    row = one("SGE-MTASTS-01", [fetched(status=404)])
    assert row.status == sge.FAIL and "HTTP 404" in row.reason
    assert one("SGE-MTASTS-01", [fetched(status=301)]).status == sge.FAIL
    # RFC 8461 §3.2: version: STSv1, and max_age of whole seconds up to 31557600.
    row = one("SGE-MTASTS-01", [fetched(version="STSv2")])
    assert row.status == sge.FAIL and "STSv2" in row.reason
    assert one("SGE-MTASTS-01", [fetched(max_age="")]).status == sge.FAIL
    assert one("SGE-MTASTS-01", [fetched(max_age="31557601")]).status == sge.FAIL
    assert one("SGE-MTASTS-01", [fetched(max_age="31557600")]).status == sge.PASS
    # A fetch that never got an answer is still a limit of the instrument.
    offline = fetched(status=None, valid=None)
    offline["notes"] = "mode=unknown"
    row = one("SGE-MTASTS-01", [offline])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    # The mx entries of a policy that is not valid are not compared.
    row = one("SGE-MTASTS-02", [fetched(status=404), mx_row("mx1.example.com")])
    assert row.status == sge.NOT_MEASURED and "SGE-MTASTS-01" in row.evidence


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
    assert "true number may be higher" in row.reason
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


@pytest.mark.parametrize("np_", ["none", "quarantine"])
def test_a_root_np_weaker_than_reject_fails_the_sub_domain_policy(np_):
    # RFC 9989 §4.7: np= is the policy a receiver applies to names that do not exist.
    row = one("SGE-NED-DMARC-01", [dmarc(f"v=DMARC1; p=reject; np={np_}")])
    assert (row.status, row.observed) == (sge.FAIL, f"np={np_}") and row.breaches_must
    assert "RFC 9989 §4.7" in row.reason and "does not exist in DNS" in row.reason
    both = one("SGE-NED-DMARC-01", [dmarc(f"v=DMARC1; p=reject; sp=none; np={np_}")])
    assert both.observed == f"sp=none; np={np_}"
    # np=reject, or no np= (inheriting sp=, then p=), leaves the root settling nothing.
    for record in ("v=DMARC1; p=reject; np=reject", "v=DMARC1; p=reject"):
        assert one("SGE-NED-DMARC-01", [dmarc(record)]).reason == sge.NOT_COLLECTED


def test_a_swept_name_that_does_not_exist_falls_back_to_np():
    sweep = {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
             "extra": {"control_usable": True, "names_in_scope": 2, "dmarc_records": {},
                       "names_nonexistent": ["gone.example.com"],
                       "read_at": "t", "resolvers": ["192.0.2.53"]}}
    # sp=quarantine fails only the name that exists; np= is reject, so the other is covered.
    row = one("SGE-NED-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine; np=reject"), sweep])
    assert row.status == sge.FAIL and row.observed.startswith("1 of 2")
    # With no np=, a name that does not exist inherits sp=, as RFC 9989 §4.7 says.
    row = one("SGE-NED-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine"), sweep])
    assert row.observed.startswith("2 of 2")


def test_a_wildcard_explained_control_lets_the_sweep_grade():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["node.example.com"],
                                     control_basis="wildcard")])
    assert row.status == sge.FAIL and "answered by the published wildcard" in row.subject_note
    assert "answered by the published wildcard" not in one(
        "SGE-NED-SPF-01", [ned("ned-spf", ["node.example.com"])]).subject_note


WHOLE = {"population": {"zone": D, "zones": [D], "complete": True,
                         "attested_by": "Example Widgets Ltd, DNS administrator",
                         "attested_on": "2030-01-31"},
         "names_disagreeing_with_zone": []}


def test_an_attested_complete_zone_lets_the_sweep_pass():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", [], **WHOLE)])
    assert row.status == sge.PASS
    assert "whole population, not a floor" in row.reason
    assert "Example Widgets Ltd, DNS administrator attested complete on 2030-01-31" in row.reason
    # A failing row over the whole population says so instead of calling its count a floor.
    failing = one("SGE-NED-SPF-01", [ned("ned-spf", ["a.example.com"], **WHOLE)])
    assert failing.status == sge.FAIL and "true number" not in failing.reason
    rejecting_root = dmarc("v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@example.com")
    sweep = walked_sweep({}, ["a.example.com", "b.example.com"], **WHOLE)
    for req_id in ("SGE-NED-DMARC-01", "SGE-NED-DMARC-R01", "SGE-DMARC-R05"):
        assert one(req_id, [rejecting_root, sweep]).status == sge.PASS, req_id


@pytest.mark.parametrize("spoiler, words", [
    ({"names_unread": ["c.example.com"]}, "some names were not read"),
    ({"names_unsettled": ["c.example.com"]}, "the resolvers disagreed"),
    ({"names_dropped_by_cap": 4}, "beyond the sweep's ceiling"),
    ({"names_disagreeing_with_zone": ["new.example.com"]}, "no longer describe the zone"),
    ({"population": {**WHOLE["population"], "complete": False,
                     "why_not": "no zone file for example.com was supplied"}},
     "no zone file for example.com was supplied"),
])
def test_an_attested_zone_still_leaves_a_floor_when_the_reading_falls_short(spoiler, words):
    row = one("SGE-NED-SPF-01", [ned("ned-spf", [], **{**WHOLE, **spoiler})])
    assert row.status == sge.NOT_MEASURED and words in row.evidence
    assert "A zone file is attested complete for example.com" in row.evidence


def test_a_resolver_that_invents_answers_is_named_not_read_as_a_wildcard():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["a"], usable=False,
                                     control_basis=dnsevidence.RESOLVER_SYNTHESISES)])
    assert row.reason == sge.INCONCLUSIVE and "unusable resolver reading" in row.evidence
    assert "control name answered" in one(
        "SGE-NED-SPF-01", [ned("ned-spf", ["a"], usable=False)]).evidence


def test_the_rows_say_where_the_swept_names_came_from():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["a.example.com"], names_by_source={
        "certificate transparency": 2, "zone file": 3})])
    assert "names from certificate transparency (2), zone file (3)" in row.subject_note


# ── Policy discovery: the DNS Tree Walk (RFC 9989 §4.10) ──────────────

def held(records: dict, unsettled: tuple[str, ...] = ()) -> sge.HeldRecords:
    return sge.HeldRecords(D, dict(records), set(unsettled))


def test_the_tree_walk_follows_rfc_9989_section_4_10():
    assert dnsevidence.tree_walk("a.mail.example.com") == ["mail.example.com", "example.com",
                                                           "com"]
    # More than eight labels: the walk jumps to the right-most seven (§4.10 step 4).
    assert dnsevidence.tree_walk("a.b.c.d.e.f.g.h.i.j.mail.example.com")[:2] == [
        "g.h.i.j.mail.example.com", "h.i.j.mail.example.com"]
    assert dnsevidence.intermediate_names(D, ["a.mail.example.com", "b.example.com"]) == [
        "mail.example.com"]


def test_the_shortest_record_governs_unless_an_intermediate_says_psd_n():
    root, mid = "v=DMARC1; p=reject; sp=none", "v=DMARC1; p=reject"
    name = "a.mail.example.com"
    base = {D: root, "mail.example.com": mid, name: ""}
    # §4.10.2 step 3: the record with the fewest labels is the Organizational Domain's.
    assert sge.policy_record(name, held(base)) == (D, root)
    # Step 1: psd=n makes the intermediate name the Organizational Domain.
    psd_n = "v=DMARC1; p=reject; psd=n"
    assert sge.policy_record(name, held({**base, "mail.example.com": psd_n})) == (
        "mail.example.com", psd_n)
    # With nothing at the domain, the intermediate record is the shortest found.
    assert sge.policy_record(name, held({D: "", "mail.example.com": mid, name: ""})) == (
        "mail.example.com", mid)
    # Step 2: psd=y at the domain makes the name one label below it the Organizational Domain.
    psd_y = "v=DMARC1; p=none; psd=y"
    assert sge.policy_record(name, held({**base, D: psd_y})) == ("mail.example.com", mid)
    # A name's own record is always the one applied.
    assert sge.policy_record("mail.example.com", held(base)) == ("mail.example.com", mid)
    # Nothing found, and a walk through a name that was not read, are kept apart.
    assert sge.policy_record(name, held({D: "", "mail.example.com": "", name: ""})) == ("", "")
    assert sge.policy_record(name, held({D: root, name: ""})) is sge.UNREAD
    assert sge.policy_record(name, held(base, ("mail.example.com",))) is sge.UNREAD


def walked_sweep(records: dict, without: list[str], **extra) -> dict:
    return {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
            "extra": {"control_usable": True, "names_in_scope": len(records) + len(without),
                      "dmarc_records": records, "names_without_own_dmarc": without,
                      "read_at": "t", "resolvers": ["192.0.2.53"], **extra}}


def test_a_psd_n_intermediate_record_governs_the_swept_names_beneath_it():
    weak_root = dmarc("v=DMARC1; p=reject; sp=none")
    names = ["a.mail.example.com", "b.mail.example.com"]
    strict = "v=DMARC1; p=reject; psd=n; adkim=s; aspf=s; rua=mailto:d@example.com"
    sweep = walked_sweep({}, names, intermediate_dmarc={"mail.example.com": strict})
    rows = {r.requirement: r for r in sge.evaluate([weak_root, sweep], [D], STD).rows
            if r.subject == D and r.requirement in ("SGE-NED-DMARC-01", "SGE-NED-DMARC-R01")}
    # The root's own sp=none still fails the root's row; the names beneath are covered.
    assert rows["SGE-NED-DMARC-01"].observed == "sp=none"
    beneath = one("SGE-NED-DMARC-01",
                  [dmarc("v=DMARC1; p=reject; sp=quarantine; np=reject"), sweep])
    assert beneath.status == sge.NOT_MEASURED
    assert "a.mail.example.com by mail.example.com" in beneath.subject_note
    # Without psd=n the root governs them, as before.
    plain = walked_sweep({}, names, intermediate_dmarc={"mail.example.com": "v=DMARC1; p=reject"})
    row = one("SGE-NED-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine; np=reject"), plain])
    assert (row.status, row.observed) == (sge.FAIL, "2 of 2 sub-domains without a reject policy")
    align = one("SGE-NED-DMARC-R01", [dmarc("v=DMARC1; p=reject"), sweep])
    assert align.status == sge.NOT_MEASURED


def test_a_name_whose_walk_passes_an_unread_name_is_counted_neither_way():
    sweep = walked_sweep({}, ["a.mail.example.com", "b.example.com"],
                         intermediate_unsettled=["mail.example.com"])
    row = one("SGE-NED-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine"), sweep])
    assert (row.status, row.observed) == (sge.FAIL, "1 of 2 sub-domains without a reject policy")
    assert "1 name(s) counted neither way" in row.subject_note
    assert "a.mail.example.com" in row.subject_note


def test_a_mail_handling_name_takes_the_record_discovery_finds():
    names = {"a.mail.example.com": sub()}
    root = dmarc("v=DMARC1; p=reject; sp=quarantine")
    governed = walked_sweep({}, [], intermediate_dmarc={"mail.example.com": "v=DMARC1; p=reject; "
                                                                           "psd=n"})
    assert discovered("SGE-DMARC-01", [root, governed, mail_subs(names)]).status == (
        sge.NOT_MEASURED)
    plain = walked_sweep({}, [], intermediate_dmarc={"mail.example.com": ""})
    row = discovered("SGE-DMARC-01", [root, plain, mail_subs(names)])
    assert row.status == sge.FAIL and f"record at {D}" in row.reason


def test_a_mail_handling_name_whose_walk_is_unread_is_counted_neither_way():
    names = {"a.mail.example.com": sub(), "b.example.com": sub()}
    sweep = walked_sweep({}, [], intermediate_unsettled=["mail.example.com"])
    row = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject"), sweep, mail_subs(names)])
    # Only the settled name is read; the other is listed, never counted as meeting it.
    assert (row.status, row.observed) == (sge.NOT_MEASURED, "all 1 read meet it")
    assert "1 of the 2 name(s) counted neither way" in row.subject_note
    assert "a.mail.example.com" not in row.evidence
    weak = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine"), sweep,
                                       mail_subs(names)])
    assert (weak.status, weak.observed) == (sge.FAIL, "1 of 1 short of it")
    alone = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject"), sweep,
                                        mail_subs({"a.mail.example.com": sub()})])
    assert (alone.status, alone.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)


# ── Discovered sub-domains that handle mail ───────────────────────────

SUBJECT = sge.discovered_mail_subject(D)


def mail_subs(names: dict, usable: bool = True) -> dict:
    return {"name": f"Mail-handling sub-domains of {D}", "protocol": "subdomain-mail",
            "host": D, "extra": {"control_usable": usable, "read_at": "t",
                                 "resolvers": ["192.0.2.53"], "names": names}}


def sub(spf: str = "v=spf1 -all", dmarc: str = "", exists: bool = True) -> dict:
    return {"spf_record": spf, "dmarc_record": dmarc, "mx_records": ["10 mx.example.net."],
            "exists": exists, "because": "publishes an MX record"}


def discovered(req_id: str, assets: list):
    [row] = [r for r in rows_for(req_id, assets) if r.subject == SUBJECT]
    assert row.discovered and sge.DISCOVERED_NOTE in row.subject_note
    return row


def test_a_discovered_mail_sub_domain_is_graded_against_the_email_domain_spf_rule():
    assets = [mail_subs({"mail.example.com": sub("v=spf1 mx ~all"),
                         "out.example.com": sub()})]
    row = discovered("SGE-SPF-01", assets)
    assert (row.status, row.observed) == (sge.FAIL, "1 of 2 short of it") and row.breaches_must
    assert "mail.example.com: its record ends ~all" in row.reason
    assert "out.example.com" not in row.reason
    # Every name read meeting it settles nothing: the names are a floor.
    clean = discovered("SGE-SPF-01", [mail_subs({"out.example.com": sub()})])
    assert (clean.status, clean.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)
    assert "(discovered)" in sge._format(sge.evaluate(assets, [D], STD), [D])


def test_a_discovered_name_without_dmarc_falls_back_to_the_organisational_record():
    assets = [mail_subs({"mail.example.com": sub()})]
    # No record of its own is not a failure by itself: p=reject at the root covers it.
    row = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject"), *assets])
    assert row.status == sge.NOT_MEASURED
    row = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject; sp=quarantine"), *assets])
    assert row.status == sge.FAIL and "sp=quarantine" in row.reason
    # A name that does not exist falls back to np= instead.
    gone = [mail_subs({"old.example.com": sub(exists=False)})]
    row = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject; np=none"), *gone])
    assert row.status == sge.FAIL and "np=none" in row.reason
    # No record anywhere is a failure; so is a record of its own short of reject.
    assert discovered("SGE-DMARC-01", assets).status == sge.FAIL
    own = [mail_subs({"mail.example.com": sub(dmarc="v=DMARC1; p=none")})]
    row = discovered("SGE-DMARC-01", [dmarc("v=DMARC1; p=reject"), *own])
    assert row.status == sge.FAIL and "p=none" in row.reason


def test_a_discovered_name_setting_sp_is_a_recommendation_unmet():
    own = [mail_subs({"mail.example.com": sub(dmarc="v=DMARC1; p=reject; sp=reject")})]
    row = discovered("SGE-DMARC-R05", own)
    assert row.status == sge.FAIL and not row.breaches_must


def test_a_discovered_name_publishing_an_unwanted_dmarc_tag_is_a_recommendation_unmet():
    own = [mail_subs({"mail.example.com": sub(dmarc="v=DMARC1; p=reject; fo=1"),
                      "out.example.com": sub()})]
    row = discovered("SGE-DMARC-R03", own)
    assert row.status == sge.FAIL and not row.breaches_must
    assert "mail.example.com: its own record publishes fo" in row.reason
    assert "out.example.com" not in row.reason


def test_unwanted_dmarc_tags_on_the_swept_names_beneath_an_email_domain():
    sweep = {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
             "extra": {"control_usable": True, "names_in_scope": 2,
                       "dmarc_records": {"a.example.com": "v=DMARC1; p=reject; pct=50"},
                       "read_at": "t", "resolvers": ["192.0.2.53"]}}
    rows = {r.subject: r for r in rows_for("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject"), sweep])}
    assert rows[D].status == sge.PASS
    beneath = rows[sge.parked_subdomains_subject(D)]
    assert beneath.status == sge.FAIL and not beneath.breaches_must
    assert "a.example.com (pct)" in beneath.reason
    sweep["extra"]["dmarc_records"] = {"a.example.com": "v=DMARC1; p=reject"}
    rows = {r.subject: r for r in rows_for("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject"), sweep])}
    assert rows[sge.parked_subdomains_subject(D)].status == sge.NOT_MEASURED
    # No sweep reading: the domain's own row stands alone.
    assert len(rows_for("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject")])) == 1


def test_no_discovered_row_without_mail_handling_names_and_none_graded_on_a_bad_control():
    assert not [r for r in rows_for("SGE-SPF-01", [mail_subs({})]) if r.discovered]
    row = discovered("SGE-SPF-01", [mail_subs({"mail.example.com": sub("")}, usable=False)])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)


@pytest.mark.parametrize("req_id, protocol", [("SGE-NED-SPF-01", "ned-spf"),
                                              ("SGE-NED-DKIM-01", "ned-dkim")])
def test_a_set_aside_name_is_called_graded_as_an_email_domain_only_when_that_grading_is_here(
        req_id, protocol):
    graded = "graded against the rules for email domains instead"
    ungraded = "because this observation holds no usable mail-handling reading of them"
    sweep = ned(protocol, ["a.example.com"],
                names_email_enabled=["mail.example.com", "out.example.com"])
    # The mail-handling row is here and holds both names: both are graded as email domains.
    both = {"mail.example.com": sub(), "out.example.com": sub()}
    note = one(req_id, [sweep, mail_subs(both)]).subject_note
    assert f"{graded}: mail.example.com, out.example.com" in note and ungraded not in note
    # No mail-handling row at all: the note must not claim a grading the report lacks.
    note = one(req_id, [sweep]).subject_note
    assert graded not in note
    assert f"{ungraded}: mail.example.com, out.example.com" in note
    # A mail-handling row on an unusable control grades nothing either.
    note = one(req_id, [sweep, mail_subs(both, usable=False)]).subject_note
    assert graded not in note and f"{ungraded}: mail.example.com, out.example.com" in note
    # A row holding one of the names: each is described as what happened to it.
    note = one(req_id, [sweep, mail_subs({"mail.example.com": sub()})]).subject_note
    assert f"{graded}: mail.example.com;" in note and f"{ungraded}: out.example.com" in note
    # Another domain's mail-handling row says nothing about this one's names.
    elsewhere = {**mail_subs(both), "host": "example.org"}
    assert graded not in one(req_id, [sweep, elsewhere]).subject_note


def test_mail_handling_names_beneath_a_parked_domain_are_marked_parked_and_discovered():
    assets = [{**mail_subs({"mail.example.com": sub("")}), "host": "example.org"}]
    report = sge.evaluate(assets, [], STD, parked=["example.org"])
    [row] = [r for r in report.rows if r.requirement == "SGE-SPF-01"]
    assert (row.subject, row.parked, row.discovered, row.status) == (
        sge.discovered_mail_subject("example.org"), True, True, sge.FAIL)


# ── Discovered mail-handling names: MTA-STS, TLS-RPT and DKIM ─────────

def sts_read(mode: str = "enforce", published: bool = True, status: int | None = 200,
             valid: bool | None = True, mx: list[str] | None = None, **more) -> dict:
    return {"published": published, "policy_fetched": published,
            "policy_reachable": status is not None, "policy_http_status": status,
            "policy_certificate_valid": valid, "policy_fetch_error": "",
            "policy_version": "STSv1" if status == 200 else "",
            "policy_max_age": "604800" if status == 200 else "",
            "mode": mode if status == 200 else "",
            "mx": (["mx.example.net"] if mx is None else mx) if status == 200 else [],
            "record": "v=STSv1; id=20300101T000000" if published else "", **more}


def read_sub(mta_sts: dict | None = None, rpt: str | None = "v=TLSRPTv1; rua=mailto:t@example.com",
             keys: list[dict] | None = None, not_read: dict | None = None, **base) -> dict:
    """A mail-handling name as the sweep row holds it once its mail records were read."""
    out = {**sub(**base), "not_read": dict(not_read or {}), "dkim": list(keys or []),
           "dkim_selectors_tried": 11}
    if mta_sts is not None:
        out["mta_sts"] = mta_sts
    if rpt is not None:
        out["tls_rpt"] = {"published": rpt.startswith("v=TLSRPTv1"), "record": rpt}
    return out


KEY_1024, KEY_2048 = "A" * 216, "B" * 392


def test_a_discovered_name_is_graded_for_mta_sts_as_an_email_domain_is():
    names = {"a.example.com": read_sub(sts_read()),
             "b.example.com": read_sub(sts_read("testing")),
             "c.example.com": read_sub(sts_read(published=False, status=None, valid=None)),
             "d.example.com": read_sub(sts_read(status=None, valid=False)),
             "e.example.com": read_sub(sts_read(status=404))}
    row = discovered("SGE-MTASTS-01", [mail_subs(names)])
    assert (row.status, row.observed) == (sge.FAIL, "4 of 5 short of it") and row.breaches_must
    assert "b.example.com: its policy mode is testing" in row.reason
    assert "c.example.com: publishes no _mta-sts TXT record" in row.reason
    assert "d.example.com: its policy is not valid: the policy host's certificate" in row.reason
    assert "e.example.com: its policy is not valid: the policy host answered HTTP 404" in row.reason
    assert "a.example.com:" not in row.reason
    # A policy the instrument could not fetch is counted neither way, never a breach.
    lost = {"a.example.com": read_sub(sts_read(status=None, valid=None,
                                               policy_fetch_error="curl: (28) timed out"))}
    row = discovered("SGE-MTASTS-01", [mail_subs(lost)])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    assert "could not be fetched from this machine" in row.subject_note
    # Every name read meeting it is still not a pass.
    clean = discovered("SGE-MTASTS-01", [mail_subs({"a.example.com": read_sub(sts_read())})])
    assert (clean.status, clean.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)


def test_a_discovered_name_policy_must_list_its_mx_hosts_without_wildcards():
    names = {"a.example.com": read_sub(sts_read(mx=["mx.example.net"])),
             "b.example.com": read_sub(sts_read(mx=["other.example.net"])),
             "c.example.com": read_sub(sts_read(mx=["*.example.net"]))}
    row = discovered("SGE-MTASTS-02", [mail_subs(names)])
    assert (row.status, row.observed) == (sge.FAIL, "2 of 3 short of it")
    assert "b.example.com: its MX host(s) mx.example.net are matched by no mx entry" in row.reason
    assert "c.example.com: its policy uses the wildcard entry *.example.net" in row.reason
    # A null MX (RFC 7505) names no host for the policy to list.
    null = discovered("SGE-MTASTS-02", [mail_subs(
        {"a.example.com": {**read_sub(sts_read()), "mx_records": ["0 ."]}})])
    assert null.status == sge.NOT_MEASURED
    # No valid policy: graded under SGE-MTASTS-01, counted neither way here.
    none = discovered("SGE-MTASTS-02", [mail_subs(
        {"a.example.com": read_sub(sts_read(published=False, status=None, valid=None))})])
    assert none.status == sge.NOT_MEASURED and "graded under SGE-MTASTS-01" in none.subject_note


def test_a_discovered_name_needs_tls_reporting_with_an_address():
    names = {"a.example.com": read_sub(sts_read()),
             "b.example.com": read_sub(sts_read(), rpt="v=TLSRPTv1;"),
             "c.example.com": read_sub(sts_read(), rpt="")}
    row = discovered("SGE-TLSRPT-01", [mail_subs(names)])
    assert (row.status, row.observed) == (sge.FAIL, "2 of 3 short of it") and row.breaches_must
    assert "b.example.com: its v=TLSRPTv1 record carries no rua=" in row.reason
    assert "c.example.com: publishes no _smtp._tls TXT record" in row.reason


def test_a_record_whose_lookup_did_not_settle_counts_neither_way_and_says_why():
    names = {"a.example.com": read_sub(sts_read(), rpt=None, not_read={
                 "TLS-RPT": "_smtp._tls.a.example.com: SERVFAIL"}),
             "b.example.com": read_sub(sts_read(), rpt="")}
    row = discovered("SGE-TLSRPT-01", [mail_subs(names)])
    assert (row.status, row.observed) == (sge.FAIL, "1 of 1 short of it")
    assert "1 of the 2 name(s) counted neither way" in row.subject_note
    assert "a.example.com (its TLS-RPT lookup did not settle" in row.subject_note
    assert "SERVFAIL" in row.subject_note


def test_an_observation_that_never_read_the_records_reads_not_collected():
    # A sweep row taken before mail-handling names were read holds no such readings.
    row = discovered("SGE-TLSRPT-01", [mail_subs({"a.example.com": sub()})])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)
    assert "did not read its TLS-RPT record" in row.subject_note
    for req_id in ("SGE-MTASTS-01", "SGE-MTASTS-02", "SGE-DKIM-R01", "SGE-DKIM-R02"):
        old = discovered(req_id, [mail_subs({"a.example.com": sub()})])
        assert (old.status, old.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED), req_id


def test_a_discovered_name_dkim_key_is_graded_only_under_a_selector_that_answered():
    weak = {"selector": "s1", "key_bits": 1024, "public_key": KEY_1024}
    strong = {"selector": "s2", "key_bits": 2048, "public_key": KEY_2048}
    names = {"a.example.com": read_sub(sts_read(), keys=[weak, strong]),
             "b.example.com": read_sub(sts_read(), keys=[strong])}
    row = discovered("SGE-DKIM-R01", [mail_subs(names)])
    assert (row.status, row.observed) == (sge.FAIL, "1 of 2 short of it")
    assert not row.breaches_must and "s1 (1024-bit)" in row.reason
    # No selector answering is silence: counted neither way, never a pass or a fail.
    silent = discovered("SGE-DKIM-R01", [mail_subs({"a.example.com": read_sub(sts_read())})])
    assert (silent.status, silent.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    assert "none of the 11 selector(s) tried answered" in silent.subject_note
    # The empty key publishes no key to size.
    blank = {"selector": "s1", "key_bits": None, "public_key": ""}
    empty = discovered("SGE-DKIM-R01", [mail_subs({"a.example.com": read_sub(sts_read(),
                                                                              keys=[blank])})])
    assert empty.status == sge.NOT_MEASURED and "the empty key" in empty.subject_note


def test_a_discovered_name_sharing_a_key_with_another_selector_is_a_recommendation_unmet():
    names = {"a.example.com": read_sub(sts_read(), keys=[
        {"selector": "s2", "key_bits": 2048, "public_key": KEY_2048}])}
    row = discovered("SGE-DKIM-R02", [dkim("s1", 2048, KEY_2048), mail_subs(names)])
    assert row.status == sge.FAIL and not row.breaches_must
    assert "the selectors s1, s2 publish one public key" in row.reason
    alone = discovered("SGE-DKIM-R02", [dkim("s1", 2048, KEY_1024), mail_subs(names)])
    assert alone.status == sge.NOT_MEASURED


def test_reporting_and_alignment_on_a_discovered_name_come_from_the_record_applied_to_it():
    names = {"a.example.com": read_sub(sts_read())}
    bare = discovered("SGE-DMARC-04", [dmarc("v=DMARC1; p=reject"), mail_subs(names)])
    assert bare.status == sge.FAIL and bare.breaches_must
    assert "the organisational domain's DMARC record" in bare.reason
    reported = discovered("SGE-DMARC-04", [dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com"),
                                           mail_subs(names)])
    assert reported.status == sge.NOT_MEASURED
    # The name's own record, when it has one, is the one read.
    own = {"a.example.com": read_sub(sts_read(), dmarc="v=DMARC1; p=reject; aspf=s")}
    assert discovered("SGE-DMARC-R02", [dmarc("v=DMARC1; p=reject; aspf=s"),
                                        mail_subs(own)]).status == sge.NOT_MEASURED
    relaxed = discovered("SGE-DMARC-R02", [dmarc("v=DMARC1; p=reject"), mail_subs(names)])
    assert relaxed.status == sge.FAIL and not relaxed.breaches_must
    assert "by omitting the tag" in relaxed.reason
    # A walk through a name that was not read settles neither.
    sweep = walked_sweep({}, [], intermediate_unsettled=["mail.example.com"])
    deep = {"a.mail.example.com": read_sub(sts_read())}
    row = discovered("SGE-DMARC-04", [dmarc("v=DMARC1; p=reject"), sweep, mail_subs(deep)])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)


def test_an_attested_complete_zone_does_not_let_a_mail_handling_row_pass():
    names = {"a.example.com": read_sub(sts_read())}
    complete = mail_subs(names)
    complete["extra"]["population"] = {"zone": D, "complete": True, "zones": [D],
                                       "attested_by": "Example Widgets Ltd, DNS administrator",
                                       "attested_on": "2030-01-31"}
    for req_id in ("SGE-SPF-01", "SGE-MTASTS-01", "SGE-TLSRPT-01"):
        row = discovered(req_id, [dmarc("v=DMARC1; p=reject"), complete])
        assert row.status == sge.NOT_MEASURED, req_id
        assert "a complete list of names is not a complete list of sending domains" in (
            row.evidence)


# ── TLS on the mail path ──────────────────────────────────────────────

def gateway(host: str, versions: list[str], flags: list[str] | None = None,
            port: str = "25") -> dict:
    return {"name": f"smtp {host}", "protocol": "tls", "host": host, "port": port,
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


def test_every_mx_host_gets_a_row_and_only_a_port_25_probe_is_read():
    base = [mx_row("mx1.example.com", "mx2.example.com")]
    # mx2 has no probe: it is reported, not dropped.
    rows = rows_for("SGE-TLS-01", base + [gateway("mx1.example.com", ["TLSv1.2"])])
    by_host = {r.subject: r for r in rows}
    assert by_host["mx1.example.com"].status == sge.PASS
    unprobed = by_host["mx2.example.com"]
    assert (unprobed.status, unprobed.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)
    assert "MX host of example.com" in unprobed.evidence and "port 25" in unprobed.evidence
    # A TLS row on another port, or with no port (a certificate-log record), is not
    # what an inbound sender is offered, so it is not read for the floor.
    other = rows_for("SGE-TLS-01", base + [
        gateway("mx1.example.com", ["TLSv1.0"], port="443"),
        {"name": "certificate mx2.example.com", "protocol": "tls", "host": "mx2.example.com"}])
    by_host = {r.subject: r for r in other}
    assert by_host["mx1.example.com"].reason == sge.NOT_COLLECTED
    assert "port(s) 443" in by_host["mx1.example.com"].evidence
    assert by_host["mx2.example.com"].reason == sge.NOT_COLLECTED
    # A null MX names no host.
    null = [{"name": f"MX {D}", "protocol": "mx", "host": D, "extra": {"records": ["0 ."]}}]
    assert [r.subject for r in rows_for("SGE-TLS-01", null)][:1] == [""]


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


def test_implicit_tls_on_the_receiving_side_reads_port_25_and_never_passes():
    base = [mx_row("mx1.example.com", "mx2.example.com", "mx3.example.com")]
    rows = {r.subject: r for r in rows_for("SGE-ITLS-01", base + [
        gateway("mx1.example.com", [], ["plaintext:smtp"]),
        gateway("mx2.example.com", ["TLSv1.2"]),
        gateway("mx3.example.com", ["TLSv1.2"], port="465")])}
    assert sge.PASS not in {r.status for r in rows.values()}
    assert (rows["mx1.example.com"].reason, rows["mx1.example.com"].observed) == (
        sge.INCONCLUSIVE, "no STARTTLS offered on port 25")
    assert "fails SGE-TLS-01" in rows["mx1.example.com"].evidence
    assert rows["mx2.example.com"].observed == "STARTTLS offered on port 25"
    # A port-465 row is RFC 8314 submission, not relay: the host reads as not probed.
    unprobed = rows["mx3.example.com"]
    assert unprobed.reason == sge.NOT_COLLECTED and "RFC 8314" in unprobed.evidence
    # The organisation's own row (the transport export) is still there.
    assert rows[sge._ITLS_SUBJECT].reason == sge.NOT_COLLECTED


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


# ── A note describes what this observation holds ──────────────────────

def _unused_tag_sweep(records: dict, in_scope: int) -> dict:
    return {"name": f"DMARC on sub-domains of {D}", "protocol": "ned-dmarc", "host": D,
            "extra": {"control_usable": True, "names_in_scope": in_scope,
                      "dmarc_records": records, "read_at": "t", "resolvers": ["192.0.2.53"]}}


def _beneath(req_id: str, assets: list):
    return {r.subject: r for r in rows_for(req_id, assets)}[sge.parked_subdomains_subject(D)]


def test_the_unused_tag_sweep_row_reads_as_a_must_not_carry_requirement():
    # Names with no DMARC record of their own carry nothing to grade, and say so.
    row = _beneath("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject"), _unused_tag_sweep({}, 3)])
    assert (row.status, row.reason) == (sge.NOT_MEASURED, sge.NOT_COLLECTED)
    assert row.observed == "none of 3 sub-domains read carries ruf, fo, pct, rf, ri; 0 publish " \
                           "a DMARC record of their own"
    assert "there is no sub-domain record here to grade" in row.evidence
    assert "a single record carrying one is the answer" in row.evidence
    # The "must publish" reasoning is the wrong way round for this requirement.
    assert "a single name without it is the answer" not in row.evidence
    assert "the other 3 publish none, so carry no tag of their own" in row.subject_note
    # Some records of their own, none carrying a tag: counted over the names read.
    clean = _beneath("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject"), _unused_tag_sweep(
        {"a.example.com": "v=DMARC1; p=reject"}, 3)])
    assert clean.observed.startswith("none of 3 sub-domains read carries") and \
        clean.observed.endswith("1 publish a DMARC record of their own")
    assert "no DMARC record published by an enumerated sub-domain" in clean.evidence
    # One record carrying a tag is the answer, whatever the names not read hold.
    bad = _beneath("SGE-DMARC-R03", [dmarc("v=DMARC1; p=reject"), _unused_tag_sweep(
        {"a.example.com": "v=DMARC1; p=reject; ruf=mailto:f@example.com"}, 3)])
    assert (bad.status, bad.observed) == (sge.FAIL, "1 of 3 sub-domains read carry ruf")
    assert "one record carrying such a tag settles this" in bad.reason


def test_the_sweep_names_only_the_sources_that_supplied_its_names():
    sources = {"a.example.com": [dnsevidence.NAME_FROM_CT],
               "b.example.com": [dnsevidence.NAME_FROM_CT],
               "c.example.com": [dnsevidence.NAME_FROM_CT, dnsevidence.NAME_FROM_SPF]}
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["a.example.com"], name_sources=sources,
                                     names_by_source={dnsevidence.NAME_FROM_CT: 3,
                                                      dnsevidence.NAME_FROM_SPF: 1,
                                                      dnsevidence.NAME_FROM_ZONE: 0})])
    assert "names from certificate transparency (3), sender policy (1)" in row.subject_note
    assert dnsevidence.NAME_FROM_ZONE not in row.subject_note
    assert sge.SOURCES_NOT_RECORDED not in row.subject_note
    # The requirement's own limit no longer lists every source the sweep can use.
    assert "supplied zone files" not in row.reason


def test_a_sweep_that_recorded_no_provenance_names_no_source():
    row = one("SGE-NED-SPF-01", [ned("ned-spf", ["a.example.com"])])
    assert sge.SOURCES_NOT_RECORDED in row.subject_note
    assert "names from" not in row.subject_note
    for source in ("certificate", "zone file", "sender polic", "profile"):
        assert source not in row.subject_note
    assert "supplied zone files" not in row.reason
    dkim_row = one("SGE-NED-DKIM-01", [ned("ned-dkim", [])])
    assert "supplied zone files" not in dkim_row.evidence
    sp_row = one("SGE-DMARC-R05", [dmarc("v=DMARC1; p=reject"), _unused_tag_sweep({}, 2)])
    assert sge.SOURCES_NOT_RECORDED in sp_row.subject_note


def test_a_discovered_row_names_the_sources_of_its_own_names_only():
    subs = mail_subs({"mail.example.com": sub()})
    subs["extra"]["name_sources"] = {"mail.example.com": [dnsevidence.NAME_FROM_ZONE],
                                     "web.example.com": [dnsevidence.NAME_FROM_CT]}
    row = discovered("SGE-SPF-01", [subs])
    assert "names from zone file (1)" in row.subject_note
    assert dnsevidence.NAME_FROM_CT not in row.subject_note
    assert "certificate-transparency" not in sge.DISCOVERED_NOTE
    bare = discovered("SGE-SPF-01", [mail_subs({"mail.example.com": sub()})])
    assert sge.SOURCES_NOT_RECORDED in bare.subject_note


def test_policy_discovery_is_named_only_when_the_observation_holds_the_walk():
    weak = dmarc("v=DMARC1; p=reject; sp=none")
    # The sweep lists the names to walk and the names between: discovery was read.
    walked = walked_sweep({}, ["a.mail.example.com"],
                          intermediate_dmarc={"mail.example.com": ""})
    row = one("SGE-NED-DMARC-R01", [weak, walked])
    assert row.status == sge.FAIL
    assert "applies the record policy discovery finds for them" in row.subject_note
    assert "was not looked up" not in row.subject_note
    # sp=none alone settles the domain's own row, so the sweep is read under sp=quarantine.
    soft = dmarc("v=DMARC1; p=reject; sp=quarantine; np=reject")
    reject = one("SGE-NED-DMARC-01", [soft, walked])
    assert "take the record policy discovery finds for them" in reject.subject_note
    # No walk held: only the organisational record was read, and the note says so.
    unwalked = _unused_tag_sweep({}, 1)
    row = one("SGE-NED-DMARC-R01", [weak, unwalked])
    assert row.status == sge.FAIL
    assert "policy discovery" not in row.subject_note
    assert "read against the organisational domain's record" in row.subject_note
    assert "any name between them and the domain was not looked up" in row.subject_note
    reject = one("SGE-NED-DMARC-01", [soft, unwalked])
    assert reject.status == sge.FAIL
    assert "policy discovery" not in reject.subject_note
    assert "was not looked up" in reject.subject_note


def test_a_discovered_name_without_a_walk_is_read_against_the_organisational_record():
    names = {"a.mail.example.com": sub()}
    root = dmarc("v=DMARC1; p=reject; sp=quarantine")
    row = discovered("SGE-DMARC-01", [root, mail_subs(names)])
    assert row.status == sge.FAIL
    assert "policy discovery" not in row.reason
    assert "organisational domain's record" in row.reason and "not looked up" in row.reason
    walked = walked_sweep({}, [], intermediate_dmarc={"mail.example.com": ""})
    row = discovered("SGE-DMARC-01", [root, walked, mail_subs(names)])
    assert f"record at {D}" in row.reason and "not looked up" not in row.reason
