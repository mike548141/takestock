"""Normalising a run's rows: merging, readings across rows, grading, and the summary."""

from __future__ import annotations

import json
from dataclasses import replace

from takestock import coverage, normalise
from takestock.disposition import deciding_entry, load_dispositions
from takestock.model import CryptoAsset


def _tls(host: str, port: str = "443", **kw) -> CryptoAsset:
    return CryptoAsset(name=f"TLS {host}:{port}", data_state="in-transit", protocol="tls",
                       host=host, port=port, **kw)


# ── merging ──

def test_rows_describing_the_same_thing_merge_into_the_first():
    a = _tls("web-01.example.test", source="tls_scan", protocol_versions=["TLSv1.2"],
             flags=["x"], notes="first", extra={"k": 1})
    b = _tls("web-01.example.test", source="other", protocol_versions=["TLSv1.3", "TLSv1.2"],
             flags=["y"], notes="second", software="widget-httpd", extra={"k": 2, "j": 3})
    c = _tls("web-02.example.test")
    rows, folded = normalise.merge_duplicates([a, b, c])
    assert folded == 1
    assert [r.host for r in rows] == ["web-01.example.test", "web-02.example.test"]
    m = rows[0]
    assert m.protocol_versions == ["TLSv1.2", "TLSv1.3"]
    assert m.flags == ["x", "y"]
    assert m.software == "widget-httpd"
    assert m.notes == "first; second"
    assert m.extra["k"] == 1 and m.extra["j"] == 3
    assert m.extra[normalise.MERGED_ROWS_KEY] == 2
    assert m.extra[normalise.MERGED_SOURCES_KEY] == ["tls_scan", "other"]


def test_a_merge_keeps_the_weakest_graded_verdict():
    rows, _ = normalise.merge_duplicates([_tls("h.example.test", verdict="strong"),
                                         _tls("h.example.test", verdict="weak"),
                                         _tls("h.example.test")])
    assert rows[0].verdict == "weak"


def test_rows_differing_in_port_do_not_merge():
    rows, folded = normalise.merge_duplicates([_tls("h.example.test", "443"),
                                               _tls("h.example.test", "8443")])
    assert folded == 0 and len(rows) == 2


# ── readings across rows ──

def test_a_key_served_by_two_hosts_is_flagged_on_both():
    rows = [_tls("a.example.test", extra={"pubkey_sha256": "k1", "cert_sha256": "c1"}),
            _tls("b.example.test", extra={"pubkey_sha256": "k1", "cert_sha256": "c2"}),
            _tls("c.example.test", extra={"pubkey_sha256": "k2"})]
    assert normalise.flag_shared_keys(rows) == {"keys": 1, "assets": 2}
    assert "shared-key:2" in rows[0].flags and "shared-key:2" in rows[1].flags
    assert rows[0].extra["shared_key_hosts"] == ["b.example.test"]
    assert rows[0].extra["shared_key_certs"] == 2
    assert not rows[2].flags


def test_a_redirect_without_effective_hsts_is_strippable():
    listener = CryptoAsset(name="HTTP a:80", data_state="in-transit", host="a.example.test",
                           port="80", flags=["http-redirect:https"])
    weak = CryptoAsset(name="HSTS a", data_state="in-transit", host="A.example.test.",
                       source="hsts", extra={"hsts_effective": False})
    other = CryptoAsset(name="HSTS b", data_state="in-transit", host="b.example.test",
                        source="hsts", extra={"hsts_effective": False})
    assert normalise.flag_strippable_redirects([listener, weak, other]) == {"assets": 1}
    assert normalise.STRIPPABLE_FLAG in weak.flags
    assert weak.extra["http_redirect_from_port_80"] is True
    assert not other.flags


def test_http_protocol_readings_are_carried_to_the_tls_row():
    hsts_row = CryptoAsset(name="HSTS", data_state="in-transit", host="a.example.test",
                           port="443", source="hsts",
                           extra={"alt_svc_protocols": ["h3"], "http3_advertised": True,
                                  "dns_https_outcome": "none-published", "hsts_max_age": 1})
    tls_row = _tls("a.example.test", source="tls_scan")
    assert normalise.carry_http_protocol_readings([hsts_row, tls_row]) == {"assets": 1}
    assert tls_row.extra == {"alt_svc_protocols": ["h3"], "http3_advertised": True,
                             "dns_https_outcome": "none-published"}


def test_a_logged_expiry_gives_way_to_the_served_certificate():
    logged = CryptoAsset(name="certificate a.example.test", data_state="certificate",
                         protocol="tls", host="a.example.test", source="ct_dns",
                         flags=["expiry-soon"], notes="expires soon",
                         extra={"not_after": "2030-01-10T00:00:00Z"})
    served = _tls("a.example.test", source="tls_scan",
                  extra={"cert_not_after": "2031-01-10T00:00:00Z", "cert_days_remaining": 400})
    assert normalise.reconcile_certificate_expiry([logged, served]) == {
        "annotated": 1, "expiry_withdrawn": 1}
    assert logged.flags == [normalise.EXPIRY_READ_BY_HANDSHAKE_FLAG]
    assert logged.extra["log_expiry_flag_withdrawn"] == "expiry-soon"
    assert "2031-01-10" in logged.notes and logged.notes.endswith("expires soon")


# ── the whole pass ──

def test_finalise_grades_places_and_stamps_every_row(policy):
    weak = CryptoAsset(name="SSH legacy-01.example.test:22", data_state="in-transit",
                       protocol="ssh", host="legacy-01.example.test", port="22",
                       software_binary="sshd",
                       extra={"ssh_kex": ["diffie-hellman-group1-sha1"]})
    dup = CryptoAsset(name="SSH legacy-01.example.test:22", data_state="in-transit",
                      protocol="ssh", host="legacy-01.example.test", port="22")
    lifecycle = {"migration_strategy": {"retire": [r"^legacy-01\."]},
                 "support_status": {"end-of-support": [r"^nothing-matches$"]}}
    rows, passes = normalise.finalise([weak, dup], policy, {"sshd": {"product": "OpenSSH"}},
                                      lifecycle=lifecycle)
    assert len(rows) == 1 and passes["merged_duplicates"] == 1
    row = rows[0]
    assert row.verdict == "weak"
    assert row.software == "OpenSSH"
    assert row.migration_strategy == "retire"
    assert row.disposition and row.disposition_basis
    assert row.evidence_depth
    assert passes["lifecycle_unmatched"] == [
        "support_status.end-of-support: /^nothing-matches$/ matched no asset"]


_PLAN_MARKS = {"replaced_by": [r"^edge-01\.", r"^app-01\.", r"^gone-"],
               "retiring_by": [r"^edge-01\.", r"^app-02\."]}


def _marked_rows() -> list[CryptoAsset]:
    return [
        _tls("edge-01.example.test", protocol_versions=["TLSv1.0"], internet_facing=True),
        _tls("app-01.example.test", protocol_versions=["TLSv1.3"], symmetric=["AES-256-GCM"],
             key_exchange=["X25519MLKEM768"], signatures=["ecdsa-p256"], hashes=["sha384"]),
        _tls("app-02.example.test", protocol_versions=["TLSv1.2"], symmetric=["AES-128-GCM"],
             key_exchange=["ecdhe-x25519"], signatures=["rsa-2048"], hashes=["sha256"]),
    ]


def test_plan_marks_place_tolerable_rows_and_report_unmatched_patterns(policy):
    rules = load_dispositions()
    rows, passes = normalise.finalise(_marked_rows(), policy, {}, rules, lifecycle=_PLAN_MARKS)
    edge, replaced, retiring = rows
    assert edge.extra["replaced_by"] is True and edge.extra["retiring_by"] is True
    assert (replaced.verdict, deciding_entry(replaced, rules)[1]["id"]) == (
        "strong", "accept-replacement-tolerable-control")
    assert (retiring.verdict, deciding_entry(retiring, rules)[1]["id"]) == (
        "acceptable", "defer-migration-retiring-infrastructure")
    assert passes["lifecycle_unmatched"] == ["replaced_by: /^gone-/ matched no asset"]


def test_a_weak_internet_facing_row_is_never_softened_by_a_plan_mark(policy):
    # The bundled rules, with the verdict filter taken off both mark rules, so
    # only the order of the rules can keep the marked weak row on its rung.
    bundled = load_dispositions()
    unfiltered = [
        dict(r, match={k: v for k, v in r["match"].items() if k != "verdict"})
        if r["id"] in ("accept-replacement-tolerable-control",
                       "defer-migration-retiring-infrastructure") else r
        for r in bundled.rules]
    ids = [r["id"] for r in unfiltered]
    assert ids.index("internet-facing-weak") < ids.index("accept-replacement-tolerable-control")
    assert ids.index("internet-facing-weak") < ids.index("defer-migration-retiring-infrastructure")
    for rules in (bundled, replace(bundled, rules=unfiltered)):
        rows, _ = normalise.finalise(_marked_rows()[:1], policy, {}, rules, lifecycle=_PLAN_MARKS)
        (edge,) = rows
        assert edge.verdict == "weak"
        assert (edge.disposition, deciding_entry(edge, rules)[1]["id"]) == (
            "wave-1", "internet-facing-weak")


def test_findings_are_weak_verdicts_and_out_of_cycle_work():
    rows = [CryptoAsset(name="a", data_state="x", verdict="weak"),
            CryptoAsset(name="b", data_state="x", verdict="strong", disposition="critical"),
            CryptoAsset(name="c", data_state="x", verdict="unknown"),
            CryptoAsset(name="d", data_state="x", verdict="acceptable", disposition="wave-1")]
    found = normalise.findings(rows, {"critical"})
    assert [(f["name"], f["why"]) for f in found] == [
        ("a", ["weak-verdict"]), ("b", ["disposition-critical"])]


def test_a_not_measured_flag_becomes_a_low_fidelity_gap():
    row = _tls("a.example.test", flags=["not-measured:key-exchange-group"])
    (g,) = normalise.not_measured_gaps([row])
    assert coverage.kind_of(g) == coverage.NOT_MEASURED
    assert coverage.nature_of(g) == coverage.LOW_FIDELITY
    assert "a.example.test" in g


def test_the_summary_round_trips_through_json_with_its_gap_classifications(policy):
    rows, _ = normalise.finalise([_tls("a.example.test", protocol_versions=["TLSv1.0"])],
                                 policy, {})
    gap = coverage.gap(coverage.NOT_COLLECTED, "inbox/hosts.csv not supplied", required=False,
                       nature=coverage.NO_DATA)
    s = json.loads(json.dumps(normalise.summarise(rows, [gap], load_dispositions()),
                              default=str))
    assert s["total_assets"] == 1 and s["by_verdict"] == {"weak": 1}
    assert s["weak_assets"] == ["TLS a.example.test:443"]
    assert s["gaps"] == ["inbox/hosts.csv not supplied"]
    assert s["gap_kinds"] == [coverage.NOT_COLLECTED]
    assert s["gap_required"] == [False]
    assert s["gap_natures"] == [coverage.NO_DATA]
    assert s["dispositions"]["out_of_cycle"] == ["critical"]
    for key in ("pq_readiness", "evidence_depth", "lifecycle", "usage_bands", "plaintext",
                "ungraded", "shared_keys", "agility", "binding"):
        assert key in s
