"""The cleartext check: the probe plan and its refusals, nmap parsing, and grading."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from probe_helpers import FakeRun, fixture, has, never_run, target

from takestock import plaintext
from takestock.collectors import plaintext_scan as ps
from takestock.inside_scope import MAX_HOSTS
from takestock.model import CryptoAsset, is_informational_flag

WHEN = datetime(2030, 1, 31, tzinfo=UTC)
LOCAL = "127.0.0.1"            # the captured fixtures were taken against loopback


def overlay(sections: dict, budget: dict | None = None, path: str = "example.derived-ports.yaml"
            ) -> dict:
    return {"_path": path, "probe_list": {**sections, **({"budget": budget} if budget else {})}}


def web_target(*hosts: str, **kw) -> dict:
    return target(tls_443=list(hosts or ["web-01.example.test"]), **kw)


# ── the plan ──

def test_the_profile_list_applies_to_every_published_host():
    t = web_target("web-01.example.test", "web-02.example.test")
    t["plaintext_ports"] = ["80/tcp", "8080/tcp", "161/udp"]
    plan = ps.build_plan(t, derived={})
    assert [s.host for s in plan.steps] == ["web-01.example.test", "web-02.example.test"]
    assert plan.steps[0].ports == ("80/tcp", "8080/tcp")
    assert plan.steps[0].deferred == ("161/udp",)
    assert (plan.hosts, plan.tcp_pairs, plan.udp_pairs) == (2, 4, 2)


def test_no_list_and_no_overlay_is_refused_there_is_no_default():
    with pytest.raises(ps.PortListRefused, match="There is no default"):
        ps.build_plan(web_target(), derived={})


@pytest.mark.parametrize("bad", ["1-1024/tcp", "80,443/tcp", "*/tcp", "80", "T:80", "80/sctp"])
def test_a_port_sweep_cannot_be_expressed(bad):
    t = web_target()
    t["plaintext_ports"] = [bad]
    with pytest.raises(ps.PortListRefused, match="refused by construction"):
        ps.build_plan(t, derived={})


def test_too_many_ports_on_a_host_is_refused_not_shortened():
    t = web_target()
    t["plaintext_ports"] = [f"{8000 + n}/tcp" for n in range(ps.MAX_PORTS_PER_HOST + 1)]
    with pytest.raises(ps.PortListRefused, match="REFUSED rather than shortened"):
        ps.build_plan(t, derived={})


def test_too_many_hosts_is_refused_not_truncated():
    t = web_target(*[f"web-{n:02}.example.test" for n in range(MAX_HOSTS + 1)])
    t["plaintext_ports"] = ["80/tcp"]
    with pytest.raises(ps.PortListRefused, match="REFUSED"):
        ps.build_plan(t, derived={})


def test_a_repeated_port_is_refused():
    t = web_target()
    t["plaintext_ports"] = ["80/tcp", "80/tcp"]
    with pytest.raises(ps.PortListRefused, match="repeats"):
        ps.build_plan(t, derived={})


def test_a_derived_plan_with_a_matching_budget_runs():
    t = web_target("web-01.example.test", "web-02.example.test")
    plan = ps.build_plan(t, overlay(
        {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp", "8080/tcp"],
                 "basis": "web front ends"}},
        {"hosts": 2, "tcp_pairs": 4, "udp_pairs": 0}))
    assert plan.tcp_pairs == 4
    assert plan.steps[0].basis == "web front ends"


def test_a_budget_that_does_not_match_is_refused():
    t = web_target("web-01.example.test", "web-02.example.test")
    with pytest.raises(ps.PortListRefused, match="declared budget says tcp_pairs=2"):
        ps.build_plan(t, overlay(
            {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp", "8080/tcp"],
                     "basis": "web front ends"}},
            {"hosts": 2, "tcp_pairs": 2, "udp_pairs": 0}))


def test_a_plan_without_a_budget_is_refused():
    with pytest.raises(ps.PortListRefused, match="declares no `budget:`"):
        ps.build_plan(web_target(), overlay(
            {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp"], "basis": "b"}}))


def test_a_section_with_no_basis_is_refused():
    with pytest.raises(ps.PortListRefused, match="names no `basis:`"):
        ps.build_plan(web_target(), overlay(
            {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp"]}},
            {"hosts": 1, "tcp_pairs": 1, "udp_pairs": 0}))


def test_a_section_may_not_bring_its_own_hosts():
    with pytest.raises(ps.PortListRefused, match="may not introduce"):
        ps.build_plan(web_target(), overlay(
            {"web": {"hosts_from": "web-09.example.test", "ports": ["80/tcp"], "basis": "b"}},
            {"hosts": 1, "tcp_pairs": 1, "udp_pairs": 0}))


def test_a_section_naming_a_missing_group_is_refused():
    with pytest.raises(ps.PortListRefused, match="no `scan_targets.mail_self:` group"):
        ps.build_plan(web_target(), overlay(
            {"mail": {"hosts_from": "scan_targets.mail_self", "ports": ["80/tcp"], "basis": "b"}},
            {"hosts": 1, "tcp_pairs": 1, "udp_pairs": 0}))


def test_a_section_with_only_udp_ports_is_refused():
    with pytest.raises(ps.PortListRefused, match="only non-TCP ports"):
        ps.build_plan(web_target(), overlay(
            {"snmp": {"hosts_from": "scan_targets.tls_443", "ports": ["161/udp"], "basis": "b"}},
            {"hosts": 1, "tcp_pairs": 0, "udp_pairs": 1}))


def test_a_host_claimed_by_two_sections_is_refused():
    t = web_target()
    t["scan_targets"]["mail_self"] = ["web-01.example.test"]
    with pytest.raises(ps.PortListRefused, match="already claimed"):
        ps.build_plan(t, overlay(
            {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp"], "basis": "b"},
             "mail": {"hosts_from": "scan_targets.mail_self", "ports": ["25/tcp"], "basis": "b"}},
            {"hosts": 2, "tcp_pairs": 2, "udp_pairs": 0}))


def test_a_derived_plan_may_widen_the_profile_list_but_never_narrow_it():
    t = web_target()
    t["plaintext_ports"] = ["80/tcp", "8080/tcp"]
    with pytest.raises(ps.PortListRefused, match="would stop probing 1"):
        ps.build_plan(t, overlay(
            {"web": {"hosts_from": "scan_targets.tls_443", "ports": ["80/tcp"], "basis": "b"}},
            {"hosts": 1, "tcp_pairs": 1, "udp_pairs": 0}))


def test_the_budget_names_every_host_and_port_before_anything_runs(port_table):
    t = web_target()
    t["plaintext_ports"] = ["80/tcp", "443/tcp", "25/tcp", "161/udp"]
    lines = ps.budget_lines(ps.build_plan(t, derived={}), port_table)
    text = "\n".join(lines)
    assert "web-01.example.test  ->  80/tcp, 443/tcp, 25/tcp" in text
    assert "NOT probed here : 1 UDP pair(s) (161/udp)" in text
    assert "smtp_starttls measures" in text           # 25 produces no row of its own
    assert "encryption is inherent" in text            # nor does 443


def test_ssh_hosts_given_as_mappings_are_probed_by_address():
    t = target(ssh_22=[{"host": "bastion.example.test", "ip": "192.0.2.22"}])
    assert ps.scan_hosts(t) == ["192.0.2.22"]


# ── parsing and classifying nmap ──

def test_the_captured_http_title_run_is_read():
    scan = ps.parse_nmap(fixture("nmap-http-title.txt"))
    assert scan.reached
    assert scan.ports["8080/tcp"].title == "Example Widgets intranet"
    assert scan.ports["8000/tcp"].title.startswith("Did not follow redirect to https://")
    assert scan.ports["23/tcp"].state == "closed"


def test_a_run_with_no_port_table_is_not_reached():
    scan = ps.parse_nmap("Failed to resolve \"nowhere.example.test\".\n")
    assert not scan.reached
    assert scan.detail.startswith("Failed to resolve")


@pytest.mark.parametrize(("state", "answer"), [
    ("filtered", True), ("open|filtered", True), ("closed", False), ("open", False)])
def test_no_answer_states(state, answer):
    assert ps.no_answer(state) is answer


def _obs(spec: str, **kw) -> ps.PortObservation:
    port, _, transport = spec.partition("/")
    return ps.PortObservation(port=port, transport=transport, **kw)


def test_a_page_served_in_clear_is_a_finding(port_table):
    outcome, evidence = ps.classify(_obs("8080/tcp", state="open", title="Example"),
                                    plaintext.lookup("8080", "tcp", port_table))
    assert outcome == ps.CLEARTEXT_SERVED
    assert "Measured" in evidence


def test_a_redirect_to_https_is_not_a_finding(port_table):
    outcome, _ = ps.classify(
        _obs("80/tcp", state="open", title="Did not follow redirect to https://www.example.test/"),
        plaintext.lookup("80", "tcp", port_table))
    assert outcome == ps.REDIRECT_HTTPS


def test_a_redirect_to_plain_http_is_still_cleartext(port_table):
    outcome, _ = ps.classify(
        _obs("80/tcp", state="open", title="Did not follow redirect to http://www.example.test/"),
        plaintext.lookup("80", "tcp", port_table))
    assert outcome == ps.CLEARTEXT_SERVED


def test_an_open_port_with_no_readable_page_is_inconclusive(port_table):
    outcome, _ = ps.classify(_obs("80/tcp", state="open"), plaintext.lookup("80", "tcp", port_table))
    assert outcome == ps.INCONCLUSIVE


def test_a_non_http_cleartext_listener_rests_on_the_port_convention(port_table):
    outcome, evidence = ps.classify(_obs("23/tcp", state="open"),
                                    plaintext.lookup("23", "tcp", port_table))
    assert outcome == ps.CLEARTEXT_LISTENING
    assert "the protocol is inferred" in evidence


def test_an_upgradable_listener_is_a_gap_not_a_finding(port_table):
    outcome, _ = ps.classify(_obs("21/tcp", state="open"), plaintext.lookup("21", "tcp", port_table))
    assert outcome == ps.UPGRADABLE_LISTENING


def test_closed_filtered_and_unreached_are_told_apart(port_table):
    row = plaintext.lookup("80", "tcp", port_table)
    assert ps.classify(_obs("80/tcp", state="closed"), row)[0] == ps.NOT_LISTENING
    assert ps.classify(_obs("80/tcp", state="filtered"), row)[0] == ps.FILTERED_NO_ANSWER
    assert ps.classify(_obs("80/tcp", state="filtered"), row,
                       host_unreached=True)[0] == ps.UNREACHED


# ── the plain-HTTP confirmation ──

def test_a_plain_http_answer_confirms_cleartext():
    outcome, evidence = ps.verified_outcome("8080/tcp", "Example", fixture("curl-plain-http.txt"))
    assert outcome == ps.CLEARTEXT_SERVED
    assert "`HTTP/1.0 200 OK`" in evidence


def test_a_plain_http_redirect_to_https_is_not_cleartext():
    outcome, _ = ps.verified_outcome("8000/tcp", "x", fixture("curl-redirect-https.txt"))
    assert outcome == ps.REDIRECT_HTTPS


def test_no_plain_http_answer_is_inconclusive():
    outcome, evidence = ps.verified_outcome("8443/tcp", "x", fixture("curl-tls-port.txt"))
    assert outcome == ps.INCONCLUSIVE
    assert "HTTP/0.9" in evidence


def test_a_400_is_not_taken_as_cleartext():
    out = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    assert ps.verified_outcome("443/tcp", "x", out)[0] == ps.INCONCLUSIVE


def test_the_verify_command_is_one_plain_request():
    cmd = ps.verify_command("2001:db8::10", "8080")
    assert cmd[0] == "curl" and cmd[-1] == "http://[2001:db8::10]:8080/"
    assert "-L" not in cmd


def test_a_stored_row_is_rechecked_and_dated(monkeypatch):
    monkeypatch.setattr(ps, "run", FakeRun([(has("curl"), fixture("curl-redirect-https.txt"))]))
    stored = CryptoAsset(name="http web-01.example.test:80", data_state="in-transit",
                         protocol="http", host="web-01.example.test", port="80",
                         collected_at="2030-01-01", verdict="weak",
                         flags=["plaintext:http"],
                         extra={"plaintext_outcome": ps.CLEARTEXT_SERVED, "http_title": "x"})
    fresh = ps.verify_cleartext_http(stored, ref_time=WHEN)
    assert fresh.verdict == "n/a"
    assert fresh.extra["cleartext_verified_on"] == "2030-01-31"
    assert "scanned 2030-01-01" in fresh.notes
    assert stored.verdict == "weak"                    # the original is untouched


# ── collect ──

@pytest.fixture()
def table_with_8000(port_table, monkeypatch):
    """The bundled table plus a synthetic row for 8000/tcp, which the captured run used."""
    table = dict(port_table)
    table["8000/tcp"] = table["8000"] = {**port_table["8080/tcp"], "port": "8000"}
    monkeypatch.setattr(ps, "load_port_encryption", lambda: table)
    return table


def local_target(**kw) -> dict:
    t = target(tls_443=[LOCAL], **kw)
    t["plaintext_ports"] = ["23/tcp", "8000/tcp", "8080/tcp", "8443/tcp"]
    return t


def test_collect_measures_each_planned_port(monkeypatch, table_with_8000, policy):
    fake = FakeRun([
        (has("http-title"), fixture("nmap-http-title.txt")),
        (has("http://127.0.0.1:8080/"), fixture("curl-plain-http.txt")),
        (has("http://127.0.0.1:8000/"), fixture("curl-redirect-https.txt")),
    ])
    monkeypatch.setattr(ps, "run", fake)
    monkeypatch.setattr(ps.shutil, "which", lambda name: f"/usr/bin/{name}")
    said: list[str] = []
    assets, failures = ps.collect(local_target(), ref_time=WHEN, announce=said.append)
    assert failures == []
    by_port = {a.port: a for a in assets}
    assert set(by_port) == {"23", "8000", "8080"}         # 8443 is TLS by convention: no row
    assert by_port["8080"].verdict == "weak"
    assert "plaintext:http-alt" in by_port["8080"].flags
    assert by_port["8080"].extra["cleartext_verified_by"] == ps.VERIFY_INSTRUMENT
    assert by_port["8000"].verdict == "n/a"
    assert by_port["23"].verdict == "n/a"                  # closed: nothing listening
    assert said[0].startswith("plaintext_scan: PROBE BUDGET")
    nmap_calls = [c for c in fake.calls if c[0] == "nmap"]
    assert nmap_calls == [["nmap", *ps.NMAP_FLAGS, "-p", "23,8000,8080,8443",
                           "--script", "http-title", LOCAL]]
    for a in assets:
        policy.apply(a)


def test_a_host_that_answers_on_no_port_is_unreached_not_clean(monkeypatch, table_with_8000):
    monkeypatch.setattr(ps, "run", FakeRun([
        (has("http-title"), fixture("nmap-http-title-unreached.txt"))]))
    monkeypatch.setattr(ps.shutil, "which", lambda name: f"/usr/bin/{name}")
    t = target(tls_443=["192.0.2.10"])
    t["plaintext_ports"] = ["8000/tcp", "8080/tcp"]
    said: list[str] = []
    assets, _ = ps.collect(t, ref_time=WHEN, announce=said.append)
    assert {a.verdict for a in assets} == {"unknown"}
    assert all(f.startswith(ps.UNREACHED_FLAG) for a in assets for f in a.flags)
    assert is_informational_flag(assets[0].flags[0])
    assert any("UNREACHED" in line for line in said)


def test_a_planned_port_with_no_table_row_is_a_failure(monkeypatch, port_table):
    monkeypatch.setattr(ps, "run", FakeRun([
        (has("http-title"), fixture("nmap-http-title.txt")),
        (has("curl"), fixture("curl-plain-http.txt"))]))
    monkeypatch.setattr(ps.shutil, "which", lambda name: f"/usr/bin/{name}")
    assets, failures = ps.collect(local_target(), ref_time=WHEN, announce=lambda _l: None)
    assert any("8000/tcp is in the probe plan but" in f for f in failures)


def test_a_refused_plan_contacts_nothing(monkeypatch):
    monkeypatch.setattr(ps, "run", never_run)
    t = web_target()
    t["plaintext_ports"] = ["1-65535/tcp"]
    assets, failures = ps.collect(t, announce=lambda _l: None)
    assert assets == []
    assert failures[0].startswith("plaintext_scan: REFUSED to probe")


def test_without_authorisation_nothing_is_contacted(monkeypatch):
    monkeypatch.setattr(ps, "run", never_run)
    t = web_target(authorised=False)
    t["plaintext_ports"] = ["80/tcp"]
    assets, failures = ps.collect(t, announce=lambda _l: None)
    assert assets == [] and failures[0].startswith("plaintext_scan: REFUSED, nothing contacted")


def test_missing_nmap_is_a_failure_after_the_budget_is_shown(monkeypatch):
    monkeypatch.setattr(ps, "run", never_run)
    monkeypatch.setattr(ps.shutil, "which", lambda name: None)
    t = web_target()
    t["plaintext_ports"] = ["80/tcp"]
    said: list[str] = []
    assets, failures = ps.collect(t, announce=said.append)
    assert assets == [] and "nmap is not on PATH" in failures[0]
    assert said and said[0].startswith("plaintext_scan: PROBE BUDGET")


def test_redirect_query_strings_are_redacted():
    out = ps._redact_redirect_queries(
        "|_http-title: Did not follow redirect to https://www.example.test/login?token=abc\n")
    assert "token=abc" not in out
    assert "https://www.example.test/login [query string redacted]" in out
