"""Corroborated DNS evidence, the services configuration and the sub-domain sweep."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from probe_helpers import fixture

from takestock import config, dnsevidence
from takestock.dnsevidence import Corroborated, Lookup


def test_no_configured_resolver_means_the_system_one(tmp_path):
    config.set_workspace(tmp_path)
    assert dnsevidence.resolvers({}) == ("",)
    assert dnsevidence.resolver_label("") == dnsevidence.SYSTEM_RESOLVER_LABEL


def test_the_profile_overrides_the_data_file(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / dnsevidence.SERVICES_FILE).write_text(
        "resolvers: [192.0.2.53, 198.51.100.53]\nct_search_api: https://ct.example.com/v1\n")
    config.set_workspace(tmp_path)
    assert dnsevidence.resolvers({}) == ("192.0.2.53", "198.51.100.53")
    target = {"dns": {"resolvers": ["203.0.113.53", "203.0.113.53"], "ct_search_api": ""}}
    assert dnsevidence.resolvers(target) == ("203.0.113.53",)
    # An empty override leaves the data file's value in place.
    assert dnsevidence.services(target)["ct_search_api"] == "https://ct.example.com/v1"
    with pytest.raises(ValueError):
        dnsevidence.services({"dns": ["not", "a", "mapping"]})


def test_dkim_selectors_put_the_profile_first_and_keep_the_defaults():
    target = {"discovery": {"dkim_selectors": ["widgets2030", "s1"]}}
    got = dnsevidence.dkim_selectors(target)
    assert got[:2] == ["widgets2030", "s1"]
    assert set(dnsevidence.DEFAULT_DKIM_SELECTORS) <= set(got)
    assert len(got) == len(set(got))


def test_corroboration_agrees_only_when_every_answer_matches():
    same = Corroborated("example.com", "TXT", [
        Lookup("example.com", "TXT", "192.0.2.53", "t", answers=["a", "b"], rcode="NOERROR"),
        Lookup("example.com", "TXT", "198.51.100.53", "t", answers=["b", "a"], rcode="NOERROR"),
        Lookup("example.com", "TXT", "203.0.113.53", "t", error="timed out"),
    ])
    assert same.agreed and same.value == ["a", "b"] and same.rcode == "NOERROR"
    differ = Corroborated("example.com", "TXT", [
        Lookup("example.com", "TXT", "192.0.2.53", "t", answers=["a"], rcode="NOERROR"),
        Lookup("example.com", "TXT", "", "t", answers=[], rcode="NXDOMAIN"),
    ])
    assert not differ.agreed and differ.rcode == ""
    assert differ.resolvers_asked == ["192.0.2.53", dnsevidence.SYSTEM_RESOLVER_LABEL]


@pytest.mark.parametrize("record, denying", [
    ("v=spf1 -all", True), ("V=SPF1   -ALL", True), ("v=spf1 ~all", False),
    ("v=spf1 ip4:192.0.2.1 -all", False), ("", False),
])
def test_denying_spf(record, denying):
    assert dnsevidence.is_denying_spf(record) is denying


@pytest.mark.parametrize("record, blank", [
    ("v=DKIM1; p=", True), ("v=DKIM1; k=rsa; p=", True), ("v=DKIM1; p=MIIB", False),
    ("v=DKIM1", False), ("p=", False),
])
def test_blank_dkim(record, blank):
    assert dnsevidence.is_blank_dkim(record) is blank


def test_sender_policy_hosts():
    assert dnsevidence.sender_policy_hosts(
        "v=spf1 a:Relay.Example.com/24 mx:mail.example.com. ip4:192.0.2.1 -all") == [
        "mail.example.com", "relay.example.com"]


def _status_reader(table: dict[tuple[str, str], tuple[str, list[str]]]):
    def fake(name: str, rtype: str, resolvers: tuple[str, ...] = ("",)) -> Corroborated:
        rcode, answers = table.get((name, rtype), ("NXDOMAIN", []))
        return Corroborated(name, rtype, [Lookup(name, rtype, r, "2030-01-01T00:00:00Z",
                                                 answers=list(answers), rcode=rcode)
                                          for r in resolvers])
    return fake


def test_the_sweep_scopes_names_and_checks_its_control(monkeypatch):
    table = {
        ("example.com", "TXT"): ("NOERROR", ['"v=spf1 a:sender.example.com -all"']),
        ("quiet.example.com", "TXT"): ("NOERROR", ['"v=spf1 -all"']),
        ("*._domainkey.quiet.example.com", "TXT"): ("NOERROR", ['"v=DKIM1; p="']),
        ("_dmarc.quiet.example.com", "TXT"): ("NOERROR", ['"v=DMARC1; p=reject"']),
        ("mail.example.com", "MX"): ("NOERROR", ["10 mx.example.net."]),
        ("sender.example.com", "TXT"): ("NOERROR", []),
        ("lax.example.com", "TXT"): ("NOERROR", ['"v=spf1 include:x.example.net ~all"']),
    }
    fake = _status_reader(table)
    monkeypatch.setattr(dnsevidence, "corroborate", fake)
    monkeypatch.setattr(dnsevidence, "corroborate_status", fake)
    names = ["quiet.example.com", "mail.example.com", "sender.example.com",
             "lax.example.com", "gone.example.com"]
    cap = dnsevidence.capture_subdomains("example.com", names, ("192.0.2.53",))
    assert cap["control"]["usable"] and cap["names_dropped_by_cap"] == 0
    by = {r["name"]: r for r in cap["subdomains"]}
    quiet = by["quiet.example.com"]
    assert not quiet["email_enabled"] and quiet["spf_conformant"] and quiet["dkim_conformant"]
    assert quiet["dmarc_record"] == "v=DMARC1; p=reject"
    assert by["mail.example.com"]["email_enabled_because"].startswith("publishes an MX record")
    assert "sender policy names it" in by["sender.example.com"]["email_enabled_because"]
    assert by["lax.example.com"]["email_enabled_because"].startswith("publishes a sender policy")
    assert not by["gone.example.com"]["exists"] and not by["gone.example.com"]["email_enabled"]

    capped = dnsevidence.capture_subdomains("example.com", names, ("192.0.2.53",), max_names=4)
    assert capped["names_dropped_by_cap"] == 1
    assert "sender.example.com" not in {r["name"] for r in capped["subdomains"]}


CONTROL = f"{dnsevidence.CONTROL_LABEL}.example.com"


def _sweep(monkeypatch, table: dict, names: list[str] | None = None) -> dict:
    fake = _status_reader(table)
    monkeypatch.setattr(dnsevidence, "corroborate", fake)
    monkeypatch.setattr(dnsevidence, "corroborate_status", fake)
    return dnsevidence.capture_subdomains("example.com", names or [], ("192.0.2.53",))


def test_an_answer_at_the_control_that_no_wildcard_explains_spoils_it(monkeypatch):
    # Nothing is published at *.example.com, yet the control answers.
    cap = _sweep(monkeypatch, {(CONTROL, "TXT"): ("NOERROR", ['"v=spf1 -all"'])})
    assert not cap["control"]["usable"] and cap["control"]["basis"] == ""
    text = "\n".join(dnsevidence.subdomain_transcript([cap]))
    assert "THIS SHOULD HAVE BEEN NXDOMAIN" in text
    # A wildcard is published, but the control's answer is not the wildcard's.
    cap = _sweep(monkeypatch, {("*.example.com", "TXT"): ("NOERROR", ['"v=spf1 -all"']),
                               (CONTROL, "TXT"): ("NOERROR", ['"v=spf1 ~all"'])})
    assert not cap["control"]["usable"]


def test_a_published_wildcard_explains_the_control_and_each_name_is_read_for_itself(
        monkeypatch):
    wild = ("NOERROR", ['"v=spf1 -all"'])
    table = {("*.example.com", "TXT"): wild, (CONTROL, "TXT"): wild,
             # A name with no node of its own is given the wildcard's record ...
             ("quiet.example.com", "TXT"): wild,
             # ... and a name that exists with no TXT record is not.
             ("node.example.com", "TXT"): ("NOERROR", [])}
    cap = _sweep(monkeypatch, table, ["quiet.example.com", "node.example.com"])
    assert cap["control"]["usable"] and cap["control"]["basis"] == dnsevidence.CONTROL_WILDCARD
    by = {r["name"]: r for r in cap["subdomains"]}
    assert by["quiet.example.com"]["spf_conformant"]
    assert not by["node.example.com"]["spf_conformant"] and by["node.example.com"]["settled"]
    text = "\n".join(dnsevidence.subdomain_transcript([cap]))
    assert "answered with the wildcard's own record" in text


def test_an_empty_wildcard_explains_the_control_only_once_real_records_are_seen(monkeypatch):
    # A wildcard with no TXT record answers NOERROR with nothing, which is also what a
    # resolver answering nothing to every question would say.
    empty = ("NOERROR", [])
    table = {("*.example.com", "TXT"): empty, (CONTROL, "TXT"): empty}
    assert not _sweep(monkeypatch, table)["control"]["usable"]
    table[("example.com", "TXT")] = ("NOERROR", ['"v=spf1 -all"'])
    assert _sweep(monkeypatch, table)["control"]["basis"] == dnsevidence.CONTROL_WILDCARD


def test_a_name_whose_resolvers_disagree_is_not_settled(monkeypatch):
    def fake(name: str, rtype: str, resolvers: tuple[str, ...] = ("",)) -> Corroborated:
        answers = {"192.0.2.53": ['"v=spf1 -all"'], "198.51.100.53": []}
        if name != "split.example.com" or rtype != "TXT":
            return Corroborated(name, rtype, [Lookup(name, rtype, r, "t", rcode="NXDOMAIN")
                                              for r in resolvers])
        return Corroborated(name, rtype, [Lookup(name, rtype, r, "t", answers=answers[r],
                                                 rcode="NOERROR") for r in resolvers])
    monkeypatch.setattr(dnsevidence, "corroborate", fake)
    monkeypatch.setattr(dnsevidence, "corroborate_status", fake)
    cap = dnsevidence.capture_subdomains("example.com", ["split.example.com"],
                                         ("192.0.2.53", "198.51.100.53"))
    [rec] = cap["subdomains"]
    assert rec["read"] and not rec["agreed"] and not rec["settled"]


def test_active_transport_probing_needs_an_authorisation_stanza():
    assert dnsevidence._authorisation_problems({}) == [
        "no `authorisation:` stanza in the target profile"]
    assert dnsevidence._authorisation_problems(
        {"authorisation": {"scope": "mail hosts", "authorised_by": "", "date": "2030-01-01"}}
    ) == ["`authorisation.authorised_by` is missing or empty"]
    assert dnsevidence._authorisation_problems(
        {"authorisation": {"scope": "s", "authorised_by": "a", "date": "d"}}) == []


def test_dkim_key_size_is_read_by_openssl():
    if not shutil.which("openssl"):
        pytest.skip("openssl is not installed")
    # A throwaway 1024-bit public key generated with openssl for this test.
    key = ("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRYSnnmN7GxUj7lUMUoH1SR7TQIphv3AJEdOveaZ5"
           "zwpCqV8/APmt5tdshsTf9OZ+vz+lU7hxfrbegVsdSlpGxOtsVkz58G1oTraalK3sq+Qb/ipTbw8hF"
           "JXo+RFAzpl2OT8XJ4wDCdexAZMxuxTTgpacc/m9/JaIsedfV57vI3wIDAQAB")
    assert dnsevidence._rsa_bits(key) == 1024
    assert dnsevidence._rsa_bits("!!!") == 0


def _openssl_says(monkeypatch, out: str) -> None:
    def fake(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 1, stdout=out, stderr="")
    monkeypatch.setattr(dnsevidence.subprocess, "run", fake)


def test_a_version_the_client_would_not_offer_is_not_recorded_as_refused(monkeypatch):
    _openssl_says(monkeypatch, fixture("openssl3-tls1-not-offered.txt"))
    got = dnsevidence._starttls("mail-01.example.test", "tls1")
    assert got["state"] == "could-not-ask"
    assert "DEFAULT@SECLEVEL=0" in got["detail"]


def test_a_server_refusal_is_still_recorded_as_refused(monkeypatch):
    _openssl_says(monkeypatch, fixture("smtp-tls1.txt"))
    assert dnsevidence._starttls("mail-01.example.test", "tls1")["state"] == "refused"


def test_an_mta_sts_policy_is_read_as_rfc_8461_defines_it():
    body = ("version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.example.net\r\n"
            "max_age: 604800\r\nmode: none\r\n")
    fields = dnsevidence.mta_sts_fields(body)
    # mx repeats; any other repeated field keeps its first value (§3.2).
    assert fields["mx"] == ["mx1.example.com", "*.example.net"]
    assert (fields["version"], fields["mode"], fields["max_age"]) == ("STSv1", "enforce", "604800")
    assert dnsevidence.mta_sts_faults(True, 200, "STSv1", "604800") == []
    assert dnsevidence.mta_sts_faults(None, None, None, None) == []      # nothing was read
    assert len(dnsevidence.mta_sts_faults(True, 200, "", "1e6")) == 2
