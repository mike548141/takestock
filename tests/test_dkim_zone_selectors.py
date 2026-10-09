"""DKIM selectors read from supplied zone files, beside the profile's and the common ones.

Every zone, name and key here is synthetic; no network is used.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, dnsevidence, zonefile
from takestock.collectors import ct_dns

NOW = datetime(2030, 6, 15, tzinfo=UTC)
KEY = '"v=DKIM1; k=rsa; p=' + base64.b64encode(bytes(256)).decode() + '"'

ZONE = """\
$ORIGIN example.com.
$TTL 3600
@                       IN SOA   ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300
@                       IN MX    10 mx1.example.test.
mail2030._domainkey     IN TXT   "v=DKIM1; k=rsa; p=AAAA"
s1.eu._domainkey        IN CNAME s1.eu.dkim.example.net.
news._domainkey.mail    IN TXT   "v=DKIM1; k=rsa; p=AAAA"
*._domainkey            IN TXT   "v=DKIM1; p="
_domainkey              IN TXT   "o=-"
www                     IN A     192.0.2.80
"""

OTHER_ZONE = """\
$ORIGIN example.net.
@                       IN SOA   ns1.example.net. hostmaster.example.net. 1 3600 600 604800 300
elsewhere._domainkey    IN TXT   "v=DKIM1; k=rsa; p=AAAA"
"""


def _zones() -> list[zonefile.ZoneFile]:
    return [zonefile.parse(ZONE, "example.com"), zonefile.parse(OTHER_ZONE, "example.net")]


def test_the_zone_files_give_every_selector_beneath_the_domain():
    assert ct_dns.zone_dkim_selectors("example.com", _zones()) == ["mail2030", "s1.eu", "news"]
    assert ct_dns.zone_dkim_selectors("mail.example.com", _zones()) == ["news"]
    assert ct_dns.zone_dkim_selectors("example.net", _zones()) == ["elsewhere"]
    assert ct_dns.zone_dkim_selectors("example.org", _zones()) == []


def test_each_selector_says_where_it_came_from_in_the_order_tried():
    target = {"discovery": {"dkim_selectors": ["mail2030", "selector1"]}}
    sources = dnsevidence.dkim_selector_sources(target, ["mail2030", "s1.eu"])
    profile, zone, default = (dnsevidence.SELECTOR_FROM_PROFILE, dnsevidence.SELECTOR_FROM_ZONE,
                              dnsevidence.SELECTOR_FROM_DEFAULT)
    assert list(sources)[:4] == ["mail2030", "selector1", "s1.eu", "selector2"]
    assert sources["mail2030"] == [profile, zone]
    assert sources["selector1"] == [profile, default]
    assert sources["s1.eu"] == [zone]
    assert sources["selector2"] == [default]
    assert dnsevidence.dkim_selectors(target, ["mail2030", "s1.eu"]) == list(sources)


def test_without_zone_files_the_selectors_are_unchanged():
    target = {"discovery": {"dkim_selectors": ["mail2030"]}}
    assert dnsevidence.dkim_selectors(target) == [
        "mail2030", *dnsevidence.DEFAULT_DKIM_SELECTORS]


def _dig(table: dict) -> object:
    return lambda name, rtype="A", short=True: table.get((name, rtype), [])


def test_a_dkim_row_names_where_its_selector_came_from(monkeypatch):
    monkeypatch.setattr(ct_dns, "dig", _dig({
        ("mail2030._domainkey.example.com", "TXT"): [KEY],
        ("selector1._domainkey.example.com", "TXT"): [KEY],
    }))
    sources = dnsevidence.dkim_selector_sources(
        {"discovery": {"dkim_selectors": ["selector1"]}}, ["mail2030"])
    keys = ct_dns.dkim_keys("example.com", list(sources), sources)
    assert {k["selector"]: k["selector_from"] for k in keys} == {
        "selector1": [dnsevidence.SELECTOR_FROM_PROFILE, dnsevidence.SELECTOR_FROM_DEFAULT],
        "mail2030": [dnsevidence.SELECTOR_FROM_ZONE]}
    # Without sources, a key carries no such field.
    assert all("selector_from" not in k for k in ct_dns.dkim_keys("example.com", ["mail2030"]))


def test_collect_tries_the_zone_selectors_and_records_their_source(tmp_path: Path, monkeypatch):
    (tmp_path / "dns-zones").mkdir()
    (tmp_path / "dns-zones" / "example.com.zone").write_text(ZONE)
    config.set_inbox(tmp_path)
    asked: list[str] = []
    table = {("mail2030._domainkey.example.com", "TXT"): [KEY]}

    def dig(name: str, rtype: str = "A", short: bool = True) -> list[str]:
        if "._domainkey." in name and rtype == "TXT":
            asked.append(name)
        return table.get((name, rtype), [])
    monkeypatch.setattr(ct_dns, "dig", dig)
    monkeypatch.setattr(dnsevidence, "run", lambda *a, **k: "__ERROR__ no resolver here")
    monkeypatch.setattr(ct_dns, "http_get_full", lambda *a, **k: ("__ERROR__ refused", {}))
    swept: list[dict] = []
    monkeypatch.setattr(ct_dns, "_ned_assets",
                        lambda *a, **k: (swept.append(k), [])[1])
    lines: list[str] = []
    assets, _failures, _ = ct_dns.collect(
        {"discovery": {"email_domains": ["example.com"]}}, None, NOW, progress=lines.append)

    for selector in ("mail2030", "s1.eu", "news"):
        assert f"{selector}._domainkey.example.com" in asked
    dkim = [a for a in assets if a.protocol == "dkim"]
    assert [(a.extra["selector"], a.extra["selector_from"]) for a in dkim] == [
        ("mail2030", [dnsevidence.SELECTOR_FROM_ZONE])]
    assert any("mail2030, s1.eu, news" in line for line in lines)
    # The sub-domain sweep tries them too, and is told where each came from.
    assert swept and swept[0]["selectors"][:3] == ["mail2030", "s1.eu", "news"]
    assert swept[0]["selector_sources"]["news"] == [dnsevidence.SELECTOR_FROM_ZONE]


def test_a_mail_handling_sub_domain_reading_carries_the_source(monkeypatch):
    monkeypatch.setattr(ct_dns, "dig", _dig({("news._domainkey.mail.example.com", "TXT"): [KEY]}))
    monkeypatch.setattr(dnsevidence, "run", lambda *a, **k: "__ERROR__ no resolver here")
    sources = dnsevidence.dkim_selector_sources({}, ["news"])
    got = ct_dns.mail_subdomain_records("mail.example.com", list(sources), ("",), sources)
    assert [(k["selector"], k["selector_from"]) for k in got["dkim"]] == [
        ("news", [dnsevidence.SELECTOR_FROM_ZONE])]


@pytest.fixture(autouse=True)
def _no_ct_token(monkeypatch):
    monkeypatch.setattr(ct_dns, "token", lambda: "")
