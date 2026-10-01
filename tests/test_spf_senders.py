"""The SPF sender surface row, its flags and gaps, and relay probing through a supplied probe."""

from __future__ import annotations

from datetime import UTC, datetime

from takestock import coverage
from takestock.collectors import spf_senders
from takestock.model import CryptoAsset
from takestock.spf import ANSWERED, VOID, Answer

NOW = datetime(2030, 6, 15, tzinfo=UTC)
TARGET = {"discovery": {"email_domains": ["example.com", "example.com", " "]},
          "scan_targets": {"smtp_25": [{"host": "gw.example.com"}, "gw2.example.com"]}}


def resolver(table):
    def resolve(name, rtype):
        return table.get((name, rtype), Answer([], VOID))
    return resolve


BASE = {
    ("example.com", "TXT"): Answer(['"v=spf1 a:relay.example.com a:gw.example.com '
                                    'ip4:192.0.2.0/24 -all"'], ANSWERED),
    ("relay.example.com", "A"): Answer(["192.0.2.25"], ANSWERED),
    ("gw.example.com", "A"): Answer(["192.0.2.26"], ANSWERED),
}


def test_the_surface_row_describes_what_is_authorised():
    assets, gaps = spf_senders.collect(TARGET, NOW, resolve=resolver(BASE))
    assert spf_senders.domains(TARGET) == ["example.com"]
    a = assets[0]
    assert a.protocol == "spf-senders" and a.flags == []
    assert a.extra["named_host_count"] == 2 and a.extra["ipv4_address_count"] == 256
    assert a.extra["dns_read_at"] == "2030-06-15T00:00:00Z"
    assert "ends -all — recorded, not graded" in a.notes
    texts = " ".join(gaps)
    assert "ran without --scan" in texts and "declared inbound gateways" in texts
    assert all(coverage.kind_of(g) == coverage.COULD_NOT_TEST for g in gaps)


def test_headroom_and_limit_flags():
    terms = " ".join(f"include:p{i}.example.net" for i in range(8))
    table = {("example.com", "TXT"): Answer([f'"v=spf1 {terms} -all"'], ANSWERED)}
    for i in range(8):
        table[(f"p{i}.example.net", "TXT")] = Answer(['"v=spf1 -all"'], ANSWERED)
    a = spf_senders.collect(TARGET, NOW, resolve=resolver(table))[0][0]
    assert a.flags == [spf_senders.LOOKUP_HEADROOM_FLAG]
    table[("example.com", "TXT")] = Answer(['"v=spf1 include:x1.example.net '
                                            'include:x2.example.net -all"'], ANSWERED)
    a = spf_senders.collect(TARGET, NOW, resolve=resolver(table))[0][0]
    assert a.flags == [spf_senders.VOID_AT_LIMIT_FLAG]
    assert "at the recommended ceiling with no margin" in a.notes


def test_relays_are_probed_with_the_supplied_probe():
    seen: list[tuple[str, str]] = []

    def probe(host: str, role: str) -> tuple[CryptoAsset, list[str]]:
        seen.append((host, role))
        return CryptoAsset(name=f"smtp {host}", data_state="in-transit", protocol="tls",
                           host=host, notes="offers TLS 1.3"), (["no answer"] if host else [])

    assets, gaps = spf_senders.collect(TARGET, NOW, scan=True, resolve=resolver(BASE),
                                       probe=probe)
    assert [h for h, _ in seen] == ["relay.example.com"]  # the declared gateway is skipped
    assert "permitted to send by example.com" in seen[0][1]
    relay = assets[1]
    assert relay.source == spf_senders.SOURCE_KEY and relay.extra["named_by_spf"] == "example.com"
    assert relay.notes.startswith("offers TLS 1.3; a STARTTLS probe")
    assert any("did not answer on 25/tcp" in g for g in gaps)
    assert not any("ran without --scan" in g for g in gaps)


def test_scanning_without_a_probe_says_so():
    _, gaps = spf_senders.collect(TARGET, NOW, scan=True, resolve=resolver(BASE))
    assert any("no STARTTLS probe was available" in g for g in gaps)
    assert not any("ran without --scan" in g for g in gaps)


def test_carried_results_are_reused():
    carried = ([CryptoAsset(name="carried", data_state="in-transit")], [])
    assets, _ = spf_senders.collect(TARGET, NOW, resolve=resolver(BASE), carried=carried)
    assert assets[-1].name == "carried"


def test_no_domains_no_rows():
    assert spf_senders.collect({}, NOW) == ([], [])


def test_unpublished_and_unmeasured_voids_are_described():
    a = spf_senders.collect(TARGET, NOW, resolve=lambda n, t: [])[0][0]
    assert a.notes.startswith("no SPF record published")
    assert a.extra["void_lookups_measured"] is False
