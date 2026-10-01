"""SPF expansion: references followed, limits counted, voids told apart from failures."""

from __future__ import annotations

from takestock import spf
from takestock.spf import ANSWERED, INCONCLUSIVE, VOID, Answer


def resolver(table: dict[tuple[str, str], Answer | list[str]]):
    """A resolver answering from ``table``; anything else is a void (NXDOMAIN) answer."""
    def resolve(name: str, rtype: str):
        return table.get((name, rtype), Answer([], VOID))
    return resolve


def test_includes_redirects_hosts_and_ranges_are_followed():
    r = resolver({
        ("example.com", "TXT"): Answer(['"v=spf1 ip4:192.0.2.0/24 include:_spf.example.net '
                                        'a:relay.example.com mx ~all"'], ANSWERED),
        ("_spf.example.net", "TXT"): Answer(['"v=spf1 ip4:198.51.100.0/25 '
                                             'ip6:2001:db8::/48 redirect=_r.example.org"'],
                                            ANSWERED),
        ("_r.example.org", "TXT"): Answer(['"v=spf1 ip4:203.0.113.0/26 -all"'], ANSWERED),
        ("relay.example.com", "A"): Answer(["192.0.2.25"], ANSWERED),
        ("example.com", "MX"): Answer(["10 mx1.example.com."], ANSWERED),
        ("mx1.example.com", "A"): Answer(["192.0.2.26"], ANSWERED),
    })
    s = spf.expand("example.com", r)
    assert s.published and s.all_qualifier == "~all"
    assert s.ranges == ["192.0.2.0/24", "198.51.100.0/25", "203.0.113.0/26"]
    assert s.ipv6_ranges == ["2001:db8::/48"]
    assert s.hosts == ["relay.example.com", "mx1.example.com"]
    assert s.policies == ["_spf.example.net", "_r.example.org"]
    assert s.addresses == 256 + 128 + 64
    assert s.lookups == 4 and s.depth == 2
    assert s.void_measured and s.void_lookups == 0


def test_overlapping_ranges_are_counted_once():
    s = spf.Surface(domain="example.com", ranges=["192.0.2.0/24", "192.0.2.0/25", "bad"])
    assert s.addresses == 256


def test_no_record_means_nothing_authorised():
    s = spf.expand("example.com", resolver({}))
    assert not s.published and s.hosts == [] and s.record == ""


def test_lookup_limit_is_counted_across_the_chain():
    terms = " ".join(f"include:p{i}.example.net" for i in range(11))
    table: dict = {("example.com", "TXT"): Answer([f'"v=spf1 {terms} -all"'], ANSWERED)}
    for i in range(11):
        table[(f"p{i}.example.net", "TXT")] = Answer(['"v=spf1 -all"'], ANSWERED)
    s = spf.expand("example.com", resolver(table))
    assert s.lookups == 11 and s.over_lookup_limit


def test_void_lookups_are_counted_and_named():
    r = resolver({
        ("example.com", "TXT"): Answer(['"v=spf1 include:gone1.example.net '
                                        'include:gone2.example.net a:v6only.example.com -all"'],
                                       ANSWERED),
        ("v6only.example.com", "AAAA"): Answer(["2001:db8::1"], ANSWERED),
    })
    s = spf.expand("example.com", r)
    assert s.void_lookups == 3 and s.over_void_limit and not s.at_void_limit
    assert any("AAAA present" in t for t in s.void_terms)
    assert "v6only.example.com (named by SPF, has an IPv6 address but no IPv4 one)" in s.unresolved
    assert any("void lookup" in u for u in s.unresolved)


def test_a_failed_lookup_is_not_a_void_one():
    r = resolver({
        ("example.com", "TXT"): Answer(['"v=spf1 include:flaky.example.net -all"'], ANSWERED),
        ("flaky.example.net", "TXT"): Answer([], INCONCLUSIVE),
    })
    s = spf.expand("example.com", r)
    assert s.void_lookups == 0 and s.inconclusive_lookups == 1


def test_plain_lists_leave_voids_unmeasured():
    s = spf.expand("example.com", lambda n, t: ['"v=spf1 -all"'] if t == "TXT" else [])
    assert s.published and not s.void_measured and not s.over_void_limit


def test_unknown_and_unparseable_terms_are_recorded():
    r = resolver({("example.com", "TXT"): Answer(
        ['"v=spf1 exists:%{i}.example.com ip4:not-an-address foo:bar exp=x.example.com -all"'],
        ANSWERED)})
    s = spf.expand("example.com", r)
    assert "exists:%{i}.example.com" in s.unexpandable
    assert "unparseable address term not-an-address" in s.unexpandable
    assert "unknown mechanism foo:bar" in s.unexpandable


def test_include_loops_are_followed_once():
    r = resolver({
        ("example.com", "TXT"): Answer(['"v=spf1 include:a.example.net -all"'], ANSWERED),
        ("a.example.net", "TXT"): Answer(['"v=spf1 include:example.com"'], ANSWERED),
    })
    s = spf.expand("example.com", r)
    assert s.policies == ["a.example.net", "example.com"]


def test_combined_merges_surfaces():
    a = spf.Surface(domain="a.example", ranges=["192.0.2.0/25"], hosts=["h.example"])
    b = spf.Surface(domain="b.example", ranges=["192.0.2.0/25", "192.0.2.128/25"],
                    ipv6_ranges=["2001:db8::/64"], hosts=["h.example"])
    assert spf.combined([a, b]) == (["192.0.2.0/25", "192.0.2.128/25"], 256,
                                    ["2001:db8::/64"], ["h.example"])


def test_txt_strings_are_joined():
    assert spf.join_strings('"v=spf1 " "-all"') == "v=spf1 -all"
    assert spf.join_strings("v=spf1 -all") == "v=spf1 -all"
