"""The shared DNS-name helpers: public or private, attribution, declarations, matching."""

from __future__ import annotations

from takestock import dnsnames
from takestock.collectors import dns_zones


def test_normalise_trims_lowers_and_drops_the_trailing_dot():
    assert dnsnames.normalise("  WWW.Widgets.Example.COM. ") == "www.widgets.example.com"
    assert dnsnames.normalise(None) == ""
    assert dnsnames.normalise("") == ""


def test_single_labels_and_private_endings_are_not_public():
    assert dnsnames.is_public("cdn.widgets.example.com")
    for name in ("", "printer", "nas.local", "db.internal", "_dns.resolver.arpa",
                 "files.lan", "router.home", "app.corp", "host.test", "a.example",
                 "x.invalid", "hidden.onion"):
        assert not dnsnames.is_public(name), name
    # A caller may hand in its own list.
    assert dnsnames.is_public("host.test", non_public=(".lan",))
    assert not dnsnames.is_public("shop.widgets.example.com", non_public=[".example.com"])


def test_a_profile_adds_its_own_internal_endings():
    assert dnsnames.non_public_suffixes() == dnsnames.NON_PUBLIC_SUFFIXES
    endings = dnsnames.non_public_suffixes(["Corp.Widgets.", ".intra", "", None, "lan", ".intra"])
    assert endings[:len(dnsnames.NON_PUBLIC_SUFFIXES)] == dnsnames.NON_PUBLIC_SUFFIXES
    assert endings[len(dnsnames.NON_PUBLIC_SUFFIXES):] == (".corp.widgets", ".intra")
    assert dnsnames.is_public("files.intra")
    assert not dnsnames.is_public("files.intra", endings)
    assert not dnsnames.is_public("hr.corp.widgets", endings)
    assert dnsnames.is_public("shop.widgets", endings)


def test_suffix_lookup_takes_the_longest_listed_suffix():
    table = {"widgets.example.com": "Widget Works",
             "eu.widgets.example.com": "Widget Works Europe",
             "empty.example.com": "", "test": "Everybody"}
    assert dnsnames.suffix_lookup("a.eu.widgets.example.com", table) == "Widget Works Europe"
    assert dnsnames.suffix_lookup("b.widgets.example.com", table) == "Widget Works"
    assert dnsnames.suffix_lookup("widgets.example.com", table) == "Widget Works"
    # An empty value is passed over, and the top-level label is never looked up.
    assert dnsnames.suffix_lookup("x.empty.example.com", table) is None
    assert dnsnames.suffix_lookup("other.test", table) is None


def test_registrable_and_extra_second_level_labels():
    assert dnsnames.registrable("a.b.widgets.example.com") == "example.com"
    assert dnsnames.registrable("www.parts.ac.zz") == "parts.ac.zz"
    assert dnsnames.registrable("printer") == "printer"
    labels = dnsnames.second_level_labels(["shop", "club"])
    assert {"shop", "club"} <= labels and dnsnames.SECOND_LEVEL_LABELS <= labels
    assert dnsnames.second_level_labels() == dnsnames.SECOND_LEVEL_LABELS
    assert dnsnames.registrable("www.parts.shop.zz") == "shop.zz"
    assert dnsnames.registrable("www.parts.shop.zz", labels) == "parts.shop.zz"
    # Only directly under a two-letter ending.
    assert dnsnames.registrable("www.parts.shop.zzz", labels) == "shop.zzz"


def test_dns_zones_uses_the_shared_helpers():
    assert dns_zones.registrable is dnsnames.registrable
    assert dns_zones.suffix_lookup is dnsnames.suffix_lookup
    assert dns_zones.declared_vendor_domains is dnsnames.declared_vendor_domains


def test_declared_vendors_merges_every_place_a_supplier_is_named():
    target = {
        "third_party": [
            {"name": "Widget Works", "uses": ["TLS"], "domains": ["Widgets.Example.COM."]},
            {"name": "Gadget Hosting", "crypto": ["SSH"], "pq_roadmap": "Hybrid exchange planned",
             "domains": ["gadgets.test"]},
            "not a mapping",
            {"name": "  ", "domains": ["ignored.test"]},
        ],
        "infrastructure": [
            {"name": "Widget Works", "uses": [], "pq_roadmap": "Shipped",
             "domains": ["parts.widgets.example.com", ""]},
            {"name": "Rack Supplies", "domains": ["racks.example"]},
        ],
        "scan_targets": {
            "saas_443": [{"vendor": "Gadget Hosting", "uses": ["HTTPS"],
                          "domains": ["racks.example"]}],
            "smtp_25": [{"vendor": "Mail Relay Co", "host": "mx.relay.test"}],
        },
    }
    entries, domains = dnsnames.declared_vendors(target)
    assert list(entries) == ["Widget Works", "Gadget Hosting", "Rack Supplies", "Mail Relay Co"]
    widget = entries["Widget Works"]
    assert widget["kind"] == "third-party"
    assert widget["uses"] == ["TLS"]  # an empty later list keeps the earlier one
    assert widget["pq_roadmap"] == "Shipped"
    assert widget["domains"] == ["widgets.example.com", "parts.widgets.example.com"]
    gadget = entries["Gadget Hosting"]
    assert gadget["uses"] == ["HTTPS"]  # a later non-empty list replaces ``crypto``
    assert gadget["pq_roadmap"] == "Hybrid exchange planned"
    assert gadget["domains"] == ["gadgets.test", "racks.example"]
    assert entries["Mail Relay Co"] == {"name": "Mail Relay Co", "kind": "scan-target",
                                        "uses": [], "pq_roadmap": "", "domains": []}
    # A domain declared twice belongs to the later declaration.
    assert domains == {"widgets.example.com": "Widget Works",
                       "parts.widgets.example.com": "Widget Works",
                       "gadgets.test": "Gadget Hosting", "racks.example": "Gadget Hosting"}
    assert dnsnames.declared_vendor_domains(target) == domains
    assert dnsnames.declared_vendors({}) == ({}, {})
    assert dnsnames.declared_vendors({"scan_targets": ["odd"]}) == ({}, {})


def test_words_and_slugs():
    assert dnsnames.split_words("Widget-Works (EU) 2.0") == ["Widget", "Works", "EU", "2", "0"]
    assert dnsnames.split_words(" -- ") == []
    assert dnsnames.slug("Widget Works, Ltd.") == "widget-works-ltd"
    assert dnsnames.slug("***") == "unnamed"
    assert dnsnames.vendor_words("Widget Works, Inc.") == ["widget", "works"]
    assert dnsnames.vendor_words("The Gadget Technologies Corporation") == ["gadget"]
    assert dnsnames.vendor_words("(Rack) Supplies & Co.") == ["rack", "supplies"]
    # A name made only of corporate words is kept whole.
    assert dnsnames.vendor_words("The Co") == ["the co"]
    assert dnsnames.vendor_words("Widget Works", ignore={"works"}) == ["widget"]


def test_a_declared_match_needs_every_word_as_a_whole_word():
    declared = ["Terabyte Cloud", "Blue Harbour Hosting", "Widget Works Portal",
                "Widget Works (EU) tenant", "Ann's Tools Online"]
    # Substrings and partial overlaps are not matches.
    assert dnsnames.declared_matches("Tera Labs", declared) == []
    assert dnsnames.declared_matches("Blue Finch", declared) == []
    # Corporate words are ignored, case is ignored, and every match is returned in order.
    assert dnsnames.declared_matches("WIDGET WORKS LTD", declared) == [
        "Widget Works Portal", "Widget Works (EU) tenant"]
    assert dnsnames.declared_match("Widget Works Ltd", declared) == "Widget Works Portal"
    assert dnsnames.declared_match("Harbour", declared) == "Blue Harbour Hosting"
    # A word with punctuation inside it is no declared word.
    assert dnsnames.declared_matches("Ann's Tools", declared) == []
    assert dnsnames.declared_match("", declared) == ""
    assert dnsnames.declared_match("Nobody", declared) == ""
    # The entries mapping declared_vendors returns can be passed as it is.
    entries, _ = dnsnames.declared_vendors({"third_party": [{"name": "Terabyte Cloud"}]})
    assert dnsnames.declared_matches("Terabyte", entries) == ["Terabyte Cloud"]
