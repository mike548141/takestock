"""The IP address plan page: every label, count and section comes from the plan."""

from __future__ import annotations

import ipaddress
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from takestock import htmlpage, ipam, ipam_view

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets" / "targets" / "example-widgets.ipam.yaml"
EXPORTS = ROOT / "examples" / "example-widgets" / "exports"


@pytest.fixture(scope="module")
def sample() -> dict:
    return ipam.for_writing(ipam.build_plan(SAMPLE, EXPORTS, built_on="2030-03-02"))


class _Sections(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.panels: list[tuple[str, str, str | None]] = []
        self.ids: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.append(str(a["id"]))
        if tag == "section" and "panel" in (a.get("class") or "").split():
            self.panels.append((str(a["id"]), str(a["data-label"]), a.get("data-count")))


def sections(page: str) -> _Sections:
    p = _Sections()
    p.feed(page)
    return p


def tiny_plan(**extra) -> dict:
    """A hand-made plan with one site and one subnet, nothing optional."""
    plan = {
        "title": "IP address plan", "organisation": "Example Widgets Ltd", "built_on": "2030-01-01",
        "sources": [{"id": "inv", "label": "Bench inventory", "kind": "csv", "as_of": "2030-01-01",
                     "as_of_basis": "exported", "evidence_class": "observed", "notes": []}],
        "sites": [{"id": "lab", "name": "Test lab", "kind": "laboratory", "status": "in use",
                   "ranges": ["192.0.2.0/24"]}],
        "subnets": [{"cidr": "192.0.2.0/25", "site": "lab", "purpose": "Benches", "scope": "private",
                     "evidence": ["inv"], "vlans": [], "segments": [], "address_count": 1,
                     "usable": 126, "ip_version": 4,
                     "addresses": [{"ip": "192.0.2.1", "names": ["bench-01"], "sources": ["inv"],
                                    "evidence": ["observed"], "last_observed": "2030-01-01",
                                    "sightings": []}]}],
        "segments": [], "mirrors": [], "actions": [], "set_aside": {},
        "checks": {k: [] for k in ipam_view.CHECKS},
        "counts": {"sites": 1, "sites_by_kind": {"laboratory": 1}, "subnets": 1, "addresses": 1,
                   "addresses_seen_in_use": 1},
    }
    plan.update(extra)
    return plan


def test_the_sample_page_has_a_section_for_each_kind_of_data_it_holds(sample):
    s = sections(ipam_view.render(sample))
    assert [(i, n) for i, _label, n in s.panels] == [
        ("overview", None), ("sites", "4"), ("subnets", "10"), ("addresses", "15"),
        ("vlans", "8"), ("mirrors", "1"), ("public", "2"), ("checks", "7"),
        ("set-aside", "6"), ("actions", "1"), ("sources", "5")]


def test_optional_sections_are_absent_when_their_data_is():
    s = sections(ipam_view.render(tiny_plan()))
    assert [i for i, _l, _n in s.panels] == [
        "overview", "sites", "subnets", "addresses", "checks", "set-aside", "sources"]


def test_site_kinds_and_source_labels_come_from_the_plan():
    page = ipam_view.render(tiny_plan())
    assert "laboratory: 1" in page
    assert "Test lab" in page
    assert "Bench inventory" in page
    assert "IP address plan: Example Widgets Ltd" in page


def test_every_subnet_and_check_has_an_anchor_the_page_links_to(sample):
    page = ipam_view.render(sample)
    ids = set(sections(page).ids)
    for s in sample["subnets"]:
        assert ipam_view.anchor(s["cidr"]) in ids
    for href in re.findall(r'href="#([^"]+)"', page):
        if href.startswith(("filter=", "find=")):
            continue  # a view the script opens, not an element
        assert href in ids, href


def test_values_from_the_data_are_escaped():
    plan = tiny_plan()
    plan["subnets"][0]["purpose"] = "<script>alert(1)</script>"
    plan["sites"][0]["name"] = "</script><b>lab</b>"
    page = ipam_view.render(plan)
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    embedded = page.split('id="ipam-lookup">', 1)[1].split("</script>", 1)[0]
    assert "<" not in embedded
    data = json.loads(embedded)
    assert data["subnets"][0]["site"] == "</script><b>lab</b>"


def test_the_lookup_data_carries_each_subnet_as_a_number_and_length(sample):
    page = ipam_view.render(sample)
    embedded = page.split('id="ipam-lookup">', 1)[1].split("</script>", 1)[0]
    data = json.loads(embedded)
    first = data["subnets"][0]
    assert (first["cidr"], first["v"], first["base"], first["len"]) == (
        "192.0.2.0/26", 4, str(0xC0000200), 26)
    known = data["addresses"][f"4:{0xC000020A}"]
    assert known["names"][0] == "app-01" and known["where"] == "192.0.2.10"
    assert data["subnets"][known["s"]]["cidr"] == "192.0.2.0/26"
    assert "Asset register export" in known["sources"]


def test_the_page_uses_the_shared_shell_and_no_colour_of_its_own(sample):
    page = ipam_view.render(sample)
    assert page.startswith("<!doctype html>")
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", ipam_view._EXTRA_CSS)


def test_an_address_shows_how_it_was_given_out_and_its_vlans():
    plan = tiny_plan()
    plan["subnets"][0]["addresses"][0].update(
        assignment="static", assignment_basis=["Bench inventory: allocation static"], vlans=[20])
    page = ipam_view.render(plan)
    assert "Assigned: static (Bench inventory: allocation static)" in page
    assert "VLAN: 20" in page


def test_the_page_shows_the_audience_segment_meanings_and_exposure_chains():
    plan = tiny_plan(audience="network engineers",
                     segments=[{"site": "lab", "name": "lab-users-20", "vlan": 20, "subnet": None,
                                "switch": "sw-01", "source": "inv", "meaning": ["Staff devices"]}],
                     exposure_chains=[{"name": "Public web service", "source": "inv",
                                       "as_of": "2030-01-01",
                                       "hops": [{"label": "public address", "address": "203.0.113.5"},
                                                {"label": "web server", "address": "192.0.2.1",
                                                 "name": "bench-01"},
                                                {"label": "workers", "network": "192.0.2.64/27"}]}])
    page = ipam_view.render(plan)
    assert "Written for network engineers." in page
    assert "lab-users-20 (Staff devices)" in page
    assert ("public" in [i for i, _l, _n in sections(page).panels]
            and "as Bench inventory describes it, 2030-01-01" in page
            and "<code>192.0.2.1</code> (bench-01)" in page
            and "workers: any address in the network <code>192.0.2.64/27</code>" in page)


def test_the_page_shows_a_segments_mode_location_and_where_its_vlan_came_from():
    plan = tiny_plan(segments=[
        {"site": "lab", "name": "cl2.users", "vlan": 20, "subnet": None, "switch": "sw-01",
         "source": "inv", "vlan_source": "old", "meaning": ["Staff devices"],
         "location": "cl2", "location_meaning": "the second cluster"},
        {"site": "lab", "name": "uplink", "vlan": None, "subnet": None, "switch": "sw-01",
         "source": "inv", "mode": "trunk", "trunk_vlans": "10,20,30-39"}])
    plan["sources"].append({"id": "old", "label": "Old switch list", "kind": "csv",
                            "as_of": "2029-12-01", "as_of_basis": "exported",
                            "evidence_class": "observed", "notes": []})
    page = ipam_view.render(plan)
    assert "cl2.users (Staff devices); defined in cl2 (the second cluster)" in page
    assert "VLAN as stated by Old switch list, 2029-12-01" in page
    assert "<td>trunk 10,20,30-39</td>" in page


def test_a_summary_heading_is_shown_above_its_paragraph():
    plan = tiny_plan(summary=[{"heading": "What this covers", "text": "The bench network."},
                              "A plain paragraph."])
    page = ipam_view.render(plan)
    assert "<h3>What this covers</h3><p>The bench network.</p><p>A plain paragraph.</p>" in page
    assert "{&#x27;heading&#x27;" not in page and "{'heading'" not in page


def test_an_unknown_addressing_value_is_shown_as_read_as_static():
    plan = tiny_plan()
    plan["checks"]["unknown_addressing"] = [{"subnet": "192.0.2.0/25", "addressing": "dyanmic"}]
    page = ipam_view.render(plan)
    assert "Unknown addressing values" in page
    assert "<code>dyanmic</code></td><td>treated as static" in page


def test_the_page_carries_a_part_label_and_an_author_line(sample):
    plan = tiny_plan(part="Part 3", author="Prepared by the <network> team")
    page = ipam_view.render(plan)
    assert '<p class="eyebrow">Part 3</p>' in page
    assert '<p class="byline">Prepared by the &lt;network&gt; team</p>' in page
    page = ipam_view.render(plan, part="Appendix B", author="")
    assert '<p class="eyebrow">Appendix B</p>' in page and 'class="byline"' not in page
    assert sample["part"] == "" and sample["author"] == ""


def test_a_mac_address_finds_every_address_it_was_seen_at(sample):
    page = ipam_view.render(sample)
    data = json.loads(page.split('id="ipam-lookup">', 1)[1].split("</script>", 1)[0])
    seen = data["macs"]["020000000010"]
    assert [ip for ip, _i in seen] == ["192.0.2.10", "2001:db8:10:1::10"]
    assert [data["subnets"][i]["cidr"] for _ip, i in seen] == ["192.0.2.0/26", "2001:db8:10:1::/64"]
    assert ipam_view.mac_key("02-00-00-00-00-10") == ipam_view.mac_key("0200.0000.0010") == "020000000010"
    assert ipam_view.mac_key("not a mac") == ""


def test_the_view_is_kept_in_the_address_without_breaking_a_sandboxed_preview():
    # A preview may show the page in a sandboxed frame where changing the
    # address throws, so every change to it must sit inside a try block.
    script = ipam_view._SCRIPT
    calls = [m.start() for m in re.finditer(r"history\.\w+State", script)]
    assert calls
    for at in calls:
        line = script[script.rfind("\n", 0, at):script.find("\n", at)]
        assert "try {" in line and "catch" in line, line
    # A link carrying a view (#find=..., #filter=...) opens on it only once the
    # controls listen, so the opening call comes after the last listener.
    assert script.rindex("go(location.hash)") > script.rindex("addEventListener")


# A range a site holds (/16), a subnet inside it, and a container platform's
# internal network, each widened outside the documentation ranges from an address inside them.
RANGE = str(ipaddress.ip_network("198.51.100.0/16", strict=False))
CHILD = "198.51.100.0/24"
OVERLAY = str(ipaddress.ip_network("203.0.113.0/18", strict=False))


def blocks_plan() -> dict:
    """One of each kind of address block, plus segments, for the headline."""
    def block(cidr, **extra):
        return {"cidr": cidr, "site": "lab", "purpose": "", "scope": "private", "evidence": ["inv"],
                "vlans": [], "segments": [], "address_count": 0, "usable": 1, "ip_version": 4,
                "addresses": [], **extra}
    return tiny_plan(
        subnets=[block(RANGE), block(CHILD, parent=RANGE),
                 block(OVERLAY, addressing="overlay"), block("198.51.100.7/32"),
                 block("2001:db8:40::/48"), block("2001:db8:40:1::/64")],
        segments=[{"site": "lab", "name": n, "vlan": v, "subnet": None, "switch": "sw-01",
                   "source": "inv", **extra}
                  for n, v, extra in (("a", 20, {}), ("b", None, {}), ("c", 0, {}),
                                      ("d", 30, {"superseded_by": "New list"}))])


def test_the_headline_counts_each_kind_of_block_once():
    assert ipam_view.headline(blocks_plan()) == {
        "subnet": 2, "site_range": 2, "single_address": 1, "cluster_internal": 1,
        "segments": 3, "segments_with_vlan": 1}


def test_the_headline_tiles_open_the_page(sample):
    page = ipam_view.render(sample)
    stats = page.split('<div class="stats">', 1)[1].split("</div></div>", 1)[0]
    assert page.index('<div class="stats">') < page.index('id="ipam-tabs"')
    h = ipam_view.headline(sample)
    assert f"<b>{h['subnet']} subnets</b>" in stats
    assert f"<b>{sample['counts']['addresses_seen_in_use']} addresses</b>" in stats
    assert "<b>1 action</b>" in stats and "for people to close" in stats
    assert "planned" in stats  # the sample's showroom


def test_the_audience_reads_as_part_of_a_sentence():
    assert "Written for network engineers." in ipam_view.render(tiny_plan(audience="Network engineers"))
    assert "Written for IT staff." in ipam_view.render(tiny_plan(audience="IT staff"))


def test_actions_are_grouped_by_kind_and_say_who_closes_them():
    plan = tiny_plan(actions=[
        {"id": "B2", "kind": "decide", "title": "Pick a range", "who": "Network lead"},
        {"id": "B1", "kind": "collect", "title": "Collect the DHCP settings", "subnets": ["192.0.2.0/25"]},
        {"id": "B3", "kind": "audit", "title": "Walk the racks"}])
    plan["subnets"][0]["action_ids"] = ["B1"]
    page = ipam_view.render(plan)
    body = page.split('id="actions"', 1)[1]
    assert body.index("Collect data") < body.index("Decide") < body.index("audit")
    assert "<b>Who:</b> Network lead" in body
    assert 'class="card action k-collect" id="action-B1"' in body
    overview = page.split('id="overview"', 1)[1].split('id="sites"', 1)[0]
    assert "What needs a person" in overview and '<a href="#action-B2">B2</a>' in overview
    subnets = page.split('id="subnet-table"', 1)[1]
    assert '<a href="#action-B1">B1</a>' in subnets


def test_actions_without_a_kind_are_listed_as_they_come():
    page = ipam_view.render(tiny_plan(actions=[{"id": "C1", "title": "Check it"}]))
    body = page.split('id="actions"', 1)[1]
    assert "Collect data" not in body and 'id="action-C1"' in body


def test_every_subnet_opens_to_its_detail_even_with_no_address():
    plan = tiny_plan()
    plan["subnets"].append({"cidr": "192.0.2.128/25", "site": "lab", "purpose": "Spare",
                            "scope": "private", "evidence": ["inv"], "vlans": [], "segments": [],
                            "address_count": 0, "usable": 126, "ip_version": 4, "addresses": [],
                            "addressing": "dynamic", "confidence": "declared"})
    page = ipam_view.render(plan)
    detail = page.split('<details id="s-192-0-2-128-25"', 1)[1].split("</details>", 1)[0]
    assert "No source reported an address here" in detail
    assert ipam_view.ADDRESSING_TEXT["dynamic"] in detail
    assert "Bench inventory: exported 2030-01-01" in detail and "under a month old" in detail
    assert "status-fail" in detail and ipam_view.CONFIDENCE["declared"] in detail


def test_a_subnet_names_its_parent_and_children_and_counts_their_addresses():
    plan = blocks_plan()
    plan["subnets"][1]["address_count"] = 3
    page = ipam_view.render(plan)
    parent = page.split(f'<details id="{ipam_view.anchor(RANGE)}"', 1)[1].split("</details>", 1)[0]
    child = page.split(f'<details id="{ipam_view.anchor(CHILD)}"', 1)[1].split("</details>", 1)[0]
    assert "<dt>Contains</dt>" in parent and f'href="#{ipam_view.anchor(CHILD)}"' in parent
    assert "<dt>Inside</dt>" in child and f'href="#{ipam_view.anchor(RANGE)}"' in child
    row = page.split(f'href="#{ipam_view.anchor(RANGE)}"', 1)[1].split("</tr>", 1)[0]
    assert "3 <span class=\"muted\">in its subnets</span>" in row


def test_a_cloud_site_assigns_its_own_addresses_and_an_overlay_is_explained():
    plan = blocks_plan()
    plan["sites"][0]["kind"] = "cloud"
    page = ipam_view.render(plan)
    assert ipam_view.CLOUD_ASSIGNED in page.split(f'<details id="{ipam_view.anchor(CHILD)}"', 1)[1]
    overlay = page.split(f'<details id="{ipam_view.anchor(OVERLAY)}"', 1)[1].split("</details>", 1)[0]
    assert htmlpage.esc(ipam_view.ADDRESSING_TEXT["overlay"]) in overlay


def test_only_small_ipv4_subnets_with_addresses_get_a_map(sample):
    page = ipam_view.render(sample)
    mapped = set(re.findall(r'<details id="[^"]+" data-map="([^"]+)"', page))
    expected = {s["cidr"] for s in sample["subnets"] if s["ip_version"] == 4 and s["addresses"]
                and 23 <= int(s["cidr"].split("/")[1]) <= 30}
    assert mapped == expected and mapped
    row = re.search(r'<tr data-ip="192\.0\.2\.10" data-seen="(\d)">', page)
    assert row and row.group(1) == "1"


def test_the_subnet_search_reads_names_macs_and_qualifier_data(sample):
    page = ipam_view.render(sample)
    row = re.search(r'<tr data-i="0" data-search="([^"]*)" data-sources="([^"]*)">', page)
    assert row
    words = row.group(1).split()
    assert {"app-01", "020000000010", "192.0.2.10", "servers"} <= set(words)
    assert "asset register export" in row.group(2)
    for chip in ('data-f="site" data-v="head-office"', 'data-f="flag" data-v="actions"'):
        assert chip in page


def test_the_vlan_view_marks_a_vlan_carrying_two_subnets_and_explains_name_codes(sample):
    page = ipam_view.render(sample)
    vlans = page.split('id="vlans"', 1)[1].split('id="mirrors"', 1)[0]
    assert '<tr class="conflict">' in vlans and "carries several subnets" in vlans
    segs = [{"site": "lab", "name": n, "vlan": 20, "subnet": c, "switch": "sw-01", "source": "inv"}
            for n, c in (("lab-a", "192.0.2.0/25"), ("lab-b", "192.0.2.128/25"))]
    plan = tiny_plan(segments=segs)
    plan["checks"]["vlan_conflicts"] = [{"site": "lab", "vlan": 20,
                                         "subnets": ["192.0.2.0/25", "192.0.2.128/25"]}]
    page = ipam_view.render(plan)
    assert page.count('<tr class="conflict">') == 2
    assert "<td>lab-a, lab-b</td>" in page.split('id="check-vlan_conflicts"', 1)[1]
    plan = tiny_plan(segments=[{"site": "lab", "name": "lab-users", "vlan": 20, "subnet": None,
                                "switch": "sw-01", "source": "inv", "meaning": ["Staff devices"]}],
                     segment_codes={"users": {"meaning": "Staff devices", "environment": ""}})
    page = ipam_view.render(plan)
    assert "What the parts of a segment name mean" in page
    assert "<td><code>users</code></td><td>Staff devices</td>" in page


def test_public_addresses_are_grouped_by_who_announces_them():
    # The page treats an AS number as an opaque label, so the test uses letters.
    def pub(cidr, ip, asn, prefix):
        reg = {"asn": asn, "as_name": f"EXAMPLE-{asn}", "announced_prefix": prefix,
               "registrant": "Example Transit"}
        return {"cidr": cidr, "site": "lab", "purpose": "", "scope": "public", "evidence": ["inv"],
                "vlans": [], "segments": [], "address_count": 1, "usable": 1, "ip_version": 4,
                "addresses": [{"ip": ip, "names": [], "sources": ["inv"], "evidence": ["observed"],
                               "last_observed": "", "sightings": [], "internet_registry": reg}]}
    plan = tiny_plan()
    plan["subnets"] += [pub("203.0.113.5/32", "203.0.113.5", "X1", "203.0.113.0/24"),
                        pub("203.0.113.9/32", "203.0.113.9", "X1", "203.0.113.0/24"),
                        pub("198.51.100.20/32", "198.51.100.20", "X2", "198.51.100.0/24")]
    page = ipam_view.render(plan)
    public = page.split('id="public"', 1)[1]
    assert "Who routes and holds these addresses" in public
    assert public.index("ASX1") < public.index("ASX2")
    assert re.search(r"<td>ASX1</td>.*?<td class=\"num\">2</td>", public)


def test_sources_a_month_old_are_listed_but_documents_are_not():
    plan = tiny_plan(built_on="2030-06-15")
    plan["sources"] += [
        {"id": "old", "label": "Old switch list", "kind": "csv", "as_of": "2030-02",
         "as_of_basis": "exported", "evidence_class": "observed", "notes": []},
        {"id": "doc", "label": "Network diagram", "kind": "document", "as_of": "2029-01-01",
         "as_of_basis": "issued", "evidence_class": "documented", "notes": []}]
    page = ipam_view.render(plan)
    stale = page.split('id="check-stale-sources"', 1)[1]
    assert "<td>Old switch list</td><td>2030-02</td><td>4 months old</td>" in stale
    assert "Network diagram</td><td>2029" not in stale
    assert "<td>Bench inventory</td><td>2030-01-01</td>" in stale


def test_a_source_date_is_read_at_any_precision():
    assert ipam_view.months_before("2030-01-01", "2030-07-01") == 6
    assert ipam_view.months_before("2030-01", "2030-01-20") == 0
    assert ipam_view.months_before("2030-01-15", "2030-02-14") == 0
    assert ipam_view.months_before("2030-01-15", "2030-02-15") == 1
    assert ipam_view.months_before("2030-01-31", "2030-03-01") == 1
    assert ipam_view.months_before("2029", "2030-01-01") == 12
    assert ipam_view.months_before("not a date", "2030-01-01") is None
    assert ipam_view.age_text("2030-01-10", "2030-01-20") == "under a month old"
    assert ipam_view.age_text("", "2030-01-20") == ""


def test_every_special_range_agrees_with_the_standard_library():
    # Each row's first and last address carries the flag its kind names where
    # the standard library has one, and is not global (the library counts
    # multicast as global, so for it the multicast flag is the check).
    flag = {"loopback": "is_loopback", "link-local": "is_link_local", "multicast": "is_multicast",
            "private": "is_private"}
    for version, base, length, kind in ipam_view.SPECIAL_RANGES:
        if kind in ("public", "mapped") or length == 0:
            continue
        cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
        net = cls((base, length))
        for ip in (net.network_address, net.broadcast_address):
            assert ipam_view.address_kind(str(ip)) == kind, (net, ip)
            assert kind == "multicast" or not ip.is_global, (net, kind)
            if kind in flag:
                assert getattr(ip, flag[kind]), (net, kind)


def test_every_ipv4_address_the_table_calls_public_is_global():
    # One probe in every /16: the table and the standard library agree on
    # which are public.
    for top in range(1 << 16):
        ip = ipaddress.IPv4Address((top << 16) | 1)
        if ipam_view.address_kind(str(ip)) == "public":
            assert ip.is_global, ip
        else:
            assert ip.is_multicast or not ip.is_global, ip


def test_ipv6_kinds_outside_global_unicast_are_never_public():
    # Built from integers: the guard keeps literal addresses to the documentation range.
    for value, kind in ((0, "reserved"), (1, "loopback"), ((0xFE80 << 112) | 1, "link-local"),
                        ((0xFD00 << 112) | 5, "private"), ((0xFF02 << 112) | 1, "multicast"),
                        ((0x20010DB8 << 96) | 7, "documentation"), ((0x4000 << 112) | 1, "reserved"),
                        ((0xFFFF << 32) | 0x01020304, "mapped"), ((0x2000 << 112) | 1, "public")):
        text = str(ipaddress.IPv6Address(value))
        assert ipam_view.address_kind(text) == kind, text
        ip = ipaddress.ip_address(text)
        if kind == "public":
            assert ip.is_global and not ip.is_reserved, text
        elif kind == "reserved":
            assert ip.is_reserved or not ip.is_global, text
        elif kind not in ("multicast", "mapped"):  # mapped takes its IPv4 address's flags
            assert not ip.is_global, text


def test_the_page_carries_the_special_ranges_and_what_each_kind_says(sample):
    page = ipam_view.render(sample)
    data = json.loads(page.split('id="ipam-lookup">', 1)[1].split("</script>", 1)[0])
    assert len(data["special"]) == len(ipam_view.SPECIAL_RANGES)
    assert data["kinds"] == ipam_view.ADDRESS_KINDS
    assert {r[3] for r in data["special"]} <= set(ipam_view.ADDRESS_KINDS)
