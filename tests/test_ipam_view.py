"""The IP address plan page: every label, count and section comes from the plan."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from takestock import ipam, ipam_view

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
    assert data["addresses"][f"4:{0xC000020A}"][0] == "app-01"


def test_the_page_uses_the_shared_shell_and_no_colour_of_its_own(sample):
    page = ipam_view.render(sample)
    assert page.startswith("<!doctype html>")
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", ipam_view._EXTRA_CSS)
