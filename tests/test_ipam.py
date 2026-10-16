"""The IP address plan: reading sources, placing addresses, the checks, and the outputs."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import yaml

from takestock import config, ipam
from takestock.ipam import Harvest, IpamError, Segment, Sighting

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "examples" / "example-widgets"
SAMPLE = SAMPLE_DIR / "targets" / "example-widgets.ipam.yaml"
EXPORTS = SAMPLE_DIR / "exports"


@pytest.fixture(scope="module")
def sample() -> dict:
    return ipam.build_plan(SAMPLE, EXPORTS, built_on="2030-03-02")


def subnet(plan: dict, cidr: str) -> dict:
    return next(s for s in plan["subnets"] if s["cidr"] == cidr)


def address(plan: dict, ip: str) -> dict:
    return next(a for s in plan["subnets"] for a in s["addresses"] if a["ip"] == ip)


def write_plan(tmp_path: Path, doc: dict, files: dict[str, str] | None = None) -> Path:
    exports = tmp_path / "exports"
    exports.mkdir(exist_ok=True)
    for name, text in (files or {}).items():
        (exports / name).parent.mkdir(parents=True, exist_ok=True)
        (exports / name).write_text(text, encoding="utf-8")
    path = tmp_path / "plan.ipam.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def minimal(**extra) -> dict:
    doc = {"sites": [{"id": "lab", "name": "Lab", "kind": "lab", "ranges": ["192.0.2.0/24"]}],
           "subnets": [{"cidr": "192.0.2.0/25", "site": "lab", "purpose": "Benches"}],
           "sources": [{"id": "inv", "kind": "csv", "label": "Inventory", "path": "inv.csv",
                        "as_of": "2030-01-01", "columns": {"ip": "ip", "name": "host"}}]}
    doc.update(extra)
    return doc


# --- the sample organisation ---------------------------------------------------

def test_the_sample_counts_sites_by_the_kinds_its_plan_gives_them(sample):
    c = sample["counts"]
    assert c["sites"] == 4
    assert c["sites_by_kind"] == {"internet-facing": 1, "office": 2, "warehouse": 1}
    assert c["sites_planned"] == 1


def test_every_address_is_classed_by_the_strongest_evidence_for_it(sample):
    c = sample["counts"]
    assert (c["addresses_seen_in_use"], c["addresses_named_only"],
            c["addresses_documented_only"]) == (11, 2, 2)
    assert c["addresses"] == 15
    # DNS names it and the asset register sees it: seen in use wins, both are kept.
    app = address(sample, "192.0.2.10")
    assert app["evidence"] == ["observed", "named"]
    assert app["last_observed"] == "2030-02-27"
    assert "app-01.example.test" in app["names"]
    # Only DNS names it.
    assert address(sample, "203.0.113.9")["evidence"] == ["named"]
    # Only a dated document names it.
    doc = address(sample, "192.0.2.193")
    assert doc["evidence"] == ["documented"] and doc["last_documented"] == "2030-02-10"


def test_addresses_go_to_the_most_specific_subnet_with_their_source(sample):
    assert [a["ip"] for a in subnet(sample, "192.0.2.0/26")["addresses"]] == [
        "192.0.2.10", "192.0.2.11", "192.0.2.12"]
    v6 = subnet(sample, "2001:db8:10:1::/64")
    assert [a["ip"] for a in v6["addresses"]] == ["2001:db8:10:1::10"]
    assert v6["usable"] == 2 ** 64


def test_a_roaming_source_cannot_found_a_subnet_and_says_why_each_sighting_was_set_aside(sample):
    aside = sample["set_aside"]["laptop-checkins"]
    assert aside == {
        "loopback": 1,
        "unspecified": 1,
        "inside a machine: container bridge on staff laptops": 1,
        "outside every subnet in the plan (a roaming source)": 1,
        "inside Warehouse, but not an address Asset register export holds": 1,
        "inside 192.0.2.192/27, which only Network diagram, Asset register export may populate": 1,
    }
    # Its one sighting inside a subnet at a site with no authoritative source is kept.
    assert address(sample, "192.0.2.70")["sources"] == ["laptop-checkins"]
    assert not any(s["cidr"].startswith("2001:db8:99") for s in sample["subnets"])


def test_the_checks_are_found_in_the_data(sample):
    ch = sample["checks"]
    assert [(i["ip"], i["name_conflict"]) for i in ch["name_conflicts"]] == [
        ("192.0.2.130", ["print-01", "print-02"])]
    assert ch["vlan_conflicts"] == [{"site": "warehouse", "vlan": 40,
                                     "subnets": ["198.51.100.64/26", "198.51.100.192/27"]}]
    assert [(i["ip"], i["site_stated"]) for i in ch["site_disagreements"]] == [
        ("198.51.100.20", ["Head office"])]
    assert [(i["ip"], i["not_in_authoritative_source"])
            for i in ch["not_in_authoritative_source"]] == [("198.51.100.193", "Asset register export")]
    assert [i["ip"] for i in ch["only_in_superseded"]] == ["192.0.2.12"]
    assert ch["no_addresses_found"] == ["203.0.113.16/28"]
    assert ch["documented_only"] == ["203.0.113.16/28"]


def test_a_dual_stack_vlan_is_not_a_conflict(sample):
    # VLAN 10 at the head office carries one IPv4 and one IPv6 subnet.
    assert not any(c["site"] == "head-office" for c in sample["checks"]["vlan_conflicts"])
    assert "head-office:10" in subnet(sample, "2001:db8:10:1::/64")["vlans"]


def test_a_superseded_source_gives_previous_names(sample):
    db = address(sample, "192.0.2.11")
    assert db["machine_names"] == ["db-01"]
    assert db["previous_names"] == ["file-01"]
    assert "only_in_superseded" not in db


def test_the_mirror_pairs_subnets_by_position(sample):
    (m,) = sample["mirrors"]
    assert m["left"]["label"] == "Head office" and m["right"]["label"] == "Warehouse"
    assert [(r["position"], r["left"], r["right"]) for r in m["rows"]] == [
        ("+0 /26", "192.0.2.0/26", "198.51.100.0/26"),
        ("+64 /26", "192.0.2.64/26", "198.51.100.64/26"),
        ("+128 /27", "192.0.2.128/27", None),
        ("+192 /27", "192.0.2.192/27", "198.51.100.192/27"),
    ]
    assert (m["both"], m["left_only"], m["right_only"]) == (3, 1, 0)


def test_sources_carry_their_notes_and_evidence_class(sample):
    by_id = {s["id"]: s for s in sample["sources"]}
    assert by_id["dns"]["evidence_class"] == "named"
    assert by_id["network-diagram"]["evidence_class"] == "documented"
    assert "1 value in the address column was not an address and was skipped" in (
        by_id["asset-register"]["notes"])


def test_a_declared_scope_overrides_the_computed_one(sample):
    assert subnet(sample, "203.0.113.0/28")["scope"] == "public"
    assert subnet(sample, "192.0.2.0/26")["scope"] == "private"


# --- the plan file never asserts an address ---------------------------------------

def test_a_subnet_entry_cannot_list_addresses(tmp_path):
    doc = minimal()
    doc["subnets"][0]["addresses"] = ["192.0.2.1"]
    path = write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"})
    with pytest.raises(IpamError, match="cannot list addresses"):
        ipam.build_plan(path, tmp_path / "exports")


@pytest.mark.parametrize("source", ["inv", "nowhere"])
def test_a_documented_address_must_name_a_document_source(tmp_path, source):
    doc = minimal(documented_addresses=[{"ip": "192.0.2.5", "name": "x", "source": source}])
    path = write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"})
    with pytest.raises(IpamError, match="must be a declared source of kind"):
        ipam.build_plan(path, tmp_path / "exports")


def test_an_unknown_site_or_source_is_refused(tmp_path):
    doc = minimal()
    doc["subnets"][0]["site"] = "nowhere"
    with pytest.raises(IpamError, match="unknown site"):
        ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"}), tmp_path / "exports")
    doc = minimal()
    doc["subnets"][0]["evidence"] = ["nothing"]
    with pytest.raises(IpamError, match="unknown source"):
        ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"}), tmp_path / "exports")


# --- readers -------------------------------------------------------------------------

def test_the_csv_reader_names_a_missing_column(tmp_path):
    path = write_plan(tmp_path, minimal(), {"inv.csv": "address,host\n192.0.2.1,a\n"})
    with pytest.raises(IpamError, match="has no column 'ip'"):
        ipam.build_plan(path, tmp_path / "exports")


def test_the_csv_reader_refuses_an_unknown_column_key(tmp_path):
    doc = minimal()
    doc["sources"][0]["columns"]["colour"] = "c"
    path = write_plan(tmp_path, doc, {"inv.csv": "ip,host,c\n"})
    with pytest.raises(IpamError, match="unknown column keys colour"):
        ipam.build_plan(path, tmp_path / "exports")


def test_the_csv_reader_reads_several_addresses_a_delimiter_and_optional_columns(tmp_path):
    doc = minimal()
    doc["sources"][0].update(delimiter=";", columns={"ip": "addr", "name": "host",
                                                      "date": "when", "mac": "hw"})
    text = ("host;addr;when;hw\n"
            "bench-01;192.0.2.1, 192.0.2.2 | 2001:db8::1;2030-01-02T03:04:05;02:00:00:00:00:01\n")
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": text}), tmp_path / "exports")
    a = address(plan, "192.0.2.2")
    assert a["names"] == ["bench-01"] and a["last_observed"] == "2030-01-02"
    assert a["sightings"][0]["mac"] == "02:00:00:00:00:01"
    assert plan["set_aside"]["inv"] == {"outside every subnet in the plan": 1}


def test_a_missing_export_is_an_error_not_a_silent_gap(tmp_path):
    path = write_plan(tmp_path, minimal())
    with pytest.raises(IpamError, match="missing"):
        ipam.build_plan(path, tmp_path / "exports")


def test_source_paths_default_to_the_workspace_inbox(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "inv.csv").write_text("ip,host\n192.0.2.9,bench-09\n", encoding="utf-8")
    path = write_plan(tmp_path, minimal())
    config.set_workspace(tmp_path)
    plan = ipam.build_plan(path)
    assert address(plan, "192.0.2.9")["names"] == ["bench-09"]


def test_the_dns_reader_reads_zone_files_and_private_zone_exports(tmp_path):
    zone = ("$ORIGIN example.test.\n@ IN TXT \"v=spf1 ip4:192.0.2.7 ip4:192.0.2.64/26 -all\"\n"
            "web IN A 192.0.2.5\nweb IN AAAA 2001:db8::5\n")
    private = json.dumps([{"fqdn": "db.example.test.", "type": "A",
                           "ttl": 300, "aRecords": [{"ipv4Address": "192.0.2.6"}]}])
    doc = minimal(sources=[{"id": "dns", "kind": "dns-zones", "path": "dns"}])
    path = write_plan(tmp_path, doc, {"dns/example.test.zone": zone,
                                      "dns/private/example.test.json": private})
    plan = ipam.build_plan(path, tmp_path / "exports")
    names = {a["ip"]: (a["names"], a["sightings"][0]["name_is"])
             for s in plan["subnets"] for a in s["addresses"]}
    assert names == {"192.0.2.5": (["web.example.test"], "alias"),
                     "192.0.2.6": (["db.example.test"], "alias"),
                     "192.0.2.7": (["authorised mail sender for example.test"], "label")}
    assert plan["set_aside"]["dns"] == {"outside every subnet in the plan": 1}


# --- the reader registry -------------------------------------------------------------

@pytest.fixture()
def clean_registry(monkeypatch):
    monkeypatch.setattr(ipam, "READERS", dict(ipam.READERS))
    monkeypatch.setattr(ipam, "_entry_points_loaded", False)


def test_an_organisation_can_plug_in_its_own_reader(tmp_path, clean_registry):
    def read_switches(src: dict, paths: list[Path], h: Harvest) -> None:
        for line in paths[0].read_text().splitlines():
            vlan, cidr, name = line.split(",")
            h.segments.append(Segment(src["id"], "lab", name, int(vlan), cidr, "sw-01"))
        h.declared["198.51.100.0/24"] = {"source": src["id"], "name": "management range"}
        h.sightings.append(Sighting("192.0.2.200", "sw-01", src["id"], "2030-01-03", {}, "machine"))

    ipam.register_reader("switch-export", read_switches)
    doc = minimal(sources=[{"id": "sw", "kind": "switch-export", "label": "Switch export",
                            "path": "sw.txt", "as_of": "2030-01-03"}])
    text = "10,192.0.2.128/25,users\n20,192.0.2.128/25,voice\n"
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"sw.txt": text}), tmp_path / "exports")
    users = subnet(plan, "192.0.2.128/25")
    assert users["origin"] == "declared by a source" and users["site"] == "lab"
    assert [s["name"] for s in users["segments"]] == ["users", "voice"]
    assert [a["ip"] for a in users["addresses"]] == ["192.0.2.200"]
    assert subnet(plan, "198.51.100.0/24")["purpose"] == "Management range"
    assert subnet(plan, "198.51.100.0/24")["site"] == ipam.NO_SITE
    assert plan["counts"]["segments"] == 2


def test_the_registry_refuses_a_duplicate_a_document_kind_and_an_unknown_kind(tmp_path, clean_registry):
    with pytest.raises(ValueError, match="already registered"):
        ipam.register_reader("csv", ipam.read_csv)
    with pytest.raises(ValueError, match="document kind"):
        ipam.register_reader("document", ipam.read_csv)
    doc = minimal(sources=[{"id": "x", "kind": "no-such-kind", "path": "x"}])
    with pytest.raises(IpamError, match="no reader for kind 'no-such-kind'"):
        ipam.build_plan(write_plan(tmp_path, doc), tmp_path / "exports")


def test_readers_are_found_through_entry_points(tmp_path, clean_registry, monkeypatch):
    def read_none(src, paths, h):
        h.notes[src["id"]].append("read by a plugged-in reader")

    class EntryPoint:
        name = "from-plugin"

        def load(self):
            return read_none

    monkeypatch.setattr(ipam.metadata, "entry_points",
                        lambda group: [EntryPoint()] if group == ipam.ENTRY_POINT_GROUP else [])
    doc = minimal(sources=[{"id": "p", "kind": "from-plugin", "path": "p.txt"}])
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"p.txt": ""}), tmp_path / "exports")
    assert plan["sources"][0]["notes"] == ["read by a plugged-in reader"]


# --- placement rules on small plans --------------------------------------------------

def test_two_names_on_a_dynamic_subnet_are_not_a_conflict(tmp_path):
    doc = minimal()
    doc["subnets"].append({"cidr": "192.0.2.128/25", "site": "lab", "addressing": "dynamic"})
    text = "ip,host\n192.0.2.1,a\n192.0.2.1,b\n192.0.2.129,c\n192.0.2.129,d\n"
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": text}), tmp_path / "exports")
    assert [i["ip"] for i in plan["checks"]["name_conflicts"]] == ["192.0.2.1"]


def test_an_address_history_names_past_holders_without_a_conflict(tmp_path):
    doc = minimal()
    doc["sources"].append({"id": "past", "kind": "csv", "label": "Address history",
                           "path": "past.csv", "as_of": "2030-01-02", "name_is": "history",
                           "columns": {"ip": "addresses", "name": "device"}})
    files = {"inv.csv": "ip,host\n192.0.2.5,bench-05\n",
             "past.csv": "device,addresses\nbench-07,192.0.2.5 192.0.2.6\nbench-08,192.0.2.5\n"}
    plan = ipam.build_plan(write_plan(tmp_path, doc, files), tmp_path / "exports")
    held = address(plan, "192.0.2.5")
    assert held["names"] == ["bench-05", "bench-07", "bench-08"]
    assert held["machine_names"] == ["bench-05"]
    assert "name_conflict" not in held and not plan["checks"]["name_conflicts"]
    only_past = address(plan, "192.0.2.6")
    assert only_past["machine_names"] == [] and only_past["evidence"] == ["observed"]


def test_each_address_carries_how_it_was_given_out_and_its_vlans(tmp_path, clean_registry):
    def read_hosts(src: dict, paths: list[Path], h: Harvest) -> None:
        h.sightings.append(Sighting("192.0.2.3", "hv-01", src["id"], "", {"dhcp": False, "vlan": 30}))
        h.sightings.append(Sighting("192.0.2.4", "hv-02", src["id"], "", {"dhcp": "true"}))

    ipam.register_reader("host-settings", read_hosts)
    doc = minimal()
    doc["sources"][0]["columns"].update(assignment="alloc", vlan="vlan")
    doc["sources"].append({"id": "hosts", "kind": "host-settings", "label": "Host settings",
                           "path": "hosts.txt"})
    text = ("ip,host,alloc,vlan\n192.0.2.1,bench-01,Static,20\n192.0.2.2,bench-02,,\n"
            "192.0.2.4,hv-02,Static,\n")
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": text, "hosts.txt": ""}),
                           tmp_path / "exports")
    one = address(plan, "192.0.2.1")
    assert (one["assignment"], one["assignment_basis"], one["vlans"]) == (
        "static", ["Inventory: allocation static"], [20])
    assert "assignment" not in address(plan, "192.0.2.2") and "vlans" not in address(plan, "192.0.2.2")
    hv = address(plan, "192.0.2.3")
    assert (hv["assignment"], hv["assignment_basis"], hv["vlans"]) == (
        "static", ["Host settings: DHCP off"], [30])
    disputed = address(plan, "192.0.2.4")
    assert disputed["assignment"] == "disputed"
    assert disputed["assignment_basis"] == ["Host settings: DHCP on", "Inventory: allocation static"]


def test_a_mirror_needs_two_prefixes_of_one_size(tmp_path):
    doc = minimal(mirrors=[{"name": "m", "left": {"prefix": "192.0.2.0/24"},
                            "right": {"prefix": "198.51.100.0/25"}}])
    with pytest.raises(IpamError, match="same size"):
        ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"}), tmp_path / "exports")


def test_the_plan_file_is_an_overlay_not_a_profile():
    assert config.is_overlay(Path("example.ipam.yaml"))


# --- internet registry lookups -------------------------------------------------------

CYMRU = """AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
64496   | 203.0.113.5      | 203.0.113.0/24      | ZZ | examplenic | 2030-01-01 | EXAMPLE-AS, ZZ
NA      | 203.0.113.16     | NA                  |    | other    |            | NA
"""

RDAP = {"objectClassName": "ip network", "handle": "EX-1", "name": "EXAMPLE-NET",
        "startAddress": "203.0.113.0", "endAddress": "203.0.113.255", "country": "ZZ",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "entities": [{"roles": ["registrant"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Example Widgets Ltd"]]]}]}

BOOTSTRAP = {"services": [[["203.0.113.0/24"], ["http://rdap.example.test/", "https://rdap.example.test/"]],
                          [["203.0.113.0/28"], ["https://rdap-narrow.example.test"]]]}


def test_cymru_and_rdap_replies_parse_to_the_fields_an_engineer_reads():
    got = ipam.parse_cymru(CYMRU)
    assert got["203.0.113.5"]["asn"] == "64496"
    assert got["203.0.113.5"]["as_name"] == "EXAMPLE-AS, ZZ"
    assert got["203.0.113.16"]["asn"] == "NA"
    assert ipam.parse_rdap(RDAP) == {
        "registered_range": "203.0.113.0 – 203.0.113.255",
        "registered_cidrs": ["203.0.113.0/24"], "network_name": "EXAMPLE-NET",
        "handle": "EX-1", "registrant": "Example Widgets Ltd", "registered_country": "ZZ"}


def test_the_rdap_bootstrap_takes_the_longest_match_and_prefers_https():
    assert ipam.rdap_base("203.0.113.5", BOOTSTRAP) == "https://rdap-narrow.example.test/"
    assert ipam.rdap_base("203.0.113.200", BOOTSTRAP) == "https://rdap.example.test/"
    assert ipam.rdap_base("198.51.100.1", BOOTSTRAP) == ""


def test_lookups_are_saved_and_read_back_onto_public_addresses(tmp_path):
    asked: list[tuple[str, list[str]]] = []
    fetched: list[str] = []

    def query(host, ips):
        asked.append((host, ips))
        return CYMRU

    def fetch(url):
        fetched.append(url)
        return BOOTSTRAP if url in ipam.RDAP_BOOTSTRAP.values() else RDAP

    folder = tmp_path / "exports" / "asn"
    n = ipam.lookup_asn(["203.0.113.5", "203.0.113.0"], folder, "2030-01-05",
                        whois_host="whois.example.test", query=query, fetch=fetch)
    assert n == 2 and asked == [("whois.example.test", ["203.0.113.0", "203.0.113.5"])]
    assert "https://rdap-narrow.example.test/ip/203.0.113.5" in fetched
    # A second run asks nothing.
    assert ipam.lookup_asn(["203.0.113.5"], folder, "2030-01-06", query=query, fetch=fetch) == 0

    doc = minimal(subnets=[{"cidr": "203.0.113.0/28", "site": "lab", "scope": "public"}],
                  sources=[{"id": "inv", "kind": "csv", "path": "inv.csv", "columns": {"ip": "ip"}},
                           {"id": "asn", "kind": "asn-lookups", "path": "asn"}])
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip\n203.0.113.5\n"}),
                           tmp_path / "exports")
    pub = subnet(plan, "203.0.113.0/28")
    assert pub["internet_registry"]["registrant"] == "Example Widgets Ltd"
    assert pub["addresses"][0]["internet_registry"]["asn"] == "64496"
    assert ipam.public_addresses(plan) == ["203.0.113.0", "203.0.113.5"]


def test_an_asn_source_with_nothing_saved_is_a_note_not_an_error(tmp_path):
    doc = minimal(sources=[{"id": "asn", "kind": "asn-lookups", "path": "asn"}])
    plan = ipam.build_plan(write_plan(tmp_path, doc), tmp_path / "exports")
    assert plan["sources"][0]["notes"] == ["nothing saved yet at asn"]


# --- writing ----------------------------------------------------------------------

def test_outputs_drop_local_paths_and_refuse_a_credential(sample, tmp_path):
    clean = ipam.for_writing(sample)
    assert all("path" not in s for s in clean["sources"])
    bad = {**sample, "summary": ["password = hunter2-example"]}
    with pytest.raises(IpamError, match="shaped like a credential"):
        ipam.write_outputs(bad, tmp_path)
    assert not list(tmp_path.iterdir())


def test_write_outputs_writes_json_csv_and_html(sample, tmp_path):
    paths = ipam.write_outputs(sample, tmp_path)
    assert sorted(p.name for p in paths.values()) == [
        "example-widgets.csv", "example-widgets.html", "example-widgets.json"]
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["counts"] == sample["counts"]
    with paths["csv"].open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(sample["subnets"])
    first = rows[0]
    assert first["subnet"] == "192.0.2.0/26" and first["site_name"] == "Head office"
    assert first["evidence"].startswith("Asset register export (exported 2030-03-01)")


def test_the_command_line_builds_the_sample_and_reports_errors(tmp_path, capsys):
    assert ipam.main([str(SAMPLE), str(tmp_path / "out"), "--exports", str(EXPORTS)]) == 0
    assert (tmp_path / "out" / "example-widgets.html").is_file()
    assert ipam.main([str(SAMPLE), str(tmp_path / "out"), "--exports", str(tmp_path)]) == 2
    assert "missing" in capsys.readouterr().err


def test_segment_codes_say_what_a_segment_name_means(tmp_path, clean_registry):
    def read_switches(src: dict, paths: list[Path], h: Harvest) -> None:
        h.segments.append(Segment(src["id"], "lab", "lab-app-db-prd-110", 110,
                                  "192.0.2.128/26", "sw-01"))
        h.segments.append(Segment(src["id"], "lab", "plain-users", 120, None, "sw-01"))

    ipam.register_reader("switch-export", read_switches)
    doc = minimal(segment_codes={"lab": {}, "app-db": {"meaning": "Application databases"},
                                 "PRD": {"meaning": "production", "environment": "production"},
                                 "users": "Staff devices"},
                  sources=[{"id": "sw", "kind": "switch-export", "label": "Switch export",
                            "path": "sw.txt", "as_of": "2030-01-03"}])
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"sw.txt": ""}), tmp_path / "exports")
    by_name = {s["name"]: s for s in plan["segments"]}
    assert by_name["lab-app-db-prd-110"]["meaning"] == ["Application databases", "production"]
    assert by_name["lab-app-db-prd-110"]["environment"] == "production"
    assert by_name["plain-users"]["meaning"] == ["plain", "Staff devices"]
    assert "environment" not in by_name["plain-users"]
    declared = subnet(plan, "192.0.2.128/26")
    assert declared["purpose"] == "Network segment lab-app-db-prd-110: Application databases, production"
    assert declared["environment"] == "production"
    assert plan["segment_codes"]["users"] == {"meaning": "Staff devices", "environment": ""}


def test_without_segment_codes_a_segment_carries_no_meaning(tmp_path, clean_registry):
    def read_switches(src: dict, paths: list[Path], h: Harvest) -> None:
        h.segments.append(Segment(src["id"], "lab", "users", 10, "192.0.2.128/26", "sw-01"))

    ipam.register_reader("switch-export", read_switches)
    doc = minimal(sources=[{"id": "sw", "kind": "switch-export", "path": "sw.txt"}])
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"sw.txt": ""}), tmp_path / "exports")
    assert "meaning" not in plan["segments"][0]
    assert subnet(plan, "192.0.2.128/26")["purpose"] == "Network segment users"


def test_an_exposure_chain_names_a_declared_source_and_real_addresses(tmp_path):
    chain = {"name": "Public web service", "source": "design",
             "hops": [{"label": "public address", "address": "203.0.113.5"},
                      {"label": "load balancer", "address": "192.0.2.10", "name": "lb-01"}]}
    doc = minimal(audience="Network engineers", exposure_chains=[chain])
    doc["sources"].append({"id": "design", "kind": "document", "label": "Service design",
                           "as_of": "2030-01-04"})
    plan = ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"}), tmp_path / "exports")
    assert plan["audience"] == "Network engineers"
    (got,) = plan["exposure_chains"]
    assert got["as_of"] == "2030-01-04" and got["hops"][1] == {
        "label": "load balancer", "address": "192.0.2.10", "name": "lb-01"}
    for bad, why in (({**chain, "source": "nowhere"}, "not a declared source"),
                     ({**chain, "hops": chain["hops"][:1]}, "at least two hops"),
                     ({**chain, "hops": [{"address": "lb"}, chain["hops"][0]]}, "not an address")):
        doc["exposure_chains"] = [bad]
        with pytest.raises(IpamError, match=why):
            ipam.build_plan(write_plan(tmp_path, doc, {"inv.csv": "ip,host\n"}), tmp_path / "exports")
