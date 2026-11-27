"""Information flows joined to the channels that carry them (``takestock.flows``).

Every register, map and row is composed here for an invented organisation
(Example Widgets Ltd), with invented channels, ``.example.test`` hosts and
round numbers.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from takestock import config, coverage, flows, observe, plugins
from takestock.model import CryptoAsset
from takestock.plugins import Context
from takestock.policy import Policy
from takestock.readers import flows as flows_reader
from takestock.readers import library

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)

# Ten flows over five channels. Parties are invented; the classification
# column carries the uncertainty marker on two rows and nothing on one.
REGISTER = [
    {"flow_id": "F01", "direction": "Outbound", "external_party": "Acme Freight",
     "channel": "Partner file drop", "classification": "IN-CONFIDENCE",
     "compliance_flag": "compliant", "purpose": "orders"},
    {"flow_id": "F02", "direction": "Outbound", "external_party": "Globex Parts",
     "channel": "Partner file drop; Courier", "classification": "SENSITIVE???",
     "compliance_flag": "compliant", "purpose": "drawings"},
    {"flow_id": "F03", "direction": "Inbound", "external_party": "Acme Freight",
     "channel": "Partner file drop", "classification": "UNCLASSIFIED",
     "compliance_flag": "", "purpose": "manifests"},
    {"flow_id": "F04", "direction": "Outbound", "external_party": "Initech Audit",
     "channel": "Build handover", "classification": "RESTRICTED",
     "compliance_flag": "review", "purpose": "releases"},
    {"flow_id": "F05", "direction": "Inbound", "external_party": "Initech Audit",
     "channel": "Warehouse sync", "classification": "IN-CONFIDENCE",
     "compliance_flag": "review", "purpose": "stock counts"},
    {"flow_id": "F06", "direction": "Outbound", "external_party": "Umbrella Legal",
     "channel": "Warehouse sync", "classification": "SENSITIVE",
     "compliance_flag": "compliant", "purpose": "pick lists"},
    {"flow_id": "F07", "direction": "Outbound", "external_party": "Umbrella Legal",
     "channel": "Customer portal", "classification": "IN-CONFIDENCE???",
     "compliance_flag": "compliant", "purpose": "statements"},
    {"flow_id": "F08", "direction": "Inbound", "external_party": "Hooli Telecom",
     "channel": "Customer portal", "classification": "",
     "compliance_flag": "", "purpose": "usage"},
    {"flow_id": "F09", "direction": "Outbound", "external_party": "Hooli Telecom",
     "channel": "Courier", "classification": "IN-CONFIDENCE",
     "compliance_flag": "compliant", "purpose": "hardware"},
    {"flow_id": "F10", "direction": "Outbound", "external_party": "Globex Parts",
     "channel": "Courier", "classification": "OFFICIAL",
     "compliance_flag": "compliant", "purpose": "samples"},
]

MAP_YAML = """
register:
  path: inbox/flows-register.html
  source: Example_Widgets_flows_2030_01
  issued: 2030-01-15
  flows: 10
data_requests:
  R1:
    title: Customer portal address list
    owner: the web team
    asked: 2030-01-20
  R2:
    title: Scanner vendor connection statement
    owner: the logistics team
channels:
  Partner file drop:
    kind: measured
    legs:
      - {leg: file server, host: files-01.example.test, port: 22}
  Build handover:
    kind: measured-partial
    legs:
      - {leg: build server, host: build-01.example.test}
    unmeasured:
      - {what: how keys for encrypted archives are exchanged, gap: R2, scope: control}
  Warehouse sync:
    kind: measured-partial
    legs:
      - {leg: sync gateway, host: files-01.example.test, protocol: winrm}
      - leg: handheld-uplink
        measurable: false
        would_measure: the scanner vendor statement on how handhelds connect
        gap: R2
  Customer portal:
    kind: unjoined
    gap: R1
    note: the register names no address
  Courier:
    kind: not-cryptographic
"""


def _doc() -> dict:
    return yaml.safe_load(MAP_YAML)


def _asset(name: str, host: str, port: str = "", protocol: str = "ssh",
           verdict: str = "strong") -> CryptoAsset:
    return CryptoAsset(name=name, data_state="in-transit", source="ssh_audit",
                       source_class="private", host=host, port=port, protocol=protocol,
                       verdict=verdict)


def _assets() -> list[CryptoAsset]:
    return [
        _asset("files ssh", "files-01.example.test", "22", "ssh", "strong"),
        _asset("files winrm", "files-01.example.test", "5985", "winrm", "acceptable"),
        _asset("build ssh", "build-01.example.test", "22", "ssh", "weak"),
        _asset("build winrm", "build-01.example.test", "5985", "winrm", "strong"),
        _asset("elsewhere", "other-01.example.test", "22", "ssh", "strong"),
    ]


def _flows(rows: list[dict] | None = None) -> list[flows.Flow]:
    return flows.parse_register("const RAW = " + json.dumps(REGISTER if rows is None else rows))


def _join(**kw) -> dict:
    doc = _doc()
    return flows.join(_flows(), flows.build_channel_map(doc), _assets(),
                      register=doc["register"], requests=flows.build_requests(doc), **kw)


# ── reading the register ──

def test_a_const_assignment_is_read_into_flows():
    fl = _flows()
    assert [f.flow_id for f in fl] == [f"F{n:02d}" for n in range(1, 11)]
    assert {f.direction for f in fl} == {"Inbound", "Outbound"}
    assert len({f.party for f in fl}) == 5


def test_the_parser_walks_past_a_marker_that_is_not_the_data():
    page = ("<p>The rows are in const RAW = see below</p>\n<script>\nconst RAW = "
            + json.dumps(REGISTER[:2]) + ";\n</script>")
    assert [f.flow_id for f in flows.parse_register(page)] == ["F01", "F02"]


def test_a_page_with_no_register_in_it_raises():
    with pytest.raises(flows.RegisterError, match="does not look like"):
        flows.parse_register("<html><body>no rows here</body></html>")


def test_a_marker_followed_by_rubbish_raises_rather_than_half_parsing():
    with pytest.raises(flows.RegisterError):
        flows.parse_register("const RAW = [{broken")


def test_a_json_array_and_a_flows_object_are_read():
    as_array = json.dumps(REGISTER[:3])
    as_object = json.dumps({"flows": REGISTER[:3]})
    assert [f.flow_id for f in flows.parse_register(as_array)] == ["F01", "F02", "F03"]
    assert [f.flow_id for f in flows.parse_register(as_object)] == ["F01", "F02", "F03"]
    with pytest.raises(flows.RegisterError):
        flows.parse_register(json.dumps({"rows": []}))


def test_a_csv_register_is_read_and_carries_its_other_columns():
    text = ("flow_id,direction,external_party,channel,classification,compliance_flag,purpose\n"
            "F01,Outbound,Acme Freight,Partner file drop,IN-CONFIDENCE,compliant,orders\n"
            ",,,,,,\n"
            "F02,Inbound,Globex Parts,Courier; Warehouse sync,SENSITIVE???,,drawings\n")
    fl = flows.parse_register_csv(text)
    assert [f.flow_id for f in fl] == ["F01", "F02"]
    assert fl[1].channels == ("Courier", "Warehouse sync")
    assert fl[1].classification == "SENSITIVE" and not fl[1].classification_certain
    assert fl[0].extra == {"purpose": "orders"}


def test_a_csv_with_no_header_raises():
    with pytest.raises(flows.RegisterError):
        flows.parse_register_csv("")


def test_read_register_picks_the_parser_by_suffix_and_never_raises(tmp_path):
    (tmp_path / "r.csv").write_text("flow_id,channel\nF1,Courier\n")
    (tmp_path / "r.json").write_text(json.dumps(REGISTER[:2]))
    (tmp_path / "r.html").write_text("<p>nothing</p>")
    (tmp_path / "empty.json").write_text("[]")
    assert [f.flow_id for f in flows.read_register(tmp_path / "r.csv")[0]] == ["F1"]
    assert len(flows.read_register(tmp_path / "r.json")[0]) == 2
    assert flows.read_register(tmp_path / "gone.json") == ([], "file not present")
    assert "does not look like" in flows.read_register(tmp_path / "r.html")[1]
    assert flows.read_register(tmp_path / "empty.json")[1].startswith("the export decoded")


def test_unknown_columns_are_carried_through_untouched():
    fl = _flows([{"flow_id": "X", "channel": "Courier", "purpose": "p", "owner_group": 7,
                  "note": None}])
    assert fl[0].extra == {"purpose": "p", "owner_group": "7", "note": ""}


def test_a_flow_with_no_id_takes_its_position():
    fl = _flows([{"channel": "Courier"}, "not a row", {"channel": "Courier"}])
    assert [f.flow_id for f in fl] == ["1", "3"]


def test_a_multi_valued_channel_field_is_split_into_every_channel_it_names():
    f02 = _flows()[1]
    assert f02.channels == ("Partner file drop", "Courier")
    assert flows._split_channels(" a ;; b ; ") == ("a", "b")


def test_the_uncertainty_marker_becomes_a_field_and_not_a_lost_suffix():
    by_id = {f.flow_id: f for f in _flows()}
    assert (by_id["F02"].classification, by_id["F02"].classification_certain) == \
        ("SENSITIVE", False)
    assert by_id["F01"].classification_certain is True
    # Nobody assessed F08: it cannot be called a confident classification.
    assert (by_id["F08"].classification, by_id["F08"].classification_certain) == ("", False)
    assert all(flows.UNCERTAINTY_MARKER not in f.classification for f in by_id.values())


# ── classification ──

def test_sensitivity_is_ranked_against_the_published_scheme():
    by_id = {f.flow_id: f for f in _flows()}
    assert by_id["F03"].sensitivity == 0 and by_id["F04"].sensitivity == 3
    assert by_id["F01"].at_or_above() and by_id["F04"].at_or_above("SENSITIVE")
    assert not by_id["F03"].at_or_above()
    assert not by_id["F01"].at_or_above("SENSITIVE")


def test_a_classification_outside_the_scale_is_reported_not_ranked():
    by_id = {f.flow_id: f for f in _flows()}
    assert by_id["F10"].sensitivity is None and not by_id["F10"].at_or_above()
    assert _join()["totals"]["unrecognised_classifications"] == ["OFFICIAL"]


def test_a_map_can_replace_the_scale_and_the_floor():
    doc = _doc()
    doc["classification"] = {"scale": ["OFFICIAL", "OFFICIAL-SENSITIVE", "SENSITIVE"],
                             "floor": "OFFICIAL-SENSITIVE"}
    scale, floor = flows.build_scale(doc)
    assert scale == {"OFFICIAL": 0, "OFFICIAL-SENSITIVE": 1, "SENSITIVE": 2}
    payload = flows.join(_flows(), flows.build_channel_map(doc), _assets(), floor=floor,
                         scale=scale)
    assert payload["sensitivity_floor"] == "OFFICIAL-SENSITIVE"
    assert payload["classification_scale"] == ["OFFICIAL", "OFFICIAL-SENSITIVE", "SENSITIVE"]
    # F10 now ranks, and the default scheme's words are the ones outside the scale.
    assert payload["totals"]["sensitive_flows"] == 2
    assert "OFFICIAL" not in payload["totals"]["unrecognised_classifications"]
    assert "IN-CONFIDENCE" in payload["totals"]["unrecognised_classifications"]


def test_the_default_floor_is_the_second_value_of_a_custom_scale():
    assert flows.build_scale({"classification": {"scale": ["LOW", "HIGH"]}})[1] == "HIGH"
    assert flows.build_scale({"classification": {"scale": ["ONLY"]}})[1] == "ONLY"
    assert flows.build_scale({}) == (None, flows.SENSITIVITY_FLOOR)


@pytest.mark.parametrize("block", [
    {"scale": []}, {"scale": ["A", "A"]}, {"scale": ["A", ""]}, {"scale": "A"},
    {"scale": ["A", "B"], "floor": "C"}, {"scale": ["A"], "unknown": 1}, "not a mapping"])
def test_a_malformed_classification_block_raises(block):
    with pytest.raises(flows.FlowMapError):
        flows.build_scale({"classification": block})


def test_a_floor_outside_the_scale_stops_the_join():
    with pytest.raises(flows.FlowMapError, match="floor"):
        flows.join(_flows(), flows.build_channel_map(_doc()), _assets(), floor="NOPE")


# ── the map ──

def test_a_channel_missing_from_the_map_is_a_hard_failure():
    doc = _doc()
    doc["channels"].pop("Courier")
    with pytest.raises(flows.FlowMapError) as excinfo:
        flows.join(_flows(), flows.build_channel_map(doc), _assets())
    assert "Courier" in str(excinfo.value)


@pytest.mark.parametrize("spec,fragment", [
    ({"kind": "invented"}, "not one of"),
    ({"kind": "measured"}, "names no leg"),
    ({"kind": "measured-partial", "legs": [{"leg": "a", "host": "h.example.test"}]},
     "measured-partial"),
    ({"kind": "measured-partial", "legs": [{"leg": "a", "host": "h.example.test"}],
      "unmeasured": [{"what": "x", "gap": "G9", "scope": "leg"}]}, "measured-partial"),
    ({"kind": "unjoined", "gap": "G9", "legs": [{"leg": "a", "host": "h.example.test"}]},
     "not unjoined"),
    ({"kind": "unjoined"}, "`gap:`"),
    ({"kind": "not-cryptographic", "gap": "G9"}, "contradiction"),
    ({"kind": "not-cryptographic", "legs": [{"leg": "a", "host": "h.example.test"}]},
     "contradiction"),
    ({"kind": "measured", "legs": [{"leg": "a"}]}, "must name a host"),
    ({"kind": "measured", "legs": [{"leg": "a", "host": "h.example.test"}],
      "unmeasured": [{"what": "x"}]}, "needs both"),
    ({"kind": "measured", "legs": [{"leg": "a", "host": "h.example.test"}],
      "unmeasured": [{"what": "x", "gap": "G9", "scope": "elsewhere"}]}, "scope"),
    ({"kind": "measured-partial", "legs": [
        {"leg": "a", "host": "h.example.test"}, {"leg": "client", "measurable": False}]},
     "would_measure"),
    ({"kind": "measured-partial", "legs": [
        {"leg": "a", "host": "h.example.test"},
        {"leg": "client", "measurable": False, "host": "h.example.test",
         "would_measure": "an export"}]}, "must name no host"),
    ({"kind": "measured", "legs": [
        {"leg": "a", "host": "h.example.test"},
        {"leg": "client", "measurable": False, "would_measure": "an export"}]},
     "is not measured on every leg"),
    ({"kind": "measured-partial", "legs": [
        {"leg": "client", "measurable": False, "would_measure": "an export"}]},
     "names no leg to measure"),
    ({"kind": "unjoined", "gap": "G9", "legs": [
        {"leg": "client", "measurable": False, "would_measure": "an export"}]},
     "no measured transport"),
    ({"kind": "measured", "legs": [
        {"leg": "a", "host": "h.example.test", "would_measure": "an export"}]},
     "contradicts a leg that names"),
    ({"kind": "measured", "legs": "not a list"}, "must be a list"),
    ({"kind": "measured", "legs": ["not a mapping"]}, "must be a mapping"),
    ({"kind": "measured", "legs": [{"leg": "a", "host": "h"}], "unmeasured": "x"},
     "must be a list"),
])
def test_a_map_that_contradicts_itself_raises(spec, fragment):
    with pytest.raises(flows.FlowMapError) as excinfo:
        flows.build_channel_map({"channels": {"Sample channel": spec}})
    assert fragment in str(excinfo.value)


def test_a_channel_that_is_not_a_mapping_raises():
    with pytest.raises(flows.FlowMapError, match="expected a mapping"):
        flows.build_channel_map({"channels": {"Sample channel": "measured"}})


def test_a_valid_map_round_trips_every_declared_field():
    channels = flows.build_channel_map(_doc())
    assert list(channels) == ["Partner file drop", "Build handover", "Warehouse sync",
                              "Customer portal", "Courier"]
    sync = channels["Warehouse sync"]
    assert [leg.label for leg in sync.legs] == ["sync gateway", "handheld-uplink"]
    assert sync.legs[0].protocols == ("winrm",)
    assert sync.data_requests == ["R2"]
    assert channels["Build handover"].blind_spots[0].scope == "control"
    assert channels["Customer portal"].note == "the register names no address"
    assert channels["Customer portal"].data_requests == ["R1"]


def test_data_requests_need_a_title_and_an_owner():
    reqs = flows.build_requests(_doc())
    assert reqs["R1"].asked == "2030-01-20" and reqs["R2"].asked == ""
    for spec, fragment in (({"owner": "x"}, "title"), ({"title": "x"}, "owner"),
                           ("text", "expected a mapping")):
        with pytest.raises(flows.FlowMapError, match=fragment):
            flows.build_requests({"data_requests": {"D9": spec}})


def test_folded_yaml_in_a_request_becomes_one_line():
    reqs = flows.build_requests({"data_requests": {
        "R1": {"title": "a\n  b", "owner": "c\n d", "note": "e\n f"}}})
    assert (reqs["R1"].title, reqs["R1"].owner, reqs["R1"].note) == ("a b", "c d", "e f")


def test_a_request_says_who_owes_the_answer_and_whether_anyone_asked():
    unasked = flows.Request(id="R1", title="t", owner="the web team")
    asked = flows.Request(id="R2", title="t", owner="the web team", asked="2030-01-20")
    assert "Not yet requested" in unasked.attribution()
    assert "Asked on 2030-01-20" in asked.attribution()
    assert "nobody has yet been named" in flows.Request(id="R3").attribution()


# ── legs ──

def test_a_leg_with_a_host_and_no_port_matches_every_port_on_it():
    leg = flows.Leg(label="a", host="FILES-01.example.test")
    assert [a.name for a in _assets() if leg.matches(a)] == ["files ssh", "files winrm"]
    narrow = flows.Leg(label="a", host="files-01.example.test", port="22", protocols=("ssh",))
    assert [a.name for a in _assets() if narrow.matches(a)] == ["files ssh"]


def test_an_unmeasurable_leg_matches_nothing_even_if_it_somehow_carries_a_host():
    leg = flows.Leg(label="client", host="files-01.example.test", measurable=False,
                    would_measure="an export")
    assert not any(leg.matches(a) for a in _assets())


def test_an_ordinary_legs_dict_carries_only_what_it_declares():
    assert flows.Leg(label="a", host="h").as_dict() == {"leg": "a", "host": "h"}
    out = flows.Leg(label="c", measurable=False, would_measure="x", gap="R2").as_dict()
    assert out == {"leg": "c", "measurable": False, "would_measure": "x", "gap": "R2"}


# ── the join ──

def test_every_flow_lands_in_exactly_one_class():
    payload = _join()
    totals = payload["totals"]
    assert totals["flows"] == 10 == sum(totals["by_class"].values())
    assert all(row["kind"] in flows.KINDS for row in payload["flows"])
    assert totals["by_class"] == {"measured": 3, "measured-partial": 3, "unjoined": 2,
                                  "not-cryptographic": 2}
    assert totals["joined"] == 6


def test_a_flow_riding_several_channels_takes_the_best_joined_class():
    f02 = next(r for r in _join()["flows"] if r["flow_id"] == "F02")
    assert f02["channel_kinds"] == ["measured", "not-cryptographic"]
    assert f02["kind"] == "measured"


def test_an_unmeasured_channel_outranks_a_non_cryptographic_one():
    doc = _doc()
    rows = [{"flow_id": "A", "channel": "Customer portal; Courier"}]
    payload = flows.join(_flows(rows), flows.build_channel_map(doc), [])
    assert payload["flows"][0]["kind"] == "unjoined"
    assert flows.KIND_RANK["unjoined"] < flows.KIND_RANK["not-cryptographic"]


def test_a_flow_naming_no_channel_is_unjoined_not_dropped():
    payload = flows.join(_flows([{"flow_id": "A"}]), flows.build_channel_map(_doc()), [])
    assert payload["flows"][0]["kind"] == "unjoined"
    assert payload["totals"]["by_class"]["unjoined"] == 1


def test_a_channel_rollup_carries_what_a_reader_has_to_weigh():
    channels = {r["channel"]: r for r in _join()["channels"]}
    drop = channels["Partner file drop"]
    assert (drop["flows"], drop["parties"], drop["sensitive_flows"]) == (3, 2, 2)
    assert (drop["uncertain_flows"], drop["inbound"], drop["outbound"]) == (1, 1, 2)
    assert drop["assets"] == ["files ssh"] and drop["worst_verdict"] == "strong"
    assert drop["flow_ids"] == ["F01", "F02", "F03"]
    # The leg is declared by host and port, so the winrm row is not in the join.
    assert "files winrm" not in drop["assets"]
    build = channels["Build handover"]
    assert build["assets"] == ["build ssh", "build winrm"] and build["worst_verdict"] == "weak"


def test_a_measured_channel_can_still_owe_a_data_request():
    row = next(r for r in _join()["channels"] if r["channel"] == "Build handover")
    assert row["kind"] == "measured-partial" and row["data_requests"] == ["R2"]
    assert row["blind_spots"] == [{"what": "how keys for encrypted archives are exchanged", "gap": "R2",
                                   "scope": "control"}]


def test_parties_are_counted_distinctly_and_never_summed():
    payload = _join()
    assert payload["totals"]["parties"] == 5
    per_channel = sum(r["parties"] for r in payload["channels"])
    assert per_channel > payload["totals"]["parties"]
    asset = payload["by_asset"]["files winrm"]
    assert asset["parties"] == 2 and asset["flows"] == 2


def test_the_compliance_crosstab_accounts_for_every_flow():
    payload = _join()
    crosstab = payload["compliance_by_class"]
    assert sum(sum(v.values()) for v in crosstab.values()) == payload["totals"]["flows"]
    assert all(set(v) == set(flows.KINDS) for v in crosstab.values())
    assert "(unrecorded)" in crosstab


def test_the_channel_table_leads_with_the_least_evidence():
    kinds = [r["kind"] for r in _join()["channels"]]
    assert kinds == sorted(kinds, key=lambda k: flows.CONCERN_RANK[k])
    assert kinds[0] == "unjoined" and kinds[-1] == "not-cryptographic"


def test_the_per_asset_index_says_what_rides_each_row():
    by_asset = _join()["by_asset"]
    assert set(by_asset) == {"files ssh", "files winrm", "build ssh", "build winrm"}
    entry = by_asset["files ssh"]
    assert entry["channels"] == ["Partner file drop"]
    assert (entry["flows"], entry["parties"], entry["sensitive_flows"]) == (3, 2, 2)
    assert by_asset["build ssh"]["data_requests"] == ["R2"]


def test_only_requests_a_channel_owes_are_echoed_with_their_owners():
    payload = _join()
    assert sorted(payload["requests"]) == ["R1", "R2"]
    assert payload["requests"]["R1"]["owner"] == "the web team"


def test_the_payload_is_json_serialisable_and_carries_dates_as_text():
    doc = _doc()
    doc["register"]["issued"] = "2030-01-15"
    payload = flows.join(_flows(), flows.build_channel_map(doc), _assets(),
                         register=doc["register"])
    assert json.loads(json.dumps(payload)) == payload


def test_the_empty_payload_has_the_same_shape_as_a_real_one():
    real, empty = _join(), flows.empty_payload()

    def shape(value):
        if isinstance(value, dict):
            return {k: shape(v) for k, v in value.items() if k not in ("by_class",)}
        return type(value).__name__
    assert set(real) == set(empty)
    assert shape(real["totals"]).keys() == shape(empty["totals"]).keys()
    assert empty["totals"]["by_class"] == {k: 0 for k in flows.KINDS}


# ── building from a profile ──

def _workspace(tmp_path: Path, *, register: bool = True, map_text: str = MAP_YAML) -> dict:
    targets = tmp_path / "targets"
    targets.mkdir(exist_ok=True)
    (targets / "acme.yaml").write_text("name: acme\n")
    if map_text:
        (targets / "acme.flows.yaml").write_text(map_text)
    if register:
        (tmp_path / "inbox").mkdir(exist_ok=True)
        (tmp_path / "inbox" / "flows-register.html").write_text(
            "const RAW = " + json.dumps(REGISTER))
    return {"_path": str(targets / "acme.yaml")}


@pytest.fixture(autouse=True)
def _isolated_workspace(tmp_path: Path):
    config.set_workspace(tmp_path)
    config.set_inbox(None)
    yield
    config.set_workspace(None)
    config.set_inbox(None)


def test_no_map_means_no_flows_and_no_gap(tmp_path):
    payload, gaps = flows.build({"_path": str(tmp_path / "targets" / "acme.yaml")}, tmp_path, [])
    assert payload == flows.empty_payload() and gaps == []
    assert flows.build({}, tmp_path, [])[1] == []


def test_a_map_with_no_export_is_a_gap_not_a_zero(tmp_path):
    target = _workspace(tmp_path, register=False)
    payload, gaps = flows.build(target, tmp_path, _assets())
    assert payload["totals"]["flows"] == 0 and payload["register"]["flows"] == "10"
    (gap,) = gaps
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION
    assert "inbox/flows-register.html" in gap and "file not present" in gap


def test_an_unreadable_export_says_so_rather_than_reporting_none(tmp_path):
    target = _workspace(tmp_path)
    (tmp_path / "inbox" / "flows-register.html").write_text("<p>not a register</p>")
    payload, gaps = flows.build(target, tmp_path, [])
    assert payload["totals"]["flows"] == 0 and "does not look like" in gaps[0]


def test_the_default_register_path_is_used_when_the_map_declares_none(tmp_path):
    target = _workspace(tmp_path, register=False,
                        map_text="channels:\n  Courier: {kind: not-cryptographic}\n")
    _, gaps = flows.build(target, tmp_path, [])
    assert flows.DEFAULT_REGISTER_PATH in gaps[0]
    assert flows.register_path_for_target(target) == flows.DEFAULT_REGISTER_PATH


def test_the_register_path_is_the_one_the_map_declares(tmp_path):
    target = _workspace(tmp_path)
    assert flows.register_path_for_target(target) == "inbox/flows-register.html"
    assert flows.register_path_for_target({}) == flows.DEFAULT_REGISTER_PATH


def test_a_full_build_joins_and_raises_one_gap_per_request_and_per_hole(tmp_path):
    target = _workspace(tmp_path)
    payload, gaps = flows.build(target, tmp_path, _assets())
    assert payload["totals"]["flows"] == 10
    texts = [str(g) for g in gaps]
    assert len(gaps) == 3
    leg = next(t for t in texts if t.startswith("channel "))
    assert "handheld-uplink" in leg and "measures a listener" in leg
    assert "the logistics team" in leg and "Not yet requested" in leg
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert "says nothing about this one" in gaps[0].impact
    assert gaps[0].harvest == "the scanner vendor statement on how handhelds connect"
    d1 = next(t for t in texts if "data request R1" in t)
    assert "Customer portal address list" in d1 and "names no endpoint" in d1
    assert "Asked on 2030-01-20" in d1 and "the web team" in d1
    d2 = next(t for t in texts if "data request R2" in t)
    assert "is measured on the legs an instrument can reach" in d2
    assert "how keys for encrypted archives are exchanged" in d2
    assert "the handheld-uplink leg" in d2


def test_a_declared_leg_with_no_row_is_recorded_and_gapped_not_raised(tmp_path):
    target = _workspace(tmp_path)
    without_build = [a for a in _assets() if a.host != "build-01.example.test"]
    payload, gaps = flows.build(target, tmp_path, without_build)
    row = next(r for r in payload["channels"] if r["channel"] == "Build handover")
    assert row["legs_unjoined"] == ["build server"] and row["assets"] == []
    gap = next(g for g in gaps if "'build server'" in g)
    assert coverage.kind_of(gap) == coverage.COULD_NOT_TEST
    assert "joined on the remaining legs only" in gap


def test_an_unmeasurable_leg_is_declared_uncovered_and_not_a_rescan_gap(tmp_path):
    payload, gaps = flows.build(_workspace(tmp_path), tmp_path, _assets())
    row = next(r for r in payload["channels"] if r["channel"] == "Warehouse sync")
    assert row["legs_unjoined"] == ["handheld-uplink"]
    assert row["legs_unmeasurable"] == ["handheld-uplink"]
    assert not any(coverage.kind_of(g) == coverage.COULD_NOT_TEST for g in gaps)


def test_the_registers_source_name_is_echoed_in_display_form(tmp_path):
    payload, _ = flows.build(_workspace(tmp_path), tmp_path, [])
    assert payload["register"]["source"] == "Example Widgets flows 2030 01"
    assert payload["register"]["issued"] == "2030-01-15"
    assert all(isinstance(v, str) for v in payload["register"].values())


def test_a_map_can_be_named_directly(tmp_path):
    target = _workspace(tmp_path, map_text="")
    assert flows.map_path_for_target(target) is None
    other = tmp_path / "elsewhere.yaml"
    other.write_text(MAP_YAML)
    payload, _ = flows.build(target, tmp_path, [], map_path=other)
    assert payload["totals"]["flows"] == 10


def test_a_map_that_contradicts_itself_stops_the_build(tmp_path):
    target = _workspace(tmp_path, map_text="channels:\n  A: {kind: measured}\n")
    with pytest.raises(flows.FlowMapError):
        flows.build(target, tmp_path, [])


def test_a_repeated_key_in_the_map_is_refused(tmp_path):
    target = _workspace(tmp_path, map_text="channels:\n  A: {kind: not-cryptographic}\n"
                                           "channels:\n  B: {kind: not-cryptographic}\n")
    with pytest.raises(config.DuplicateKeyError):
        flows.build(target, tmp_path, [])


def test_the_overlay_is_never_read_as_a_profile():
    assert config.is_overlay(Path("targets/acme.flows.yaml"))
    assert flows.MAP_SUFFIX in config.OVERLAY_SUFFIXES


# ── back onto the rows ──

def test_the_sentence_says_how_many_flows_to_how_many_organisations():
    assert flows.carries_sentence({}) == ""
    one = {"flows": 1, "parties": 1, "sensitive_flows": 0, "channels": ["A"]}
    assert flows.carries_sentence(one) == (
        "1 recorded information flow to 1 organisation — channel: A")
    many = {"flows": 5, "parties": 3, "sensitive_flows": 2, "channels": ["A", "B"]}
    assert flows.carries_sentence(many, "SENSITIVE") == (
        "5 recorded information flows to 3 organisations, 2 at SENSITIVE or above"
        " — channel: A; B")


def test_annotate_writes_a_string_and_is_idempotent():
    payload = _join()
    rows = _assets()
    assert flows.annotate(rows, payload) == 4
    first = rows[0].extra[flows.EXTRA_KEY]
    assert isinstance(first, str) and "3 recorded information flows to 2 organisations" in first
    assert flows.annotate(rows, payload) == 4 and rows[0].extra[flows.EXTRA_KEY] == first
    assert flows.EXTRA_KEY not in rows[4].extra
    rows[4].extra[flows.EXTRA_KEY] = "stale"
    flows.annotate(rows, payload)
    assert flows.EXTRA_KEY not in rows[4].extra


def test_annotations_are_keyed_by_bom_ref_and_leave_the_rows_alone():
    payload, rows = _join(), _assets()
    out = flows.row_annotations(rows, payload)
    assert set(out) == {a.bom_ref() for a in rows[:4]}
    assert all(flows.EXTRA_KEY not in a.extra for a in rows)
    # The same sentences annotate would have written.
    scratch = _assets()
    flows.annotate(scratch, payload)
    assert out == {a.bom_ref(): {"flows": a.extra["flows"]} for a in scratch
                   if "flows" in a.extra}


# ── the plug-in ──

def _ctx(target: dict, assets: list[CryptoAsset], settings: dict | None = None) -> Context:
    return Context(plugin=flows_reader.PLUGIN, target=target, settings=settings or {},
                   input=None, ref_time=NOW, raw_dir=Path("."),
                   policy=Policy(config.load_baseline()), baseline={}, dictionary={},
                   port_table={}, collected_on="2030-01-31", assets=tuple(assets))


def test_the_reader_is_an_annotation_in_the_library():
    plugin = library()["flows"]
    assert plugin is flows_reader.PLUGIN
    assert plugin.kind == "annotation" and plugin.annotation_keys == ("flows",)
    assert plugin.gap_prefix is False and plugin.input == "" and not plugin.late


def test_the_step_returns_sentences_gaps_and_the_payload(tmp_path):
    target = _workspace(tmp_path)
    out = flows_reader.step(_ctx(target, _assets()))
    assert len(out.annotations) == 4 and len(out.gaps) == 3
    assert out.summary["totals"]["flows"] == 10
    assert json.loads(json.dumps(out.summary)) == out.summary


def test_the_step_with_no_map_gives_the_empty_payload_and_no_gap(tmp_path):
    out = flows_reader.step(_ctx({}, _assets()))
    assert out.annotations == {} and out.gaps == [] and out.summary == flows.empty_payload()


def test_the_step_reads_a_map_the_profile_names(tmp_path):
    target = _workspace(tmp_path, map_text="")
    (tmp_path / "other.flows.yaml").write_text(MAP_YAML)
    out = flows_reader.step(_ctx(target, _assets(), {"map": "other.flows.yaml"}))
    assert out.summary["totals"]["flows"] == 10
    missing = flows_reader.step(_ctx(target, _assets(), {"map": "gone.yaml"}))
    assert len(missing.gaps) == 1 and "does not exist" in missing.gaps[0]
    assert missing.annotations == {}


# ── an observation end to end ──

@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(plugins.metadata, "entry_points", lambda group="": [])
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    shutil.copytree(SAMPLE / "exports", tmp_path / "inbox")
    config.set_workspace(tmp_path)
    config.set_inbox(tmp_path / "inbox")
    return tmp_path


def test_an_observation_puts_the_sentence_on_the_rows_and_the_join_in_the_summary(workspace):
    (workspace / "targets" / "example-widgets.flows.yaml").write_text(MAP_YAML)
    (workspace / "inbox" / "flows-register.html").write_text("const RAW = " + json.dumps(REGISTER))
    target = config.load_target("example-widgets")
    target["plugins"] = ["flows"]
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    by_name = {a.name: a for a in result.assets}
    # Only the sample rows the map's hosts select carry the key.
    assert "3 recorded information flows to 2 organisations" in by_name[
        "SSH files-01.example.test:22"].extra["flows"]
    assert "flows" in by_name["SSH build-01.example.test:22"].extra
    assert sum(1 for a in result.assets if "flows" in a.extra) == 4
    record = result.summary["plugins"]["flows"]
    assert record["kind"] == "annotation" and record["annotated"] == 4
    assert record["summary"]["totals"]["by_class"]["not-cryptographic"] == 2
    assert any("data request R1" in g for g in result.summary["gaps"])
