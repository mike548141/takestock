"""The CrowdStrike Falcon estate coverage reader and its environment annotation.

Every export is composed in its test with made-up machines, sensor IDs,
groups, makers and dates in 2030. Nothing here was captured from a real
export.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from entra_helpers import REF_TIME, by_name, write

from takestock import config, coverage
from takestock.model import CryptoAsset
from takestock.plugins import Context
from takestock.policy import Policy
from takestock.readers import falcon_environment as annotation
from takestock.readers import falcon_estate_coverage as reader
from takestock.readers import library

HOSTS = ("hostname", "device_id", "agent_version", "product_type_desc", "platform_name",
         "host_groups", "criticality", "reduced_functionality_mode")
DISCOVERED = ("name", "manufacturer")
HEARTBEATS = ("aid", "@timestamp", "_count")
UNSUPPORTED = ("name", "manufacturer", "confidence", "review_status", "last_seen")
WORDS = {"production": ["live"], "non_production": ["pre live", "sandbox"]}


def _ms(day: int) -> str:
    return str(int(datetime(2030, 5, day, tzinfo=UTC).timestamp() * 1000))


def _export(path: Path, columns: tuple[str, ...], rows: list[dict]) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _host(name: str, sensor: str, version: str = "8.2.100", kind: str = "Workstation",
          platform: str = "Mac", groups: str = "", criticality: str = "",
          rfm: str = "no") -> dict:
    return {"hostname": name, "device_id": sensor, "agent_version": version,
            "product_type_desc": kind, "platform_name": platform, "host_groups": groups,
            "criticality": criticality, "reduced_functionality_mode": rfm}


def _ctx(plugin, path: Path | None, settings: dict | None = None,
         assets: tuple = ()) -> Context:
    return Context(plugin=plugin, target={}, settings=settings or {}, input=path,
                   ref_time=REF_TIME, raw_dir=Path("."),
                   policy=Policy(config.load_baseline()), baseline={}, dictionary={},
                   port_table={}, collected_on="2030-06-30", assets=assets)


def _hosts(tmp_path: Path) -> Path:
    return _export(tmp_path / "hosts.csv", HOSTS, [
        _host("ws-01", "aid-01", "8.2.100", groups="Live Kiosks", criticality="High"),
        _host("ws-02", "aid-02", "8.10.3", groups="Pre-Live Kiosks", criticality="Unset",
              rfm="yes"),
        _host("ws-03", "aid-03", "8.10.3", groups="Live Kiosks, Sandbox", rfm="yes"),
        _host("ws-04", "aid-04", "8.7.913", "Server", "Linux", groups="Front Desk"),
        _host("ws-05", "aid-05", "8.10.3", "Server", "Linux", groups=""),
    ])


def _discovered(tmp_path: Path) -> Path:
    rows = [{"name": f"dev-{i:02d}", "manufacturer": m} for i, m in enumerate(
        ["Example Ltd", "Example Ltd.", "Sample Corp", "", "--", "Example Ltd",
         "Other GmbH", "", "Sample Corporation", "Example Limited"])]
    return _export(tmp_path / "discovered.csv", DISCOVERED, rows)


def test_the_readers_are_in_the_library():
    assert library()["falcon_estate_coverage"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""
    assert library()["falcon_environment"] is annotation.PLUGIN
    assert annotation.PLUGIN.kind == "annotation"
    assert annotation.PLUGIN.annotation_keys == ("environment",)


def test_nothing_read_gives_one_gap():
    out = reader.step(_ctx(reader.PLUGIN, None))
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.CHANGES_CONCLUSION


def test_vendor_names_fold_across_spellings():
    assert reader.normalise_vendor("Example Ltd.") == reader.normalise_vendor("Example Ltd")
    assert reader.normalise_vendor("Sample Corporation") == "Sample"
    assert reader.normalise_vendor("--") == "" and reader.normalise_vendor("") == ""


def test_the_rows_and_gaps(tmp_path):
    hb = _export(tmp_path / "hb.csv", HEARTBEATS, [
        {"aid": "aid-01", "@timestamp": _ms(20), "_count": "40"},
        {"aid": "aid-02", "@timestamp": _ms(19), "_count": "38"},
        {"aid": "aid-03", "@timestamp": _ms(2), "_count": "5"},
        {"aid": "aid-77", "@timestamp": "2030-05-01T09:00:00Z", "_count": ""},
    ])
    unsupported = _export(tmp_path / "unsupported.csv", UNSUPPORTED, [
        {"name": "cam-01", "manufacturer": "Example Ltd", "confidence": "High",
         "review_status": "Reviewed", "last_seen": "2030-04-02T10:00:00Z"},
        {"name": "", "manufacturer": "", "confidence": "",
         "review_status": "Pending", "last_seen": "2030-04-20"},
        {"name": "-", "manufacturer": "Sample Corp", "confidence": "Low",
         "review_status": "", "last_seen": "--"},
    ])
    settings = {"discovered": str(_discovered(tmp_path)), "heartbeats": str(hb),
                "unsupported": str(unsupported), "criticality_unset": ["unset"],
                "unreviewed": "pending", "environment": WORDS}
    out = reader.step(_ctx(reader.PLUGIN, _hosts(tmp_path), settings))
    rows = by_name(out.records)
    assert list(rows) == ["Estate coverage", "Discovered device vendors",
                          "Sensor version spread", "Asset criticality assignment",
                          "Environment labelling", "Sensor reduced-functionality mode",
                          "Sensor heartbeat recency",
                          "Discovered devices that cannot take the sensor"]
    assert all(a.verdict == "n/a" and a.data_state == "discovery" for a in out.records)

    cov = rows["Estate coverage"]
    assert cov.flags == ["estate-coverage:50"] and cov.hosts_count == 10
    assert cov.extra["sensor_managed"] == "5" and cov.extra["unmanaged"] == "5"
    assert cov.extra["coverage_share"] == "0.500"
    assert cov.extra["unattributed_vendor_rows"] == "3"
    assert len(out.gaps) == 1 and coverage.kind_of(out.gaps[0]) == coverage.EXTENT_UNKNOWN

    vendors = rows["Discovered device vendors"]
    assert vendors.extra["vendor_example"] == "4" and vendors.extra["vendor_sample"] == "2"
    assert vendors.extra["vendor_other"] == "1" and vendors.flags == ["vendor-unattributed:3"]

    spread = rows["Sensor version spread"]
    assert spread.extra["newest"] == "8.10.3" and spread.extra["not_newest"] == "2"
    assert spread.extra["type_server"] == "2" and spread.extra["platform_linux"] == "2"
    assert spread.flags == ["sensor-versions:3"]

    crit = rows["Asset criticality assignment"]
    assert crit.flags == ["criticality-unassigned:1"] and crit.hosts_count == 2
    assert crit.extra == {"criticality_high": "1", "criticality_unset": "1"}

    env = rows["Environment labelling"]
    assert env.flags == ["environment-census:3", "environment-contested:1"]
    assert env.extra["environment_production"] == "1"
    assert env.extra["environment_non_production"] == "1"
    assert env.extra["environment_labelled_production"] == "2"
    assert env.extra["environment_no_group"] == "1"
    assert env.extra["environment_widest_silent_group"] == "Front Desk"

    rfm = rows["Sensor reduced-functionality mode"]
    assert rfm.flags == ["sensor-rfm:2"] and rfm.extra["rfm_hosts"] == "ws-02, ws-03"
    assert rfm.hosts_count == 5

    beat = rows["Sensor heartbeat recency"]
    assert beat.flags == ["sensor-silent:2"]
    assert beat.extra["not_in_host_list"] == "1" and beat.extra["silent_not_in_host_list"] == "1"
    assert beat.extra["host_list_without_heartbeat"] == "2"
    assert beat.extra["beats_total"] == "83"
    assert beat.extra["earliest_last_heartbeat"] == "2030-05-01"

    un = rows["Discovered devices that cannot take the sensor"]
    assert un.flags == ["unsupported-discovered:3"]
    assert un.extra["named"] == "1" and un.extra["reviewed"] == "1"
    assert un.extra["confidence_(not_recorded)"] == "1"
    assert "between 2030-04-02 and 2030-04-20" in un.notes


def test_settings_change_the_line(tmp_path):
    hb = _export(tmp_path / "hb.csv", HEARTBEATS, [
        {"aid": "aid-01", "@timestamp": _ms(20), "_count": "1"},
        {"aid": "aid-02", "@timestamp": _ms(12), "_count": "1"},
    ])
    out = reader.step(_ctx(reader.PLUGIN, _hosts(tmp_path),
                           {"heartbeats": str(hb), "silent_days": 10}))
    beat = by_name(out.records)["Sensor heartbeat recency"]
    assert beat.flags == ["sensor-silent:0"] and beat.extra["silent_days"] == "10"


def test_without_settings_nothing_is_guessed(tmp_path):
    out = reader.step(_ctx(reader.PLUGIN, _hosts(tmp_path)))
    rows = by_name(out.records)
    # No environment words: no environment row. No unset word: no unset count.
    assert "Environment labelling" not in rows
    assert rows["Asset criticality assignment"].flags == []
    # The main host list carries the mode column, so it is read from there.
    assert rows["Sensor reduced-functionality mode"].flags == ["sensor-rfm:2"]
    # No discovered list: no coverage ratio; the heartbeat and unsupported lists are gaps.
    assert "Estate coverage" not in rows
    assert [coverage.kind_of(g) for g in out.gaps] == [coverage.NOT_COLLECTED] * 2


def test_a_named_rfm_list_and_other_headings(tmp_path):
    rfm = _export(tmp_path / "rfm.csv", ("Machine", "Sensor", "Mode"), [
        {"Machine": "ws-01", "Sensor": "aid-01", "Mode": "Yes"},
        {"Machine": "ws-02", "Sensor": "aid-02", "Mode": "No"},
    ])
    settings = {"rfm": str(rfm), "columns": {"rfm": {"machine": "Machine",
                                                     "sensor_id": "Sensor", "rfm": "Mode"}}}
    out = reader.step(_ctx(reader.PLUGIN, _hosts(tmp_path), settings))
    row = by_name(out.records)["Sensor reduced-functionality mode"]
    assert row.extra["rfm_hosts"] == "ws-01" and row.hosts_count == 2


def test_classify():
    words = reader.environment_words({"environment": WORDS})
    assert reader.classify("Live Kiosks", words).value == reader.PRODUCTION
    pre = reader.classify("Pre-Live Kiosks", words)
    assert pre.value == reader.NON_PRODUCTION and not pre.contested
    both = reader.classify("Live Kiosks, Sandbox", words)
    assert both.value == reader.PRODUCTION and both.contested
    assert reader.classify("", words).absence == reader.NO_GROUP
    assert reader.classify("Front Desk", words).absence == reader.GROUP_SILENT
    # Whole words only: "lively" is not "live".
    assert reader.classify("Lively Kiosks", words).absence == reader.GROUP_SILENT
    assert not reader.environment_words({}).any


def _asset(name: str, host: str = "", aid: str = "", state: str = "in-transit",
           source: str = "probe") -> CryptoAsset:
    return CryptoAsset(name=name, data_state=state, protocol="tls", host=host, source=source,
                       extra={"aid": aid} if aid else {})


def test_the_annotation_labels_machine_rows(tmp_path):
    hosts = _export(tmp_path / "hosts.csv", HOSTS, [
        _host("ws-01", "aid-01", groups="Live Kiosks"),
        _host("ws-02", "aid-02", groups="Sandbox"),
        _host("twin", "aid-03", groups="Live Kiosks"),
        _host("twin", "aid-04", groups="Sandbox"),
        _host("same", "aid-05", groups="Front Desk"),
        _host("same", "aid-06", groups="Front Desk"),
    ])
    assets = (_asset("a", host="WS-01"), _asset("b", aid="aid-02", host="elsewhere"),
              _asset("c", host="twin"), _asset("d", aid="aid-04"), _asset("e", host="same"),
              _asset("f", host="ws-01", state="certificate"),
              _asset("g", host="ws-01", source="ct_dns"), _asset("h", host="nobody"))
    out = annotation.step(_ctx(annotation.PLUGIN, hosts, {"environment": WORDS}, assets))
    got = {next(a.name for a in assets if a.bom_ref() == ref): keys["environment"]
           for ref, keys in out.annotations.items()}
    assert sorted(got) == ["a", "b", "d", "e"]
    assert got["a"]["value"] == "production" and got["a"]["valid_at"] == "2030-03-17"
    assert got["b"]["value"] == "non-production"
    assert got["d"]["value"] == "non-production"
    assert got["e"]["value"] == "" and got["e"]["absent"] == "not-measured"
    assert got["a"]["source"] == "falcon_environment"
    assert out.gaps == []


def test_the_annotation_does_nothing_without_words(tmp_path):
    out = annotation.step(_ctx(annotation.PLUGIN, _hosts(tmp_path), {},
                               (_asset("a", host="ws-01"),)))
    assert out.annotations == {} and out.gaps == []


def test_the_annotation_through_the_host(tmp_path):
    """An observation's host runs the annotation over the graded rows."""
    from takestock import plugins

    hosts = _export(tmp_path / "hosts.csv", HOSTS, [_host("ws-01", "aid-01", groups="Live Kiosks")])
    host = plugins.Host({"plugins": [{"name": "falcon_environment", "input": str(hosts),
                                      "settings": {"environment": WORDS}}]},
                        tmp_path / "raw", REF_TIME)
    rows = [_asset("a", host="ws-01")]
    host.annotate(rows)
    assert rows[0].extra["environment"]["value"] == "production"


def test_full_coverage_raises_no_gap(tmp_path):
    disc = _export(tmp_path / "discovered.csv", DISCOVERED,
                   [{"name": f"dev-{i}", "manufacturer": "Example Ltd"} for i in range(5)])
    out = reader.step(_ctx(reader.PLUGIN, _hosts(tmp_path), {"discovered": str(disc)}))
    cov = by_name(out.records)["Estate coverage"]
    assert cov.flags == ["estate-coverage:100"] and cov.extra["unmanaged"] == "0"
    assert coverage.EXTENT_UNKNOWN not in [coverage.kind_of(g) for g in out.gaps]
