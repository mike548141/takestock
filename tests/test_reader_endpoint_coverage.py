"""The ``endpoint_coverage`` plug-in: control families no instrument reaches.

Every row is composed here for invented devices (``.example`` hosts, short
sensor identifiers) with round counts.
"""

from __future__ import annotations

import copy
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, observe, plugins
from takestock.model import CryptoAsset
from takestock.plugins import Context
from takestock.policy import Policy
from takestock.readers import endpoint_coverage as ec
from takestock.readers import library

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)

ALL_IDS = [f.slug for f in ec.FAMILIES]
SENSOR = "falcon_estate_coverage"


def _device(source: str, n: int, *, aid: bool = True, host: bool = True, **extra) -> CryptoAsset:
    """One reading of device ``n`` by ``source``, naming it by sensor id and/or host."""
    keys = {"aid": f"agent-a{n}"} if aid else {}
    return CryptoAsset(name=f"{source} {n}", data_state="at-rest", source=source,
                       host=f"pc-{n:03d}.example.test" if host else "",
                       extra={**keys, **extra})


def _fleet(source: str, count: int, **kw) -> list[CryptoAsset]:
    return [_device(source, n, **kw) for n in range(1, count + 1)]


def _texts(gaps: list, token: str) -> list[str]:
    return [str(g) for g in gaps if token in str(g)]


def _unreached_ids(gaps: list) -> set[str]:
    texts = _texts(gaps, ec.FAMILY_TOKEN)
    return {f.slug for f in ec.FAMILIES if any(f.name in g for g in texts)}


def test_the_reader_is_in_the_library():
    plugin = library()["endpoint_coverage"]
    assert plugin is ec.PLUGIN
    assert plugin.kind == "coverage-check" and plugin.late and plugin.gap_prefix is False


def test_the_family_list_is_well_formed():
    assert len(set(ALL_IDS)) == len(ALL_IDS)
    for f in ec.FAMILIES:
        assert f.name and f.question and f.impact and f.harvest, f.slug
    # Some families are deliberately left with no instrument: that is the list's point.
    assert [f.slug for f in ec.FAMILIES if not f.evidence] == [
        "fleet-trend", "configuration-baseline", "application-control", "removable-media",
        "device-retirement"]


def test_an_empty_run_reaches_no_family_and_says_so_without_a_device_count():
    rows, gaps = ec.collect({}, [])
    assert rows == []
    assert _unreached_ids(gaps) == set(ALL_IDS)
    first = _texts(gaps, ec.FAMILY_TOKEN)[0]
    assert "no device has been looked at" in first
    assert "none of the" not in first
    assert not _texts(gaps, ec.SUPPORT_TOKEN) and not _texts(gaps, ec.MANAGEMENT_TOKEN)


def test_an_unreached_family_carries_the_device_count_and_is_not_a_finding():
    rows, gaps = ec.collect({}, _fleet(SENSOR, 10))
    text = next(g for g in _texts(gaps, ec.FAMILY_TOKEN) if "recovery-key" in g.lower())
    assert "none of the 10 device(s) this observation reached" in text
    assert "not evidence that the control is absent" in text
    gap = next(g for g in gaps if "recovery-key" in str(g).lower())
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.nature_of(gap) == coverage.NO_DATA
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION


def test_a_reached_family_is_quiet_when_it_covers_every_device():
    assets = _fleet(SENSOR, 4) + _fleet("falcon_zta", 4)
    _, gaps = ec.collect({}, assets)
    assert "agent-coverage" not in _unreached_ids(gaps)
    assert "platform-integrity" not in _unreached_ids(gaps)
    assert not _texts(gaps, ec.POPULATION_TOKEN)


def test_a_family_reaching_some_devices_names_both_numbers():
    assets = _fleet(SENSOR, 10) + _fleet("falcon_zta", 4)
    rows, gaps = ec.collect({}, assets)
    (text,) = _texts(gaps, ec.POPULATION_TOKEN)
    assert "evidenced for 4 of the 10 device(s)" in text and "other 6" in text
    assert "not devices that failed" in text
    gap = next(g for g in gaps if ec.POPULATION_TOKEN in str(g))
    assert coverage.kind_of(gap) == coverage.EXTENT_UNKNOWN
    assert coverage.nature_of(gap) == coverage.NO_DATA


def test_fleet_level_rows_are_low_fidelity_not_unreached():
    aggregate = [_device("falcon_software", 1, aid=False, host=False)]
    _, gaps = ec.collect({}, _fleet(SENSOR, 5) + aggregate)
    (text,) = _texts(gaps, ec.AGGREGATE_TOKEN)
    assert "installed on the device" in text and "(1 row(s))" in text
    assert "software-inventory" not in _unreached_ids(gaps)
    gap = next(g for g in gaps if ec.AGGREGATE_TOKEN in str(g))
    assert coverage.nature_of(gap) == coverage.LOW_FIDELITY
    assert coverage.kind_of(gap) == coverage.EXTENT_UNKNOWN
    # The aggregate row names no machine, so it adds no device to the population.
    assert ec.device_population(_fleet(SENSOR, 5) + aggregate) == ec.device_population(
        _fleet(SENSOR, 5))


# ── the device population ──

def test_two_exports_naming_a_machine_differently_are_one_device():
    by_both = _device(SENSOR, 1)
    by_host_only = CryptoAsset(name="m", data_state="at-rest", source="m365_bitlocker",
                               host="PC-001.example.test")
    by_id_only = CryptoAsset(name="z", data_state="at-rest", source="falcon_zta",
                             extra={"aid": "agent-a1"})
    assert len(ec.device_population([by_both, by_host_only, by_id_only])) == 1


def test_a_machine_known_only_by_its_host_to_one_export_and_its_id_to_another_stay_two():
    a = CryptoAsset(name="a", data_state="at-rest", source=SENSOR, extra={"aid": "agent-a1"})
    b = CryptoAsset(name="b", data_state="at-rest", source="m365_bitlocker",
                    host="pc-001.example.test")
    # Nothing ties them: no row carries both, so the tool does not guess.
    assert len(ec.device_population([a, b])) == 2


def test_identifiers_chain_across_rows():
    rows = [CryptoAsset(name="a", data_state="x", source=SENSOR, host="h1.example.test",
                        extra={"aid": "s1"}),
            CryptoAsset(name="b", data_state="x", source="falcon_zta", host="h1.example.test",
                        extra={"aid": "s2"})]
    assert len(ec.device_population(rows)) == 1


def test_a_row_from_an_instrument_no_family_names_is_not_a_device():
    other = CryptoAsset(name="o", data_state="x", source="tls_scan", host="web.example.test")
    assert ec.device_population([other]) == set()


# ── the management comparison ──

def test_devices_missing_from_a_management_export_are_named_by_count():
    assets = _fleet(SENSOR, 10) + _fleet("m365_bitlocker", 4, aid=False)
    _, gaps = ec.collect({}, assets)
    (text,) = _texts(gaps, ec.MANAGEMENT_TOKEN)
    assert "4 of 10 device(s)" in text and "6 appear only" in text
    assert "not necessarily unmanaged" in text


def test_no_management_export_is_no_management_gap():
    _, gaps = ec.collect({}, _fleet(SENSOR, 10))
    assert _texts(gaps, ec.MANAGEMENT_TOKEN) == []


def test_a_management_export_covering_every_device_is_quiet():
    _, gaps = ec.collect({}, _fleet(SENSOR, 3) + _fleet("m365_bitlocker", 3))
    assert _texts(gaps, ec.MANAGEMENT_TOKEN) == []


# ── the profile block ──

def test_a_family_can_be_excluded():
    _, gaps = ec.collect({"endpoint_control_families": {"exclude": ["removable-media"]}}, [])
    assert "removable-media" not in _unreached_ids(gaps)
    assert len(_unreached_ids(gaps)) == len(ALL_IDS) - 1
    assert _texts(gaps, ec.PROFILE_TOKEN) == []


def test_an_excluded_id_that_names_no_family_is_reported_and_suppresses_nothing():
    _, gaps = ec.collect({"endpoint_control_families": {"exclude": ["removable-medai"]}}, [])
    assert _unreached_ids(gaps) == set(ALL_IDS)
    (text,) = _texts(gaps, ec.PROFILE_TOKEN)
    assert "removable-medai" in text and "removable-media" in text
    gap = next(g for g in gaps if ec.PROFILE_TOKEN in str(g))
    assert coverage.kind_of(gap) == coverage.COULD_NOT_TEST
    assert coverage.impact_kind_of(gap) == coverage.NARROWS_CONFIDENCE


def test_a_profile_can_add_an_instrument_as_evidence_for_a_family():
    block = {"evidence": {"configuration-baseline": ["compliance_report"]}}
    assets = _fleet(SENSOR, 4) + _fleet("compliance_report", 3, aid=False)
    _, gaps = ec.collect({"endpoint_control_families": block}, assets)
    assert "configuration-baseline" not in _unreached_ids(gaps)
    (text,) = _texts(gaps, ec.POPULATION_TOKEN)
    assert "evidenced for 3 of the 4" in text


def test_evidence_for_an_unknown_family_is_reported():
    _, gaps = ec.collect({"endpoint_control_families": {"evidence": {"nonsense": ["x"]}}}, [])
    (text,) = _texts(gaps, ec.PROFILE_TOKEN)
    assert "nonsense" in text


def test_a_block_that_is_not_a_mapping_is_ignored():
    _, gaps = ec.collect({"endpoint_control_families": ["removable-media"]}, [])
    assert _unreached_ids(gaps) == set(ALL_IDS)


def test_resolve_does_not_change_the_shipped_list():
    families, excluded, unknown = ec.resolve({"endpoint_control_families": {
        "evidence": {"removable-media": ["usb_policy"]}, "exclude": ["fleet-trend", "nope"]}})
    assert excluded == {"fleet-trend"} and unknown == ["nope"]
    assert next(f for f in families if f.slug == "removable-media").evidence == ("usb_policy",)
    assert next(f for f in ec.FAMILIES if f.slug == "removable-media").evidence == ()


def test_excluding_a_family_does_not_shrink_the_device_population():
    # Leaving a control out of the report does not make its instrument's rows any
    # less a reading of a device: the denominator stays put.
    assets = _fleet(SENSOR, 4) + _fleet("falcon_software", 4, aid=False) + [
        _device("falcon_zta", 5)]
    plain = ec.collect({}, assets)[1]
    skipped = ec.collect({"endpoint_control_families": {"exclude": ["software-inventory"]}},
                         assets)[1]
    (a,) = _texts(plain, "credential protection")
    (b,) = _texts(skipped, "credential protection")
    assert "of the 5 device(s)" in a and "of the 5 device(s)" in b


# ── the support horizon ──

def _with_status(n: int, status: str = "supported") -> CryptoAsset:
    a = _device(SENSOR, n)
    a.support_status = status
    return a


def test_devices_with_no_support_status_are_counted_against_those_with_one():
    assets = [_with_status(1), _with_status(2)] + [_device(SENSOR, n) for n in (3, 4, 5, 6)]
    gaps = ec.support_gaps(assets)
    (text,) = [str(g) for g in gaps]
    assert "2 of 6 device(s)" in text and "4 do not" in text
    assert coverage.nature_of(gaps[0]) == coverage.LOW_FIDELITY
    assert coverage.kind_of(gaps[0]) == coverage.EXTENT_UNKNOWN


def test_every_device_with_a_status_is_no_support_gap():
    assert ec.support_gaps([_with_status(n) for n in (1, 2, 3)]) == []
    assert ec.support_gaps([]) == []


def test_a_declared_support_status_is_applied_to_copies_before_counting():
    target = {"lifecycle": {"support_status": {"supported": [r"^pc-00[12]\."]}}}
    assets = _fleet(SENSOR, 4)
    before = copy.deepcopy(assets)
    _, gaps = ec.collect(target, assets)
    (text,) = _texts(gaps, ec.SUPPORT_TOKEN)
    assert "2 of 4 device(s)" in text
    # The rows handed in are never changed.
    assert [a.support_status for a in assets] == [a.support_status for a in before] == [""] * 4


def test_a_bundled_windows_band_is_derived_on_copies_too():
    known = _device(SENSOR, 1, os_version="10.0.26100.1000", sku_family="Enterprise")
    known.collected_at = "2030-01-15"
    unknown = _device(SENSOR, 2)
    _, gaps = ec.collect({}, [known, unknown])
    (text,) = _texts(gaps, ec.SUPPORT_TOKEN)
    assert "1 of 2 device(s)" in text and "1 do not" in text
    assert known.support_status == "" and known.support_end == ""


# ── the step ──

def test_the_step_returns_gaps_only():
    ctx = Context(plugin=ec.PLUGIN, target={}, settings={}, input=None, ref_time=NOW,
                  raw_dir=Path("."), policy=Policy(config.load_baseline()), baseline={},
                  dictionary={}, port_table={}, collected_on="2030-01-31",
                  assets=tuple(_fleet(SENSOR, 2)))
    out = ec.step(ctx)
    assert out.records == [] and len(out.gaps) > 0
    assert all(isinstance(g, coverage.Gap) for g in out.gaps)


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


def test_an_observation_files_the_gaps_and_writes_no_rows(workspace):
    target = config.load_target("example-widgets")
    target["plugins"] = ["endpoint_coverage"]
    target["endpoint_control_families"] = {"exclude": ["fleet-trend"]}
    result = observe.observe(target, observe.Options(now=NOW, offline=True,
                                                     announce=lambda _line: None))
    assert [a for a in result.assets if a.source == "endpoint_coverage"] == []
    gaps = _texts(result.summary["gaps"], ec.FAMILY_TOKEN)
    # The sample's remote-administration export reaches that family, and fleet-trend is excluded.
    assert _unreached_ids(gaps) == set(ALL_IDS) - {"fleet-trend", "remote-management"}
    assert result.summary["plugins"]["endpoint_coverage"]["status"] == "ran"
    assert result.summary["plugins"]["endpoint_coverage"]["rows"] == 0
