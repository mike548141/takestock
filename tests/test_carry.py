"""Carrying an earlier observation's active-probe rows into a new one (``--carry-scan``).

Nothing here reaches a network. The collectors are replaced by steps that
return synthetic rows, and the one plain-HTTP request a carry may send is
answered by a stand-in for the program that sends it. Every name is reserved.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from probe_helpers import fixture

from takestock import carry, cli, collectors, config, coverage, obsarchive, observe
from takestock.collectors import plaintext_scan as ps
from takestock.collectors import spf_senders, ssh_audit
from takestock.model import CryptoAsset
from takestock.util import now_date

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example-widgets"
HELD_AT = datetime(2030, 1, 20, 9, 30, tzinfo=UTC)
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)
RELAY = "relay.example.test"
SILENT_RELAY = "quiet-relay.example.test"


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    config.set_workspace(tmp_path)
    config.set_inbox(SAMPLE / "exports")
    return tmp_path


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class Transport:
    """Stands in for the program the re-check runs, and records every command."""

    def __init__(self) -> None:
        self.sent: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: int = 60, stdin_text: str | None = None) -> str:
        self.sent.append(list(cmd))
        return fixture("curl-plain-http.txt")


def _row(run: observe.Run, name: str, source: str, **kw: object) -> CryptoAsset:
    return CryptoAsset(name=name, data_state="in-transit", source=source, source_class="public",
                       internet_facing=True, collected_at=now_date(run.ref_time), **kw)  # type: ignore[arg-type]


def _tls(run: observe.Run) -> tuple[list[CryptoAsset], list[str], list]:
    (run.raw / "tls-transcript-www.txt").write_text("synthetic transcript\n")
    return [_row(run, "TLS www.example.test:443", "tls_scan", protocol="tls",
                 host="www.example.test", port="443", protocol_versions=["TLSv1.2"])], [], []


def _plaintext(run: observe.Run) -> tuple[list[CryptoAsset], list[str], list]:
    return [
        _row(run, "HTTP shop.example.test:80", "plaintext_scan", protocol="http",
             host="shop.example.test", port="80", flags=["plaintext:http"],
             extra={"plaintext_outcome": ps.CLEARTEXT_SERVED, "http_title": "Shop"}),
        # Cleartext, but not HTTP: the re-check sends nothing for it.
        _row(run, "FTP shop.example.test:21", "plaintext_scan", protocol="ftp",
             host="shop.example.test", port="21",
             extra={"plaintext_outcome": ps.CLEARTEXT_SERVED}),
    ], [], []


def _ssh(run: observe.Run) -> tuple[list[CryptoAsset], list[str], list]:
    return [_row(run, "SSH 203.0.113.22:22", "ssh_audit", protocol="ssh", host="203.0.113.22",
                 port="22", source_name=ssh_audit.SOURCE_ACTIVE)], [], []


def _nothing(run: observe.Run) -> tuple[list[CryptoAsset], list[str], list]:
    return [], [], []


def _spf(calls: list) -> object:
    def collect(target: dict, ref_time: datetime | None = None, scan: bool = False,
                probe: object = None, carried: tuple | None = None, **_kw: object) -> tuple:
        calls.append({"scan": scan, "carried": carried})
        surface = CryptoAsset(name="SPF senders example.com", data_state="email-auth",
                              source=spf_senders.SOURCE_KEY, source_name=spf_senders.SOURCE_NAME,
                              host="example.com", collected_at=now_date(ref_time))
        if carried is not None:
            return [surface, *carried[0]], list(carried[1])
        if not scan:
            return [surface], []
        relay = CryptoAsset(name=f"SMTP {RELAY}:25", data_state="in-transit", protocol="tls",
                            host=RELAY, port="25", source=spf_senders.SOURCE_KEY,
                            source_name=spf_senders.SOURCE_PROBE,
                            collected_at=now_date(ref_time))
        return [surface, relay], [spf_senders.unreachable_gap(SILENT_RELAY),
                                  spf_senders.unreachable_gap(RELAY)]
    return collect


@pytest.fixture()
def stubs(monkeypatch: pytest.MonkeyPatch) -> list:
    """Every collector replaced: synthetic probe rows, no passive rows, a recording SPF step."""
    _no_network(monkeypatch)
    for name in collectors.names("passive"):
        if name != "spf_senders":
            monkeypatch.setitem(observe.PLANS, name,
                                observe.Plan(_nothing, late=observe.PLANS[name].late))
    probes = {"tls_scan": _tls, "plaintext_scan": _plaintext, "ssh_audit": _ssh}
    for name in collectors.names("active"):
        monkeypatch.setitem(observe.PLANS, name, observe.Plan(probes.get(name, _nothing)))
    calls: list = []
    monkeypatch.setattr(spf_senders, "collect", _spf(calls))
    return calls


def _opts(now: datetime = NOW, **kw: object) -> observe.Options:
    opts = observe.Options(now=now, announce=lambda _line: None)
    for k, v in kw.items():
        setattr(opts, k, v)
    return opts


def _held(workspace: Path, when: datetime = HELD_AT) -> Path:
    """A finished --scan observation of the sample target, with a few extra raw files."""
    result = observe.observe(config.load_target("example-widgets"), _opts(when, scan=True))
    raw = result.observation / "raw"
    (raw / "ct-example.test.json").write_text("[]")           # a passive collector's answer
    (raw / "plugins" / "example").mkdir(parents=True)
    (raw / "plugins" / "example" / "note.txt").write_text("a plug-in's own file")
    return result.observation


def _observations(workspace: Path) -> list[str]:
    return sorted(p.name for p in (workspace / "observations").iterdir()
                  if obsarchive.is_stamp(p.name))


# ── carrying within the window ──

def test_a_carry_reuses_the_probe_rows_with_their_dates_and_sources(workspace, stubs,
                                                                     monkeypatch):
    held = _held(workspace)
    transport = Transport()
    monkeypatch.setattr(ps, "run", transport)
    result = observe.observe(config.load_target("example-widgets"),
                             _opts(carry_scan=held.name))
    rows = {a.name: a for a in result.assets}

    tls = rows["TLS www.example.test:443"]
    assert (tls.source, tls.collected_at) == ("tls_scan", "2030-01-20")
    assert rows["SSH 203.0.113.22:22"].source == "ssh_audit"
    assert rows["FTP shop.example.test:21"].collected_at == "2030-01-20"
    http = rows["HTTP shop.example.test:80"]
    assert (http.source, http.collected_at) == ("plaintext_scan", "2030-01-20")
    assert http.extra["cleartext_verified_on"] == "2030-01-31"
    # The ssh-audit files are read afresh by the ingest collector, never carried as well.
    assert sum(1 for a in result.assets if a.name == "SSH build-01.example.test:22") == 1
    inbox_rows = [a for a in result.assets if a.source == "ssh_audit" and a.host != "203.0.113.22"]
    assert inbox_rows and all(a.collected_at != "2030-01-20" for a in inbox_rows)

    # One request, for the one cleartext row on a port that speaks HTTP.
    assert len(transport.sent) == 1 and "http://shop.example.test:80/" in transport.sent[0]

    s = json.loads((result.observation / "summary.json").read_text())
    assert s["observation"]["scan"] is False
    assert s["observation"]["collectors_carried"] == collectors.names("active")
    assert not set(s["observation"]["collectors_skipped"]) & set(collectors.names("active"))
    assert not any("active probes need --scan" in g for g in s["gaps"])
    record = s["carried_scan"]
    assert set(record) == {"from_observation", "from_collected_at", "measured", "age_days",
                           "max_age_days", "collectors", "rows", "by_source", "raw_files",
                           "rechecked"}
    assert record["from_observation"] == held.name == "2030-01-20T0930Z"
    assert record["from_collected_at"] == "2030-01-20T09:30:00Z"
    assert record["measured"] == ["2030-01-20"]
    assert (record["age_days"], record["max_age_days"]) == (11, 31)
    assert record["collectors"] == collectors.names("active")
    assert record["by_source"] == {"plaintext_scan": 2, "spf_senders": 1, "ssh_audit": 1,
                                   "tls_scan": 1}
    assert record["rows"] == 5
    assert record["rechecked"] == [{
        "host": "shop.example.test", "port": "80", "before": ps.CLEARTEXT_SERVED,
        "after": http.extra["plaintext_outcome"], "collected_at": "2030-01-20",
        "verified_on": "2030-01-31", "status": http.extra["cleartext_verify_status"]}]
    assert record["rechecked"][0]["status"].startswith("HTTP/")

    raw = result.observation / "raw"
    assert (raw / "tls-transcript-www.txt").is_file()
    assert len(list(raw.glob("plaintext-verify-*.txt"))) == 1
    assert not (raw / "ct-example.test.json").exists()
    assert not (raw / "plugins" / "example").exists()
    assert record["raw_files"] == 1

    bom = json.loads((result.observation / "bom.cdx.json").read_text())
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["takestock:carried_scan"] == held.name and props["takestock:scan"] == "false"


def test_the_relays_carried_rows_and_gaps_stand_in_for_the_probe(workspace, stubs, monkeypatch):
    held = _held(workspace)
    monkeypatch.setattr(ps, "run", Transport())
    result = observe.observe(config.load_target("example-widgets"),
                             _opts(carry_scan=held.name))
    carried = stubs[-1]["carried"]
    assert stubs[-1]["scan"] is False and carried is not None
    assert [a.host for a in carried[0]] == [RELAY]
    # Only the relay the earlier run actually probed is named as unanswered.
    assert [spf_senders.unreachable_host(g) for g in carried[1]] == [RELAY]
    relay = next(a for a in result.assets if a.host == RELAY)
    assert (relay.source, relay.collected_at) == ("spf_senders", "2030-01-20")
    assert any(spf_senders.unreachable_host(g) == RELAY for g in result.summary["gaps"])


def test_an_uncarried_active_collector_is_a_skip_with_the_earlier_reason(workspace, stubs,
                                                                         monkeypatch):
    held = _held(workspace)
    summary = json.loads((held / "summary.json").read_text())
    summary["observation"]["collectors_run"].remove("intel_amt")
    summary["observation"]["collectors_skipped"]["intel_amt"] = "no hosts were named for it"
    (held / "summary.json").write_text(json.dumps(summary))
    monkeypatch.setattr(ps, "run", Transport())
    result = observe.observe(config.load_target("example-widgets"),
                             _opts(carry_scan=held.name))
    obs = result.summary["observation"]
    assert "intel_amt" not in obs["collectors_carried"]
    assert obs["collectors_skipped"]["intel_amt"] == (
        f"not run in the observation its probe rows were carried from ({held.name}): "
        "no hosts were named for it")


def test_the_age_limit_is_a_setting(workspace, stubs, monkeypatch):
    held = _held(workspace, datetime(2029, 12, 1, 9, 30, tzinfo=UTC))
    target = config.load_target("example-widgets")
    with pytest.raises(observe.ObserveRefused, match="61 days old, past the 31-day limit"):
        observe.observe(target, _opts(carry_scan=held.name))
    assert _observations(workspace) == [held.name]
    monkeypatch.setattr(ps, "run", Transport())
    result = observe.observe(target, _opts(carry_scan=held.name, carry_max_age_days=90))
    assert result.summary["carried_scan"]["max_age_days"] == 90
    assert result.summary["carried_scan"]["age_days"] == 61


# ── the re-check is a probe ──

def test_the_recheck_is_refused_without_an_authorisation_record_and_sends_nothing(
        workspace, stubs, monkeypatch):
    held = _held(workspace)
    transport = Transport()
    monkeypatch.setattr(ps, "run", transport)
    target = config.load_target("example-widgets")
    del target["authorisation"]
    with pytest.raises(observe.ObserveRefused,
                       match="re-checks 1 carried cleartext row.*authorisation"):
        observe.observe(target, _opts(carry_scan=held.name))
    assert transport.sent == []
    assert _observations(workspace) == [held.name]


def test_a_carry_with_nothing_to_recheck_needs_no_authorisation_record(workspace, stubs,
                                                                     monkeypatch):
    monkeypatch.setitem(observe.PLANS, "plaintext_scan", observe.Plan(_nothing))
    held = _held(workspace)
    transport = Transport()
    monkeypatch.setattr(ps, "run", transport)
    target = config.load_target("example-widgets")
    del target["authorisation"]
    result = observe.observe(target, _opts(carry_scan=held.name))
    assert transport.sent == [] and result.summary["carried_scan"]["rechecked"] == []
    assert "TLS www.example.test:443" in {a.name for a in result.assets}


# ── refusals ──

def _refused(workspace: Path, held: Path, match: str, **kw: object) -> None:
    before = _observations(workspace)
    with pytest.raises(observe.ObserveRefused, match=match):
        observe.observe(config.load_target("example-widgets"), _opts(carry_scan=held.name, **kw))
    assert _observations(workspace) == before


def test_carry_with_scan_or_offline_is_refused(workspace, stubs):
    held = _held(workspace)
    _refused(workspace, held, "--carry-scan and --scan", scan=True)
    _refused(workspace, held, "--carry-scan and --offline", offline=True)


def test_carry_from_an_observation_without_scan_is_refused(workspace, stubs):
    held = observe.observe(config.load_target("example-widgets"), _opts(HELD_AT)).observation
    _refused(workspace, held, "taken without --scan")


def test_carry_from_a_carry_is_refused(workspace, stubs, monkeypatch):
    first = _held(workspace)
    monkeypatch.setattr(ps, "run", Transport())
    second = observe.observe(config.load_target("example-widgets"),
                             _opts(datetime(2030, 1, 25, 9, 30, tzinfo=UTC),
                                   carry_scan=first.name)).observation
    _refused(workspace, second, "it was itself a carry")


def test_carry_from_another_target_is_refused(workspace, stubs):
    held = _held(workspace)
    summary = json.loads((held / "summary.json").read_text())
    summary["observation"]["organisation"] = "Example Gadgets Ltd"
    (held / "summary.json").write_text(json.dumps(summary))
    _refused(workspace, held, "Another target's probe rows")


def test_carry_from_a_run_whose_probe_failed_is_refused(workspace, stubs):
    held = _held(workspace)
    summary = json.loads((held / "summary.json").read_text())
    summary["observation"]["failed_collectors"] = ["tls_scan"]
    (held / "summary.json").write_text(json.dumps(summary))
    _refused(workspace, held, "failure in tls_scan")


def test_carry_from_an_unfinished_or_missing_observation_is_refused(workspace, stubs):
    held = _held(workspace)
    (held / "bom.cdx.json").unlink()
    _refused(workspace, held, "has not finished")
    with pytest.raises(observe.ObserveRefused, match="no observation '2030-03-03T0303Z'"):
        observe.observe(config.load_target("example-widgets"),
                        _opts(carry_scan="2030-03-03T0303Z"))


def test_carry_from_an_observation_dated_after_this_one_is_refused(workspace, stubs):
    held = _held(workspace, datetime(2030, 2, 5, 9, 30, tzinfo=UTC))
    _refused(workspace, held, "dated after this observation")


def test_a_negative_age_limit_is_refused(workspace, stubs):
    held = _held(workspace)
    _refused(workspace, held, "whole number of days", carry_max_age_days=-1)


# ── an archived observation ──

def test_an_archived_observation_unpacks_and_carries(workspace, stubs, monkeypatch):
    held = _held(workspace)
    root = held.parent
    entry = obsarchive.archive(held)
    manifest = obsarchive.read_manifest(root)
    manifest["archives"].append(entry)
    obsarchive.write_manifest(root, manifest)
    shutil.rmtree(held)
    monkeypatch.setattr(ps, "run", Transport())
    result = observe.observe(config.load_target("example-widgets"),
                             _opts(carry_scan=held.name))
    assert result.summary["carried_scan"]["from_observation"] == held.name
    assert (result.observation / "raw" / "tls-transcript-www.txt").is_file()
    assert "TLS www.example.test:443" in {a.name for a in result.assets}


# ── the pieces ──

def test_active_sources_are_the_sources_the_active_collectors_write():
    for name in collectors.names("active"):
        module = collectors.load(name)
        assert getattr(module, "SOURCE", None) in carry.active_sources(), name


def test_which_rows_count_as_probe_rows():
    def row(source: str, source_name: str = "") -> CryptoAsset:
        return CryptoAsset(name="r", data_state="in-transit", source=source,
                           source_name=source_name)
    assert carry.is_probe_row(row("tls_scan"))
    assert carry.is_probe_row(row("ssh_audit", ssh_audit.SOURCE_ACTIVE))
    assert not carry.is_probe_row(row("ssh_audit", f"{ssh_audit.INBOX_SOURCE_PREFIX} (x)"))
    assert carry.is_probe_row(row("spf_senders", spf_senders.SOURCE_PROBE))
    assert not carry.is_probe_row(row("spf_senders", spf_senders.SOURCE_NAME))
    assert not carry.is_probe_row(row("ct_dns"))
    assert not carry.is_probe_row(row("netdev"))


def test_an_unreachable_relay_gap_names_its_host():
    gap = spf_senders.unreachable_gap(RELAY)
    assert spf_senders.unreachable_host(gap) == RELAY
    assert spf_senders.unreachable_host("some other gap") == ""
    gaps = spf_senders.carried_gaps([CryptoAsset(name="r", data_state="in-transit", host=RELAY)],
                                    [str(gap), str(spf_senders.unreachable_gap(SILENT_RELAY))])
    assert [str(g) for g in gaps] == [str(gap)]
    assert isinstance(gaps[0], coverage.Gap)


def test_run_info_names_the_carried_collectors(tmp_path):
    run = observe.Run(target={}, raw=tmp_path, observations=tmp_path, options=_opts())
    run.carried = ["tls_scan"]
    assert observe.run_info(run).carried == ("tls_scan",)


# ── the command line ──

def test_the_command_line_passes_the_carry_through(workspace, monkeypatch, capsys):
    seen: list[observe.Options] = []

    def fake(target: dict, options: observe.Options) -> object:
        seen.append(options)
        raise observe.ObserveRefused("stopped here")
    monkeypatch.setattr(cli, "observe", fake)
    argv = ["observe", "example-widgets", "--workspace", str(workspace)]
    assert cli.main([*argv, "--carry-scan", "2030-01-20T0930Z"]) == 2
    assert seen[-1].carry_scan == "2030-01-20T0930Z"
    assert seen[-1].carry_max_age_days == carry.CARRY_MAX_AGE_DAYS == 31
    cli.main([*argv, "--carry-scan", "2030-01-20T0930Z", "--carry-max-age", "7"])
    assert seen[-1].carry_max_age_days == 7
    calls = len(seen)
    assert cli.main([*argv, "--carry-scan", "2030-01-20T0930Z", "--scan"]) == 2
    assert "not allowed with" in capsys.readouterr().err and len(seen) == calls
