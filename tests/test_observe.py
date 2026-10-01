"""Taking an observation, and the command line around it."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import cli, collectors, config, observe

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """A copy of the sample organisation's profile in a fresh workspace."""
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    config.set_workspace(tmp_path)
    config.set_inbox(SAMPLE / "exports")
    return tmp_path


def _quiet() -> observe.Options:
    return observe.Options(now=NOW, announce=lambda _line: None)


# ── what runs ──

def test_every_registered_collector_has_a_step():
    assert sorted(observe.PLANS) == sorted(collectors.REGISTRY)


def test_scan_without_an_authorisation_record_writes_and_contacts_nothing(workspace, monkeypatch):
    _no_network(monkeypatch)
    target = config.load_target("example-widgets")
    del target["authorisation"]
    opts = _quiet()
    opts.scan = True
    with pytest.raises(observe.ObserveRefused, match="authorisation"):
        observe.observe(target, opts)
    assert not (workspace / "observations").exists()


def test_scan_and_offline_together_are_refused(workspace):
    opts = _quiet()
    opts.scan = opts.offline = True
    with pytest.raises(observe.ObserveRefused, match="opposite"):
        observe.observe(config.load_target("example-widgets"), opts)


def test_an_existing_observation_directory_is_never_reused(workspace, monkeypatch):
    _no_network(monkeypatch)
    (workspace / "observations" / observe.stamp_for(NOW)).mkdir(parents=True)
    opts = _quiet()
    opts.offline = True
    with pytest.raises(observe.ObserveRefused, match="already exists"):
        observe.observe(config.load_target("example-widgets"), opts)


def test_an_offline_observation_reads_only_the_supplied_exports(workspace, monkeypatch):
    _no_network(monkeypatch)
    opts = _quiet()
    opts.offline = True
    result = observe.observe(config.load_target("example-widgets"), opts)
    obs = workspace / "observations" / "2030-01-31T0930Z"
    assert result.observation == obs
    assert (workspace / "observations" / "latest").resolve() == obs.resolve()
    for name in ("assets.json", "summary.json", "bom.cdx.json"):
        assert (obs / name).is_file()
    assert (obs / "raw").is_dir()

    s = json.loads((obs / "summary.json").read_text())
    # The zone reader runs last because it compares the zones with every other row.
    # Ingest collectors run offline; the late ones compare their reading with every other row.
    ingest = ["ssh_audit_inbox", "netdev", "dns_zones", "winrm_config"]
    assert s["observation"]["collectors_run"] == ingest
    assert set(s["observation"]["collectors_skipped"]) == set(collectors.REGISTRY) - set(ingest)
    assert any("run offline" in g for g in s["gaps"])
    assert not any("independent DNS resolvers" in g for g in s["gaps"])
    sources = {r["source"] for r in json.loads((obs / "assets.json").read_text())}
    assert {"ssh_audit", "dns_zones", "netdev", "winrm_config"} <= sources
    assert s["complete"] is False and s["collector_failures"] == []

    rows = {r["name"]: r for r in json.loads((obs / "assets.json").read_text())}
    legacy = rows["SSH build-01.example.test:22"]
    assert legacy["verdict"] == "weak"
    assert legacy["disposition"] == "accept-replacement-planned"
    assert legacy["disposition_basis"] == "decided"
    assert legacy["migration_strategy"] == "retire"
    assert legacy["support_status"] == "end-of-support"
    assert rows["SSH files-01.example.test:22"]["verdict"] in ("strong", "pqc")
    assert result.exit_code == observe.EXIT_FINDINGS
    assert sorted(f["name"] for f in result.findings) == [
        "SSH build-01.example.test:22", "WinRM configuration — build-01.example.test"]

    bom = json.loads((obs / "bom.cdx.json").read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert len(bom["components"]) == s["total_assets"] == len(rows)
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["takestock:organisation"] == "Example Widgets Ltd"
    assert props["takestock:offline"] == "true"


def test_a_collector_that_raises_is_a_failure_not_a_crash(workspace, monkeypatch):
    _no_network(monkeypatch)

    def broken(run: object) -> object:
        raise RuntimeError("synthetic defect")
    monkeypatch.setitem(observe.PLANS, "ssh_audit_inbox", observe.Plan(broken, offline=True))
    opts = _quiet()
    opts.offline = True
    result = observe.observe(config.load_target("example-widgets"), opts)
    assert result.failures == ["ssh_audit_inbox: stopped with RuntimeError: synthetic defect"]
    assert result.exit_code == observe.EXIT_ERROR
    assert json.loads((result.observation / "summary.json").read_text())["complete"] is False


# ── the command line ──

def test_help_documents_the_exit_codes(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for line in ("0  clean", "1  findings present", "2  error"):
        assert line in out
    assert cli.main(["observe", "--help"]) == 0
    assert "--offline" in capsys.readouterr().out


def test_version_and_no_command(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.startswith("takestock ")
    assert cli.main([]) == 2


def test_bad_arguments_and_unreadable_inputs_exit_2(tmp_path, capsys):
    assert cli.main(["observe"]) == 2
    assert cli.main(["observe", "x", "--scan", "--offline"]) == 2
    assert cli.main(["observe", "missing-profile", "--workspace", str(tmp_path)]) == 2
    assert cli.main(["cmdb", str(tmp_path / "no-such-observation")]) == 2
    assert "takestock" in capsys.readouterr().err


def test_a_refused_scan_exits_2_and_writes_nothing(workspace, monkeypatch, capsys):
    _no_network(monkeypatch)
    profile = workspace / "targets" / "example-widgets.yaml"
    profile.write_text(profile.read_text().replace("authorisation:", "unused_record:"))
    assert cli.main(["observe", "example-widgets", "--scan", "--workspace", str(workspace)]) == 2
    assert "REFUSED" in capsys.readouterr().err
    assert not (workspace / "observations").exists()


def test_observe_offline_from_the_command_line(workspace, monkeypatch, capsys):
    _no_network(monkeypatch)
    code = cli.main(["observe", "example-widgets", "--offline", "--workspace", str(workspace),
                     "--inbox", str(SAMPLE / "exports")])
    assert code == 1
    out = capsys.readouterr().out
    assert out.startswith("observations/")
    assert "2 finding(s)" in out


def test_ipam_delegates_to_the_ipam_module(monkeypatch):
    seen: list[list[str]] = []
    fake = types.ModuleType("takestock.ipam")
    fake.main = lambda argv: seen.append(argv) or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "takestock.ipam", fake)
    assert cli.main(["ipam", "plan.ipam.yaml", "out", "--exports", "exp"]) == 0
    assert seen == [["plan.ipam.yaml", "out", "--exports", "exp"]]


def test_ipam_without_the_module_is_an_error(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "takestock.ipam", None)
    assert cli.main(["ipam", "plan.ipam.yaml", "out"]) == 2
    assert "not installed" in capsys.readouterr().err
