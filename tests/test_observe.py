"""Taking an observation, and the command line around it."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import types
from datetime import UTC, datetime, timedelta
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
    ingest = ["ssh_audit_inbox", "netdev", "software_inventory", "dns_zones", "winrm_config"]
    assert s["observation"]["collectors_run"] == ingest
    assert set(s["observation"]["collectors_skipped"]) == set(collectors.REGISTRY) - set(ingest)
    assert any("run offline" in g for g in s["gaps"])
    assert not any("independent DNS resolvers" in g for g in s["gaps"])
    sources = {r["source"] for r in json.loads((obs / "assets.json").read_text())}
    assert {"ssh_audit", "dns_zones", "netdev", "winrm_config", "software_inventory"} <= sources
    assert s["complete"] is False and s["collector_failures"] == []
    assert s["observation"]["failed_collectors"] == []
    from takestock.disposition import load_dispositions_for_target, set_digest
    digest = s["observation"]["dispositions_digest"]
    assert digest.startswith("sha256:")
    assert digest == set_digest(load_dispositions_for_target(config.load_target("example-widgets")))

    rows = {r["name"]: r for r in json.loads((obs / "assets.json").read_text())}
    legacy = rows["SSH build-01.example.test:22"]
    assert legacy["verdict"] == "weak"
    assert legacy["disposition"] == "accept-replacement-planned"
    assert legacy["disposition_basis"] == "decided"
    assert legacy["migration_strategy"] == "retire"
    assert legacy["support_status"] == "end-of-support"
    assert rows["SSH files-01.example.test:22"]["verdict"] in ("strong", "pqc")
    capped = rows["OpenSSL 1.0.2"]
    assert "capability-ceiling:TLSv1.2" in capped["flags"] and capped["verdict"] == "unknown"
    assert rows["OpenSSL 1.1.1"]["extra"]["hosts"] == "vpn.example.test"
    assert rows["OpenSSL 3.0.0"]["hosts_count"] == 2
    assert "version-spread:3" in rows["OpenSSL version spread"]["flags"]
    assert "Example Office Suite 1.0.0" not in rows
    placed = {p["position"]: p["groups"] for p in s["agility"]["positions"]}
    assert [g["label"] for g in placed["replacement"]] == ["OpenSSL 1.0.2"]
    assert [(g["label"], g["count"]) for g in placed["library"]] == [("OpenSSL", 3)]
    assert result.exit_code == observe.EXIT_FINDINGS
    assert sorted(f["name"] for f in result.findings) == [
        "SSH build-01.example.test:22", "WinRM configuration — build-01.example.test"]

    bom = json.loads((obs / "bom.cdx.json").read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert len(bom["components"]) == s["total_assets"] == len(rows)
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["takestock:organisation"] == "Example Widgets Ltd"
    assert props["takestock:offline"] == "true"


def _dispensations(workspace: Path, minute: int = 0) -> dict:
    opts = _quiet()
    opts.offline = True
    opts.now = NOW + timedelta(minutes=minute)      # each run needs its own directory
    result = observe.observe(config.load_target("example-widgets"), opts)
    payload = json.loads((result.observation / "summary.json").read_text())["dispensations"]
    assert payload == result.summary["dispensations"]
    return payload


def _row(payload: dict, name: str) -> dict:
    (row,) = [r for r in payload["rows"] if r["asset"] == name]
    return row


def test_dispensations_are_assessed_on_the_observation_date(workspace, monkeypatch):
    _no_network(monkeypatch)
    payload = _dispensations(workspace)
    assert payload["asof"] == "2030-01-31" and payload["records"] == 1
    build = _row(payload, "SSH build-01.example.test:22")
    assert (build["state"], build["record"]) == ("covered", "DSP-01")
    assert [b["control"] for b in build["breaches"]] == ["17.2.19.C.01"]
    assert payload["counts"]["covered"] == 1
    assert _row(payload, "SSH files-01.example.test:22")["state"] == "not-applicable"


def test_a_dispensation_past_its_review_date_is_lapsed(workspace, monkeypatch):
    _no_network(monkeypatch)
    overlay = workspace / "targets" / "example-widgets.dispositions.yaml"
    overlay.write_text(overlay.read_text().replace('review_by: "2030-06"', 'review_by: "2029-12"'))
    assert _row(_dispensations(workspace), "SSH build-01.example.test:22")["state"] == "lapsed"


def test_a_third_party_dispensation_reads_the_profile_outside_provider_list(workspace,
                                                                           monkeypatch):
    _no_network(monkeypatch)
    overlay = workspace / "targets" / "example-widgets.dispositions.yaml"
    overlay.write_text(overlay.read_text().replace(
        "      protocol: ssh\n    controls:", "      third_party: true\n    controls:"))
    assert _row(_dispensations(workspace),
                "SSH build-01.example.test:22")["state"] == "no-dispensation"
    profile = workspace / "targets" / "example-widgets.yaml"
    profile.write_text(profile.read_text() + "\nthird_party:\n  - name: Example Build Hosting\n"
                       "    domains: [build-01.example.test]\n")
    assert _row(_dispensations(workspace, minute=1),
                "SSH build-01.example.test:22")["state"] == "covered"


def test_an_out_of_cycle_rung_is_acting_not_waiting(workspace, monkeypatch):
    _no_network(monkeypatch)
    from takestock import disposition
    urgent = next(r["track"] for r in disposition.load_ladder() if r["out_of_cycle"])
    overlay = workspace / "targets" / "example-widgets.dispositions.yaml"
    overlay.write_text(overlay.read_text().replace(
        "disposition: accept-replacement-planned", f"disposition: {urgent}"))
    assert _row(_dispensations(workspace), "SSH build-01.example.test:22")["state"] == "acting"


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
    summary = json.loads((result.observation / "summary.json").read_text())
    assert summary["complete"] is False
    assert summary["observation"]["failed_collectors"] == ["ssh_audit_inbox"]


# ── running one step outside an observation ──

def test_one_collector_runs_through_the_public_step_runner(workspace, tmp_path, monkeypatch):
    _no_network(monkeypatch)
    target = config.load_target("example-widgets")
    opts = _quiet()
    opts.offline = True
    run = observe.Run(target=target, raw=tmp_path / "raw", observations=tmp_path / "obs",
                      options=opts)
    rows, failures, _gaps = observe.run_step(run, "ssh_audit_inbox")
    assert rows and failures == [] and run.assets == rows and run.ran == ["ssh_audit_inbox"]
    # A passive collector may not run offline: skipped, and nothing added.
    assert observe.run_step(run, "dnssec") == ([], [], [])
    assert run.skipped == {"dnssec": "the observation was run offline"}
    # Nothing was written: grading and the observation files are observe()'s.
    assert not (tmp_path / "obs").exists() and not (workspace / "observations").exists()
    with pytest.raises(KeyError):
        observe.run_step(run, "no_such_collector")


def test_the_step_runner_never_probes_without_an_authorisation_record(workspace, tmp_path,
                                                                     monkeypatch):
    _no_network(monkeypatch)
    target = config.load_target("example-widgets")
    del target["authorisation"]
    opts = _quiet()
    opts.scan = True
    run = observe.Run(target=target, raw=tmp_path, observations=tmp_path, options=opts)
    assert observe.run_step(run, "tls_scan") == ([], [], [])
    assert "authorisation" in run.skipped["tls_scan"]


def test_a_broken_step_is_returned_as_a_failure(tmp_path, monkeypatch):
    def broken(run: object) -> object:
        raise RuntimeError("synthetic defect")
    monkeypatch.setitem(observe.PLANS, "netdev", observe.Plan(broken, offline=True))
    run = observe.Run(target={}, raw=tmp_path, observations=tmp_path, options=_quiet())
    assert observe.run_step(run, "netdev") == (
        [], ["netdev: stopped with RuntimeError: synthetic defect"], [])
    assert run.failures == ["netdev: stopped with RuntimeError: synthetic defect"]
    assert run.failed == ["netdev"] and run.ran == []
    monkeypatch.setitem(observe.PLANS, "netdev", observe.Plan(
        lambda run: ([], ["netdev: export unreadable", "netdev: second file unreadable"], []),
        offline=True))
    observe.run_step(run, "netdev")
    assert run.failed == ["netdev"] and len(run.failures) == 3


def test_resume_ct_finishes_deferred_reads_and_files_the_failure_gap(tmp_path, monkeypatch):
    from takestock.collectors import ct_dns
    run = observe.Run(target={}, raw=tmp_path, observations=tmp_path, options=_quiet())
    assert observe.resume_ct(run) == ([], [], [])          # nothing was deferred
    run.ct_deferral = ct_dns.CTDeferral(pending=[object()])  # type: ignore[list-item]
    monkeypatch.setattr(ct_dns, "resume", lambda _d: ([], ["ct_dns: example.com: HTTP 429"]))
    rows, failures, gaps = observe.resume_ct(run)
    assert rows == [] and failures == ["ct_dns: example.com: HTTP 429"]
    assert len(gaps) == 1 and run.gaps == gaps and run.failures == failures
    assert run.ct_failures == failures
    assert run.failed == ["ct_dns"]


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
