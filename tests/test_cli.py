"""The ``takestock`` command: each subcommand matches the module it wraps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takestock import cli, config, ipam, sge

D = "example.com"


def _sge_workspace(tmp_path: Path, domains: list[str]) -> Path:
    """A workspace with one profile and one observation holding a soft-failing SPF row."""
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "example.yaml").write_text(
        "name: example\n" + (f"discovery:\n  email_domains: [{', '.join(domains)}]\n"
                             if domains else ""))
    obs = tmp_path / "observations" / "2030-01-31T0930Z"
    obs.mkdir(parents=True)
    rows = [{"name": f"SPF {D}", "protocol": "spf", "host": D, "flags": ["softfail-all"],
             "notes": "v=spf1 ~all", "extra": {"record": "v=spf1 ~all"}}]
    (obs / "assets.json").write_text(json.dumps(rows))
    return obs


def test_ipam_passes_the_lookup_flag_on(monkeypatch: pytest.MonkeyPatch):
    seen: list[list[str]] = []
    monkeypatch.setattr(ipam, "main", lambda argv: seen.append(argv) or 0)
    assert cli.main(["ipam", "plan.ipam.yaml", "out", "--lookup-asn"]) == 0
    assert cli.main(["ipam", "plan.ipam.yaml", "out", "--exports", "ex"]) == 0
    assert seen == [["plan.ipam.yaml", "out", "--lookup-asn"],
                    ["plan.ipam.yaml", "out", "--exports", "ex"]]


def test_sge_prints_the_module_report_with_the_cli_exit_codes(tmp_path: Path,
                                                              capsys: pytest.CaptureFixture):
    obs = _sge_workspace(tmp_path, [D])
    config.set_workspace(tmp_path)
    module_code = sge.main(["example", "--observation", obs.name])
    module_out = capsys.readouterr().out

    code = cli.main(["sge", str(obs), "example", "--workspace", str(tmp_path)])
    out = capsys.readouterr().out
    assert out == module_out
    assert "SGE-SPF-01" in out and "unmet MUST requirement(s)." in out
    assert code == module_code == 1


def test_sge_without_email_domains_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture):
    obs = _sge_workspace(tmp_path, [])
    assert cli.main(["sge", str(obs), "example", "--workspace", str(tmp_path)]) == 2
    assert "email_domains" in capsys.readouterr().err


def test_sge_with_a_missing_observation_is_an_error(tmp_path: Path):
    _sge_workspace(tmp_path, [D])
    assert cli.main(["sge", str(tmp_path / "nowhere"), "example",
                     "--workspace", str(tmp_path)]) == 2
