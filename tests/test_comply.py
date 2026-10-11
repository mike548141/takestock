"""``takestock comply <standard>``: the standards registry and the command over it.

The sample organisation is observed offline, so nothing here reaches a network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from takestock import cli, comply, config, sge, sge_note

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example-widgets"


@pytest.fixture()
def sample_obs(tmp_path: Path) -> Path:
    """An offline observation of the sample organisation, in a copy of its workspace."""
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    code = cli.main(["observe", "example-widgets", "--offline", "--inbox", str(SAMPLE / "exports"),
                     "--workspace", str(tmp_path)])
    assert code in (0, 1)
    return (tmp_path / "observations" / "latest").resolve()


@pytest.fixture()
def unmet_obs(tmp_path: Path) -> Path:
    """A workspace whose one observation holds a soft-failing SPF record: a MUST unmet."""
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "example.yaml").write_text(
        "name: example\ndiscovery:\n  email_domains: [example.com]\n")
    obs = tmp_path / "observations" / "2030-01-31T0930Z"
    obs.mkdir(parents=True)
    rows = [{"name": "SPF example.com", "protocol": "spf", "host": "example.com",
             "flags": ["softfail-all"], "notes": "v=spf1 ~all",
             "extra": {"record": "v=spf1 ~all"}}]
    (obs / "assets.json").write_text(json.dumps(rows))
    config.set_workspace(tmp_path)
    return obs


def test_the_registry_lists_sge_with_its_data():
    std = comply.get("sge")
    assert std.data == "secure-government-email.yaml"
    assert (config.BUNDLED_DATA_DIR / std.data).is_file()
    assert comply.listing().splitlines()[0].split()[0] == "sge"


def test_list_prints_every_standard_and_exits_0(capsys: pytest.CaptureFixture):
    assert cli.main(["comply", "--list"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("sge ") and "Secure Government Email" in out


def test_an_unknown_standard_exits_2_naming_the_known_ones(capsys: pytest.CaptureFixture):
    assert cli.main(["comply", "no-such-standard", "obs", "target"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("takestock comply: unknown standard 'no-such-standard'")
    assert "known standards: sge" in err


@pytest.mark.parametrize("argv", [["comply"], ["comply", "sge"], ["comply", "sge", "obs"]])
def test_a_missing_argument_exits_2(argv: list[str], capsys: pytest.CaptureFixture):
    assert cli.main(argv) == 2
    assert capsys.readouterr().err.startswith("takestock comply: ")


def test_an_unknown_format_is_a_usage_error():
    assert cli.main(["comply", "sge", "obs", "target", "--format", "pdf"]) == 2


def test_the_old_per_standard_commands_are_gone():
    assert cli.main(["sge", "obs", "target"]) == 2
    assert cli.main(["sge-note", "obs", "target"]) == 2


def test_registering_an_id_twice_is_refused():
    with pytest.raises(ValueError, match="already registered"):
        comply.register(comply.get("sge"))


def test_comply_sge_text_is_the_module_report_byte_for_byte(sample_obs: Path,
                                                            capsys: pytest.CaptureFixture):
    module_code = sge.main(["example-widgets", "--observation", sample_obs.name])
    module_out = capsys.readouterr().out
    code = cli.main(["comply", "sge", str(sample_obs), "example-widgets", "--format", "text"])
    assert capsys.readouterr().out == module_out
    assert code == module_code == 0          # offline: every requirement is not measured


def test_comply_sge_writes_the_module_note_byte_for_byte_by_default(sample_obs: Path, tmp_path: Path,
                                                          capsys: pytest.CaptureFixture):
    module_out = tmp_path / "module.html"
    module_code = sge_note.main([str(sample_obs), "example-widgets", str(module_out)])
    capsys.readouterr()
    code = cli.main(["comply", "sge", str(sample_obs), "example-widgets"])
    written = sample_obs / "sge-note.html"
    assert capsys.readouterr().out.strip() == str(written)
    assert written.read_bytes() == module_out.read_bytes()
    assert code == module_code


def test_text_written_with_out_matches_what_the_terminal_shows(unmet_obs: Path, tmp_path: Path,
                                                                capsys: pytest.CaptureFixture):
    assert cli.main(["comply", "sge", str(unmet_obs), "example", "--format", "text"]) == 1
    shown = capsys.readouterr().out
    out = tmp_path / "report.txt"
    assert cli.main(["comply", "sge", str(unmet_obs), "example", "--format", "text",
                     "--out", str(out)]) == 1
    assert capsys.readouterr().out.strip() == str(out)
    assert out.read_text(encoding="utf-8") == shown


def test_an_unmet_must_exits_1_in_both_formats(unmet_obs: Path, tmp_path: Path):
    assert cli.main(["comply", "sge", str(unmet_obs), "example", "--format", "text"]) == 1
    assert cli.main(["comply", "sge", str(unmet_obs), "example",
                     "--out", str(tmp_path / "note.html")]) == 1


def test_a_new_standard_is_reached_by_registering_it(unmet_obs: Path,
                                                     monkeypatch: pytest.MonkeyPatch,
                                                     capsys: pytest.CaptureFixture):
    monkeypatch.setattr(comply, "REGISTRY", dict(comply.REGISTRY))
    comply.register(comply.Standard(
        id="toy", title="A toy standard", data="baseline.yaml", html_name="toy.html",
        evaluate=lambda obs, target: len(comply.load_assets(obs)),
        text=lambda n, obs, target: f"{n} row(s)",
        html=lambda n, obs, target: f"<p>{n} row(s)</p>",
        unmet=lambda n: n > 0))
    assert cli.main(["comply", "--list"]) == 0
    assert "toy  A toy standard" in capsys.readouterr().out
    assert cli.main(["comply", "toy", str(unmet_obs), "example", "--format", "text"]) == 1
    assert capsys.readouterr().out == "1 row(s)\n"
    assert cli.main(["comply", "toy", str(unmet_obs), "example"]) == 1
    assert capsys.readouterr().out.strip() == str(unmet_obs / "toy.html")
    assert (unmet_obs / "toy.html").read_text() == "<p>1 row(s)</p>"
