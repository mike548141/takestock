"""Every entry point exits 2 on a missing or unreadable input, never 1 (which means findings)."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from takestock import cli, cmdb, dnsevidence, exits, ipam, requirements, sge, sge_note

PROFILE = "name: example\ndiscovery:\n  email_domains: [example.com]\n"


@pytest.fixture()
def ws(tmp_path: Path) -> Path:
    """A workspace with a profile, an observation whose assets.json is not JSON, and nothing else."""
    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / "example.yaml").write_text(PROFILE)
    bad = tmp_path / "observations" / "bad"
    bad.mkdir(parents=True)
    (bad / "assets.json").write_text("this is not json")
    (tmp_path / "broken.yaml").write_text("name: [unclosed\n")
    return tmp_path


def _cases(ws: Path) -> dict[str, tuple[str, Callable[[], int]]]:
    missing = ws / "observations" / "missing"
    bad = ws / "observations" / "bad"
    profile = str(ws / "targets" / "example.yaml")
    out = str(ws / "out")
    return {
        "requirements, missing observation":
            ("takestock.requirements", lambda: requirements.main([str(missing), out])),
        "requirements, malformed assets":
            ("takestock.requirements", lambda: requirements.main([str(bad), out])),
        "sge, missing profile":
            ("takestock.sge", lambda: sge.main([str(ws / "nowhere.yaml")])),
        "sge, missing observation":
            ("takestock.sge", lambda: sge.main([profile, "--observation", "missing"])),
        "sge, malformed assets":
            ("takestock.sge", lambda: sge.main([profile, "--observation", "bad"])),
        "sge_note, missing observation":
            ("takestock.sge_note", lambda: sge_note.main([str(missing), profile, out])),
        "sge_note, malformed profile":
            ("takestock.sge_note", lambda: sge_note.main([str(bad), str(ws / "broken.yaml"), out])),
        "cmdb, missing observation":
            ("takestock.cmdb", lambda: cmdb.main([str(missing)])),
        "cmdb, malformed assets":
            ("takestock.cmdb", lambda: cmdb.main([str(bad)])),
        "ipam, missing plan":
            ("", lambda: ipam.main([str(ws / "nowhere.ipam.yaml"), out])),
        "dnsevidence, missing profile":
            ("takestock.dnsevidence", lambda: dnsevidence.main([str(ws / "nowhere.yaml")])),
        "takestock requirements, missing observation":
            ("takestock requirements", lambda: cli.main(["requirements", str(missing)])),
        "takestock comply sge, malformed assets":
            ("takestock comply", lambda: cli.main(["comply", "sge", str(bad), profile])),
        "takestock comply sge --format html, missing profile":
            ("takestock comply", lambda: cli.main(["comply", "sge", str(bad), str(ws / "x.yaml"),
                                                   "--format", "html"])),
        "takestock cmdb, malformed assets":
            ("takestock cmdb", lambda: cli.main(["cmdb", str(bad)])),
        "takestock observe, malformed profile":
            ("takestock observe", lambda: cli.main(["observe", str(ws / "broken.yaml")])),
    }


CASE_NAMES = list(_cases(Path("/unused")))


@pytest.mark.parametrize("case", CASE_NAMES)
def test_an_unreadable_input_exits_2_with_a_one_line_message(case: str, ws: Path,
                                                             monkeypatch: pytest.MonkeyPatch,
                                                             capsys: pytest.CaptureFixture):
    monkeypatch.setenv("TAKESTOCK_HOME", str(ws))
    prog, run = _cases(ws)[case]
    assert run() == exits.EXIT_ERROR
    err = capsys.readouterr().err
    assert "Traceback" not in err, err
    if prog:
        assert err.startswith(f"{prog}: "), err


def test_python_dash_m_exits_2_rather_than_with_a_traceback(tmp_path: Path):
    src = Path(requirements.__file__).resolve().parents[1]
    p = subprocess.run([sys.executable, "-m", "takestock.requirements",
                        str(tmp_path / "missing"), str(tmp_path / "out")],
                       capture_output=True, text=True, cwd=tmp_path,
                       env={"PYTHONPATH": str(src), "PATH": "/usr/bin:/bin"})
    assert p.returncode == 2, p.stderr
    assert "Traceback" not in p.stderr
    assert p.stderr.startswith("takestock.requirements: ")


def test_a_defect_still_exits_2_and_keeps_its_traceback(capsys: pytest.CaptureFixture):
    def broken(_: None) -> int:
        raise RuntimeError("a defect")
    assert exits.guarded("prog", broken, None) == exits.EXIT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("prog: internal error") and "RuntimeError: a defect" in err


def test_a_usage_error_passes_through_as_argparse_exits():
    with pytest.raises(SystemExit) as exc:
        sge.main([])
    assert exc.value.code == exits.EXIT_ERROR


def test_findings_and_clean_runs_keep_their_codes():
    assert exits.guarded("prog", lambda n: n, exits.EXIT_FINDINGS) == 1
    assert exits.guarded("prog", lambda n: n, exits.EXIT_CLEAN) == 0
