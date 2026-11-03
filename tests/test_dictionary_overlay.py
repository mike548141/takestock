"""A profile's own daemon-dictionary rows, merged over the bundled table."""

from __future__ import annotations

import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, observe, plugins, rerun
from takestock.plugins import Context, Plugin, StepResult

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)

OVERLAY = """\
daemon_dictionary:
  widgetsrv:
    product: Widget Server
    vendor: Example Co
    category: app-server
    confidence: certain
  sshd:
    product: Example Secure Shell
    vendor: Example Co
    category: remote-access
    confidence: likely
    notes: an in-house build that replaces the packaged server
"""


def _profile(tmp_path: Path, overlay: str | None = OVERLAY) -> dict:
    (tmp_path / "t.yaml").write_text("name: x\n")
    if overlay is not None:
        (tmp_path / "t.daemon-dictionary.yaml").write_text(overlay)
    return {"_path": str(tmp_path / "t.yaml")}


# ── loading and merging ──

def test_overlay_rows_are_added_and_win_over_the_bundled_row(tmp_path):
    bundled = config.load_dictionary()
    merged = config.load_dictionary(_profile(tmp_path))
    assert "widgetsrv" not in bundled
    assert merged["widgetsrv"] == {"binary": "widgetsrv", "product": "Widget Server",
                                   "vendor": "Example Co", "category": "app-server",
                                   "confidence": "certain", "notes": ""}
    # The overlay row replaces the bundled one whole: no bundled cell survives.
    assert bundled["sshd"]["product"] != "Example Secure Shell"
    assert merged["sshd"]["product"] == "Example Secure Shell"
    assert merged["sshd"]["confidence"] == "likely"
    assert merged["sshd"]["notes"] == "an in-house build that replaces the packaged server"
    # Every other row is the bundled table's.
    assert {k: v for k, v in merged.items() if k not in ("widgetsrv", "sshd")} == {
        k: v for k, v in bundled.items() if k != "sshd"}


def test_no_target_or_no_overlay_gives_the_bundled_table(tmp_path):
    bundled = config.load_dictionary()
    assert config.load_dictionary(_profile(tmp_path, overlay=None)) == bundled
    assert config.load_dictionary({}) == bundled
    assert config.load_dictionary_overlay({"_path": str(tmp_path / "t.yaml")}) == {}


def test_an_empty_overlay_adds_nothing(tmp_path):
    assert config.load_dictionary_overlay(_profile(tmp_path, overlay="")) == {}
    assert config.load_dictionary_overlay(_profile(tmp_path, overlay="daemon_dictionary:\n")) == {}


def test_the_overlay_is_never_read_as_a_profile(tmp_path):
    _profile(tmp_path)
    assert config.is_overlay(tmp_path / "t.daemon-dictionary.yaml")
    assert config.target_profiles(tmp_path) == [tmp_path / "t.yaml"]


def test_the_overlay_merges_over_a_workspace_data_copy(tmp_path):
    config.set_workspace(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "daemon-dictionary.csv").write_text("\n".join([
        "binary,product,vendor,category,confidence,notes",
        "exampled,Example Daemon,Example Co,database,certain,", ""]))
    merged = config.load_dictionary(_profile(tmp_path))
    assert set(merged) == {"exampled", "widgetsrv", "sshd"}


# ── what the overlay may hold ──

ROW = "    product: P\n    vendor: V\n    category: backup\n    confidence: certain\n"


@pytest.mark.parametrize("text, message", [
    ("- widgetsrv\n", "must be a mapping with one key"),
    ("daemon_dictionary: {}\nrows: {}\n", "unexpected top-level key(s) rows"),
    ("daemon_dictionary: [widgetsrv]\n", "must be a mapping from binary name"),
    ("daemon_dictionary:\n  widgetsrv: Widget Server\n", "`widgetsrv`: must be a mapping"),
    ("daemon_dictionary:\n  widget srv:\n" + ROW, "`widget srv`: a binary name is"),
    ("daemon_dictionary:\n  true:\n" + ROW, "`True`: a binary name is"),
    ("daemon_dictionary:\n  widgetsrv:\n" + ROW + "    port: 8080\n",
     "unknown field(s) port"),
    ("daemon_dictionary:\n  widgetsrv:\n    product: P\n    category: backup\n"
     "    confidence: certain\n", "missing vendor"),
    ("daemon_dictionary:\n  widgetsrv:\n" + ROW.replace("backup", "Backup software"),
     "category 'Backup software' is not one of"),
    ("daemon_dictionary:\n  widgetsrv:\n" + ROW.replace("certain", "high"),
     "confidence 'high' is not one of"),
    ("daemon_dictionary:\n  widgetsrv:\n" + ROW + "    notes: [a, b]\n",
     "`notes` must be text"),
    ("daemon_dictionary:\n  widgetsrv:\n" + ROW + "  widgetsrv:\n" + ROW, "declared twice"),
    ("daemon_dictionary:\n  widgetsrv: [\n", "not readable as YAML"),
])
def test_a_malformed_overlay_is_refused_naming_the_file(tmp_path, text, message):
    with pytest.raises(ValueError) as caught:
        config.load_dictionary(_profile(tmp_path, overlay=text))
    assert message in str(caught.value)
    assert "t.daemon-dictionary.yaml" in str(caught.value)


def test_notes_are_optional_in_an_overlay_row(tmp_path):
    rows = config.load_dictionary_overlay(
        _profile(tmp_path, overlay="daemon_dictionary:\n  widgetsrv:\n" + ROW))
    assert rows["widgetsrv"]["notes"] == ""


# ── what readers and the run see ──

def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"nothing should touch the network or run a program: {args}")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class _EntryPoint:
    def __init__(self, obj: Plugin) -> None:
        self.name = obj.name
        self._obj = obj

    def load(self) -> Plugin:
        return self._obj


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The sample organisation in a fresh workspace, with its own inbox."""
    _no_network(monkeypatch)
    shutil.copytree(SAMPLE / "targets", tmp_path / "targets")
    shutil.copytree(SAMPLE / "exports", tmp_path / "inbox")
    config.set_workspace(tmp_path)
    config.set_inbox(tmp_path / "inbox")
    return tmp_path


def _listener(monkeypatch: pytest.MonkeyPatch, seen: dict) -> None:
    def step(ctx: Context) -> StepResult:
        seen["dictionary"] = ctx.dictionary
        return StepResult(records=[
            {"device": "app-01.example.test", "port": 443, "transport": "tcp",
             "process": "widgetsrv"},
            {"device": "app-01.example.test", "port": 22, "transport": "tcp",
             "process": "sshd"}])
    plugin = Plugin(name="listeners", kind="host-listener", step=step)
    monkeypatch.setattr(plugins.metadata, "entry_points",
                        lambda group="": [_EntryPoint(plugin)]
                        if group == plugins.ENTRY_POINT_GROUP else [])


def _observe(target: dict) -> observe.Result:
    return observe.observe(target, observe.Options(now=NOW, offline=True,
                                                   announce=lambda _line: None))


def _rows(result: observe.Result) -> dict[str, str]:
    return {a.software_binary: a.software for a in result.assets if a.source == "listeners"}


def test_readers_and_the_run_get_the_merged_table(workspace, monkeypatch):
    seen: dict = {}
    _listener(monkeypatch, seen)
    (workspace / "targets" / "example-widgets.daemon-dictionary.yaml").write_text(OVERLAY)
    target = config.load_target("example-widgets")
    target["plugins"] = ["listeners"]
    result = _observe(target)
    assert seen["dictionary"]["widgetsrv"]["product"] == "Widget Server"
    assert seen["dictionary"]["sshd"]["product"] == "Example Secure Shell"
    # finalise names each row's product from the same merged table.
    assert _rows(result) == {"widgetsrv": "Widget Server", "sshd": "Example Secure Shell"}


def test_without_the_overlay_the_run_gets_the_bundled_table(workspace, monkeypatch):
    seen: dict = {}
    _listener(monkeypatch, seen)
    target = config.load_target("example-widgets")
    target["plugins"] = ["listeners"]
    result = _observe(target)
    assert "widgetsrv" not in seen["dictionary"]
    assert _rows(result) == {"widgetsrv": "", "sshd": config.load_dictionary()["sshd"]["product"]}


def test_a_malformed_overlay_stops_the_observation_before_anything_is_written(workspace):
    (workspace / "targets" / "example-widgets.daemon-dictionary.yaml").write_text(
        "daemon_dictionary:\n  widgetsrv:\n" + ROW.replace("certain", "high"))
    target = config.load_target("example-widgets")
    with pytest.raises(observe.ObserveRefused, match="confidence 'high'"):
        _observe(target)
    assert not (workspace / "observations").exists() or not any(
        (workspace / "observations").iterdir())


def test_a_rerun_names_its_new_rows_from_the_merged_table(workspace, monkeypatch):
    _listener(monkeypatch, {})
    target = config.load_target("example-widgets")
    target["plugins"] = ["listeners"]
    _observe(target)
    (workspace / "targets" / "example-widgets.daemon-dictionary.yaml").write_text(OVERLAY)
    later = datetime(2030, 1, 31, 10, 30, tzinfo=UTC)
    derived = rerun.rerun(target, "2030-01-31T0930Z",
                          rerun.Options(plugins=("listeners",), now=later))
    assert _rows(derived) == {"widgetsrv": "Widget Server", "sshd": "Example Secure Shell"}
