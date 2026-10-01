"""Workspace resolution and data-file loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from takestock import config


def test_the_workspace_defaults_to_the_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert config.workspace_root() == tmp_path.resolve()
    assert config.targets_dir() == tmp_path.resolve() / "targets"
    assert config.observations_dir() == tmp_path.resolve() / "observations"


def test_the_environment_beats_the_cwd_and_the_override_beats_both(tmp_path, monkeypatch):
    env_ws, cli_ws = tmp_path / "env", tmp_path / "cli"
    monkeypatch.setenv(config.ENV_VAR, str(env_ws))
    assert config.workspace_root() == env_ws.resolve()
    config.set_workspace(cli_ws)
    assert config.workspace_root() == cli_ws.resolve()
    config.set_workspace(None)
    assert config.workspace_root() == env_ws.resolve()


def test_inbox_paths_follow_the_inbox(tmp_path, monkeypatch):
    config.set_workspace(tmp_path)
    assert config.inbox_dir() == tmp_path.resolve() / "inbox"
    inbox = tmp_path.resolve() / "inbox"
    assert config.inbox_path("inbox/exports/hosts.csv") == inbox / "exports" / "hosts.csv"
    assert config.inbox_path("targets/x.yaml") == tmp_path.resolve() / "targets" / "x.yaml"
    assert config.inbox_path("/abs/file.csv") == Path("/abs/file.csv")
    elsewhere = tmp_path / "drop"
    monkeypatch.setenv(config.INBOX_ENV_VAR, str(elsewhere))
    assert config.inbox_path("inbox/hosts.csv") == elsewhere.resolve() / "hosts.csv"


def test_display_path_is_relative_inside_the_workspace(tmp_path):
    config.set_workspace(tmp_path)
    assert config.display_path(tmp_path.resolve() / "targets" / "a.yaml") == "targets/a.yaml"
    assert config.display_path("/elsewhere/b.yaml") == "/elsewhere/b.yaml"


def test_a_workspace_data_file_overrides_the_bundled_one(tmp_path):
    config.set_workspace(tmp_path)
    assert config.data_file("baseline.yaml") == config.BUNDLED_DATA_DIR / "baseline.yaml"
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "baseline.yaml").write_text("tls_versions: {TLSv1.3: strong}\n")
    assert config.load_baseline() == {"tls_versions": {"TLSv1.3": "strong"}}


def test_a_data_folder_in_the_current_directory_is_never_read(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "baseline.yaml").write_text("tls_versions: {}\n")
    monkeypatch.chdir(tmp_path)
    assert config.explicit_workspace() is None
    assert config.workspace_root() == tmp_path.resolve()
    assert config.data_file("baseline.yaml") == config.BUNDLED_DATA_DIR / "baseline.yaml"


def test_a_data_folder_is_read_when_the_environment_names_the_workspace(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "baseline.yaml").write_text("tls_versions: {}\n")
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path))
    assert config.data_file("baseline.yaml") == tmp_path.resolve() / "data" / "baseline.yaml"


def test_the_inbox_override_beats_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(config.INBOX_ENV_VAR, str(tmp_path / "env"))
    config.set_inbox(tmp_path / "cli")
    assert config.inbox_dir() == (tmp_path / "cli").resolve()
    assert config.inbox_path("inbox/x.csv") == (tmp_path / "cli").resolve() / "x.csv"
    config.set_inbox(None)
    assert config.inbox_dir() == (tmp_path / "env").resolve()


def test_a_missing_data_file_names_the_bundled_location(tmp_path):
    config.set_workspace(tmp_path)
    assert config.data_file("absent.yaml") == config.BUNDLED_DATA_DIR / "absent.yaml"


def test_duplicate_keys_are_refused(tmp_path):
    p = tmp_path / "dup.yaml"
    p.write_text("a: 1\nb: 2\na: 3\n")
    with pytest.raises(config.DuplicateKeyError, match="declared twice"):
        config.load_yaml_strict(p)


def test_an_empty_yaml_file_loads_as_an_empty_mapping(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("# nothing here\n")
    assert config.load_yaml_strict(p) == {}


def test_targets_load_by_name_and_overlays_are_not_profiles(tmp_path):
    config.set_workspace(tmp_path)
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "widgets.yaml").write_text("name: Example Widgets Ltd\n")
    (targets / "widgets.dispositions.yaml").write_text("rules: []\n")
    (targets / "widgets.derived-ports.yaml").write_text("derived_ports:\n  www.example.test: [443]\n")
    assert [p.name for p in config.target_profiles()] == ["widgets.yaml"]
    t = config.load_target("widgets")
    assert t["name"] == "Example Widgets Ltd"
    assert t["_path"].endswith("widgets.yaml")
    derived = config.load_derived_ports(t)
    assert derived["www.example.test"] == [443]
    assert derived["_path"].endswith("widgets.derived-ports.yaml")
    rel, absolute = config.recorded_target_paths(t["_path"])
    assert rel == "targets/widgets.yaml" and absolute.endswith("widgets.yaml")


def test_derived_ports_must_be_a_mapping(tmp_path):
    (tmp_path / "t.yaml").write_text("name: x\n")
    (tmp_path / "t.derived-ports.yaml").write_text("derived_ports: [1, 2]\n")
    with pytest.raises(ValueError, match="must be a mapping"):
        config.load_derived_ports({"_path": str(tmp_path / "t.yaml")})
    assert config.load_derived_ports({}) == {}


def test_bundled_reference_lists_load_through_the_config_readers():
    assert config.load_dictionary()["sshd"]["product"]
    assert config.load_vendor_domains()["github.com"]["vendor"] == "GitHub"
    assert config.load_software_lifecycle()["schema"] == 1
    assert config.load_windows_lifecycle()["schema"] == 1


def test_absent_optional_data_files_load_as_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "BUNDLED_DATA_DIR", tmp_path / "nowhere")
    config.set_workspace(tmp_path)
    assert config.load_dictionary() == {}
    assert config.load_vendor_domains() == {}
    assert config.load_software_lifecycle() == {}
    assert config.load_windows_lifecycle() == {}


def test_workspace_data_rows_are_read(tmp_path):
    config.set_workspace(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "daemon-dictionary.csv").write_text("\n".join([
        "binary,product,vendor,category,confidence,notes",
        "widgetd,Widget Daemon,Example Co,Service,certain,", ""]))
    (tmp_path / "data" / "vendor-domains.csv").write_text("\n".join([
        "domain,vendor,category,notes", "Example.COM,Example Co,saas,", ",,,", ""]))
    assert config.load_dictionary()["widgetd"]["product"] == "Widget Daemon"
    assert list(config.load_vendor_domains()) == ["example.com"]


def test_the_bundled_port_table_and_dispositions_load():
    table = config.load_port_encryption()
    assert table["443/tcp"]["posture"] == "encrypted"
    rules = config.load_yaml_strict(config.dispositions_path())
    assert rules["decisions"] == []


def test_data_csv_comment_lines_are_skipped(tmp_path):
    from takestock import config

    f = tmp_path / "x.csv"
    f.write_text("# a header comment\n# another\nbinary,product\nexampled,Example Daemon\n")
    with f.open(newline="") as fh:
        rows = list(config._csv_rows(fh))
    assert rows == [{"binary": "exampled", "product": "Example Daemon"}]


def test_a_module_can_register_its_own_overlay(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OVERLAY_SUFFIXES", list(config.OVERLAY_SUFFIXES))
    (tmp_path / "widgets.yaml").write_text("name: x\n")
    (tmp_path / "widgets.extra-notes.yaml").write_text("notes: []\n")
    assert len(config.target_profiles(tmp_path)) == 2
    config.register_overlay_suffix(".extra-notes.yaml")
    assert [p.name for p in config.target_profiles(tmp_path)] == ["widgets.yaml"]
    with pytest.raises(ValueError):
        config.register_overlay_suffix("notes")
