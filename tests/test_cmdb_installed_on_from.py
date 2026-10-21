"""The register option naming which rows' lists of hosts draw installed-on.

Two synthetic rows name the same release of an invented product: one feed
lists two machines, and a second feed lists a third. Without the option both
lists are read; with it, only the named source's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cmdbfake
import pytest

from takestock import cmdb

PRODUCT = "Example Server"
RELEASE = "Example Server 2.1"


def _rows(*, spaced: bool = False) -> list[dict[str, Any]]:
    rows = cmdbfake.rows()
    rows.append(cmdbfake._row(
        name="inventory Example Server", data_state="inventory", source="example_inventory",
        source_name="Example software inventory", software=PRODUCT, version="2.1",
        extra={"installed_on": ["app-01.example.test", "app-02.example.test"]}))
    rows.append(cmdbfake._row(
        name="second feed Example Server", data_state="inventory", source="example_feed_rows",
        source_name="Example second feed", software=PRODUCT, version="2.1",
        extra={"plugin": "example_feed",
               "installed_on": ["app 03" if spaced else "app-03.example.test"]}))
    return rows


def _build(tmp_path: Path, rows: list[dict[str, Any]] | None = None,
           **kwargs: Any) -> cmdb.Cmdb:
    obs = cmdbfake.write_observation(tmp_path, assets=_rows() if rows is None else rows)
    return cmdb.build(obs, **kwargs)


def _key(register: cmdb.Cmdb, attribute: str, value: str) -> str | None:
    return next((a.item for a in register.assertions
                 if a.attribute == attribute and a.value == value), None)


def _installed_on(register: cmdb.Cmdb, release_label: str) -> set[str]:
    release = _key(register, "name", release_label)
    names = {a.item: a.value for a in register.assertions if a.attribute == "hostname"}
    return {str(names[e.to_key]) for e in register.edges
            if e.kind == "installed-on" and e.from_key == release}


# ── the build ──────────────────────────────────────────────────────────────


def test_without_the_option_every_row_s_list_is_read(tmp_path):
    register = _build(tmp_path)
    assert _installed_on(register, RELEASE) == {
        "app-01.example.test", "app-02.example.test", "app-03.example.test"}
    assert register.installed_on_from is None


def test_only_a_named_source_s_list_draws_installed_on(tmp_path):
    register = _build(tmp_path, installed_on_from=["example_inventory"])
    assert _installed_on(register, RELEASE) == {"app-01.example.test", "app-02.example.test"}
    # The unread list makes no machine and says nothing about one.
    assert _key(register, "hostname", "app-03.example.test") is None
    # The row's own product and release are kept.
    release = _key(register, "name", RELEASE)
    assert release is not None
    assert any(e.kind == "release-of" and e.from_key == release for e in register.edges)


def test_a_row_is_named_by_its_plug_in_too(tmp_path):
    register = _build(tmp_path, installed_on_from=["example_feed"])
    assert _installed_on(register, RELEASE) == {"app-03.example.test"}


def test_a_row_s_own_host_still_carries_its_software(tmp_path):
    register = _build(tmp_path, installed_on_from=["example_inventory"])
    assert _installed_on(register, "OpenSSL 3.0.13") == {"app-01.example.test"}


def test_an_empty_list_reads_no_row_s_list(tmp_path):
    register = _build(tmp_path, installed_on_from=[])
    assert _installed_on(register, RELEASE) == set()
    assert _installed_on(register, "OpenSSL 3.0.13") == {"app-01.example.test"}


def test_an_unread_list_is_not_checked(tmp_path):
    with pytest.raises(ValueError, match="holds a space"):
        _build(tmp_path / "all", _rows(spaced=True))
    register = _build(tmp_path / "named", _rows(spaced=True),
                      installed_on_from=["example_inventory"])
    assert _installed_on(register, RELEASE) == {"app-01.example.test", "app-02.example.test"}


def test_an_unread_list_is_not_counted_as_machines_seen(tmp_path):
    def instruments(register: cmdb.Cmdb) -> set[str]:
        return {p.instrument for p in register.populations}
    assert "Example second feed" in instruments(_build(tmp_path / "all"))
    assert "Example second feed" not in instruments(
        _build(tmp_path / "named", installed_on_from=["example_inventory"]))


@pytest.mark.parametrize("bad", [
    "example_inventory", {"example_inventory": True}, {"example_inventory"}, 3,
    ["example_inventory", ""], ["  "], [3]],
    ids=["string", "mapping", "set", "number", "empty-name", "blank-name", "non-text-name"])
def test_anything_but_a_list_or_tuple_of_names_is_refused(tmp_path, bad):
    with pytest.raises(ValueError, match="installed_on_from must be a list or tuple"):
        _build(tmp_path, installed_on_from=bad)


def test_a_tuple_is_accepted(tmp_path):
    register = _build(tmp_path, installed_on_from=("example_inventory",))
    assert register.installed_on_from == ("example_inventory",)


# ── the register and the profile ───────────────────────────────────────────


def test_the_register_records_the_option_only_when_set(tmp_path):
    obs = cmdbfake.write_observation(tmp_path, assets=_rows())
    plain = cmdb.build_register(obs)
    assert "installed_on_from" not in plain["register"]
    named = cmdb.build_register(obs, installed_on_from=["example_inventory"])
    assert named["register"]["installed_on_from"] == ["example_inventory"]
    assert named["register"]["counts"]["relationships"] < plain["register"]["counts"][
        "relationships"]


def test_a_profile_sets_the_option(tmp_path):
    obs = cmdbfake.write_observation(tmp_path, assets=_rows())
    options = cmdb.profile_options({"cmdb": {"installed_on_from": ["example_inventory"]}})
    assert options.installed_on_from == ("example_inventory",)
    register = cmdb.build_register(obs, **options.build_kwargs())
    assert register["register"]["installed_on_from"] == ["example_inventory"]
    assert cmdb.profile_options({}).installed_on_from is None


@pytest.mark.parametrize("bad", ["example_inventory", ["  "], {"a": 1}, ("example_inventory",)],
                         ids=["string", "blank-name", "mapping", "tuple"])
def test_a_profile_s_bad_list_is_refused(bad):
    with pytest.raises(ValueError, match="cmdb.installed_on_from must be a list"):
        cmdb.profile_options({"cmdb": {"installed_on_from": bad}})


def test_the_written_json_carries_the_option(tmp_path):
    obs = cmdbfake.write_observation(tmp_path / "obs", assets=_rows())
    register = cmdb.build_register(obs, installed_on_from=["example_inventory"])
    written = cmdb.write_outputs(register, tmp_path / "out")
    data = next(p for p in written if p.suffix == ".json" and "keys" not in p.name)
    assert json.loads(data.read_text())["register"]["installed_on_from"] == [
        "example_inventory"]
